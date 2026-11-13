"""Triase OFFLINE (stdlib-only, NOL jaringan).

Sinyal per capture (semua deterministik dari data):
  - redirect-chain    : >= 3 hop redirect dari halaman pertama
                        (malvertising/jebakan klasik)
  - cross-domain-post : POST ke host selain host halaman pertama
                        (risiko kredensial dikirim keluar)
  - credentials-in-url: kueri memuat password/token/apikey/secret/email=
  - ip-literal / punycode / shortener / http-not-https pada entry
  - third-party-script: >= 5 skrip dari host selain host pertama
                        (kepadatan tracker)
  - tracking-pixel    : >= 3 gambar <500 byte dari host sama
Skor capture = jumlah sinyal; >= 3 high, 2 medium, 1 low, 0 info.

Fail-closed: bukan HAR ({log:{entries:[...]}}) -> exit 2. Entry tanpa
url valid diabaikan; capture kosong -> exit 2.

Pemakaian:
  python tools/capture_triage.py --file capture.har --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

SCHEMA = "secai.capture-triage/1"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "t.ly",
               "qr.link", "qrco.de", "rebrand.ly", "ow.ly", "buff.ly",
               "rb.gy", "shorturl.at", "tiny.cc", "bit.do"}
_CREDQ = re.compile(r"[?&](password|passwd|pwd|token|apikey|api_key|secret|"
                    r"access_token|email|user)=", re.I)
_PIXEL_MIN = 3
_PIXEL_MAXBYTES = 500
_SCRIPT_MIN = 5


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _url_signals(url: str) -> list[str]:
    sig: list[str] = []
    try:
        parsed = urlparse(url)
    except ValueError:
        return sig
    host = (parsed.hostname or "").lower()
    if _IP_RE.match(host):
        sig.append("ip-literal")
    if "xn--" in host:
        sig.append("punycode")
    if host in _SHORTENERS:
        sig.append("shortener")
    if url.lower().startswith("http://"):
        sig.append("http-not-https")
    if _CREDQ.search(url):
        sig.append("credentials-in-url")
    return sig


def triage_har(doc: dict, source: str) -> dict:
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = (log or {}).get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("bukan HAR valid (log.entries kosong/tidak ada)")

    urls: list[str] = []
    hosts: Counter = Counter()
    redirects = 0
    for e in entries:
        u = ((e.get("request") or {}).get("url")) if isinstance(e, dict) else None
        if not u or not u.startswith(("http://", "https://")):
            continue
        urls.append(u)
        hosts[_host(u)] += 1
        if (e.get("response") or {}).get("redirectURL"):
            redirects += 1
    if not urls:
        raise ValueError("HAR tanpa entry URL valid")

    first_party = _host(urls[0]) or _host(urls[0])
    signals: list[str] = []
    if redirects >= 3:
        signals.append("redirect-chain")

    findings: list[dict] = []

    for u in urls:
        method = ""
        for e in entries:
            if isinstance(e, dict) and (e.get("request") or {}).get("url") == u:
                method = (e.get("request") or {}).get("method", "")
                break
        sigs = _url_signals(u)
        if method == "POST" and _host(u) != first_party:
            sigs.append("cross-domain-post")
        if sigs:
            findings.append({
                "type": "risky-entry",
                "severity": ("high" if "cross-domain-post" in sigs
                             or "credentials-in-url" in sigs
                             else "medium" if len(sigs) >= 2 else "low"),
                "detail": f"{method} {u[:160]}",
                "evidence": f"signals={sigs}; first_party={first_party}",
            })
        signals.extend(sigs)

    # hitung skrip pihak ketiga dari mimeType respons
    tp_scripts = 0
    tp_hosts: set[str] = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        u = (e.get("request") or {}).get("url") or ""
        if not u.startswith(("http://", "https://")):
            continue
        h = _host(u)
        mime = ((e.get("response") or {}).get("content") or {}).get("mimeType") or ""
        if mime.startswith("application/javascript") and h != first_party:
            tp_scripts += 1
            tp_hosts.add(h)
    if tp_scripts >= _SCRIPT_MIN:
        signals.append("third-party-script")
        findings.append({
            "type": "third-party-script",
            "severity": "low",
            "detail": f"{tp_scripts} skrip pihak ketiga dari "
                      f"{len(tp_hosts)} host",
            "evidence": f"hosts={sorted(tp_hosts)[:6]}",
        })

    pixel_hosts: Counter = Counter()
    for e in entries:
        if not isinstance(e, dict):
            continue
        u = (e.get("request") or {}).get("url") or ""
        h = _host(u)
        resp = e.get("response") or {}
        mime = (resp.get("content") or {}).get("mimeType") or ""
        size = (resp.get("content") or {}).get("size") or 0
        if (mime.startswith("image/") and 0 < size < _PIXEL_MAXBYTES
                and h != first_party):
            pixel_hosts[h] += 1
    if any(v >= _PIXEL_MIN for v in pixel_hosts.values()):
        signals.append("tracking-pixel")
        findings.append({
            "type": "tracking-pixel",
            "severity": "low",
            "detail": ">= 3 gambar mungil dari host sama (pixel tracking)",
            "evidence": f"hosts={dict(pixel_hosts.most_common(3))}",
        })

    # dedupe sinyal utk skor
    unique = sorted(set(signals))
    score = len(unique)
    sev = ("high" if score >= 3 else
           "medium" if score == 2 else
           "low" if score == 1 else "info")
    return {
        "schema": SCHEMA,
        "file": source,
        "entries": len(entries),
        "hosts": len(hosts),
        "first_party": first_party,
        "redirect_hops": redirects,
        "top_hosts": dict(hosts.most_common(6)),
        "severity": sev,
        "signals": unique,
        "signal_histogram": dict(sorted(
            Counter(signals).items(), key=lambda kv: -kv[1])),
        "finding_count": len(findings),
        "findings": findings,
        "clean": len(findings) == 0,
        "note": "triase pasif capture HAR — bukan keputusan final; "
                "verifikasi manual tetap diperlukan",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="capture HAR (.har)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        result = triage_har(doc, str(path))
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
