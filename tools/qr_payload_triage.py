"""[SAFETY: read-only] qr_payload_triage — skor OFFLINE payload hasil decode
QR code (dari scanner/gateway ekspor berizin) untuk indikasi quishing
(phishing via QR: credential-harvest, redirect berantai, pelacakan).

Port konsep dari entri QR-phishing di A-poc/RedTeam-Tools (SquarePhish,
evilqr — kampanye phishing berbasis QR) — versi triase pasif: kode ini
ditulis from scratch, stdlib-only, NOL jaringan: input = daftar payload
TERDEKODE (file teks satu-payload-per-baris, atau JSON/CSV dari ekspor
scanner), TIDAK melakukan fetch, resolve, maupun scan gambar.

Mekanisme skor (semua lead berbasis bukti, bobot bisa diatur):
  - credential-lure   : path/kueri memuat kata jebakan login (login,
                        signin, verify, secure, update, password, wallet,
                        sso, oauth) di dalam host/path
  - ip-literal        : host = IP literal (bukan domain resmi)
  - shortener         : domain shortener umum (bit.ly, t.co, tinyurl,
                        is.gd, cutt.ly, t.ly, qr.link, ...)
  - embedded-url      : URL di dalam parameter url/next/redirect/r/u
                        (redirect terbuka berantai — pola quishing klasik)
  - userinfo-trick    : scheme://user@host (kaburkan host asli)
  - punycode          : host mengandung xn-- (homograph)
  - non-http-scheme   : tel:/sms:/mailto:/data: (pola social-engineering)
  - autoredir-marker  : payload memuat pola auto-redirect JS/meta khas
                        halaman jebakan
Skor = jumlah sinyal; >= 3 high, >= 2 medium, 1 low.

Fail-closed: tidak ada payload valid -> exit 2. Temuan = LEAD skor, bukan
keputusan phishing final.

Pemakaian:
  python tools/qr_payload_triage.py --file payloads.txt --out skor.json
  python tools/qr_payload_triage.py --file scan.csv --csv-col 2
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCHEMA = "secai.qr-payload-triage/1"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_LURE = re.compile(
    r"(login|log[-_ ]?in|signin|sign[-_ ]?in|verify|secure|update|password|"
    r"wallet|sso|oauth|recover|unlock|billing|invoice|account)", re.I)
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "t.ly", "qr.link",
    "qrco.de", "rebrand.ly", "ow.ly", "buff.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "bit.do",
}
_OPENRED = re.compile(r"[?&](url|next|redirect|redir|r|u|return|to|goto)=",
                      re.I)
_SCHEME_BAD = re.compile(r"^(tel|sms|mailto|data|javascript):", re.I)
_NONHTTP = ("tel:", "sms:", "mailto:", "data:", "javascript:")
_UNPARSED_SAMPLE_MAX = 10


def _parse_payloads(path: Path, csv_col: int) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return []
    if path.suffix.lower() in (".json",) and text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        out: list[str] = []
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    out += [str(x) for x in v]
                elif isinstance(v, str):
                    out.append(v)
        elif isinstance(data, list):
            for it in data:
                if isinstance(it, str):
                    out.append(it)
                elif isinstance(it, dict):
                    for k in ("url", "payload", "value", "qr", "decoded"):
                        if it.get(k):
                            out.append(str(it[k]))
        return [x.strip() for x in out if x.strip()]
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        if "," in s and csv_col > 1:
            parts = s.split(",")
            if len(parts) >= csv_col:
                s = parts[csv_col - 1].strip().strip('"')
        lines.append(s)
    return lines


def score_payload(raw: str, weights: dict | None = None) -> dict:
    weights = weights or {"credential-lure": 2}
    signals: list[str] = []
    host = ""
    scheme = ""
    try:
        pr = urlparse(raw)
        scheme = (pr.scheme or "").lower()
        host = (pr.hostname or "").lower()
    except ValueError:
        pass
    low = raw.lower()

    if _LURE.search(low):
        signals.append("credential-lure")
    if host and _IP_RE.match(host):
        signals.append("ip-literal")
    if host in _SHORTENERS or any(s in low for s in _SHORTENERS):
        signals.append("shortener")
    qs = parse_qs(urlparse(raw).query) if "://" in raw else {}
    for k in qs:
        if _OPENRED.search(f"?{k}="):
            signals.append("embedded-url")
            break
    if _OPENRED.search(low):
        if "embedded-url" not in signals:
            signals.append("embedded-url")
    if "@" in raw and "://" in raw:
        pre, _, rest = raw.rpartition("@")
        if pr and pr.hostname and rest and pr.hostname in raw.split("@")[-1]:
            signals.append("userinfo-trick")
    if host.startswith("xn--") or ".xn--" in host:
        signals.append("punycode")
    if _SCHEME_BAD.match(raw.strip()):
        signals.append("non-http-scheme")
        scheme = raw.strip().split(":", 1)[0]
    if re.search(r"(http[-_ ]?equiv|meta http-equiv|window\.location|"
                 r"location\.replace|document\.location)", low):
        signals.append("autoredir-marker")

    # dedup sinyal; skor berbobot sederhana
    unique = sorted(set(signals))
    score = sum(weights.get(s, 1) for s in unique)
    sev = "info"
    if score >= 3:
        sev = "high"
    elif score == 2:
        sev = "medium"
    elif score == 1:
        sev = "low"
    return {
        "payload": raw[:160],
        "scheme": scheme or ("n/a"),
        "host": host[:80],
        "signals": unique,
        "score": score,
        "severity": sev,
    }


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")  # (terdefinisi di atas)


def triage_file(path: Path, csv_col: int,
                weights: dict) -> dict:
    payloads = _parse_payloads(path, csv_col)
    payloads = [p for p in payloads if len(p) >= 4]
    if not payloads:
        raise ValueError("tidak ada payload valid ditemukan")
    results = [score_payload(p, weights) for p in payloads]
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        counts[r["severity"]] += 1
    ranked = sorted(results, key=lambda r: -r["score"])
    return {
        "schema": SCHEMA,
        "file": str(path),
        "payloads": len(results),
        "severity_counts": counts,
        "signal_histogram": dict(sorted(
            Counter([s for r in results for s in r["signals"]]).items(),
            key=lambda kv: -kv[1])),
        "finding_count": sum(1 for r in results if r["score"] > 0),
        "findings": [r for r in ranked if r["score"] > 0],
        "clean_count": sum(1 for r in results if r["score"] == 0),
        "thresholds": {"weights": weights},
        "note": "skor heuristik atas payload terdekodenya — bukan keputusan "
                "phishing final; verifikasi manual tetap diperlukan",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Skor payload QR terdekodenya utk indikasi quishing "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--file", required=True,
                    help="file payload terdekodenya (txt/json/csv)")
    ap.add_argument("--csv-col", type=int, default=2,
                    help="kolom payload pada input CSV (default 2)")
    ap.add_argument("--weight-credential", type=int, default=2,
                    help="bobot sinyal credential-lure (default 2)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    weights = {"credential-lure": args.weight_credential}
    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, args.csv_col, weights)
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
