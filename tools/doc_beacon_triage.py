"""[SAFETY: read-only] doc_beacon_triage — nilai KUALITAS callback/URL
beacon dokumen: OOXML external rels + RTF object/protocol tokens.

Pelengkap `maldoc_triage` (yang melaporkan KEBERADAAN rel eksternal /
attachedTemplate = remote template injection, T1221). Tool ini menilai
ISI URL callback-nya sendiri — indikasi dokumen yang menymbul ke luar:
  - ip-literal / punycode / shortener / http-tanpa-TLS pada Target rel
  - lure-path   : path/kueri memuat kata jebakan (login, verify, invoice,
                  otp, token, update)
  - protocol-handler : Target/token `ms-msdt:`/`msdt:`/`search-ms:`
                  (kelas Follina — eksekusi lewat handler, T1204/TA0002)
  - rtf-objdata + rtf-protocol-token: RTF `\objdata` dengan token
                  ms-msdt/search-ms (vektor tanpa makro, kasus Follina
                  2022) — RTF belum dicover maldoc_triage
  - beacon-density : >= 2 external URL non-brand di satu dokumen
Konsep referensi: entri maldoc/beacon di A-poc/RedTeam-Tools; dibangun
from scratch, stdlib-only, NOL jaringan, NOL eksekusi dokumen (RTF =
bytes decode latin-1; OOXML = zipfile; tidak pernah dibuka Office).

Fail-closed: file tidak ada / bukan OOXML+RTF yang bisa dibaca -> exit 2.
Tanpa URL/object -> 0 temuan (exit 0) — dokumen web normal = aman (FP
rendah, sesi pola maldoc_triage).

Pemakaian:
  python tools/doc_beacon_triage.py --file sampel.docx --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

SCHEMA = "secai.doc-beacon-triage/1"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "t.ly",
               "rebrand.ly", "ow.ly", "buff.ly", "rb.gy", "shorturl.at",
               "tiny.cc", "bit.do", "s.id"}
_LURE = re.compile(r"(login|signin|verify|otp|token|invoice|tagihan|update|"
                   r"secure|account|admin|credential|password)", re.I)
_PROTO = re.compile(r"(ms-msdt:|msdt:|search-ms:)", re.I)
_RTF_TOKEN = re.compile(
    r"\\objdata|\\object|\\objclass|ms-msdt:|msdt:|search-ms:", re.I)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)


def _url_signals(url: str) -> list[str]:
    sig: list[str] = []
    try:
        parsed = urlparse(url)
    except ValueError:
        return sig
    host = (parsed.hostname or "").lower()
    if _IP_RE.match(host):
        sig.append("ip-literal")
    if "xn--" in host or ".xn--" in url.lower():
        sig.append("punycode")
    if host in _SHORTENERS:
        sig.append("shortener")
    if url.lower().startswith("http://"):
        sig.append("http-not-https")
    if _LURE.search(parsed.path or "") or _LURE.search(parsed.query or ""):
        sig.append("lure-path")
    return sig


def _extract_ooxml_urls(data: bytes) -> tuple[list[str], list[str]]:
    """(semua external Target [URL + protokol], nama rels yang menampung)."""
    urls: list[str] = []
    sources: list[str] = []
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
        for name in zf.namelist():
            if not name.endswith(".rels"):
                continue
            xml = zf.read(name).decode("utf-8", errors="replace")
            for m in re.finditer(r'<Relationship[^>]*>', xml):
                tag = m.group(0)
                if 'TargetMode="External"' not in tag and \
                        "TargetMode='External'" not in tag:
                    continue
                tm = re.search(r'Target="([^"]+)"', tag)
                if not tm:
                    continue
                target = tm.group(1)
                if target.startswith(("http://", "https://")):
                    urls.append(target)
                    sources.append(name)
                elif _PROTO.match(target):
                    # protokol-handler (ms-msdt:/msdt:/search-ms:) —
                    # bukan http, tetap kandidat eksekusi (kelas Follina)
                    urls.append(target)
                    sources.append(name)
    return urls, sources


def triage_file(path: Path) -> dict:
    data = path.read_bytes()
    is_ooxml = data[:2] == b"PK"
    is_rtf = data[:5] == b"{\\rtf"
    if not (is_ooxml or is_rtf):
        raise ValueError(f"bukan dokumen OOXML/RTF yang dikenali: {path}")

    findings: list[dict] = []
    url_signals: list[str] = []
    urls_found = 0
    if is_ooxml:
        urls, sources = _extract_ooxml_urls(data)
        urls_found = len(urls)
        nonbrand = 0
        for url, src in zip(urls, sources):
            sigs = _url_signals(url)
            if _PROTO.match(url):
                sigs.append("protocol-handler")
            url_signals.extend(sigs)
            if sigs:
                nonbrand += 1
                findings.append({
                    "type": "beacon-url",
                    "severity": ("critical" if "protocol-handler" in sigs
                                 else "high" if len(sigs) >= 2 or "ip-literal" in sigs
                                 else "medium"),
                    "detail": f"external rel callback {url[:160]}",
                    "evidence": f"source={src}; signals={sigs}",
                })
        if len(urls) >= 2 and nonbrand >= 2:
            findings.append({
                "type": "beacon-density",
                "severity": "medium",
                "detail": f"{nonbrand} external callback berisiko dari "
                          f"{len(urls)} URL eksternal",
                "evidence": "rels scan OOXML",
            })
    else:  # RTF
        text = data.decode("latin-1", errors="replace")
        urls_found = len(set(_URL_RE.findall(text)))
        tokens = sorted(set(m.group(0).lower()
                            for m in _RTF_TOKEN.finditer(text)))
        if "\\objdata" in tokens and (_PROTO.search(text) or "objclass" in tokens):
            findings.append({
                "type": "rtf-objdata-protocol",
                "severity": "critical",
                "detail": "RTF \\objdata dengan token protokol/objclass "
                          "(kelas Follina — eksekusi tanpa makro)",
                "evidence": f"tokens={tokens[:6]}",
            })
        for url in _URL_RE.findall(text)[:20]:
            sigs = _url_signals(url)
            if sigs:
                findings.append({
                    "type": "rtf-beacon-url",
                    "severity": "high" if len(sigs) >= 2 else "medium",
                    "detail": f"URL di RTF: {url[:160]}",
                    "evidence": f"signals={sigs}",
                })
        if _PROTO.search(text):
            url_signals.append("protocol-handler")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "schema": SCHEMA,
        "file": str(path),
        "doc_type": "ooxml" if is_ooxml else "rtf",
        "external_urls": urls_found,
        "severity_counts": counts,
        "signal_histogram": dict(sorted(
            Counter(url_signals).items(), key=lambda kv: -kv[1])),
        "finding_count": len(findings),
        "findings": findings,
        "clean": len(findings) == 0,
        "note": "penilaian kualitas URL callback/objek — keberadaan rel "
                "eksternal & remote template injection dilaporkan oleh "
                "maldoc_triage (T1221); bukan keputusan final",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="dokumen OOXML/RTF")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path)
    except zipfile.BadZipFile as exc:
        print(f"ERROR: OOXML rusak: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
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
