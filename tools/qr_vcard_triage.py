"""[SAFETY: read-only] qr_vcard_triage — wave-2 QR: skor OFFLINE payload
vCard/MECARD hasil decode QR (dari scanner/gateway ekspor berizin) untuk
indikasi kontak-phishing (smishing via kontak: impersonasi brand, URL
jebakan di kartu, trap TEL/SMS, blob penyamaran).

Lanjutan `qr_payload_triage` (wave-1 menangani URL; wave-2 ini menangani
kartu kontak). Port konsep dari entri QR-phishing di A-poc/RedTeam-Tools
(SquarePhish, evilqr — kampanye phishing via QR/kontak). Dibangun from
scratch, stdlib-only, NOL jaringan: input = payload TERDEKODE; TIDAK
melakukan fetch, resolve, maupun scan gambar.

Sinyal per payload (semua deterministik dari data):
  - brand-lure        : FN/ORG/N/NOTE memuat kata impersonasi (bank,
                        support, otp, verify, invoice, paket, kantor pos,
                        jne, jnt, wallet, dana, admin, customer service)
  - shortener-url     : URL:/EMAIL: menunjuk domain shortener
  - ip-literal-url    : URL menunjuk IP literal
  - punycode-url      : URL/email memuat xn-- (homograph)
  - http-url          : URL tanpa TLS (info-leveled, tetap dihitung)
  - msg-scheme-url    : URL: dimulai MATMSG:/SMSTO:/MMSTO:/SMS: (jebakan
                        smishing klasik di kartu kontak)
  - large-photo-blob  : PHOTO: satu baris > 4096 char (penyamaran terhadap
                        scanner yang memotong payload)
  - note-instruction  : NOTE berisi instruksi aksi (scan/install/download/
                        login/klik)
  - x-custom-url      : field X-* memuat http(s) URL (side-channel)
  - email-lure        : EMAIL: memuat kata jebakan
Skor = jumlah sinyal; >= 3 high, >= 2 medium, 1 low, 0 info (kontak
normal — zero-FP).

Fail-closed: tidak ada payload vCard/MECARD valid -> exit 2. Temuan =
LEAD skor, bukan keputusan phishing final.

Pemakaian:
  python tools/qr_vcard_triage.py --file vcards.txt --out skor.json
  (payload dipisah baris kosong; atau JSON array of string via --json)
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

SCHEMA = "secai.qr-vcard-triage/1"

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "t.ly", "qr.link",
    "qrco.de", "rebrand.ly", "ow.ly", "buff.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "bit.do", "s.id", "surl.li",
}
_LURE = re.compile(
    r"(bank|banking|support|otp|verify|verifikasi|invoice|tagihan|paket|"
    r"kantor pos|jne|jnt|sicepat|wallet|dana|ovo|gopay|admin|customer "
    r"service|cs\b|briva|takalok|rekening)", re.I)
_INSTRUCTION = re.compile(r"(scan|install|unduh|download|login|masuk|klik|"
                          r"link|verifikasi)", re.I)
_MSG_SCHEME = re.compile(r"^(MATMSG|SMSTO|MMSTO|SMS):", re.I)
_PUNY = re.compile(r"xn--", re.I)

FIELD_RE = re.compile(r"^([A-Za-z0-9\-]+)(?:;([^:]*))?:(.*)$", re.M)


def parse_fields(payload: str) -> list[tuple[str, str, str]]:
    """[(NAME, params, value)] untuk baris field vCard/MECARD."""
    out = []
    for m in FIELD_RE.finditer(payload):
        out.append((m.group(1).upper(), (m.group(2) or "").upper(),
                    m.group(3).strip()))
    return out


def _url_signals(url: str) -> list[str]:
    sig: list[str] = []
    low = url.lower()
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""
    if any(d in low for d in (s + "/" for s in _SHORTENERS)) or host in _SHORTENERS:
        sig.append("shortener-url")
    if _IP_RE.match(host):
        sig.append("ip-literal-url")
    if _PUNY.search(url):
        sig.append("punycode-url")
    if url.lower().startswith("http://"):
        sig.append("http-url")
    return sig


def audit_payload(payload: str) -> dict | None:
    """Skor satu payload vCard/MECARD. None = bukan kartu kontak."""
    is_vcard = "BEGIN:VCARD" in payload.upper() and "END:VCARD" in payload.upper()
    is_mecard = payload.upper().startswith("MECARD:")
    if not (is_vcard or is_mecard):
        return None
    fields = parse_fields(payload)
    signals: list[str] = []

    identity_blob = " ".join(v for n, _p, v in fields
                             if n in ("FN", "N", "ORG", "NOTE", "NICKNAME"))
    if _LURE.search(identity_blob):
        signals.append("brand-lure")

    msg_scheme = any(_MSG_SCHEME.match(v) for n, _p, v in fields
                     if n in ("URL", "TEL"))
    if msg_scheme:
        signals.append("msg-scheme-url")

    for n, _p, v in fields:
        if n in ("URL", "EMAIL") and re.match(r"^https?://", v, re.I):
            signals.extend(_url_signals(v))
        if n == "EMAIL":
            if _LURE.search(v):
                signals.append("email-lure")
            if _PUNY.search(v):
                signals.append("punycode-url")
        if n.startswith("X-") and re.match(r"^https?://", v, re.I):
            signals.append("x-custom-url")

    if any(n == "PHOTO" and len(v) > 4096 for n, _p, v in fields):
        signals.append("large-photo-blob")
    if any(n == "NOTE" and _INSTRUCTION.search(v) for n, _p, v in fields):
        signals.append("note-instruction")

    # dedupe, jaga urutan kemunculan
    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    kind = "vcard" if is_vcard else "mecard"
    fn = next((v for n, _p, v in fields if n == "FN"), "")
    return {"kind": kind, "fn": fn[:80], "signals": signals,
            "score": len(signals)}


def load_payloads(text: str, as_json: bool) -> list[str]:
    if as_json:
        arr = json.loads(text)
        if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
            raise ValueError("JSON harus array of string")
        return arr
    # multi-payload dipisah baris kosong
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def triage_text(text: str, as_json: bool = False) -> dict:
    payloads = load_payloads(text, as_json)
    payloads = [p for p in payloads if len(p) >= 8]
    if not payloads:
        raise ValueError("tidak ada payload valid ditemukan")
    results = []
    for i, payload in enumerate(payloads):
        res = audit_payload(payload)
        if res is None:
            continue
        score = res["score"]
        res["severity"] = ("high" if score >= 3 else
                           "medium" if score >= 2 else
                           "low" if score == 1 else "info")
        res["index"] = i
        results.append(res)
    if not results:
        raise ValueError("tidak ada payload vCard/MECARD valid ditemukan")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        counts[r["severity"]] += 1
    ranked = sorted(results, key=lambda r: -r["score"])
    return {
        "schema": SCHEMA,
        "payloads": len(payloads),
        "cards": len(results),
        "severity_counts": counts,
        "signal_histogram": dict(sorted(
            Counter([s for r in results for s in r["signals"]]).items(),
            key=lambda kv: -kv[1])),
        "finding_count": sum(1 for r in results if r["score"] > 0),
        "findings": [r for r in ranked if r["score"] > 0],
        "clean_count": sum(1 for r in results if r["score"] == 0),
        "note": "skor heuristik atas kartu terdekodenya — bukan keputusan "
                "phishing final; verifikasi manual tetap diperlukan",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="payload terdekode (teks multi-payload / JSON)")
    ap.add_argument("--json", action="store_true",
                    help="input berupa JSON array of string")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, as_json=args.json)
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
