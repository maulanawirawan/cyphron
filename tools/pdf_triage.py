"""[SAFETY: read-only] pdf_triage — triase statis PDF berbahaya.

Port konsep dari antrean SKILL-PORT-QUEUE #0212 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-malicious-pdf-with-peepdf'
— pdfid/pdf-parser/peepdf). Dibangun from scratch, stdlib-only,
NOL jaringan, NOL pembuka PDF: file hanya dibaca sebagai byte +
dekompresi stream FlateDecode (zlib) untuk memindai isi terkompresi.

Mekanisme (pola hitung keyword ala pdfid + isi stream ala pdf-parser):
  - hitung keyword aktif: /JavaScript /JS /OpenAction /AA /Launch
    /EmbeddedFile /URI /RichMedia /SubmitForm /GoToE /XFA /AcroForm
    /JBIG2Decode / Decrypt (objek terenkripsi)
  - dekompresi stream FlateDecode lalu pindai ulang di dalamnya
    (JS payload yang disembunyikan di stream terkompresi)
  - /OpenAction atau /AA menunjuk JavaScript = vektor eksekusi otomatis
  - hitung objek (obj/endobj), header %PDF, EOF marker

Verdict fail-closed:
  - CLEAN           : header sah, nol keyword aktif (di dalam & luar stream).
  - SUSPICIOUS      : >= 2 keyword aktif, ATAU keyword berisiko tinggi tunggal.
  - MALICIOUS-LIKELY: OpenAction/AA + JavaScript bersama, ATAU >= 1 critical
                      (Launch/EmbeddedFile dengan JS, RichMedia), ATAU
                      >= 4 keyword aktif.
  - INCONCLUSIVE    : PDF terenkripsi, header rusak, atau stream tak bisa
                      didekompresi penuh — tidak pernah mengklaim CLEAN.
  - Bukan PDF -> exit 2.

Pemakaian:
  python tools/pdf_triage.py --pdf lampiran.pdf --out triage.json
  python tools/pdf_triage.py --pdf lampiran.pdf --fail-on SUSPICIOUS
Exit: 0 verdict < fail-on; 1 verdict >= fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

SCHEMA = "cyphron.pdf-triage/1"

VERDICTS = ("CLEAN", "INCONCLUSIVE", "SUSPICIOUS", "MALICIOUS-LIKELY")
MAX_EVIDENCE = 240
MAX_STREAM_BYTES = 16 * 1024 * 1024

# keyword -> risiko. critical = vektor eksekusi/sampah aktif yang nyaris
# selalu hostile ketika dikombinasikan; high = perlu konteks; info.
KEYWORDS: dict[str, str] = {
    "/JavaScript": "high",
    "/JS": "high",
    "/OpenAction": "critical",
    "/AA": "high",
    "/Launch": "critical",
    "/EmbeddedFile": "high",
    "/RichMedia": "critical",
    "/SubmitForm": "medium",
    "/URI": "medium",
    "/GoToE": "medium",
    "/GoToR": "medium",
    "/XFA": "medium",
    "/AcroForm": "info",
    "/JBIG2Decode": "high",   # sejarah CVE decoder JBIG2 (Ebola 2010)
    "/Encrypt": "info",       # terenkripsi -> INCONCLUSIVE
}

STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
FLATE_RE = re.compile(rb"/Filter\s*/FlateDecode")
OBJ_RE = re.compile(rb"\b(\d+)\s+\d+\s+obj\b")
ENDOBJ_RE = re.compile(rb"\bendobj\b")
EOF_RE = re.compile(rb"%%EOF")


def _ev(text: str, limit: int = MAX_EVIDENCE) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _count_keywords(data: bytes) -> dict[str, int]:
    """Hitung keyword ber-parameter (bukan komentar/di string tak relevan —
    pendekatan pdfid: hitung kemunculan literal)."""
    return {kw: len(re.findall(re.escape(kw.encode()) + rb"(?![A-Za-z0-9])",
                               data)) for kw in KEYWORDS}


def _extract_flate(data: bytes) -> tuple[bytes, int]:
    """Dekompresi semua stream FlateDecode; kembalikan (gabungan, gagal)."""
    chunks: list[bytes] = []
    failed = 0
    for m in STREAM_RE.finditer(data[:MAX_STREAM_BYTES * 4]):
        body = m.group(1)
        # hanya coba stream yang dekat dengan deklarasi FlateDecode
        head = data[max(0, m.start() - 512):m.start()]
        if not FLATE_RE.search(head):
            continue
        try:
            chunks.append(zlib.decompress(body))
        except zlib.error:
            # beberapa stream pakai header RFC-1951 mentah
            try:
                chunks.append(zlib.decompressobj(-15).decompress(body))
            except zlib.error:
                failed += 1
                continue
    if len(b"".join(chunks)) > MAX_STREAM_BYTES:
        chunks = [b"".join(chunks)[:MAX_STREAM_BYTES]]
    return b"".join(chunks), failed


def _add(findings: list[dict], fid: str, severity: str, detail: str,
         evidence: str = "") -> None:
    findings.append({"id": fid, "severity": severity, "detail": detail,
                     "evidence": _ev(evidence) if evidence else ""})


def _verdict(counts: dict[str, int], findings: list[dict],
             decrypt: bool, failed_streams: int,
             header_ok: bool) -> str:
    if decrypt:
        _add(findings, "pdf.encrypted", "info",
             "PDF terenkripsi — isi tak bisa dianalisis (fail-closed)")
        return "INCONCLUSIVE"
    if not header_ok:
        _add(findings, "pdf.header-invalid", "high",
             "header %PDF tidak valid di awal file")
        return "INCONCLUSIVE"

    active = {kw: n for kw, n in counts.items()
              if n > 0 and KEYWORDS[kw] != "info"}
    total = sum(active.values())

    open_action = counts.get("/OpenAction", 0) > 0
    aa = counts.get("/AA", 0) > 0
    js = counts.get("/JavaScript", 0) + counts.get("/JS", 0)
    crit_combos: list[str] = []
    if (open_action or aa) and js > 0:
        crit_combos.append("OpenAction/AA + JavaScript — eksekusi otomatis")
    if counts.get("/Launch", 0) > 0:
        crit_combos.append("/Launch — launch eksternal dari PDF")
    if counts.get("/RichMedia", 0) > 0:
        crit_combos.append("/RichMedia — Flash/embedded media aktif")

    for combo in crit_combos:
        _add(findings, "pdf.critical-combo", "critical", combo)
    if failed_streams:
        _add(findings, "pdf.stream-undecodable", "info",
             f"{failed_streams} stream FlateDecode gagal didekompresi "
             "(fail-closed: isi tak diperiksa)")

    if crit_combos or total >= 4:
        return "MALICIOUS-LIKELY"
    if total >= 2:
        return "SUSPICIOUS"
    if total == 1:
        kw, n = max(active.items(), key=lambda kv: kv[1])
        _add(findings, "pdf.keyword-single", KEYWORDS[kw],
             f"keyword aktif tunggal: {kw} x{n}")
        if KEYWORDS[kw] in ("critical", "high"):
            return "SUSPICIOUS"
        return "INCONCLUSIVE"
    if failed_streams:
        # ada isi yang tak diperiksa — jangan klaim CLEAN
        return "INCONCLUSIVE"
    return "CLEAN"


def triage(path: Path) -> dict:
    data = path.read_bytes()
    if data[:1024].find(b"%PDF-") == -1:
        raise ValueError("bukan PDF (tidak ada header %PDF-)")

    counts = _count_keywords(data)
    findings: list[dict] = []

    # pindai isi stream terkompresi sekali, gabungkan hitungannya
    flat, failed = _extract_flate(data)
    flat_counts = _count_keywords(flat) if flat else {}
    for kw, n in flat_counts.items():
        if n and KEYWORDS.get(kw) != "info":
            counts[kw] = counts.get(kw, 0) + n
            if kw in ("/JavaScript", "/JS"):
                _add(findings, "pdf.js-in-stream", "high",
                     "JavaScript ditemukan DI DALAM stream terkompresi",
                     flat[max(0, flat.find(kw.encode()) - 40):]
                     .decode("latin-1", errors="replace")[:120])

    decrypt = counts.get("/Encrypt", 0) > 0
    header_ok = data[:7] == b"%PDF-1."
    verdict = _verdict(counts, findings, decrypt, failed, header_ok)

    nobj = len(OBJ_RE.findall(data))
    nend = len(ENDOBJ_RE.findall(data))
    return {
        "schema": SCHEMA,
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "header_ok": header_ok,
        "objects": nobj,
        "endobj": nend,
        "has_eof": bool(EOF_RE.search(data[-2048:])),
        "encrypted": decrypt,
        "keyword_counts": counts,
        "verdict": verdict,
        "findings": findings,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase statis PDF berbahaya (read-only, NOL jaringan)")
    ap.add_argument("--pdf", required=True, help="path file PDF")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=VERDICTS, default="MALICIOUS-LIKELY",
                    help="gate exit 1 bila verdict >= pilihan ini")
    args = ap.parse_args(argv)

    path = Path(args.pdf)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage(path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)

    if VERDICTS.index(result["verdict"]) >= VERDICTS.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
