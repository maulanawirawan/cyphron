"""[SAFETY: read-only] maldoc_triage — triase statis dokumen Office aktif.

Yang diperiksa (input -> mekanisme -> output):
  1. OOXML (.docx/.docm/.xlsx/.xlsm/.pptx/.pptm) via zipfile:
     - vbaProject.bin          -> makro VBA ada (info; bukan otomatis jahat)
     - field code DDE/DDEAUTO  -> critical (vektor tanpa makro, T1204.002)
     - attachedTemplate + rel target eksternal -> high (remote template
       injection, T1221)
     - OLEObject ProgID Package/embedded object -> high
     - kontrol ActiveX         -> medium
     - externalLinks (Excel)   -> medium
     - hyperlink/gambar rel eksternal -> info (FP rendah: dokumen web normal)
  2. OLE legacy (.doc/.xls/.ppt, magic D0CF11E0): deteksi dangkal — nama
     stream makro heuristik; deteksi kami dangkal => verdict TIDAK PERNAH
     CLEAN, minimal INCONCLUSIVE (fail-closed: tidak mengklaim aman atas
     yang tidak bisa dipastikan).
  3. RTF: pindai teks mentah \\objdata / \\objupdate / \\objclass (Package).

Verdict fail-closed:
  - CLEAN           : nol temuan >= info yang bermuatan (arsip OOXML utuh).
  - SUSPICIOUS      : >= 1 high, ATAU >= 2 medium.
  - MALICIOUS-LIKELY: >= 1 critical, ATAU >= 2 high.
  - INCONCLUSIVE    : format dikenali tapi liputan deteksi dangkal (OLE
    legacy), ATAU arsip tak bisa diurai penuh — tidak pernah jadi CLEAN.
  - Bukan arsip dikenali / korup -> exit 2 (error), verdict tak dihasilkan.

Pemakaian:
  python tools/maldoc_triage.py --doc lampiran.docm --out triage.json
  python tools/maldoc_triage.py --doc lampiran.docm --fail-on SUSPICIOUS
Exit: 0 verdict < fail-on; 1 verdict >= fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.maldoc-triage/1"

VERDICTS = ("CLEAN", "INCONCLUSIVE", "SUSPICIOUS", "MALICIOUS-LIKELY")
MAX_EVIDENCE = 240
MAX_PART_BYTES = 32 * 1024 * 1024

OOXML_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
             ".dotx", ".dotm", ".xltm", ".potm"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
RTF_MAGIC = b"{\\rtf"

# nama stream CFB heuristik penyimpan makro (raw scan UTF-16LE)
OLE_MACRO_STREAMS = (
    b"V\x00B\x00A\x00",                      # VBA*
    b"_\x00V\x00B\x00A\x00",                 # _VBA_PROJECT
    b"M\x00a\x00c\x00r\x00o\x00",            # Macros
    b"T\x00h\x00i\x00s\x00D\x00o\x00c\x00",  # ThisDocument
    b"S\x00h\x00e\x00e\x00t\x00",            # Sheet* (xls)
)

DDE_RE = re.compile(r"<w:instrText[^>]*>([^<]*)</w:instrText>", re.I)
DDE_KEYWORD_RE = re.compile(r"\bDDEAUTO\b|\bDDE\b", re.I)
ATTACHED_TPL_RE = re.compile(r"<w:attachedTemplate[^>]*r:id=\"([^\"]+)\"", re.I)
OLEOBJECT_RE = re.compile(
    r"<o:OLEObject[^>]*ProgID=\"([^\"]+)\"[^>]*>", re.I)
REL_TARGET_RE = re.compile(r"<Relationship\b[^>]*>", re.I)
ATTR_ID_RE = re.compile(r"\bId=\"([^\"]+)\"")
ATTR_TARGET_RE = re.compile(r"\bTarget=\"([^\"]+)\"")
ATTR_TARGETMODE_RE = re.compile(r"\bTargetMode=\"External\"", re.I)
ATTR_TYPE_RE = re.compile(r"\bType=\"([^\"]+)\"")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ev(text: str, limit: int = MAX_EVIDENCE) -> str:
    """Potong bukti — jangan tanam konten dokumen penuh di JSON."""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _add(findings: list[dict], fid: str, severity: str, part: str,
         detail: str, evidence: str = "") -> None:
    findings.append({
        "id": fid, "severity": severity, "part": part,
        "detail": detail, "evidence": _ev(evidence) if evidence else "",
    })


def _scan_rels(name: str, xml: bytes, findings: list[dict],
               rid_targets: dict[str, str]) -> None:
    """Pindai satu part .rels: target eksternal non-hyperlink biasa."""
    text = xml.decode("utf-8", errors="replace")
    for m in REL_TARGET_RE.finditer(text):
        tag = m.group(0)
        rid = ATTR_ID_RE.search(tag)
        target = ATTR_TARGET_RE.search(tag)
        if not target:
            continue
        tgt = target.group(1)
        if rid:
            rid_targets.setdefault(rid.group(1), tgt)
        if not ATTR_TARGETMODE_RE.search(tag) and not tgt.lower().startswith(
                ("http://", "https://", "ftp://", "file://")):
            continue
        rtype = ATTR_TYPE_RE.search(tag)
        rtype = rtype.group(1) if rtype else ""
        if "/hyperlink" in rtype:
            _add(findings, "ooxml.hyperlink-external", "info", name,
                 f"hyperlink eksternal: {tgt}", tag)
        elif ("/image" in rtype or "/thumbnail" in rtype
              or "/attachedTemplate" in rtype):
            # gambar = pola normal; attachedTemplate dinilai lewat resolusi
            # r:id di part dokumen (hindari sinyal dobel dari rel yang sama)
            continue
        else:
            _add(findings, "ooxml.rel-external", "medium", name,
                 f"relasi eksternal non-hyperlink: {tgt}", tag)


def _scan_document_part(name: str, xml: bytes,
                        findings: list[dict]) -> None:
    text = xml.decode("utf-8", errors="replace")
    # field code DDE / DDEAUTO (T1204.002) — termasuk hasil unescape
    for m in DDE_RE.finditer(text):
        instr = (m.group(1).replace("&amp;", "&").replace("&lt;", "<")
                 .replace("&gt;", ">"))
        if DDE_KEYWORD_RE.search(instr):
            sev = "critical" if "DDEAUTO" in instr.upper() else "high"
            _add(findings, "ooxml.dde-fieldcode", sev, name,
                 f"field code DDE ({sev})", instr)
    # OLE object ter-embed
    for m in OLEOBJECT_RE.finditer(text):
        progid = m.group(1)
        sev = "high" if "package" in progid.lower() else "medium"
        _add(findings, "ooxml.embedded-oleobject", sev, name,
             f"OLEObject ProgID={progid}", m.group(0))
    # ActiveX control
    if re.search(r"<m:oleObject|activeX", text, re.I):
        _add(findings, "ooxml.activex", "medium", name,
             "referensi kontrol ActiveX", "")


def _triage_ooxml(data: bytes, findings: list[dict]) -> tuple[str, str]:
    """Kembalikan (verdict, notes). Fail-closed: zip korup -> INCONCLUSIVE."""
    import io
    import zipfile

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except zipfile.BadZipFile:
        return "INCONCLUSIVE", "zip korup — tidak bisa diurai penuh"

    macro_parts = [n for n in names if n.endswith("vbaProject.bin")]
    if macro_parts:
        _add(findings, "ooxml.vba-project", "info", macro_parts[0],
             "vbaProject.bin — dokumen makro-enabled (bukan otomatis jahat; "
             "ekstraksi VBA di luar cakupan triase ini)", "")

    rid_targets: dict[str, str] = {}
    for n in names:
        if not n.endswith(".rels"):
            continue
        _scan_rels(n, zf.read(n)[:MAX_PART_BYTES], findings, rid_targets)

    # w:attachedTemplate menunjuk rel id — selesaikan targetnya
    for n in [x for x in names if x.startswith("word/") and
              x.endswith(".xml")]:
        xml = zf.read(n)[:MAX_PART_BYTES]
        _scan_document_part(n, xml, findings)
        text = xml.decode("utf-8", errors="replace")
        for m in ATTACHED_TPL_RE.finditer(text):
            tgt = rid_targets.get(m.group(1), "")
            if tgt.startswith(("http://", "https://", "ftp://", "\\\\")):
                _add(findings, "ooxml.attached-template-remote", "high", n,
                     f"attachedTemplate menunjuk host luar: {tgt}",
                     m.group(0))

    for n in [x for x in names if "externalLink" in x and
              x.endswith(".xml")]:
        _add(findings, "ooxml.external-link", "medium", n,
             "workbook punya externalLink (rentan digantung ke file luar)",
             "")

    if not names:
        return "INCONCLUSIVE", "arsip kosong"
    return _aggregate(findings, ooxml=True), ""


def _triage_ole(data: bytes, findings: list[dict]) -> tuple[str, str]:
    for stream in OLE_MACRO_STREAMS:
        if stream in data:
            _add(findings, "ole.macro-stream-indicator", "info", "(CFB)",
                 "indikator nama stream makro VBA (heuristik UTF-16LE)", "")
            break
    # deteksi dangkal -> tidak boleh CLEAN
    return "INCONCLUSIVE", "OLE legacy: deteksi dangkal, verdict fail-closed"


def _triage_rtf(data: bytes, findings: list[dict]) -> tuple[str, str]:
    text = data.decode("latin-1", errors="replace")
    if r"\\objdata" in text or "\\objdata" in text:
        _add(findings, "rtf.objdata", "high", "(RTF)",
             "objdata ter-embed — vektor exploit/drop maldoc umum", "")
    if "\\objupdate" in text:
        _add(findings, "rtf.objupdate", "medium", "(RTF)",
             "objupdate — paksa auto-update OLE object", "")
    m = re.search(r"\\objclass\s+([A-Za-z0-9._\\]+)", text)
    if m and "package" in m.group(1).lower():
        _add(findings, "rtf.objclass-package", "high", "(RTF)",
             "objclass Package — embed berkas eksekusi", m.group(0))
    return _aggregate(findings, ooxml=True), ""


def _aggregate(findings: list[dict], ooxml: bool) -> str:
    hard = [f for f in findings if f["severity"] in
            ("critical", "high", "medium")]
    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    if crit >= 1 or high >= 2:
        return "MALICIOUS-LIKELY"
    if high >= 1 or med >= 2:
        return "SUSPICIOUS"
    if hard:
        return "INCONCLUSIVE"
    return "CLEAN" if ooxml else "INCONCLUSIVE"


def triage(path: Path) -> dict:
    data = path.read_bytes()
    findings: list[dict] = []
    notes = ""
    if data[:4] == b"PK\x03\x04":
        verdict, notes = _triage_ooxml(data, findings)
    elif data[:8] == OLE_MAGIC:
        verdict, notes = _triage_ole(data, findings)
    elif data[:5] == RTF_MAGIC:
        verdict, notes = _triage_rtf(data, findings)
    else:
        raise ValueError("format tidak dikenali (bukan ZIP/OLE/RTF)")
    if notes:
        findings.append({"id": "limits", "severity": "info", "part": "-",
                         "detail": notes, "evidence": ""})
    return {
        "schema": SCHEMA,
        "file": str(path),
        "sha256": _sha256(data),
        "size": len(data),
        "verdict": verdict,
        "findings": findings,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase statis dokumen Office aktif (read-only, "
                    "NOL jaringan, NOL eksekusi dokumen)")
    ap.add_argument("--doc", required=True, help="path dokumen Office/RTF")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=VERDICTS, default="MALICIOUS-LIKELY",
                    help="gate exit 1 bila verdict >= pilihan ini")
    args = ap.parse_args(argv)

    path = Path(args.doc)
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
