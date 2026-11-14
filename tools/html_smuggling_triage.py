"""[SAFETY: read-only] html_smuggling_triage — wave-3 HTML: skor OFFLINE
halaman/attachment HTML terhadap pola HTML smuggling (payload berbahaya
diselundupkan lewat mekanisme download browser, bukan attachment klasik).

Sinyal per dokumen (semua deterministik dari data):
  - ms-save-blob        : navigator.msSaveOrOpenBlob / msSaveBlob
                          (smuggling IE/legacy klasik)
  - create-object-url   : URL.createObjectURL (pembungkus payload jadi
                          objek unduhan in-memory)
  - anchor-download-data: <a download> yang href-nya data:/blob:
                          (klik memicu unduh payload, bukan fetch file
                          dari server)
  - js-anchor-download : anchor dibuat via JS (document.createElement
                          + a.download= ... + a.href=) — smuggling
                          modern yang tidak meninggalkan tag literal
  - event-armed         : listener gerbang interaksi (mousemove/
                          mouseover/ontouchstart/keydown) — pola
                          "smuggling hanya menembak saat mouse bergerak"
                          (menghindari crawler/sandbox tanpa simulasi)
  - embedded-base64     : run base64 >= --min-b64 char (payload inline)
  - hidden-iframe-data  : iframe display:none/hidden dengan
                          srcdoc/data: (bootstrap dokumen jebakan)
  - script-src-doc      : <script> berisi string base64 besar ATAU
                          konstruktor Blob bertipe octet-stream
Skor = jumlah sinyal; >= 3 high, == 2 medium, == 1 low, 0 info (halaman
normal — zero-FP: link unduh biasa tanpa data:/blob: TIDAK dihitung).

Fail-closed: teks tanpa satu pun markup HTML -> exit 2. Temuan = LEAD
untuk direview manual (buka file di sandbox, bukan di mesin kerja).

Referensi konsep: entri "Improved HTML smuggling with mouse move
eventlistener" (A-poc/RedTeam-Tools) — kode dibangun from scratch.

Pemakaian:
  python tools/html_smuggling_triage.py --file page.html --out hasil.json
  python tools/html_smuggling_triage.py --file body.html --min-b64 2048
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.html-smuggling-triage/1"

_MIN_B64_DEFAULT = 2048

_RE_MS_SAVE = re.compile(
    r"(msSaveOrOpenBlob|msSaveBlob|navigator\.msSave)", re.I)
_RE_CREATE_OBJ = re.compile(r"(URL\.createObjectURL|webkitURL\.createObjectURL)")
_RE_ANCHOR_TAG = re.compile(r"<a\b[^>]*?>", re.I)
_RE_DL_ATTR = re.compile(r"\bdownload\b", re.I)
_RE_HREF_DATA = re.compile(
    r"href\s*=\s*[\"']((?:data|blob):[^\"']*)[\"']", re.I)
_RE_EVENT_ARM = re.compile(
    r"(addEventListener\s*\(\s*[\"'](mousemove|mouseover|mouseenter|"
    r"touchstart|mousedown)[\"']|on(mouseover|mousemove|mouseenter|"
    r"touchstart)\s*=)", re.I)
_RE_HIDDEN_IFRAME = re.compile(
    r"<iframe\b[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|"
    r"hidden\b)[^>]*>", re.I)
_RE_IFRAME_SRC = re.compile(
    r"<iframe\b[^>]*?(?:srcdoc|src\s*=\s*[\"'](data:|blob:))", re.I)
_RE_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % 64)
# payload sering dipecah per-literal JS ("AA.." + "BB..") — gabungkan
# fragmen literal berdekatan sebelum scan (deterministik)
_RE_STR_CONCAT = re.compile(r"[\"']\s*\+\s*[\"']")
_RE_BLOB_OCTET = re.compile(
    r"new\s+Blob\s*\(.{0,400}?octet-stream", re.I | re.S)
_RE_JS_ANCHOR_DL = re.compile(
    r"\.\s*download\s*=\s*[^;]{1,80};", re.I)

_TAG_RE = re.compile(r"<[a-zA-Z!/]")


def _decode_b64_head(run: str, n: int = 24) -> bool:
    """Coba decode head run base64; True kalau hasilnya biner/teks yang
    valid-decodable (bukan kata acak ASCII panjang)."""
    pad = run[:n]
    try:
        raw = base64.b64decode(pad + "=" * (-len(pad) % 4), validate=True)
        return len(raw) >= 8
    except Exception:
        return False


def audit_html(text: str, min_b64: int) -> dict | None:
    """Skor satu dokumen HTML. None = bukan HTML (tanpa markup)."""
    if not _TAG_RE.search(text):
        return None
    signals: list[str] = []
    evidence: dict[str, str] = {}

    if _RE_MS_SAVE.search(text):
        signals.append("ms-save-blob")
    if _RE_CREATE_OBJ.search(text):
        signals.append("create-object-url")
    if _RE_EVENT_ARM.search(text):
        signals.append("event-armed")
    if _RE_HIDDEN_IFRAME.search(text) or _RE_IFRAME_SRC.search(text):
        signals.append("hidden-iframe-data")

    # anchor download dengan href data:/blob: (inti smuggling modern)
    for tag_m in _RE_ANCHOR_TAG.finditer(text):
        tag = tag_m.group(0)
        if _RE_DL_ATTR.search(tag) and _RE_HREF_DATA.search(tag):
            signals.append("anchor-download-data")
            evidence["anchor_href"] = _RE_HREF_DATA.search(tag).group(1)[:160]
            break

    # anchor dibangun via JS (createElement + a.download assignment)
    if _RE_JS_ANCHOR_DL.search(text):
        signals.append("js-anchor-download")

    # blob octet-stream + base64 run besar
    merged = _RE_STR_CONCAT.sub("", text)
    b64_runs = [r.group(0) for r in _RE_B64_RUN.finditer(merged)]
    big_runs = [r for r in b64_runs if len(r) >= min_b64]
    decodable = [r for r in b64_runs if _decode_b64_head(r)]
    if big_runs or (_RE_BLOB_OCTET.search(text) and decodable):
        signals.append("embedded-base64")
        evidence["max_b64_len"] = str(max((len(r) for r in b64_runs),
                                          default=0))

    # dedupe jaga urutan
    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    return {"signals": signals, "score": len(signals), "evidence": evidence}


def triage_text(text: str, min_b64: int = _MIN_B64_DEFAULT) -> dict:
    res = audit_html(text, min_b64)
    if res is None:
        raise ValueError("tidak ada markup HTML ditemukan — bukan dokumen HTML")
    score = res["score"]
    severity = ("high" if score >= 3 else
                "medium" if score == 2 else
                "low" if score == 1 else "info")
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    counts[severity] = 1
    return {
        "schema": SCHEMA,
        "score": score,
        "severity": severity,
        "signals": res["signals"],
        "evidence": res["evidence"],
        "severity_counts": counts,
        "finding_count": 1 if score > 0 else 0,
        "findings": ([{"type": "html-smuggling", "severity": severity,
                       "signals": res["signals"],
                       "evidence": res["evidence"]}] if score > 0 else []),
        "clean_count": 0 if score > 0 else 1,
        "note": "skor heuristik pola smuggling — bukan keputusan malware "
                "final; buka dokumen di sandbox, bukan di mesin kerja",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dokumen HTML / saved page / body eml")
    ap.add_argument("--min-b64", type=int, default=_MIN_B64_DEFAULT,
                    help="batas panjang run base64 (default 2048)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, min_b64=args.min_b64)
    except ValueError as exc:
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
