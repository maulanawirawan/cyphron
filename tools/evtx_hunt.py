"""[SAFETY: read-only] evtx_hunt — HUNT cepat level-carve di file Windows
Event Log (.evtx) BINARY: ekstrak string UTF-16LE dari tiap chunk (64
KiB, magic `ElfChnk\\x00`) dan cari indikator aktivitas (tooling, recon,
persistence, lateral movement, defense evasion).

Pemakaian:
  python tools/evtx_hunt.py --file Security.evtx --out hasil.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.evtx-hunt/1"

MAGIC_FILE = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

CATEGORIES: dict[str, list[str]] = {
    "tooling": ["mimikatz", "psexec", "wmiexec", "cobaltstrike",
                "cobalt strike", "bloodhound", "sharp_hound", "rubeus",
                "chisel", "ngrok", "seatbelt"],
    "recon": ["whoami", "net group", "net user /domain", "quser",
              "tasklist", "nltest"],
    "persistence": ["schtasks /create", "currentversion\\run",
                    " -enc ", "invoke-expression", "iex (",
                    "frombase64string", "register-scheduledtask"],
    "lateral": ["\\ipc$", "/node:", "winrm", "wmic /node", "-c thinclient"],
    "defense": ["vssadmin delete", "bcdedit", "wevtutil cl",
                "clear-eventlog"],
}


def _carve_utf16(blob: bytes) -> list[str]:
    """Ekstrak run UTF-16LE printable (>=4 char) sebagai teks ASCII."""
    out = []
    for m in UTF16_RUN.finditer(blob):
        try:
            out.append(m.group(0).decode("utf-16-le"))
        except UnicodeDecodeError:
            continue
    return out


def hunt_file(path: Path) -> dict:
    data_head = path.read_bytes()[:8]
    if data_head != MAGIC_FILE:
        raise ValueError(f"bukan file EVTX (magic tidak cocok): {path}")

    cat_hits: dict[str, list[str]] = {k: [] for k in CATEGORIES}
    chunk_count = 0
    with path.open("rb") as fh:
        window = 256 * 1024
        overlap = b""
        while True:
            blob = fh.read(window)
            if not blob:
                break
            stream = overlap + blob
            chunk_count += stream.count(CHUNK_MAGIC)
            strings = _carve_utf16(stream)
            low = [s.lower() for s in strings]
            joined = "\n".join(low)
            for cat, needles in CATEGORIES.items():
                for needle in needles:
                    if needle in joined:
                        # simpan SATU sampel string yang memuat needle
                        sample = next((s for s in low if needle in s), "")
                        if sample not in cat_hits[cat]:
                            cat_hits[cat].append(sample)
            overlap = blob[-64:]  # sambung run antar window

    findings = []
    for cat, samples in sorted(cat_hits.items()):
        if not samples:
            continue
        findings.append({
            "type": "indicator",
            "category": cat,
            "severity": ("high" if cat in ("tooling", "defense")
                         else "medium"),
            "detail": f"indikator '{cat}' ditemukan di chunk EVTX "
                      f"({len(samples)} sampel unik)",
            "evidence": f"samples={[s[:60] for s in samples[:3]]}",
        })
    return {
        "schema": SCHEMA,
        "file": str(path),
        "chunks_detected": chunk_count,
        "finding_count": len(findings),
        "findings": findings,
        "category_histogram": {k: len(v) for k, v in
                               sorted(cat_hits.items()) if v},
        "clean": len(findings) == 0,
        "note": "carve-level hunt (BUKAN parser EVTX penuh) — string "
                "UTF-16LE literal saja; bisa miss dan tidak memetakan "
                "event ID; gunakan parser penuh untuk konfirmasi",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="file .evtx binary")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = hunt_file(path)
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
