"""Test F53 — CRX (Chrome extension) + ELF section awareness.

NOL jaringan. Yang dikunci:
  - CRX3: magic Cr24 + offset ZIP dari header_len -> entri di-scan;
    magic salah / offset ZIP tidak valid = error meta fail-closed;
  - ELF: URL di .rodata membawa provenance section; file non-ELF
    tetap jalan (tanpa sections).
"""
from __future__ import annotations

import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import bundle_exposure as be  # noqa: E402
import binary_strings_surface as bs
from findings import validate_finding  # noqa: E402


def _build_crx(entries: dict[str, bytes], version: int = 3) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, blob in entries.items():
            zf.writestr(name, blob)
    header = b"\x00" * 16  # dummy protobuf header (tidak diurai)
    return (b"Cr24" + version.to_bytes(4, "little")
            + len(header).to_bytes(4, "little") + header + buf.getvalue())


def _build_elf64_rodata(payload: bytes) -> bytes:
    """ELF64 minimal: 3 section header (NULL, .shstrtab, .rodata).
    Payload URL diletakkan tepat di dalam .rodata."""
    ehsize = 64
    shentsize = 64
    shstrtab = (b"\x00.shstrtab\x00.rodata\x00")
    # layout: [ehdr 64][.rodata payload][.shstrtab][shdrs]
    rodata_off = ehsize
    shstr_off = rodata_off + len(payload)
    shoff = shstr_off + len(shstrtab)
    shstrtab = (b"\x00" + b".shstrtab\x00" + b".rodata\x00")
    n_shstr = 1          # offset nama ".shstrtab" di shstrtab
    n_rodata = 11        # 1 + len(".shstrtab\x00")
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2          # ELFCLASS64
    ehdr[5] = 1          # little endian
    struct.pack_into("<Q", ehdr, 0x28, shoff)          # e_shoff
    struct.pack_into("<H", ehdr, 0x3A, shentsize)      # e_shentsize
    struct.pack_into("<H", ehdr, 0x3C, 3)              # e_shnum
    struct.pack_into("<H", ehdr, 0x3E, 1)              # e_shstrndx
    def sh(name, stype, off, size):
        return struct.pack("<IIQQQQIIQQ", name, stype, 0, 0,
                           off, size, 0, 0, 1, 0)
    shdrs = (sh(0, 0, 0, 0)
             + sh(n_shstr, 3, shstr_off, len(shstrtab))   # STRTAB
             + sh(n_rodata, 1, rodata_off, len(payload)))  # PROGBITS
    return bytes(ehdr) + payload + shstrtab + shdrs


class CrxTest(unittest.TestCase):
    def test_crx3_entries_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ext.crx"
            f.write_bytes(_build_crx({
                "background.js": (b'const API='
                                  b'"https://api.example-app.com/v2";'
                                  b'const k="sk_live_51H8xTestKey0000";'),
                "manifest.json": b'{"version": "1.0"}'}))
            rows, meta = be.audit_archive(f)
        self.assertEqual(meta["entries_scanned"], 2)
        kinds = {r.get("kind") for r in rows}
        self.assertIn("urls", kinds)
        self.assertIn("secret-literal", kinds)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_crx_bad_magic_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "fake.crx"
            f.write_bytes(b"NOPE" + b"\x00" * 64)
            rows, meta = be.audit_archive(f)
        self.assertEqual(rows, [])
        self.assertIn("error", meta)

    def test_crx_zip_offset_invalid_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad.crx"
            f.write_bytes(b"Cr24" + (3).to_bytes(4, "little")
                          + (9999).to_bytes(4, "little") + b"\x00" * 64)
            rows, meta = be.audit_archive(f)
        self.assertEqual(rows, [])
        self.assertIn("error", meta)


class ElfSectionTest(unittest.TestCase):
    def test_url_in_rodata_carries_section_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "lib.so"
            f.write_bytes(_build_elf64_rodata(
                b"\x00https://api.example-app.com/v2/internal\x00"))
            rows, meta = bs.audit_binary(f)
        self.assertEqual(meta["filetype"], "elf")
        url_row = next(r for r in rows if r.get("kind") == "urls")
        item = url_row["items"][0]
        self.assertEqual(item["section"], ".rodata")

    def test_non_elf_still_works_without_sections(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "app.exe"
            f.write_bytes(b"MZ" + b"\x00" * 40
                          + b"https://api.example-app.com/v2/x")
            rows, meta = bs.audit_binary(f)
        self.assertEqual(meta["filetype"], "pe")
        self.assertEqual(meta["sections"], 0)
        self.assertTrue(any(r.get("kind") == "urls" for r in rows))

    def test_corrupt_elf_degrades_gracefully(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "broken.so"
            f.write_bytes(b"\x7fELF" + b"\x00" * 20
                          + b"https://api.example-app.com/v2/y")
            rows, meta = bs.audit_binary(f)
        self.assertEqual(meta["filetype"], "elf")
        self.assertEqual(meta["sections"], 0)
        self.assertTrue(any(r.get("kind") == "urls" for r in rows))


if __name__ == "__main__":
    unittest.main()
