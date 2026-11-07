"""Nol jaringan — test dpapi_blob_scan (inventarisasi blob DPAPI).

Blob sintetis dibangun in-memory sesuai struktur MS-DPAPI publik.
Tidak ada dekripsi, tidak ada jaringan — semata parse struktur.
"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import dpapi_blob_scan as db  # noqa: E402

PROVIDER_GUID_STR = "df9d8cd0-1501-11d1-8c7a-00c04fc297eb"


def make_blob(masterkey_guid: bytes = b"\x11" * 16,
              flags: int = 0x1,
              description: str = "psw",
              alg: int = 0x6610,
              alglen: int = 256,
              salt: bytes = b"\x22" * 16,
              opaque: bytes = b"\x33" * 80) -> bytes:
    out = struct.pack("<I", 1) + bytes.fromhex(
        "d08c9ddf0115d1118c7a00c04fc297eb")
    out += struct.pack("<I", 1) + masterkey_guid + struct.pack("<I", flags)
    d = description.encode("utf-16-le")
    out += struct.pack("<I", len(d)) + d
    out += struct.pack("<II", alg, alglen)
    out += struct.pack("<I", len(salt)) + salt
    out += struct.pack("<I", 0)  # strong key len 0
    out += struct.pack("<I", len(opaque)) + opaque
    return out


class TestGuid(unittest.TestCase):
    """Nol jaringan — format GUID Windows mixed-endian."""

    def test_provider_guid(self):
        self.assertEqual(db.guid_str(db.PROVIDER_DPAPI), PROVIDER_GUID_STR)

    def test_guid_little_endian_prefix(self):
        raw = struct.pack("<IHH", 0x12345678, 0xabcd, 0xef01) + b"\x99" * 8
        self.assertTrue(db.guid_str(raw).startswith("12345678-abcd-ef01-9999"))


class TestParseBlob(unittest.TestCase):
    """Nol jaringan — parser struktur fail-closed."""

    def test_blob_valid(self):
        b = db.parse_blob(make_blob() + b"junk-ekstra", 0)
        self.assertIsNotNone(b)
        self.assertEqual(b["masterkey_guid"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(b["alg_name"], "CALG_AES_256")
        self.assertEqual(b["description"], "psw")
        self.assertEqual(b["opaque_len"], 80)
        self.assertNotIn("malformed", b)

    def test_magic_salah_none(self):
        self.assertIsNone(db.parse_blob(b"\x00" * 40, 0))

    def test_truncated_ditandai(self):
        raw = make_blob()
        for cut in (21, 30, 45, len(raw) - 10):
            b = db.parse_blob(raw[:cut], 0)
            self.assertIsNotNone(b)
            self.assertIn("malformed", b)

    def test_flag_names(self):
        b = db.parse_blob(make_blob(flags=0x4 | 0x20), 0)
        self.assertEqual(set(b["flag_names"]), {"LOCAL_MACHINE", "NO_RECOVERY"})
        self.assertIn("machine-context", b["lead"])
        self.assertIn("no-recovery", b["lead"])

    def test_weak_alg_lead(self):
        b = db.parse_blob(make_blob(alg=0x6801, alglen=128), 0)
        self.assertEqual(b["alg_name"], "CALG_RC4")
        self.assertIn("weak-alg", b["lead"])

    def test_description_tak_wajar_ditolak(self):
        raw = bytearray(make_blob())
        # perbesar dlen melebihi batas -> malformed, bukan crash
        dlen_off = 20 + 4 + 16 + 4
        struct.pack_into("<I", raw, dlen_off, 99999)
        b = db.parse_blob(bytes(raw), 0)
        self.assertEqual(b["malformed"], "description-tak-wajar")


class TestScanBuffer(unittest.TestCase):
    """Nol jaringan — pencarian multi-blob + skip overlap."""

    def test_dua_blob(self):
        buf = b"\x00" * 10 + make_blob(description="satu") + b"\xff" * 7 \
            + make_blob(description="dua", alg=0x6801)
        blobs = db.scan_buffer(buf)
        self.assertEqual(len(blobs), 2)
        self.assertEqual([b["description"] for b in blobs], ["satu", "dua"])
        self.assertEqual(blobs[1]["lead"], ["weak-alg"])

    def test_buffer_kosong(self):
        self.assertEqual(db.scan_buffer(b"teks biasa tanpa blob"), [])


class TestScanPathCli(unittest.TestCase):
    """Nol jaringan — I/O file + CLI fail-closed."""

    def test_scan_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "creds.bin"
            p.write_bytes(b"xx" + make_blob() + b"yy")
            r = db.scan_path(p)
            self.assertEqual(r["blobs_found"], 1)
            self.assertEqual(r["files_scanned"], 1)

    def test_scan_dir_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(3):
                (Path(td) / f"f{i}.bin").write_bytes(make_blob())
            r = db.scan_path(Path(td), max_files=2)
            self.assertEqual(r["blobs_found"], 2)  # bounded max_files=2

    def test_cli_path_tidak_ada_exit2(self):
        self.assertEqual(db.main(["--path", "TIDAK-ADA-xyz-99"]), 2)

    def test_cli_file_tanpa_blob_lapis_jujur(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plain.txt"
            p.write_bytes(b"hanya teks")
            rc = db.main(["--path", str(p), "--out", str(Path(td) / "o.json")])
            self.assertEqual(rc, 0)
            import json
            d = json.loads((Path(td) / "o.json").read_text(encoding="utf-8"))
            self.assertEqual(d["blobs_found"], 0)


if __name__ == "__main__":
    unittest.main()
