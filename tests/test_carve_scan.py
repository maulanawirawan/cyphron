"""Nol jaringan — test carve_scan (signature + entropi + carve blob mentah).

Fixture dibangun inline: PNG minimal (signature + IEND), PDF minimal,
ZIP EOCD, blob entropi acak (seed tetap), superblock ext pada 0x438.
Tidak ada request jaringan.
"""
from __future__ import annotations

import hashlib
import random
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import carve_scan as cs  # noqa: E402
from findings import validate_finding  # noqa: E402


def minimal_png() -> bytes:
    """PNG valid minimal: signature + IHDR + IEND."""
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", 0))  # CRC 0 cukup utk carving

    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    # IEND CRC aktual (CRC32 atas b"IEND") = AE 42 60 82 — dipakai
    # forensik nyata sebagai footer carving, jadi fixture harus pakai ini
    iend = chunk(b"IEND", b"")[:-4] + b"\xae\x42\x60\x82"
    return sig + ihdr + iend


def minimal_pdf() -> bytes:
    # TANPA newline akhir — footer %%EOF adalah akhir berkas
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"


def minimal_zip_eocd() -> bytes:
    """Local file header PK\\x03\\x04 ... EOCD PK\\x05\\x06 (22 byte utuh).

    EOCD MENUTUP ZIP — ekor di luar EOCD bukan bagian berkas.
    """
    lfh = b"PK\x03\x04" + b"\x00" * 26
    eocd = b"PK\x05\x06" + b"\x00" * 18
    return lfh + b"data" + eocd


class CarveScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="carve_scan_t"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------- scan
    def test_scan_hits_and_carve_roundtrip(self) -> None:
        pad = b"\x00" * 100
        blob = (pad + minimal_png() + pad + minimal_pdf()
                + pad + minimal_zip_eocd() + pad)
        blob_path = self.tmp / "image.dd"
        blob_path.write_bytes(blob)

        hits = cs.scan_signatures(blob)
        self.assertIn("png", hits)
        self.assertIn("pdf", hits)
        self.assertIn("zip", hits)
        self.assertTrue(hits["png"][0]["carvable"])
        self.assertTrue(hits["zip"][0]["carvable"])

        out_dir = self.tmp / "carved"
        carved, skipped = cs.carve_all(blob, hits, out_dir, 16, 10**9)
        by_type = {c["type"]: c for c in carved}
        self.assertEqual(
            hashlib.sha256(minimal_png()).hexdigest(),
            by_type["png"]["sha256"])
        self.assertEqual(
            hashlib.sha256(minimal_pdf()).hexdigest(),
            by_type["pdf"]["sha256"])
        self.assertEqual(
            hashlib.sha256(minimal_zip_eocd()).hexdigest(),
            by_type["zip"]["sha256"])
        # hasil ukur benar-benar utuh di disk
        png_file = Path(by_type["png"]["file"])
        self.assertEqual(png_file.read_bytes(), minimal_png())
        self.assertEqual(skipped, [])

    def test_unclosed_header_not_carved(self) -> None:
        blob = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200  # tanpa IEND
        hits = cs.scan_signatures(blob)
        self.assertIn("png", hits)
        self.assertFalse(hits["png"][0]["carvable"])
        out_dir = self.tmp / "c2"
        carved, _ = cs.carve_all(blob, hits, out_dir, 16, 10**9)
        self.assertEqual(carved, [])

    def test_fixed_offset_ext_superblock(self) -> None:
        blob = bytearray(b"\xff" * 2048)
        blob[0x438:0x43A] = b"\x53\xef"
        hits = cs.scan_signatures(bytes(blob))
        self.assertIn("ext234-superblock", hits)
        self.assertEqual(hits["ext234-superblock"][0]["offset"], 0x438)

    # ---------------------------------------------------------- entropi
    def test_entropy_profile_low_and_high(self) -> None:
        rnd = random.Random(2811)
        noisy = bytes(rnd.randrange(256) for _ in range(4096))
        blob = b"\x00" * 4096 + noisy
        regions = cs.entropy_profile(blob, 4096)
        classes = {r["class"] for r in regions}
        self.assertIn("padding-or-empty", classes)
        self.assertIn("compressed-or-encrypted", classes)
        for r in regions:
            if r["class"] == "padding-or-empty":
                self.assertEqual(r["entropy"], 0.0)
            else:
                self.assertGreaterEqual(r["entropy"], 7.0)

    # ------------------------------------------------------------ poc/CLI
    def test_findings_contract_and_exit_codes(self) -> None:
        blob = b"\x00" * 50 + minimal_png() + b"\x00" * 50
        blob_path = self.tmp / "b.bin"
        blob_path.write_bytes(blob)
        out = self.tmp / "f.json"
        rc = cs.main(["--blob", str(blob_path), "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = __import__("json").loads(out.read_text(encoding="utf-8"))
        self.assertTrue(doc["ok"])
        self.assertGreater(len(doc["findings"]), 0)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])
        self.assertEqual(doc["data"]["total_hits"], 1)
        self.assertIn("png", doc["data"]["by_type"])

    def test_exit_0_when_no_hits(self) -> None:
        blob_path = self.tmp / "plain.bin"
        blob_path.write_bytes(b"A" * 1024)
        out = self.tmp / "f0.json"
        rc = cs.main(["--blob", str(blob_path), "--out", str(out)])
        # entropi blok tunggal 0.0 tetap ditulis sbg observasi, tapi
        # exit code mengikuti signature (0 hit -> 0)
        self.assertEqual(rc, 0)
        doc = __import__("json").loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["total_hits"], 0)
        self.assertTrue(all(
            f.get("schema") == "cyphron.carve-scan/1"
            for f in doc["findings"]))

    def test_fail_closed_missing_and_small_and_bad_params(self) -> None:
        out = self.tmp / "x.json"
        self.assertEqual(cs.main(["--blob", str(self.tmp / "nope.bin"),
                                  "--out", str(out)]), 2)
        small = self.tmp / "small.bin"
        small.write_bytes(b"ok")
        self.assertEqual(cs.main(["--blob", str(small),
                                  "--out", str(out)]), 2)
        blob_path = self.tmp / "b2.bin"
        blob_path.write_bytes(b"\x00" * 64)
        self.assertEqual(cs.main(["--blob", str(blob_path), "--out",
                                  str(out), "--block", "0"]), 2)
        self.assertEqual(cs.main(["--blob", str(blob_path), "--out",
                                  str(out), "--min-size", "10",
                                  "--max-size", "5"]), 2)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
