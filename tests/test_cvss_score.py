"""Nol jaringan — test cvss_score (kalkulator CVSS v3.1 fail-closed).

Skor acuan = contoh vektor pada spesifikasi CVSS v3.1 (FIRST) yang
nilai akhirnya sudah terverifikasi publik (mis. 9.8 utk vektor lengkap
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cvss_score as cs  # noqa: E402


class TestParse(unittest.TestCase):
    """Nol jaringan — parser vektor fail-closed."""

    def test_valid_dengan_prefix(self):
        m = cs.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(m["AV"], "N")
        self.assertEqual(m["S"], "U")

    def test_valid_tanpa_prefix(self):
        m = cs.parse_vector("AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
        self.assertEqual(len(m), 8)

    def test_metric_hilang_ditolak(self):
        with self.assertRaises(ValueError):
            cs.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # A hilang

    def test_metric_tak_kenal_ditolak(self):
        with self.assertRaises(ValueError):
            cs.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q")

    def test_duplikat_ditolak(self):
        with self.assertRaises(ValueError):
            cs.parse_vector("AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_nilai_invalid_ditolak(self):
        with self.assertRaises(ValueError):
            cs.parse_vector("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        with self.assertRaises(ValueError):
            cs.parse_vector("AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H")


class TestScore(unittest.TestCase):
    """Nol jaringan — skor acuan spesifikasi v3.1."""

    def test_98_critical(self):
        r = cs.score_vector(cs.parse_vector(
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertEqual(r["base_score"], 9.8)
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertFalse(r["scope_changed"])

    def test_scope_changed_contoh(self):
        # vektor scope-changed klasik (kerentanan VM host -> guest dsb.)
        r = cs.score_vector(cs.parse_vector(
            "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"))
        # spesifikasi: skor scope-changed dibatasi <= 10 dan di-kali 1.08
        self.assertTrue(8.0 < r["base_score"] <= 10.0)
        self.assertEqual(r["severity"], "CRITICAL")

    def test_low(self):
        r = cs.score_vector(cs.parse_vector(
            "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"))
        self.assertTrue(1.0 <= r["base_score"] <= 3.9)
        self.assertEqual(r["severity"], "LOW")

    def test_no_impact_zero(self):
        r = cs.score_vector(cs.parse_vector(
            "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))
        self.assertEqual(r["base_score"], 0.0)
        self.assertEqual(r["severity"], "NONE")

    def test_medium_band(self):
        r = cs.score_vector(cs.parse_vector(
            "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L"))
        self.assertTrue(3.9 < r["base_score"] <= 6.9)
        self.assertEqual(r["severity"], "MEDIUM")

    def test_urutan_output_normatif(self):
        # vektor output selalu urutan spec (AV..A) walau input acak
        r = cs.score_vector(cs.parse_vector(
            "C:H/A:H/I:H/S:U/UI:N/PR:N/AC:L/AV:N"))
        self.assertEqual(r["vector"],
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestCli(unittest.TestCase):
    """Nol jaringan — CLI."""

    def test_valid_exit0(self):
        out = Path(tempfile.mkdtemp()) / "cvss.json"
        rc = cs.main(["--vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      "--out", str(out)])
        self.assertEqual(rc, 0)
        d = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(d["base_score"], 9.8)
        self.assertEqual(d["schema"], "secai.cvss-score/1")

    def test_invalid_exit2(self):
        rc = cs.main(["--vector", "AV:N/AC:L/PR:N/UI:N/S:U/C:H"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
