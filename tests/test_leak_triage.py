"""Nol jaringan — test leak_triage (triase klaim kebocoran, fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import leak_triage as lt  # noqa: E402


class TestTriage(unittest.TestCase):
    """Nol jaringan — empat gerbang + kombinasi wajib."""

    def test_klaim_hampa_unverified(self):
        # klaim viral tanpa sampel, tanpa sumber resmi
        r = lt.triage("10M data dijual", 10_000_000, "nik,nama,email")
        self.assertEqual(r["verdict"], "UNVERIFIED")
        self.assertEqual(r["score"], 0)
        self.assertIn("tanpa sampel", r["rule"])

    def test_denial_resmi_tetap_unverified_tanpa_sampel(self):
        # kasus nyata: klaim + denial resmi, TANPA sampel verifiable
        r = lt.triage("10M data Coretax dijual", 10_000_000,
                      "nik,nama,npwp,email", corroborators=1,
                      official="denial-pemilik-data")
        self.assertEqual(r["verdict"], "UNVERIFIED")
        self.assertTrue(r["gates"]["official"]["pass"])
        self.assertFalse(r["gates"]["sample"]["pass"])

    def test_sampel_plus_skor_cukup_verified_candidate(self):
        r = lt.triage("leak app X", 500_000, "nik,nama,npwp",
                      sample_available=True, sample_hash="a" * 64,
                      sample_fields="nik;nama;npwp;email;phone",
                      corroborators=2, official="none")
        self.assertEqual(r["verdict"], "VERIFIED-CANDIDATE")
        self.assertTrue(r["gates"]["fingerprint"]["pass"])
        self.assertEqual(r["score"], 4)

    def test_fingerprint_mismatch_dengan_skor_cukup_debunked(self):
        # sampel ada, corroboration kuat, TAPI field tak ada irisan
        r = lt.triage("leak coretax", 10_000_000, "nik,npwp",
                      sample_available=True, sample_fields="username,password",
                      corroborators=3, official="none")
        self.assertEqual(r["verdict"], "DEBUNKED-CANDIDATE")
        self.assertFalse(r["gates"]["fingerprint"]["pass"])
        self.assertIn("TIDAK ADA", r["gates"]["fingerprint"]["detail"])

    def test_fingerprint_partial_tidak_debunked(self):
        # irisan parsial (>= 0.6) = konsisten, bukan bantahan
        r = lt.triage("leak x", 1000, "nik,nama,npwp,email",
                      sample_available=True,
                      sample_fields="nik,nama,email,alamat,kota",
                      corroborators=0, official="")
        self.assertTrue(r["gates"]["fingerprint"]["pass"])
        self.assertEqual(r["verdict"], "UNVERIFIED")  # skor 2, tanpa sampel... ada sampel tapi skor < 3

    def test_sampel_saja_tidak_cukup(self):
        r = lt.triage("leak x", 100, "nik", sample_available=True,
                      sample_fields="nik", corroborators=0, official="")
        self.assertEqual(r["verdict"], "UNVERIFIED")
        self.assertEqual(r["score"], 2)

    def test_konfirmasi_resmi_tanpa_sampel_tetap_unverified(self):
        # pemilik data KONFIRMASI bocor, tapi sampel tak pernah dipublikasi
        r = lt.triage("klaim leak", 10, "email", corroborators=2,
                      official="confirmed-by-owner")
        self.assertEqual(r["verdict"], "UNVERIFIED")  # kombi-wajib: no sample
        self.assertEqual(r["score"], 2)  # corroboration + official saja

    def test_fields_normalisasi(self):
        self.assertEqual(lt._norm_fields("NIK; Nama | email, NIK"),
                         ["email", "nama", "nik"])

    def test_runbook_per_verdict(self):
        for verdict in lt.VERDICTS:
            r = lt.triage("x", 1, "f", sample_available=True,
                          sample_fields="f", corroborators=2,
                          official="ok")
            self.assertEqual(r["verdict"], "VERIFIED-CANDIDATE")
            break
        r2 = lt.triage("x", 1, "f")
        self.assertIn("amplifikasi", " ".join(r2["runbook"]))

    def test_input_invalid(self):
        with self.assertRaises(ValueError):
            lt.triage("", 1, "x")
        with self.assertRaises(ValueError):
            lt.triage("x", -1, "x")


class TestCli(unittest.TestCase):
    """Nol jaringan — CLI fail-closed."""

    def test_cli_verified_path(self):
        out = Path(tempfile.mkdtemp()) / "triage.json"
        self.addCleanup(lambda: None)
        rc = lt.main(["--claim", "leak lab", "--records", "10",
                      "--fields", "nik,nama", "--sample-available",
                      "--sample-fields", "nik,nama", "--corroborators", "2",
                      "--official", "ack", "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "cyphron.leak-triage/1")
        self.assertEqual(data["verdict"], "VERIFIED-CANDIDATE")

    def test_cli_tanpa_claim_exit2(self):
        # --claim wajib; parse error -> SystemExit 2 dari argparse
        with self.assertRaises(SystemExit) as ctx:
            lt.main([])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
