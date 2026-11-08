"""Nol jaringan — test data_class_scan (klasifikasi data sensitif ala
custom data identifier Macie). Fixture dibangun inline; Luhn diuji dengan
nomor uji publik (Stripe/Visa). Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("tools",):
    sys.path.insert(0, str(ROOT / sub))

import data_class_scan as dcs  # noqa: E402

TOOL = ROOT / "tools" / "data_class_scan.py"


class TestLuhn(unittest.TestCase):
    def test_nomor_uji_publik(self):
        self.assertTrue(dcs.luhn_valid("4111111111111111"))
        self.assertTrue(dcs.luhn_valid("4242424242424242"))
        self.assertFalse(dcs.luhn_valid("4111111111111112"))

    def test_panjang_di_luar_rentang(self):
        self.assertFalse(dcs.luhn_valid("79927398713"))   # 11 digit
        self.assertFalse(dcs.luhn_valid("41111111111111111111"))  # 20
        self.assertFalse(dcs.luhn_valid("abcd"))


class TestDetectors(unittest.TestCase):
    def test_semua_kategori(self):
        text = ("employee SSN: 123-45-6789 (social security)\n"
                "card: 4111 1111 1111 1111\n"
                "key: AKIAIOSFODNN7EXAMPLE\n"
                "email: jane.doe@example.com")
        hits, _ = dcs.scan_text(text, [], None, 50)
        self.assertIn("pii-aws-access-key", hits)
        self.assertIn("fin-credit-card", hits)
        self.assertIn("pii-ssn-us", hits)
        self.assertIn("pii-email", hits)
        # kartu tak valid tidak dilaporkan
        bad = ("card bad: 4111 1111 1111 1112\n")
        hits_bad, _ = dcs.scan_text(bad, [], None, 50)
        self.assertNotIn("fin-credit-card", hits_bad)

    def test_ssn_tanpa_konteks_format_only(self):
        text = "alarm at 555-12-3456 nothing else here"
        hits, stats = dcs.scan_text(text, [], None, 50)
        self.assertNotIn("pii-ssn-us", hits)
        self.assertEqual(stats["ssn_format_only"], 1)

    def test_ssn_format_identik_telepon_dgn_konteks_terjauh(self):
        """Konteks keyword hanya menangkap match dalam jarak; match yang
        jauh dari keyword = format-only."""
        text = ("ssn identified below\n" + "x" * 200 +
                "\n123-45-6789 far away")
        hits, stats = dcs.scan_text(text, [], None, 50)
        self.assertNotIn("pii-ssn-us", hits)
        self.assertEqual(stats["ssn_format_only"], 1)

    def test_aws_key_asia_juga(self):
        hits, _ = dcs.scan_text("temp key ASIAIOSFODNN7EXAMPLE", [], None, 50)
        self.assertEqual(len(hits["pii-aws-access-key"]), 1)


class TestCustomIdentifier(unittest.TestCase):
    def test_dengan_keyword_dalam_jarak(self):
        cust = dcs.parse_custom("emp=EMP-[0-9]{6}|employee|staff")
        hits, _ = dcs.scan_text("EMP-123456 milik employee itu", [cust],
                                None, 50)
        self.assertEqual(len(hits["custom-emp"]), 1)

    def test_tanpa_keyword_dalam_jarak(self):
        cust = dcs.parse_custom("emp=EMP-[0-9]{6}|employee")
        text = "EMP-123456 " + "z" * 120 + " employee ada jauh"
        hits, _ = dcs.scan_text(text, [cust], None, 50)
        self.assertNotIn("custom-emp", hits)

    def test_tanpa_keywords_langsung_hitung(self):
        cust = dcs.parse_custom("proj=PRJ-[0-9]{4}")
        hits, _ = dcs.scan_text("ref PRJ-0042 dan PRJ-7777", [cust],
                                None, 50)
        self.assertEqual(len(hits["custom-proj"]), 2)

    def test_parse_gagal(self):
        with self.assertRaises(ValueError):
            dcs.parse_custom("tanpa-sama")
        with self.assertRaises(ValueError):
            dcs.parse_custom("bad=[unclosed")
        with self.assertRaises(ValueError):
            dcs.parse_custom("nama jahat!=x")


class TestAllowList(unittest.TestCase):
    def test_supresi_dihitung(self):
        import re
        allow = re.compile(r"@example\.com")
        hits, stats = dcs.scan_text(
            "a.personal@gmail.com and b.corp@example.com", [], allow, 50)
        self.assertEqual(len(hits["pii-email"]), 1)
        self.assertEqual(stats["suppressed"], 1)


class TestLadderDanMasking(unittest.TestCase):
    def test_ladder_severity(self):
        self.assertEqual(dcs._ladder_severity(1, "info"), "info")
        self.assertEqual(dcs._ladder_severity(10, "info"), "medium")
        self.assertEqual(dcs._ladder_severity(50, "info"), "high")
        # min severity tak bisa diturunkan ladder
        self.assertEqual(dcs._ladder_severity(1, "high"), "high")

    def test_masking_tidak_melepas_nilai(self):
        masked = dcs._mask("jane.doe@secret.example.com")
        self.assertNotIn("secret.example.com", masked)
        self.assertTrue(masked.startswith("jane"))
        self.assertTrue(masked.endswith(".com"))


def _mk_file(td: Path, name: str, content: str) -> Path:
    p = td / name
    p.write_text(content, encoding="utf-8")
    return p


class TestScanFiles(unittest.TestCase):
    def test_laporan_dan_severity_naik(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = _mk_file(Path(td), "log.csv",
                          "email: a@corp.io\nemail: b@corp.io\n")
            findings: list[dict] = []
            notes: list[str] = []
            summary = dcs.scan_files([f1], [], None, 50, findings, notes)
            self.assertEqual(summary["files"], 1)
            emails = [f for f in findings if f["check"] == "pii-email"]
            self.assertEqual(len(emails), 1)
            self.assertEqual(emails[0]["occurrences"], 2)

    def test_banyak_kejadian_naik_ladder(self):
        with tempfile.TemporaryDirectory() as td:
            content = "\n".join(f"user{i}@corp.io" for i in range(12))
            f1 = _mk_file(Path(td), "big.csv", content)
            findings: list[dict] = []
            summary = dcs.scan_files([f1], [], None, 50, findings, [])
            emails = [f for f in findings if f["check"] == "pii-email"]
            self.assertEqual(emails[0]["severity"], "medium")  # >=10

    def test_file_biner_dilewati(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / "blob.bin"
            f1.write_bytes(b"\x00\x01binary")
            findings: list[dict] = []
            notes: list[str] = []
            with self.assertRaises(ValueError):
                dcs.scan_files([f1], [], None, 50, findings, notes)
            self.assertEqual(len(notes), 1)  # biner dinotasikan

    def test_tanpa_teks_raise(self):
        findings: list[dict] = []
        notes: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            d.mkdir(exist_ok=True)
            with self.assertRaises(ValueError):
                dcs.scan_files([d], [], None, 50, findings, notes)


class TestCli(unittest.TestCase):
    def test_end_to_end_dan_masking(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = _mk_file(Path(td), "dump.csv",
                          "ssn: 987-65-4321 social\nkey: AKIAIOSFODNN7EXAMPLE\n")
            out = Path(td) / "hasil.json"
            r = subprocess.run([sys.executable, str(TOOL), "--file", str(f1),
                                "--json", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["kind"], "data-classification-scan")
            self.assertIn("attribution", doc)
            text_all = json.dumps(doc)
            # nilai penuh TIDAK boleh tampil di laporan (masking)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text_all)
            self.assertNotIn("987-65-4321", text_all)
            checks = {f["check"] for f in doc["findings"]}
            self.assertIn("pii-aws-access-key", checks)
            self.assertIn("pii-ssn-us", checks)

    def test_fail_on_high_hanya_aws_key(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = _mk_file(Path(td), "plain.txt",
                          "contact ops@corp.io untuk detail\n")
            r = subprocess.run([sys.executable, str(TOOL), "--file",
                                str(f1), "--fail-on", "high"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)

    def test_custom_identifier_cli(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = _mk_file(Path(td), "hr.txt",
                          "EMP-001234 assigned to employee team\n")
            r = subprocess.run([sys.executable, str(TOOL), "--file", str(f1),
                                "--custom", "emp=EMP-[0-9]{6}|employee"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("custom-emp", r.stdout)

    def test_tanpa_input_exit_2(self):
        r = subprocess.run([sys.executable, str(TOOL)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_custom_tidak_valid_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = _mk_file(Path(td), "x.txt", "isi")
            r = subprocess.run([sys.executable, str(TOOL), "--file",
                                str(f1), "--custom", "rusak"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
