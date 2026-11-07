"""Nol jaringan — test brocards_triage (gerbang 7 brocards, fail-closed).

Kasus acuan mengikuti contoh klasik brocards: eksploit dari langit
(prasyarat = dampak), perilaku terdokumentasi, CVE tanpa bukti, dsb.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import brocards_triage as bt  # noqa: E402


def report(**kw) -> dict:
    """Laporan lengkap (semua brocard PASS) — kasus acuan ACCEPT."""
    return {
        "id": "RPT-1",
        "threat_model": {"attacker": "penyerang internet", "capability": "anon",
                         "action": "kirim payload ke endpoint /api/export",
                         "impact": "baca data pengguna lain"},
        "attacker_capabilities": ["anon"],
        "impact_capability": "user",
        "reachable": True,
        "spec_behavior": "implementation",
        "documented": False,
        "severity": "high",
        "fix_cost": "low",
        "poc": "curl .../api/export?id=../2",
        "cve_id": "",
    }


class TestBrocard1(unittest.TestCase):
    """Nol jaringan — threat model wajib."""

    def test_lengkap_pass(self):
        v, why = bt.brocard_1(report())
        self.assertEqual(v, bt.PASS)

    def test_absen_needs(self):
        r = report(); del r["threat_model"]
        v, why = bt.brocard_1(r)
        self.assertEqual(v, bt.NEEDS)

    def test_field_kosong_needs(self):
        r = report(); r["threat_model"]["impact"] = "  "
        v, _ = bt.brocard_1(r)
        self.assertEqual(v, bt.NEEDS)
        self.assertIn("impact", _)


class TestBrocard2(unittest.TestCase):
    """Nol jaringan — eksploit dari langit via tangga kapabilitas."""

    def test_prasyarat_sama_dampak_dismiss(self):
        r = report(); r["attacker_capabilities"] = ["root"]
        r["impact_capability"] = "system"
        v, why = bt.brocard_2(r)
        self.assertEqual(v, bt.DISMISS)

    def test_prasyarat_di_atas_dampak_dismiss(self):
        r = report(); r["attacker_capabilities"] = ["cloud-admin"]
        r["impact_capability"] = "user"
        v, _ = bt.brocard_2(r)
        self.assertEqual(v, bt.DISMISS)

    def test_naik_tangga_pass(self):
        r = report(); r["attacker_capabilities"] = ["anon", "user"]
        r["impact_capability"] = "app-admin"
        v, _ = bt.brocard_2(r)
        self.assertEqual(v, bt.PASS)

    def test_token_tak_kenal_needs(self):
        r = report(); r["attacker_capabilities"] = ["wizard"]
        v, why = bt.brocard_2(r)
        self.assertEqual(v, bt.NEEDS)

    def test_kapabilitas_absen_needs(self):
        r = report(); del r["attacker_capabilities"]
        v, _ = bt.brocard_2(r)
        self.assertEqual(v, bt.NEEDS)


class TestBrocard3(unittest.TestCase):
    """Nol jaringan — di luar pemakaian nyata."""

    def test_unreachable_dismiss(self):
        v, _ = bt.brocard_3({**report(), "reachable": False})
        self.assertEqual(v, bt.DISMISS)

    def test_dead_code_dismiss(self):
        v, _ = bt.brocard_3({**report(), "dead_code": True})
        self.assertEqual(v, bt.DISMISS)

    def test_unknown_needs(self):
        v, _ = bt.brocard_3({**report(), "reachable": "unknown"})
        self.assertEqual(v, bt.NEEDS)


class TestBrocard4(unittest.TestCase):
    """Nol jaringan — perilaku spesifikasi."""

    def test_spec_permitted_dismiss(self):
        r = report(); r["spec_behavior"] = "spec_permitted"
        v, _ = bt.brocard_4(r)
        self.assertEqual(v, bt.DISMISS)

    def test_stricter_than_spec_pass(self):
        r = report(); r["spec_behavior"] = "spec_permitted"
        r["stricter_than_spec"] = True
        v, why = bt.brocard_4(r)
        self.assertEqual(v, bt.PASS)
        self.assertIn("LEBIH KETAT", why)

    def test_unknown_needs(self):
        v, _ = bt.brocard_4({**report(), "spec_behavior": "unknown"})
        self.assertEqual(v, bt.NEEDS)


class TestBrocard5(unittest.TestCase):
    """Nol jaringan — perilaku terdokumentasi."""

    def test_documented_dismiss(self):
        r = report(); r["documented"] = True; r["doc_warns"] = True
        v, why = bt.brocard_5(r)
        self.assertEqual(v, bt.DISMISS)
        self.assertIn("peringatan", why)

    def test_tidak_terdokumentasi_pass(self):
        r = report(); r["documented"] = False
        v, _ = bt.brocard_5(r)
        self.assertEqual(v, bt.PASS)

    def test_unknown_needs(self):
        v, _ = bt.brocard_5({**report(), "documented": "unknown"})
        self.assertEqual(v, bt.NEEDS)


class TestBrocard6(unittest.TestCase):
    """Nol jaringan — obat lebih buruk dari penyakit."""

    def test_fix_mahal_severity_rendah_dismiss(self):
        r = report(); r["severity"] = "low"; r["fix_cost"] = "high"
        v, why = bt.brocard_6(r)
        self.assertEqual(v, bt.DISMISS)
        self.assertIn("downgrade", why)

    def test_fix_mahal_severity_kritis_pass(self):
        r = report(); r["severity"] = "critical"; r["fix_cost"] = "high"
        v, _ = bt.brocard_6(r)
        self.assertEqual(v, bt.PASS)

    def test_field_absen_needs(self):
        v, _ = bt.brocard_6({"poc": "x"})
        self.assertEqual(v, bt.NEEDS)


class TestBrocard7(unittest.TestCase):
    """Nol jaringan — metadata bukan bukti."""

    def test_cve_tanpa_bukti_dismiss(self):
        r = report(); del r["poc"]
        r["cve_id"] = "CVE-2026-1234"; r["cvss"] = 9.8
        v, why = bt.brocard_7(r)
        self.assertEqual(v, bt.DISMISS)
        self.assertIn("metadata bukan bukti", why)

    def test_bukti_tanpa_metadata_pass(self):
        v, _ = bt.brocard_7({"poc": "langkah reproduksi"})
        self.assertEqual(v, bt.PASS)

    def test_hampa_duanya_needs(self):
        v, _ = bt.brocard_7({})
        self.assertEqual(v, bt.NEEDS)


class TestOverall(unittest.TestCase):
    """Nol jaringan — agregasi verdict + exit code + fail-closed input."""

    def test_semua_pass_accept(self):
        out = bt.triage(report())
        self.assertEqual(out["overall"], "ACCEPT")
        self.assertEqual(len(out["brocards"]), 7)

    def test_dismiss_menghentikan_default(self):
        r = report(); r["documented"] = True  # B5 dismiss
        out = bt.triage(r)
        self.assertEqual(out["overall"], bt.DISMISS)
        self.assertEqual([b["n"] for b in out["brocards"]], [1, 2, 3, 4, 5])

    def test_full_mengevaluasi_semua(self):
        r = report(); r["documented"] = True
        out = bt.triage(r, full=True)
        self.assertEqual(len(out["brocards"]), 7)

    def test_needs_bila_tidak_ada_dismiss(self):
        r = report(); del r["reachable"]
        out = bt.triage(r)
        self.assertEqual(out["overall"], bt.NEEDS)

    def test_bukan_objek_ditolak(self):
        with self.assertRaises(bt.InputError):
            bt.triage(["bukan", "objek"])  # type: ignore[arg-type]

    def test_load_file_tidak_ada(self):
        with self.assertRaises(bt.InputError):
            bt.load_report("TIDAK-ADA-99.json")

    def test_load_json_rusak(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.json"
            p.write_text("{rusak", encoding="utf-8")
            with self.assertRaises(bt.InputError):
                bt.load_report(str(p))

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "r.json"
            p.write_text(json.dumps(report()), encoding="utf-8")
            self.assertEqual(bt.main(["--report", str(p)]), 0)
            r2 = dict(report()); r2["documented"] = True
            p.write_text(json.dumps(r2), encoding="utf-8")
            self.assertEqual(bt.main(["--report", str(p)]), 1)
            r3 = dict(report()); del r3["reachable"]
            p.write_text(json.dumps(r3), encoding="utf-8")
            self.assertEqual(bt.main(["--report", str(p)]), 3)
            p.write_text("{{", encoding="utf-8")
            self.assertEqual(bt.main(["--report", str(p)]), 2)


if __name__ == "__main__":
    unittest.main()
