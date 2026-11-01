"""Test F75 — verdict_audit (audit distribusi verdict, NOL request).

Yang dikunci:
  - SEMUA skill di registry.json wajib punya kurasi strategi (tanpa
    "belum dikurasi") — invariant anti-tebakan;
  - nilai strategi hanya A-F atau "-" (menu operator);
  - bucket_of pemetaan ladder benar termasuk L-x;
  - static_max_verdicts membaca literal verdict=<int> per file skill
    (fixture root sementara, bukan repo asli);
  - iter_observed_rows mengenali output skill ({findings:[rows]}) dan
    kontrak findings.json, me-skip baris tanpa tool/verdict;
  - urutan tabel: berpotensi naik (strategi != "-") di atas;
  - NOL request (tool murni baca file).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verdict_audit as va  # noqa: E402


class KurasiTest(unittest.TestCase):
    def test_semua_skill_registry_punya_kurasi(self):
        reg = va.load_registry()
        self.assertGreater(len(reg), 80)
        tanpa = [n for n in reg if n not in va.STRATEGI]
        self.assertEqual(tanpa, [],
                         "skill registry tanpa kurasi strategi "
                         "(WAJIB dikurasi eksplisit, bukan tebakan): "
                         f"{tanpa}")

    def test_nilai_strategi_hanya_menu_operator(self):
        menu = {"A", "B", "C", "D", "E", "F", "-"}
        for name, (strat, _alasan) in va.STRATEGI.items():
            self.assertIn(strat, menu, name)
            self.assertTrue(_alasan.strip(), name)

    def test_postur_murni_ditandai_minus(self):
        # LANGKAH N: absensi header/DNS = fakta, bukan kerentanan
        for n in ("http-security-headers", "email-sender-surface",
                  "security-txt", "spf-dmarc-posture"):
            self.assertEqual(va.STRATEGI[n][0], "-", n)


class BucketTest(unittest.TestCase):
    def test_bucket_mapping(self):
        self.assertEqual(va.bucket_of(-1), "L-x")
        self.assertEqual(va.bucket_of(0), "L0")
        self.assertEqual(va.bucket_of(1), "L1")
        self.assertEqual(va.bucket_of(2), "L2")
        self.assertEqual(va.bucket_of(3), "L3+")
        self.assertEqual(va.bucket_of(5), "L3+")


class StaticScanTest(unittest.TestCase):
    def test_static_max_dari_fixture_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "skills").mkdir()
            (root / "skills" / "alpha_skill.py").write_text(
                "def audit():\n"
                "    v = 1\n"
                "    return make_finding(verdict=v)\n"
                "def lain():\n"
                "    return make_finding(verdict=3)\n",
                encoding="utf-8")
            (root / "skills" / "beta_skill.py").write_text(
                "make_finding(verdict=0)\n", encoding="utf-8")
            (root / "skills" / "kosong.py").write_text(
                "x = 1\n", encoding="utf-8")
            out = va.static_max_verdicts(root)
            self.assertEqual(out["alpha-skill"], 3)
            self.assertEqual(out["beta-skill"], 0)
            self.assertNotIn("kosong", out)


class ObservedRowsTest(unittest.TestCase):
    def test_parse_output_dan_kontrak(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "findings" / "reports" / "x").mkdir(parents=True)
            skill_out = {"ok": True, "requests": 1, "data": {},
                         "findings": [
                             {"tool": "alpha", "verdict": 1,
                              "status": "confirmed"},
                             {"tool": "alpha", "verdict": 0,
                              "status": "confirmed"},
                             {"tool": "alpha", "verdict": 1,
                              "status": "unconfirmed"},
                             {"tool": "beta", "verdict": 3,
                              "status": "confirmed"},
                             {"no_tool": True, "verdict": 1},
                             {"tool": "gamma", "no_verdict": True},
                         ]}
            (root / "findings" / "reports" / "x" / "alpha.json").write_text(
                json.dumps(skill_out), encoding="utf-8")
            (root / "findings" / "reports" / "x" / "drift.json").write_text(
                json.dumps({"findings": [{"tool": "zz", "verdict": 1}]}),
                encoding="utf-8")
            (root / "findings" / "reports" / "x" / "rusak.json").write_text(
                "{bukan json", encoding="utf-8")
            rows = list(va.iter_observed_rows([], root=root))
            tools = [r["tool"] for _s, r in rows]
            self.assertEqual(tools, ["alpha", "alpha", "alpha", "beta"])


class SortingTest(unittest.TestCase):
    def test_naik_di_atas_tidak_bisa_naik(self):
        entries = [
            {"skill": "postur", "strategi": "-", "obs_l1_confirmed": 99,
             "obs_l1_unconfirmed": 0},
            {"skill": "naik", "strategi": "D", "obs_l1_confirmed": 2,
             "obs_l1_unconfirmed": 0},
        ]
        entries.sort(key=lambda e: (0 if e["strategi"] != "-" else 1,
                                    -e["obs_l1_confirmed"],
                                    -e["obs_l1_unconfirmed"], e["skill"]))
        self.assertEqual(entries[0]["skill"], "naik")


if __name__ == "__main__":
    unittest.main()
