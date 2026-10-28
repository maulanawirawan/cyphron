"""Test F43 — komponen CWE (intel_sync) + cwe_check (audit referensi).

NOL jaringan (katalog fixture). Yang dikunci:
  - referensi tidak dikenal katalog = lead; Deprecated = lead; bersih =
    satu baris AMAN; katalog hilang = baris audit (bukan klaim bersih);
  - load_cwe_catalog mengurai CSV MITRE (header, CWE-ID numerik) dan
    fail-closed pada file tidak ada;
  - verify_counts komponen cwe: baris aktual vs manifest + drift.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import cwe_check as cc  # noqa: E402
import intel_sync  # noqa: E402
from findings import validate_finding  # noqa: E402

CATALOG = {
    "CWE-125": {"name": "Out-of-bounds Read", "status": "Stable",
                "abstraction": "Base"},
    "CWE-200": {"name": "Exposure of Sensitive Information",
                "status": "Stable", "abstraction": "Class"},
    "CWE-16": {"name": "Configuration", "status": "Deprecated",
               "abstraction": "Category"},
}


class CheckCwesTest(unittest.TestCase):
    def test_unknown_reference_is_lead(self):
        rows, meta = cc.check_cwes({"CWE-99999": ["skills/x.py"]}, CATALOG)
        self.assertEqual(meta["unknown"], 1)
        f = rows[0]
        self.assertEqual(f["verdict"], 1)
        self.assertIn("tidak dikenal", f["title"])
        self.assertEqual(f.get("files"), ["skills/x.py"])

    def test_deprecated_reference_is_lead(self):
        rows, meta = cc.check_cwes({"CWE-16": ["skills/y.py"]}, CATALOG)
        self.assertEqual(meta["deprecated"], 1)
        f = [r for r in rows if "usang" in r["title"]]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["cwe"], "CWE-16")

    def test_clean_catalog_single_aman_row(self):
        rows, meta = cc.check_cwes(
            {"CWE-125": ["a.py"], "CWE-200": ["b.py"]}, CATALOG)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(meta["clean"], 2)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_missing_catalog_is_audit_row_not_clean(self):
        rows, meta = cc.check_cwes({"CWE-125": ["a.py"]}, None)
        self.assertTrue(meta.get("catalog_missing"))
        self.assertEqual(len(rows), 1)
        self.assertIn("intel_sync", rows[0]["recommendation"])

    def test_empty_refs_still_aman_row(self):
        rows, meta = cc.check_cwes({}, CATALOG)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(meta["refs"], 0)


class CollectRefsTest(unittest.TestCase):
    def test_collect_from_py_dir_and_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "skills").mkdir()
            (td / "skills" / "a.py").write_text(
                'x = "CWE-125"\n# note CWE-200\n', encoding="utf-8")
            (td / "reg.json").write_text('{"desc": "lihat CWE-125"}',
                                         encoding="utf-8")
            with patch.object(cc, "ROOT", td):
                refs = cc.collect_cwe_refs(["skills", "reg.json"])
        self.assertEqual(refs["CWE-125"],
                         ["skills/a.py", "reg.json"])
        self.assertEqual(refs["CWE-200"], ["skills/a.py"])

    def test_self_file_excluded(self):
        with patch.object(cc, "ROOT", ROOT):
            refs = cc.collect_cwe_refs(["tools"])
        self.assertNotIn("tools/cwe_check.py",
                         next(iter(refs.values()), [""]))


class LoadCatalogTest(unittest.TestCase):
    def test_parse_mitre_csv(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cwe-1000.csv"
            p.write_text(
                'CWE-ID,Name,Weakness Abstraction,Status,Description\n'
                '125,"Out-of-bounds Read",Base,Stable,"baca di luar batas"\n'
                '16,Configuration,Category,Deprecated,"kategori lama"\n',
                encoding="utf-8")
            cat = intel_sync.load_cwe_catalog(p)
        self.assertEqual(cat["CWE-125"]["status"], "Stable")
        self.assertEqual(cat["CWE-16"]["status"], "Deprecated")

    def test_missing_file_is_empty(self):
        self.assertEqual(intel_sync.load_cwe_catalog(
            Path("Z:/tidak/ada.csv")), {})


class VerifyCountsCweTest(unittest.TestCase):
    def test_count_matches_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            csv = td / "cwe-1000.csv"
            csv.write_text("h\n1\n2\n3\n", encoding="utf-8")  # 3 baris data
            man = {"components": {"cwe": {"entry_count": 3,
                                          "synced_at": 1.0}}}
            (td / "manifest.json").write_text(
                __import__("json").dumps(man), encoding="utf-8")
            with patch.object(intel_sync, "INTEL", td), \
                 patch.object(intel_sync, "MANIFEST", td / "manifest.json"):
                rc = intel_sync.verify_counts({"cwe"})
        # rc None bila ok (print report exit 0)
        self.assertEqual(rc, 0)

    def test_count_mismatch_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            csv = td / "cwe-1000.csv"
            csv.write_text("h\n1\n", encoding="utf-8")  # 1 baris data
            man = {"components": {"cwe": {"entry_count": 3,
                                          "synced_at": 1.0}}}
            (td / "manifest.json").write_text(
                __import__("json").dumps(man), encoding="utf-8")
            with patch.object(intel_sync, "INTEL", td), \
                 patch.object(intel_sync, "MANIFEST", td / "manifest.json"):
                rc = intel_sync.verify_counts({"cwe"})
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
