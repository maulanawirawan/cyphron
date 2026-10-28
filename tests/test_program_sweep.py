"""Test F18 — diff-since-last otomatis per target di program_sweep.

Diff berbasis ID temuan deterministik (sha256 tool|title|target|file|
param): judul yang direvisi dihitung temuan berbeda — catatan metodologi
itu ikut di field method diff.json. NOL jaringan: helper difunctional-
kan, cyphron.exe tidak dijalankan di sini.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import program_sweep as ps  # noqa: E402


def _doc(*ids_titles):
    return {"ok": True, "data": {}, "findings": [
        {"id": i, "title": t, "severity": "low"} for i, t in ids_titles]}


class DiffSinceLastTest(unittest.TestCase):
    def test_first_sweep_marks_baseline_not_added_noise(self):
        d = ps.diff_since_last(None, _doc(("a", "x"), ("b", "y")))
        self.assertTrue(d["first_sweep"])
        self.assertEqual(d["added"], [])          # tanpa baseline -> bukan "temuan baru"
        self.assertEqual(d["total_now"], 2)

    def test_added_fixed_persist_by_id(self):
        old = {"mtime": 1700000000, "ids": {
            "A": {"id": "A", "title": "lama-ada"},
            "B": {"id": "B", "title": "diperbaiki"}}}
        d = ps.diff_since_last(old, _doc(("A", "lama-ada"), ("C", "baru")))
        self.assertFalse(d["first_sweep"])
        self.assertEqual(d["added_count"], 1)
        self.assertEqual(d["added"][0]["id"], "C")
        self.assertEqual(d["fixed_count"], 1)
        self.assertEqual(d["fixed"][0]["title"], "diperbaiki")
        self.assertEqual(d["persist"], 1)
        self.assertEqual(d["since_epoch"], 1700000000)

    def test_revised_title_counts_as_changed(self):
        # id = sha(tool|title|...) -> judul direvisi = id berubah
        # (di fixture, perubahan itu dimodelkan sebagai id berbeda)
        old = {"mtime": 0, "ids": {"A-old": {"id": "A-old", "title": "teks lama"}}}
        d = ps.diff_since_last(old, _doc(("A-new", "teks baru")))
        self.assertEqual(d["added_count"], 1)
        self.assertEqual(d["fixed_count"], 1)

    def test_cap_keeps_counts_accurate(self):
        old = {"mtime": 0, "ids": {}}
        new = _doc(*[(f"id{i:03d}", f"temuan {i}") for i in range(80)])
        d = ps.diff_since_last(old, new)
        self.assertEqual(d["added_count"], 80)
        self.assertEqual(len(d["added"]), ps.DIFF_ADDED_CAP,
                         "daftar dipangkas, hitungan tetap utuh")


class LoadLastFindingsTest(unittest.TestCase):
    def test_roundtrip_and_corrupt_fail_soft(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            self.assertIsNone(ps.load_last_findings(out))  # belum ada
            (out / "findings.json").write_text(
                json.dumps({"ok": True, "findings": [{"id": "A", "title": "x"}]}),
                encoding="utf-8")
            last = ps.load_last_findings(out)
            self.assertIn("A", last["ids"])
            self.assertGreater(last["mtime"], 0)
            # file cacat -> None (fail-soft, sweep tetap jalan)
            (out / "findings.json").write_text("{rusak", encoding="utf-8")
            self.assertIsNone(ps.load_last_findings(out))


if __name__ == "__main__":
    unittest.main(verbosity=1)
