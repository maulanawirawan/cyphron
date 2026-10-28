"""Test F24 — triage advisor (learning loop). READ-ONLY terhadap data
learning; fixture sintetis tests/fixtures/outcomes-fixture.json. NOL
jaringan."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import triage_advisor as ta  # noqa: E402
import impact_narrative as inp  # noqa: E402
import report_pdf as rp  # noqa: E402
from findings import validate_finding  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "outcomes-fixture.json"

TYPST_OK = bool(os.environ.get("CYPHRON_TYPST")
                or (ROOT / "tools/bin/typst-x86_64-pc-windows-msvc/typst.exe"
                    ).exists()
                or shutil.which("typst"))


def _outcomes():
    o, _notes = ta.load_outcomes([FIXTURE])
    return o


class StatsTest(unittest.TestCase):
    def test_counts_match_fixture_score(self):
        outcomes = _outcomes()
        stats = ta.stats_per_class(outcomes)
        self.assertEqual(stats["debug-page-exposure"]["accepted_fixing"], 1)
        self.assertEqual(stats["rate-limit-missing"]["accepted_fixing"], 1)
        self.assertEqual(stats["email-posture"]["rejected_duplicate"], 1)
        self.assertEqual(stats["wp-user-enumeration"]["rejected_duplicate"], 1)
        self.assertEqual(stats["ssrf-amplification"]["rejected_impact"], 1)
        self.assertEqual(stats["email-posture"]["acceptance_rate"], 0.0)
        self.assertEqual(stats["debug-page-exposure"]["acceptance_rate"], 1.0)

    def test_unknown_outcome_goes_to_other_not_accepted(self):
        stats = ta.stats_per_class([{"finding_class": "x",
                                     "outcome": "ACCEPTED_RESOLVED"}])
        self.assertEqual(stats["x"]["other"], 1)
        self.assertEqual(stats["x"]["accepted_fixing"], 0)
        self.assertIn("ACCEPTED_RESOLVED", stats["x"]["other_outcomes"])

    def test_load_outcomes_fail_soft_with_notes(self):
        o, notes = ta.load_outcomes([Path("TIDAK/ADA.json"), FIXTURE])
        self.assertGreater(len(o), 0)
        self.assertTrue(any("tidak ada" in n for n in notes))


class AdviseTest(unittest.TestCase):
    def test_duplicate_history_warns(self):
        adv = ta.advise("email-posture", _outcomes())
        self.assertEqual(adv["rejected_duplicate"], 1)
        self.assertTrue(any("novelty-check" in w for w in adv["warnings"]))

    def test_impact_history_warns(self):
        adv = ta.advise("ssrf-amplification", _outcomes())
        self.assertEqual(adv["rejected_impact"], 1)
        self.assertTrue(any("impact narrative" in w for w in adv["warnings"]))
        self.assertIsNone(adv["hint_extra"])

    def test_accepted_history_gives_positive_hint(self):
        adv = ta.advise("rate-limit-missing", _outcomes())
        self.assertEqual(adv["accepted_fixing"], 1)
        self.assertEqual(adv["warnings"], [])
        self.assertIn("diterima triage", adv["hint_extra"])

    def test_unknown_class_is_not_green(self):
        adv = ta.advise("kelas-asing", _outcomes())
        self.assertEqual(adv["seen"], 0)
        self.assertTrue(any("belum ada riwayat" in w
                            for w in adv["warnings"]))


class EnrichNarrativeTest(unittest.TestCase):
    def test_impact_risk_class_gets_learning_warning(self):
        data = inp.build("ssrf-amplification", "x.example")
        hint_before = data["acceptance_hint"]
        data = ta.enrich_narrative(data, [FIXTURE])
        self.assertIn("learning", data)
        self.assertTrue(any("impact narrative" in w
                            for w in data["learning"]["warnings"]))
        self.assertEqual(data["acceptance_hint"], hint_before)

    def test_accepted_class_gets_auto_hint(self):
        data = inp.build("rate-limit-missing", "x.example")
        data = ta.enrich_narrative(data, [FIXTURE])
        self.assertIn("diterima triage", data["acceptance_hint"])
        self.assertEqual(data["learning"]["warnings"], [])

    def test_no_learning_data_leaves_narrative_untouched(self):
        data = inp.build("ssrf-amplification", "x.example")
        out = ta.enrich_narrative(data, [Path("TIDAK/ADA.json")])
        self.assertNotIn("learning", out)


class ImpactNarrativeCliTest(unittest.TestCase):
    def test_main_with_fixture_learning(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "n.json"
            rc = inp.main_with_args([
                "--class-name", "ssrf-amplification", "--target",
                "x.example", "--out", str(out), "--learning", str(FIXTURE)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            row = doc["findings"][0]
            self.assertEqual(validate_finding(row), [])
            self.assertTrue(any("impact narrative" in w
                                for w in row["learning"]["warnings"]))

    def test_main_no_learning_has_no_learning_key(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "n.json"
            rc = inp.main_with_args([
                "--class-name", "rate-limit-missing", "--target", "x.example",
                "--out", str(out), "--no-learning"])
            self.assertEqual(rc, 0)
            row = json.loads(out.read_text(encoding="utf-8"))["findings"][0]
            self.assertNotIn("learning", row)


class TriageCliTest(unittest.TestCase):
    def test_class_advisory_out_contract_valid(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "adv.json"
            rc = ta.main_with_args(["--learning", str(FIXTURE),
                                    "--class-name", "email-posture",
                                    "--out", str(out)])
            self.assertEqual(rc, 0)
            row = json.loads(out.read_text(encoding="utf-8"))["findings"][0]
            self.assertEqual(validate_finding(row), [])
            self.assertTrue(any("novelty-check" in w for w in row["warnings"]))

    def test_summary_out_lists_all_classes(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "adv.json"
            rc = ta.main_with_args(["--learning", str(FIXTURE),
                                    "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(doc["findings"][0]["classes"]), 5)


class ReportPdfIntegrationTest(unittest.TestCase):
    def test_build_data_carries_class_history(self):
        f = ROOT / "tests/fixtures/report-fixture.json"
        doc = json.loads(f.read_text(encoding="utf-8"))
        outcomes = _outcomes()
        rows = ta.class_history_rows(outcomes)
        data = rp.build_data([doc], None, "Judul", "Sub",
                             class_history=rows)
        self.assertEqual(len(data["class_history"]), 5)
        self.assertEqual(data["class_history"][0]["finding_class"],
                         "debug-page-exposure")  # tie seen=1 -> alfabetis
        data2 = rp.build_data([doc], None, "Judul", "Sub")
        self.assertEqual(data2["class_history"], [])

    @unittest.skipUnless(TYPST_OK, "typst tidak tersedia")
    def test_render_includes_class_history_table(self):
        import fitz
        f = ROOT / "tests/fixtures/report-fixture.json"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.pdf"
            old_argv = sys.argv
            sys.argv = ["report_pdf.py", "--findings", str(f), "--out",
                        str(out), "--title", "Riwayat Uji",
                        "--learning", str(FIXTURE)]
            try:
                rc = rp.main()
            finally:
                sys.argv = old_argv
            self.assertEqual(rc, 0)
            d = fitz.open(str(out))
            txt = "\n".join(d[i].get_text() for i in range(d.page_count))
            d.close()
            self.assertIn("Riwayat Kelas (Learning Loop)", txt)
            self.assertIn("ssrf-amplification", txt)
            self.assertIn("email-posture", txt)


if __name__ == "__main__":
    unittest.main(verbosity=1)
