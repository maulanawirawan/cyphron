"""Test submission_gate — nol jaringan, fixture finding + profil inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import submission_gate as sg

GOOD_FINDING = {
    "tool": "oauth_redirect_audit", "check": "redirect-uri-foreign",
    "severity": "high", "status": "confirmed",
    "title": "redirect_uri OAuth menerima domain asing",
    "request": "GET /oauth/authorize?redirect_uri=https://evil.test",
    "response": "HTTP/1.1 302 Location: https://evil.test/?code=...",
    "poc": "klik tautan -> code di domain penyerang",
    "target_url": "https://auth.target.com/oauth/authorize",
}

GOOD_PROGRAM = {
    "impact_list": {"high": ["redirect", "idor"], "critical": ["rce"]},
    "exclusions": ["spam", "rate-limit"],
    "scope": ["*.target.com"],
    "requires_admin": False,
    "known_intended": [],
    "duplicates": [],
    "disclosed": [],
}


def _run(tmp, finding=None, program=None, extra=None, finding_data=None):
    fp = Path(tmp.name) / "f.json"
    fp.write_text(json.dumps(finding_data if finding_data is not None
                             else {"findings": [finding or GOOD_FINDING]}),
                  encoding="utf-8")
    pp = Path(tmp.name) / "p.json"
    pp.write_text(json.dumps(program or GOOD_PROGRAM), encoding="utf-8")
    out = Path(tmp.name) / "r.json"
    rc = sg.main(["--finding", str(fp), "--program", str(pp),
                  "--out", str(out)] + (extra or []))
    return rc, json.loads(out.read_text(encoding="utf-8"))


def _by_q(rep):
    return {a["question"]: a for a in rep["answers"]}


class TestHappyPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_pass_submit(self):
        rc, rep = _run(self.tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(rep["overall"], "SUBMIT")
        self.assertEqual(rep["kills"], [])
        self.assertEqual(len(rep["answers"]), 7)

    def test_q2_exclusion_kill(self):
        prog = dict(GOOD_PROGRAM, exclusions=["redirect"])
        rc, rep = _run(self.tmp, program=prog)
        self.assertEqual(rc, 1)
        self.assertEqual(rep["overall"], "DO-NOT-SUBMIT")
        self.assertIn("q2-impact-listed", rep["kills"])

    def test_q4_privileged_kill(self):
        prog = dict(GOOD_PROGRAM, requires_admin=True)
        rc, rep = _run(self.tmp, program=prog)
        self.assertIn("q4-no-priv-required", rep["kills"])
        self.assertEqual(rep["overall"], "DO-NOT-SUBMIT")

    def test_q5_known_intended_kill(self):
        prog = dict(GOOD_PROGRAM, known_intended=["redirect"])
        rc, rep = _run(self.tmp, program=prog)
        self.assertIn("q5-not-documented", rep["kills"])

    def test_q6_duplicate_and_disclosed_kill(self):
        prog = dict(GOOD_PROGRAM, duplicates=["auth.target.com"])
        rc, rep = _run(self.tmp, program=prog)
        self.assertIn("q6-not-duplicate", rep["kills"])
        prog2 = dict(GOOD_PROGRAM, disclosed=["redirect"])
        rc, rep = _run(self.tmp, program=prog2)
        self.assertIn("q6-not-duplicate", rep["kills"])

    def test_brocards_dismiss_respected_not_rejudged(self):
        bp = Path(self.tmp.name) / "b.json"
        bp.write_text(json.dumps({"overall": "DISMISS"}), encoding="utf-8")
        rc, rep = _run(self.tmp, extra=["--brocards", str(bp)])
        self.assertIn("q5-not-documented", rep["kills"])
        a = _by_q(rep)["q5-not-documented"]
        self.assertIn("brocards", a["reason"].lower())

    def test_brocards_needs_propagates(self):
        bp = Path(self.tmp.name) / "b.json"
        bp.write_text(json.dumps({"overall": "NEEDS-MORE-INFO"}),
                      encoding="utf-8")
        rc, rep = _run(self.tmp, extra=["--brocards", str(bp)])
        self.assertEqual(rep["overall"], "NEEDS-MORE-INFO")
        self.assertIn("q5-not-documented", rep["needs"])


class TestNeedsNotSilent(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_evidence_needs(self):
        f = dict(GOOD_FINDING, request="", response="", poc="",
                 status="unconfirmed")
        rc, rep = _run(self.tmp, finding=f)
        self.assertEqual(rc, 1)
        a = _by_q(rep)["q1-executable-now"]
        self.assertEqual(a["verdict"], "NEEDS-EVIDENCE")
        self.assertTrue(a["next_step"])

    def test_scope_missing_needs(self):
        prog = dict(GOOD_PROGRAM)
        prog.pop("scope")
        rc, rep = _run(self.tmp, program=prog)
        self.assertEqual(_by_q(rep)["q3-in-scope"]["verdict"],
                         "NEEDS-INFO")
        self.assertIn("scope_gate", _by_q(rep)["q3-in-scope"]["next_step"])

    def test_scope_verdict_out_of_scope_kill(self):
        sp = Path(self.tmp.name) / "s.json"
        sp.write_text(json.dumps({"verdicts": [
            {"asset": "auth.target.com", "verdict": "out-of-scope"}]}),
            encoding="utf-8")
        rc, rep = _run(self.tmp, extra=["--scope-verdict", str(sp)])
        self.assertIn("q3-in-scope", rep["kills"])

    def test_scope_verdict_in_scope_pass(self):
        sp = Path(self.tmp.name) / "s.json"
        sp.write_text(json.dumps({"verdicts": [
            {"asset": "auth.target.com", "verdict": "in-scope"}]}),
            encoding="utf-8")
        rc, rep = _run(self.tmp, extra=["--scope-verdict", str(sp)])
        self.assertEqual(_by_q(rep)["q3-in-scope"]["verdict"], "PASS")

    def test_priv_undefined_needs(self):
        prog = dict(GOOD_PROGRAM)
        prog.pop("requires_admin")
        rc, rep = _run(self.tmp, program=prog)
        self.assertEqual(_by_q(rep)["q4-no-priv-required"]["verdict"],
                         "NEEDS-INFO")

    def test_high_severity_without_impact_evidence_needs(self):
        f = dict(GOOD_FINDING, poc="", response="")
        rc, rep = _run(self.tmp, finding=f)
        self.assertEqual(_by_q(rep)["q7-impact-first"]["verdict"],
                         "NEEDS-INFO")

    def test_index_selection(self):
        f2 = dict(GOOD_FINDING, status="unconfirmed", request="",
                  response="", poc="")
        rc, rep = _run(self.tmp, finding_data={"findings": [GOOD_FINDING,
                                                            f2]},
                       extra=["--index", "1"])
        self.assertEqual(rep["overall"], "NEEDS-MORE-INFO")


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_program_exit2(self):
        fp = Path(self.tmp.name) / "f.json"
        fp.write_text(json.dumps({"findings": [GOOD_FINDING]}),
                      encoding="utf-8")
        rc = sg.main(["--finding", str(fp),
                      "--program", str(Path(self.tmp.name) / "nope")])
        self.assertEqual(rc, 2)

    def test_bad_finding_json_exit2(self):
        fp = Path(self.tmp.name) / "f.json"
        fp.write_text("{rusak", encoding="utf-8")
        pp = Path(self.tmp.name) / "p.json"
        pp.write_text("{}", encoding="utf-8")
        rc = sg.main(["--finding", str(fp), "--program", str(pp)])
        self.assertEqual(rc, 2)

    def test_index_out_of_range_exit2(self):
        fp = Path(self.tmp.name) / "f.json"
        fp.write_text(json.dumps({"findings": [GOOD_FINDING]}),
                      encoding="utf-8")
        pp = Path(self.tmp.name) / "p.json"
        pp.write_text(json.dumps(GOOD_PROGRAM), encoding="utf-8")
        rc = sg.main(["--finding", str(fp), "--program", str(pp),
                      "--index", "9"])
        self.assertEqual(rc, 2)

    def test_empty_findings_exit2(self):
        fp = Path(self.tmp.name) / "f.json"
        fp.write_text(json.dumps({"findings": []}), encoding="utf-8")
        pp = Path(self.tmp.name) / "p.json"
        pp.write_text(json.dumps(GOOD_PROGRAM), encoding="utf-8")
        rc = sg.main(["--finding", str(fp), "--program", str(pp)])
        self.assertEqual(rc, 2)

    def test_plain_object_finding_accepted(self):
        fp = Path(self.tmp.name) / "f.json"
        fp.write_text(json.dumps(GOOD_FINDING), encoding="utf-8")
        pp = Path(self.tmp.name) / "p.json"
        pp.write_text(json.dumps(GOOD_PROGRAM), encoding="utf-8")
        out = Path(self.tmp.name) / "r.json"
        rc = sg.main(["--finding", str(fp), "--program", str(pp),
                      "--out", str(out)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
