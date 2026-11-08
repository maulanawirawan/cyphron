"""Test chain_planner — nol jaringan, fixture findings inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import chain_planner as cp

REPO_TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _f(tool, check, severity="medium", cwe=None, title="t"):
    return {"tool": tool, "check": check, "severity": severity,
            "cwe": cwe, "title": title}


def _run(findings, tmp, extra=None):
    src = Path(tmp.name) / "findings.json"
    src.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    out = Path(tmp.name) / "r.json"
    argv = ["--findings", str(src), "--out", str(out)] + (extra or [])
    rc = cp.main(argv)
    return rc, json.loads(out.read_text(encoding="utf-8"))


class TestClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_by_tool_name_and_check(self):
        rc, rep = _run([_f("exploit_playbooks", "ssrf-callback-dns")],
                       self.tmp)
        self.assertEqual(rc, 1)
        self.assertEqual(len(rep["chains"]), 1)
        c = rep["chains"][0]
        self.assertEqual(c["chain_id"], "ssrf-cloud-metadata")
        self.assertEqual(c["state"], "candidate")
        self.assertEqual(c["combined_severity"], "critical")
        self.assertIn("SsrfChainPlaybook", c["evidence_via"])
        self.assertEqual(rep["summary"]["unmapped"], 0)

    def test_by_cwe_fallback(self):
        rc, rep = _run([_f("tool_lain_sama_sekali", "cek-aneh",
                           cwe="CWE-918")], self.tmp)
        self.assertEqual(rc, 1)
        self.assertEqual(rep["chains"][0]["chain_id"],
                         "ssrf-cloud-metadata")

    def test_ready_to_combine(self):
        rc, rep = _run([
            _f("exploit_playbooks", "ssrf-callback", "medium"),
            _f("exploit_playbooks", "ssrf-chain-metadata", "high"),
        ], self.tmp)
        self.assertEqual(rc, 1)
        c = rep["chains"][0]
        self.assertEqual(c["state"], "ready-to-combine")
        self.assertEqual(c["combined_severity"], "critical")
        self.assertEqual(rep["summary"]["ready"], 1)

    def test_idor_mutation_chain(self):
        rc, rep = _run([
            _f("exploit_playbooks", "idor-orders-read", "medium"),
            _f("exploit_playbooks", "idor-mass-write", "medium"),
        ], self.tmp)
        c = next(x for x in rep["chains"]
                 if x["chain_id"] == "idor-method-mutation")
        self.assertEqual(c["state"], "ready-to-combine")

    def test_unmapped_counted_not_dropped(self):
        rc, rep = _run([_f("totally_other", "no-pattern-here")], self.tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["unmapped"], 1)
        self.assertIn("totally_other", rep["unmapped"][0])

    def test_empty_findings(self):
        rc, rep = _run([], self.tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["chains_in"] if False else
                         rep["summary"]["findings_in"], 0)
        self.assertEqual(rep["chains"], [])

    def test_ready_sorted_before_candidate(self):
        rc, rep = _run([
            _f("takeover_fingerprint_checker", "takeover-ns", "medium"),
            _f("open_redirect_surface", "redirect-open", "low"),
            _f("oauth_redirect_audit", "redirect-uri-foreign", "high"),
        ], self.tmp)
        states = [c["state"] for c in rep["chains"]]
        self.assertEqual(states[0], "ready-to-combine")
        # redirect chain ready (B ada), takeover candidate
        by_id = {c["chain_id"]: c for c in rep["chains"]}
        self.assertEqual(by_id["redirect-oauth-code-theft"]["state"],
                         "ready-to-combine")
        self.assertEqual(by_id["takeover-oauth-redirect"]["state"],
                         "candidate")


class TestToolsDirCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_existing_tool_no_note(self):
        rc, rep = _run([_f("exploit_playbooks", "ssrf-callback")],
                       self.tmp, ["--tools-dir", str(REPO_TOOLS)])
        self.assertEqual(rep["chains"][0]["notes"], [])

    def test_missing_tool_noted(self):
        # baris tabel palsu dgn tool B yang tidak ada di repo
        cp.CHAINS.append(dict(
            chain_id="fake-chain", a_tools=("zzz_tool",),
            a_checks=(r"fakepat",), a_cwes=(), b_checks=(r"never",),
            b_step="x", b_tool="tool_tidak_ada_zz", b_probe="x",
            combined="high", uplift_note="x"))
        try:
            rc, rep = _run([_f("zzz_tool", "fakepat-x")],
                           self.tmp, ["--tools-dir", str(REPO_TOOLS)])
            c = next(x for x in rep["chains"]
                     if x["chain_id"] == "fake-chain")
            self.assertTrue(any("tidak ditemukan" in n
                                for n in c["notes"]))
        finally:
            cp.CHAINS.pop()

    def test_no_toolsdir_note(self):
        rc, rep = _run([_f("exploit_playbooks", "ssrf-callback")],
                       self.tmp)
        self.assertTrue(any("--tools-dir tidak diberikan" in n
                            for n in rep["notes"]))


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_exit2(self):
        self.assertEqual(cp.main(["--findings",
                                  str(Path(self.tmp.name) / "nope")]), 2)

    def test_bad_json_exit2(self):
        p = Path(self.tmp.name) / "f.json"
        p.write_text("{rusak", encoding="utf-8")
        self.assertEqual(cp.main(["--findings", str(p)]), 2)

    def test_non_list_exit2(self):
        p = Path(self.tmp.name) / "f.json"
        p.write_text('{"lain": 1}', encoding="utf-8")
        self.assertEqual(cp.main(["--findings", str(p)]), 2)

    def test_plain_array_accepted(self):
        p = Path(self.tmp.name) / "f.json"
        p.write_text(json.dumps([_f("exploit_playbooks", "ssrf-x")]),
                     encoding="utf-8")
        out = Path(self.tmp.name) / "r.json"
        rc = cp.main(["--findings", str(p), "--out", str(out)])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
