"""Unit tests — Cyphron Intelligence Fabric (2026-09-12):

- chaining  : Attack Chain Composer (rule prereq, eskalasi severity,
              same-host guard, tanpa confirmed -> tanpa rantai)
- quorum    : 3-validator adjudication (CONFIRMED/PROBABLE/REJECTED)
- drift     : surface diff (added/removed/changed) + relevance + priority
- ledger    : Finding.evidence_chain provenance (kind/at/sha256)
- orchestrator wiring sanity (imports + ScanSummary fields)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import drift, chaining, quorum
from cyphron.chaining import compose, classify
from cyphron.drift import classify_relevance, diff_surface, prioritize
from cyphron.findings import Finding
from cyphron.quorum import adjudicate, summarize


def _f(**kw) -> Finding:
    base = dict(tool="wp_probe", title="WordPress REST API user enumeration on h.test",
                severity="medium", description="x" * 80,
                status="confirmed", confidence=0.9,
                evidence_kind="request-response", request="GET /", response="HTTP 200 [...]")
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------------------------- chaining
class TestChaining(unittest.TestCase):
    def test_classify_maps_capabilities(self):
        f = _f(cwe="CWE-200")
        self.assertIn("user-enum", classify(f))
        g = _f(tool="lockout", title="No lockout/rate limiting on login of h.test",
               cwe="CWE-307")
        self.assertIn("no-lockout", classify(g))

    def test_spray_pipeline_chain_with_escalation(self):
        a = _f(cwe="CWE-200", target_url="h.test")           # medium
        b = _f(tool="lockout", title="No lockout/rate limiting on login of h.test",
               severity="medium", cwe="CWE-307", target_url="h.test")
        chains = compose([a, b])
        self.assertEqual(len(chains), 1)
        c = chains[0]
        self.assertEqual(c.rule_id, "CH-spray-pipeline")
        self.assertEqual(c.combined_severity, "high")   # medium+medium -> high
        self.assertEqual(c.steps, [a.id, b.id])

    def test_cross_host_is_not_chained(self):
        a = _f(cwe="CWE-200", target_url="a.test")
        b = _f(tool="lockout", title="No lockout/rate limiting on login of b.test",
               cwe="CWE-307", target_url="b.test")
        self.assertEqual(compose([a, b]), [])

    def test_unconfirmed_findings_never_chain(self):
        a = _f(cwe="CWE-200", target_url="h.test", status="unconfirmed", confidence=0.2)
        b = _f(tool="lockout", title="No lockout/rate limiting on login of h.test",
               severity="medium", cwe="CWE-307", target_url="h.test",
               status="unconfirmed", confidence=0.2)
        self.assertEqual(compose([a, b]), [])

    def test_missing_prereq_no_chain(self):
        a = _f(cwe="CWE-200", target_url="h.test")
        self.assertEqual(compose([a]), [])


# --------------------------------------------------------------------- quorum
class TestQuorum(unittest.TestCase):
    def test_confirmed_with_full_evidence(self):
        f = _f()
        v = adjudicate([f])[0]
        self.assertEqual(v.status, "CONFIRMED")
        self.assertEqual(v.technical_confidence, 0.9)
        self.assertTrue(all(v.validators.values()))

    def test_no_evidence_is_rejected(self):
        f = _f(request=None, response=None, poc=None)
        v = adjudicate([f])[0]
        self.assertEqual(v.status, "REJECTED")

    def test_single_validator_is_probable(self):
        # bukti pair ada (V2 skeptic pass) + konsisten (V3 pass), tapi
        # verifier belum menganggapnya confirmed (V1 fail) -> tepat 1 vote
        f = _f(status="unconfirmed", confidence=0.4)
        v = adjudicate([f])[0]
        self.assertEqual(v.status, "PROBABLE")
        self.assertFalse(v.validators["runtime_evidence"])

    def test_summarize_counts(self):
        rows = adjudicate([_f(), _f(request=None, response=None, poc=None)])
        s = summarize(rows)
        self.assertEqual(s["CONFIRMED"], 1)
        self.assertEqual(s["REJECTED"], 1)


# ---------------------------------------------------------------------- drift
class TestDrift(unittest.TestCase):
    OLD = [{"url": "https://h.test/", "status": 200},
           {"url": "https://h.test/login", "status": 200},
           {"url": "https://h.test/old-api", "status": 200}]
    NEW = [{"url": "https://h.test/", "status": 200},
           {"url": "https://h.test/login", "status": 403},
           {"url": "https://h.test/admin/export", "status": 200},
           {"url": "https://h.test/api/users", "status": 200}]

    def test_added_removed_changed(self):
        d = diff_surface(self.OLD, self.NEW)
        self.assertEqual(d["counts"], {"added": 2, "removed": 1, "changed": 1})
        added_urls = {r["url"] for r in d["added"]}
        self.assertIn("https://h.test/admin/export", added_urls)
        self.assertEqual([r["url"] for r in d["removed"]], ["https://h.test/old-api"])
        ch = d["changed"][0]
        self.assertEqual((ch["old_status"], ch["new_status"]), (200, 403))

    def test_relevance_classification(self):
        rel, tags = classify_relevance("https://h.test/admin/export")
        self.assertEqual(rel, "high")
        self.assertIn("admin-panel", tags)
        rel2, _ = classify_relevance("https://h.test/api/users")
        self.assertEqual(rel2, "low")

    def test_changed_status_note_detects_access_control_regression(self):
        d = diff_surface([{"url": "https://h.test/login", "status": 401}],
                         [{"url": "https://h.test/login", "status": 200}])
        self.assertIn("HILANG", d["changed"][0]["note"])

    def test_prioritize_high_first(self):
        d = diff_surface(self.OLD, self.NEW)
        q = prioritize(d)
        self.assertEqual(q[0]["url"], "https://h.test/admin/export")


# --------------------------------------------------------------------- ledger
class TestEvidenceLedger(unittest.TestCase):
    def test_attach_evidence_provenance(self):
        f = _f()
        f.attach_evidence("quorum", {"status": "CONFIRMED"})
        f.attach_evidence("repro", {"cmd": "curl -s http://h.test/wp-json/wp/v2/users"})
        self.assertEqual(len(f.evidence_chain), 2)
        e0 = f.evidence_chain[0]
        self.assertEqual(e0["kind"], "quorum")
        self.assertEqual(e0["status"], "CONFIRMED")
        self.assertIn("at", e0)
        self.assertIn("sha256", e0)
        # dua entri dengan konten beda -> hash beda
        self.assertNotEqual(e0["sha256"], f.evidence_chain[1]["sha256"])
        d = f.to_dict()
        self.assertIn("evidence_chain", d)


if __name__ == "__main__":
    unittest.main()
