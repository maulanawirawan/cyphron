"""Unit tests — Unity batch 2: escalation.py (adaptive escalation) + blind.py
(blind re-producer). Semua offline (http_engine dipatch)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import escalation, verdicts
from cyphron.blind import replay, replay_all
from cyphron.findings import Finding
from cyphron.graph import build_with_findings
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel


def _ctx(world: WorldModel | None = None) -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=world or WorldModel(), rate_limit_s=0.0,
                       timeout_s=5.0, max_requests=50)


def _finding(**kw) -> Finding:
    base = dict(tool="bola", title="IDOR pada /api/invoice",
                severity="high", description="d", target_url="https://t.test/api/invoice/123",
                confidence=0.9, status="confirmed")
    base.update(kw)
    return Finding(**base)


def _rich_world() -> WorldModel:
    w = WorldModel()
    w.target = "https://t.test"
    w.technologies = {"Server: nginx/1.24.0": "header on /",
                      "session cookie": "sessid"}
    ep1 = w.observe_endpoint("https://t.test/login", [], "GET")
    ep1.form_fields = ["email", "password"]
    ep1.status = 200
    ep2 = w.observe_endpoint("https://t.test/api/invoice/123", ["id", "uid", "ts"], "GET")
    ep2.status = 200
    ep3 = w.observe_endpoint("https://t.test/admin/dashboard", [], "GET")
    ep3.status = 200
    return w


class TestEscalation(unittest.TestCase):
    def test_thin_graph_stays_probe_even_if_offensive_allowed(self):
        plan = escalation.escalation_plan(build_with_findings(WorldModel(), []),
                                          offensive_allowed=True)
        self.assertEqual(plan["fase"], "PROBE")
        self.assertEqual(plan["unlocked_engines"], [])

    def test_no_offensive_permission_never_escalates(self):
        plan = escalation.escalation_plan(build_with_findings(_rich_world(), []),
                                          offensive_allowed=False)
        self.assertEqual(plan["fase"], "PATTERN")
        self.assertEqual(plan["unlocked_engines"], [])
        self.assertTrue(plan["patterns"])

    def test_rich_graph_escalates_and_unlocks(self):
        plan = escalation.escalation_plan(build_with_findings(_rich_world(), []),
                                          offensive_allowed=True)
        self.assertEqual(plan["fase"], "ESCALATE")
        self.assertIn("login-form", plan["patterns"])
        self.assertIn("lockout", plan["unlocked_engines"])
        self.assertIn("bola", plan["unlocked_engines"])
        self.assertIn("admin_panel", plan["unlocked_engines"])

    def test_vuln_candidates_reach_prove_phase(self):
        plan = escalation.escalation_plan(build_with_findings(_rich_world(), []),
                                          offensive_allowed=True,
                                          has_vuln_candidates=True)
        self.assertEqual(plan["fase"], "PROVE")


class TestBlindReproducer(unittest.TestCase):
    def test_non_get_never_replayed(self):
        f = _finding(request="POST https://t.test/x")
        r = replay(f, _ctx())
        self.assertFalse(r["attempted"])
        self.assertIn("non-GET", r["reason"])

    def test_insufficient_evidence(self):
        f = _finding(request="GET https://t.test/x", response="ok")
        r = replay(f, _ctx())
        self.assertFalse(r["attempted"])
        self.assertIn("evidence tidak cukup", r["reason"])

    def test_marker_match_attaches_blind_evidence(self):
        body = "selamat datang di panel admin ACME-INTERNAL-7788 terpercaya"
        seen = []

        _orig = http_engine.http_get
        def fake_get(url, **kw):
            seen.append(url)
            return 200, {}, body, 1
        http_engine.http_get = fake_get
        self.addCleanup(setattr, http_engine, "http_get", _orig)

        w = WorldModel()
        f = _finding(request="GET https://t.test/admin",
                     response=body)
        r = replay(f, _ctx(w))
        self.assertTrue(r["attempted"])
        self.assertTrue(r["match"])
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], "https://t.test/admin")
        kinds = [e["kind"] for e in f.evidence_chain]
        self.assertIn("blind", kinds)
        self.assertEqual(verdicts.verdict_of(f), verdicts.BLIND_VALIDATED)

    def test_marker_missing_is_not_rejection(self):
        _orig = http_engine.http_get
        def fake_get(url, **kw):
            return 200, {}, "halaman lain sama sekali", 1
        http_engine.http_get = fake_get
        self.addCleanup(setattr, http_engine, "http_get", _orig)
        w = WorldModel()
        f = _finding(request="GET https://t.test/admin",
                     response="konten lama yang berbeda sekali")
        r = replay(f, _ctx(w))
        self.assertTrue(r["attempted"])
        self.assertFalse(r["match"])
        self.assertNotIn("blind", [e["kind"] for e in f.evidence_chain])

    def test_replay_all_respects_cap(self):
        findings = [_finding(request="GET https://t.test/a",
                             response="konten cukup panjang sekali ya") for _ in range(5)]
        for f in findings:
            f.attach_evidence("kb", {"n": 1})
        _orig = http_engine.http_get
        http_engine.http_get = lambda url, **kw: (200, {}, "konten cukup panjang sekali ya", 1)
        self.addCleanup(setattr, http_engine, "http_get", _orig)
        out = replay_all(findings, _ctx(), cap=2)
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main()
