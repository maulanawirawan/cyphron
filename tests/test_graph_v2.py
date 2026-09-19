"""Unit tests — ROADMAP-UNITY U1: Evidence Graph v2 + Verdict Ladder.

- verdicts: tangga 0-5 + REJECTED dari status/evidence_chain; garis laporan
  level >= 3; lead = 0-2.
- graph v2: build_with_findings menambah VULNERABILITY/EVIDENCE/OBJECT +
  EXPOSES/VERIFIED_BY/TARGETS/REACHED_VIA (provenance via=tool); attack_paths
  BFS deterministik; provenance menjawab "sampai sini lewat apa"; round-trip
  JSON v1 tetap aman.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import verdicts
from cyphron.findings import Finding
from cyphron.graph import (
    attack_paths, build_from_world, build_with_findings, provenance)
from cyphron.world.model import WorldModel


def _finding(**kw) -> Finding:
    base = dict(tool="bola", title="IDOR pada /api/invoice",
                severity="high", description="d", target_url="/api/invoice/123",
                confidence=0.9, status="confirmed")
    base.update(kw)
    f = Finding(**base)
    return f


class TestVerdictLadder(unittest.TestCase):
    def test_observed_no_evidence(self):
        f = _finding(status="unconfirmed")
        self.assertEqual(verdicts.verdict_of(f), verdicts.OBSERVED)
        self.assertTrue(verdicts.is_lead(f))
        self.assertFalse(verdicts.qualifies_for_report(f))

    def test_suspected_with_evidence(self):
        f = _finding(status="unconfirmed")
        f.attach_evidence("probe", {"x": 1})
        self.assertEqual(verdicts.verdict_of(f), verdicts.SUSPECTED)

    def test_reproduced_confirmed_without_deterministic(self):
        f = _finding(status="confirmed")
        f.attach_evidence("manual-review", {"x": 1})
        self.assertEqual(verdicts.verdict_of(f), verdicts.REPRODUCED)

    def test_deterministically_verified(self):
        f = _finding(status="confirmed")
        f.attach_evidence("request-response", {"poc": "1234+1111=2345"})
        self.assertEqual(verdicts.verdict_of(f),
                         verdicts.DETERMINISTICALLY_VERIFIED)
        self.assertTrue(verdicts.qualifies_for_report(f))
        self.assertFalse(verdicts.is_lead(f))

    def test_impact_then_blind(self):
        f = _finding(status="confirmed")
        f.attach_evidence("request-response", {"poc": 1})
        f.attach_evidence("impact", {"rows": 1})
        self.assertEqual(verdicts.verdict_of(f), verdicts.IMPACT_VERIFIED)
        f.attach_evidence("blind", {"validator": "v2"})
        self.assertEqual(verdicts.verdict_of(f), verdicts.BLIND_VALIDATED)

    def test_rejected(self):
        f = _finding(status="false-positive")
        self.assertEqual(verdicts.verdict_of(f), verdicts.REJECTED)
        self.assertFalse(verdicts.qualifies_for_report(f))


class TestGraphV2(unittest.TestCase):
    def _world(self):
        w = WorldModel()
        w.target = "https://t.test"
        w.technologies = {"Server: nginx/1.24.0": "header on /"}
        ep = w.observe_endpoint("/api/invoice/123", ["id"], "GET")
        ep.status = 200
        return w

    def test_build_with_findings(self):
        w = self._world()
        f = _finding(param="id")
        f.attach_evidence("request-response", {"poc": 1})
        g = build_with_findings(w, [f])
        stats = g.stats()
        self.assertGreaterEqual(stats["nodes"].get("VULNERABILITY", 0), 1)
        self.assertGreaterEqual(stats["nodes"].get("EVIDENCE", 0), 1)
        self.assertGreaterEqual(stats["nodes"].get("OBJECT", 0), 1)
        self.assertGreaterEqual(stats["edges"].get("EXPOSES", 0), 1)
        self.assertGreaterEqual(stats["edges"].get("VERIFIED_BY", 0), 1)
        self.assertGreaterEqual(stats["edges"].get("TARGETS", 0), 1)
        self.assertGreaterEqual(stats["edges"].get("REACHED_VIA", 0), 1)
        # round-trip v2 tetap aman
        g2 = g.__class__.from_json(g.to_json())
        self.assertEqual(g2.stats(), stats)

    def test_attack_paths_and_provenance(self):
        w = self._world()
        f = _finding(param="id")
        g = build_with_findings(w, [f])
        vuln_id = f"VULNERABILITY:{f.id}"
        paths = attack_paths(g, "IDENTITY:anonymous", vuln_id)
        self.assertTrue(paths)
        self.assertIn("IDENTITY:anonymous", paths[0])
        self.assertEqual(paths[0][-1], vuln_id)
        prov = provenance(g, vuln_id, depth=2)
        self.assertTrue(any(p["rel"] in ("REACHED_VIA", "EXPOSES")
                            for p in prov))
        self.assertTrue(any(p.get("via") == "bola" for p in prov))

    def test_v1_build_unchanged(self):
        g = build_from_world(self._world())
        s = g.stats()
        self.assertIn("TARGET", s["nodes"])
        self.assertIn("IDENTITY", s["nodes"])
        self.assertIn("HAS_ENDPOINT", s["edges"])

    def test_attack_paths_cap_and_unknown_start(self):
        g = build_from_world(self._world())
        self.assertEqual(attack_paths(g, "IDENTITY:tidak-ada",
                                      "ENDPOINT:/api/invoice/123"), [])


if __name__ == "__main__":
    unittest.main()
