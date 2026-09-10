"""Unit tests FAZ 2 — Adaptive Pentest Planner v2 (re-plan + budget + EV).

Cakupan:
- Step.cost / Step.hypothesis_id default sesuai kontrak
- EV ordering deterministik: EV = impact*confidence/max(cost,1) desc, stabil
- Budget ledger konsisten: sum(allocated) <= budget, hipotesis berlangkah >= 1,
  spent = akumulasi cost step yang di-emit
- Engine max_requests di-scale ke share hipotesis (clamp(int(share), 6, default))
- observe_findings membuka H-react-* dan step follow-up masuk plan() berikutnya
  pada world yang sama
- Confidence naik setelah temuan CONFIRMED dan mengubah urutan langkah N+1
- clean_tools menurunkan confidence hipotesis CONFIRMED (x0.3, sekali per tool)
- Dua world berbeda menghasilkan urutan plan berbeda; read-only tanpa re-plan
- WorldModel snapshot menyertakan findings_seen/replan_events/budget_ledger
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.findings import Finding
from cyphron.planner import DeterministicPlanner, Step
from cyphron.world.model import WorldModel

BASE = "http://127.0.0.1:5777"

# fallback EV weight per phase (harus konsisten dengan planner)
_PHASE_WEIGHT = {"recon": (2, 1.0), "discovery": (3, 0.95),
                 "passive-audit": (2, 0.9), "active-testing": (3, 0.85)}


def _world(params=True, graphql=False, jwt=False) -> WorldModel:
    """WorldModel sintetis mode offensive dengan endpoint berparameter."""
    w = WorldModel(target=BASE, mode="offensive")
    if params:
        w.observe_endpoint(f"{BASE}/search", ["q"], discovered_by="crawler")
    if graphql:
        w.observe_endpoint(f"{BASE}/graphql", [], discovered_by="crawler")
    if jwt:
        w.technologies["jwt token detected"] = "alg=HS256"
    return w


def _finding(tool="sqli_probe", title="SQL injection (error-based)",
             severity="critical", status="confirmed",
             url=f"{BASE}/search", param="q") -> Finding:
    return Finding(tool=tool, title=title, severity=severity,
                   description="bukti sintetis", recommendation="perbaiki",
                   target_url=url, param=param, confidence=0.9, status=status,
                   evidence_kind="request-response")


def _ev_of(step: Step, planner: DeterministicPlanner) -> float:
    """EV sesuai rumus kontrak; fallback bobot fase untuk step tanpa hipotesis."""
    st = planner.budget_ledger().get(step.hypothesis_id) if step.hypothesis_id else None
    if st:
        weight = st["impact"] * st["confidence"]
    else:
        impact, conf = _PHASE_WEIGHT.get(step.phase, (2, 0.9))
        weight = impact * conf
    return weight / max(step.cost, 1)


class TestStepContract(unittest.TestCase):

    def test_step_defaults(self):
        s = Step("sqli_probe", {"url": BASE}, "rasional", "active-testing")
        self.assertEqual(s.cost, 1)
        self.assertEqual(s.hypothesis_id, "")


class TestEvOrdering(unittest.TestCase):

    def setUp(self):
        self.p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        self.w = _world(params=True, graphql=True, jwt=True)
        self.steps = self.p.plan(self.w)
        self.tools = [s.tool for s in self.steps]

    def test_order_is_ev_descending(self):
        evs = [_ev_of(s, self.p) for s in self.steps]
        self.assertEqual(evs, sorted(evs, reverse=True))

    def test_order_deterministic_across_calls(self):
        again = [s.tool for s in self.p.plan(self.w)]
        self.assertEqual(self.tools, again)

    def test_confirmed_hypothesis_steps_lead(self):
        # H-graphql dan H-jwt CONFIRMED (impact 4, conf 0.8, cost 1) -> EV 3.2,
        # di atas discovery (2.85) dan probe param (2.4); tie dipecah alfabetis
        # via tie-break deterministik _ev_key (tool, url, param).
        self.assertEqual(self.tools[0], "gql_alias")
        self.assertEqual(self.tools[1], "gql_depth")
        self.assertEqual(self.tools[2], "jwt_crack")
        self.assertEqual(self.tools[3], "jwt_jku")
        self.assertLess(self.tools.index("gql_alias"), self.tools.index("crawler"))

    def test_steps_carry_hypothesis_and_positive_cost(self):
        tagged = [s for s in self.steps if s.hypothesis_id]
        self.assertTrue(tagged, "langkah aktif harus melayani hipotesis")
        self.assertTrue(all(s.cost >= 1 for s in self.steps))
        by_tool = {s.tool: s for s in self.steps}
        self.assertEqual(by_tool["gql_depth"].hypothesis_id, "H-graphql")
        self.assertEqual(by_tool["sqli_probe"].hypothesis_id, "H-params")
        self.assertEqual(by_tool["id_seq"].hypothesis_id if "id_seq" in by_tool else "", "")


class TestBudgetLedger(unittest.TestCase):

    def test_ledger_shape_and_invariants(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        steps = p.plan(_world())
        ledger = p.budget_ledger()
        self.assertTrue(ledger)
        for hid, e in ledger.items():
            self.assertEqual(set(e), {"claim", "confidence", "impact",
                                      "allocated", "spent", "status"})
            self.assertIsInstance(e["impact"], int)
            self.assertTrue(0.0 <= e["confidence"] <= 1.0)
        self.assertLessEqual(sum(e["allocated"] for e in ledger.values()), 400)
        # tiap hipotesis yang berlangkah mendapat alokasi >= 1
        for s in steps:
            if s.hypothesis_id:
                self.assertGreaterEqual(ledger[s.hypothesis_id]["allocated"], 1)
        # spent = akumulasi cost step ter-emit per hipotesis
        for hid, e in ledger.items():
            self.assertEqual(e["spent"],
                             sum(s.cost for s in steps if s.hypothesis_id == hid))

    def test_replan_round_keeps_sum_within_budget(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        w = _world()
        p.plan(w)
        opened = p.observe_findings([_finding(
            tool="param_miner", title="Hidden parameter discovered",
            severity="low", status="unconfirmed",
            url=f"{BASE}/api/users", param="email")])
        self.assertTrue(opened)
        p.plan(w)
        self.assertLessEqual(sum(e["allocated"] for e in p.budget_ledger().values()), 400)
        self.assertGreaterEqual(p.budget_ledger()["H-react-params"]["allocated"], 1)

    def test_engine_max_requests_scaled_to_share(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=100)
        steps = p.plan(_world())
        by_tool = {s.tool: s for s in steps}
        fuzz = by_tool["fuzz_engine"]
        self.assertLess(fuzz.args["max_requests"], 80, "share 100 harus memangkas default 80")
        self.assertGreaterEqual(fuzz.args["max_requests"], 6)
        self.assertEqual(fuzz.cost, fuzz.args["max_requests"])
        tpl = by_tool["template_probe"]
        self.assertGreaterEqual(tpl.args["max_requests"], 6)
        self.assertLessEqual(tpl.args["max_requests"], 60)
        smg = by_tool["smuggle"]
        self.assertEqual(smg.args["max_requests"], 6)
        self.assertEqual(smg.cost, 6)


class TestObserveFindings(unittest.TestCase):

    def test_new_param_opens_reactive_hypothesis_and_steps(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        w = _world()
        p.plan(w)
        f = _finding(tool="param_miner", title="Hidden parameter discovered",
                     severity="low", status="unconfirmed",
                     url=f"{BASE}/api/users", param="email")
        opened = p.observe_findings([f])
        self.assertEqual([h["id"] for h in opened], ["H-react-params"])
        self.assertEqual(opened[0]["opened_by"], f.title)
        self.assertIn("claim", opened[0])
        self.assertIn("status", opened[0])
        self.assertIn("H-react-params", [h["id"] for h in w.hypotheses])
        # follow-up masuk plan() berikutnya pada world yang sama
        steps = p.plan(w)
        react = [s for s in steps if s.hypothesis_id == "H-react-params"]
        self.assertEqual({s.tool for s in react},
                         {"sqli_probe", "xss_probe", "redirect_probe"})
        self.assertTrue(any(s.args["url"] == f"{BASE}/api/users"
                            and s.args["param"] == "email" for s in react))

    def test_confirmed_high_sqli_opens_deep_and_exploit(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        w = _world()
        p.plan(w)
        f = _finding(url=f"{BASE}/item", param="id")
        opened = p.observe_findings([f])
        ids = [h["id"] for h in opened]
        self.assertIn("H-react-deep-sqli_probe", ids)
        self.assertIn("H-react-exploit", ids)
        self.assertEqual(ids[0], "H-react-params")  # param id juga belum-probe
        steps = p.plan(w)
        expl = next(s for s in steps if s.tool == "exploitability")
        self.assertEqual(expl.hypothesis_id, "H-react-exploit")
        deep = [s for s in steps if s.hypothesis_id == "H-react-deep-sqli_probe"]
        self.assertTrue(all(s.tool == "sqli_probe" for s in deep))

    def test_confidence_bump_changes_next_plan_order(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        w = _world()
        steps1 = [s.tool for s in p.plan(w)]
        # sebelum temuan: probe param (2.4) di bawah auth_probe untagged (2.55)
        self.assertLess(steps1.index("auth_probe"), steps1.index("sqli_probe"))
        f = _finding(url=f"{BASE}/search", param="q")  # pasangan sudah diprobe
        p.observe_findings([f])
        self.assertAlmostEqual(p.budget_ledger()["H-params"]["confidence"], 0.95)
        steps2 = [s.tool for s in p.plan(w)]
        # confidence H-params 0.8 -> 0.95: probe (2.85) kini di atas auth_probe
        self.assertLess(steps2.index("sqli_probe"), steps2.index("auth_probe"))

    def test_clean_tool_demotes_confirmed_hypothesis_once(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        p.plan(_world())
        self.assertAlmostEqual(p.budget_ledger()["H-params"]["confidence"], 0.8)
        p.observe_findings([], clean_tools=["sqli_probe"])
        self.assertAlmostEqual(p.budget_ledger()["H-params"]["confidence"], 0.24)
        p.observe_findings([], clean_tools=["sqli_probe"])
        self.assertAlmostEqual(p.budget_ledger()["H-params"]["confidence"], 0.24,
                               msg="demosi hanya sekali per (tool, hipotesis)")

    def test_no_new_hypothesis_for_known_surface(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        p.plan(_world())
        f = _finding(tool="xss_probe", title="Reflected XSS", severity="high",
                     status="unconfirmed")  # pasangan (search, q) sudah diprobe
        self.assertEqual(p.observe_findings([f]), [])

    def test_read_only_mode_never_opens_reactive(self):
        p = DeterministicPlanner(offensive_allowed=False, request_budget=400)
        w = _world()
        tools = [s.tool for s in p.plan(w)]
        self.assertNotIn("sqli_probe", tools)
        opened = p.observe_findings([_finding(url=f"{BASE}/x", param="y")])
        self.assertEqual(opened, [])


class TestWorldDifferences(unittest.TestCase):

    def test_different_worlds_yield_different_plans(self):
        pa = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        pb = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        tools_a = [s.tool for s in pa.plan(_world(params=True, graphql=True, jwt=True))]
        tools_b = [s.tool for s in pb.plan(_world(params=True))]
        self.assertNotEqual(tools_a, tools_b)
        self.assertEqual(tools_a[0], "gql_alias")
        self.assertEqual(tools_b[0], "browser_engine")  # discovery dulu (tie-break
        # alfabetis menempatkan browser_engine di depan crawler pada EV sama)
        self.assertNotIn("gql_depth", tools_b)
        self.assertNotIn("jwt_jku", tools_b)

    def test_hypotheses_rows_carry_faz2_keys(self):
        p = DeterministicPlanner(offensive_allowed=True, request_budget=400)
        w = _world()
        p.plan(w)
        by_id = {h["id"]: h for h in w.hypotheses}
        for h in w.hypotheses:
            self.assertIn("confidence", h)
            self.assertIn("impact", h)
            self.assertIn("budget_requests", h)
        self.assertAlmostEqual(by_id["H-params"]["confidence"], 0.8)
        self.assertEqual(by_id["H-params"]["impact"], 3)
        self.assertGreaterEqual(by_id["H-params"]["budget_requests"], 1)
        self.assertAlmostEqual(by_id["H-graphql"]["confidence"], 0.0)  # REJECTED
        self.assertAlmostEqual(by_id["H-graphql-discovery"]["confidence"], 0.3)  # PENDING


class TestWorldModelFaz2Fields(unittest.TestCase):

    def test_defaults_and_snapshot(self):
        w = WorldModel()
        self.assertEqual(w.findings_seen, [])
        self.assertEqual(w.replan_events, [])
        self.assertEqual(w.budget_ledger, {})
        w.findings_seen.append({"tool": "sqli_probe", "title": "t"})
        w.replan_events.append({"trigger_finding": "t", "hypothesis_id": "H-react-params",
                                "claim": "c", "steps": ["sqli_probe(u#p)"]})
        w.budget_ledger["H-params"] = {"claim": "c", "confidence": 0.8, "impact": 3,
                                       "allocated": 10, "spent": 4, "status": "CONFIRMED"}
        snap = w.snapshot()
        self.assertEqual(snap["findings_seen"], w.findings_seen)
        self.assertEqual(snap["replan_events"], w.replan_events)
        self.assertEqual(snap["budget_ledger"], w.budget_ledger)


if __name__ == "__main__":
    unittest.main()
