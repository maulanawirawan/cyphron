"""U2-integ: planner mengonsumsi escalation_plan — fase tercatat di world,
engine hasil unlock menjadi step planner (dedup `_once`, sekali per pola,
budget-aware), fail-closed tanpa otorisasi offensive. Semua offline."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import escalation
from cyphron.graph import build_from_world
from cyphron.orchestrator import ScanSummary
from cyphron.planner import DeterministicPlanner
from cyphron.world.model import WorldModel

# nama engine hasil unlock yang benar-benar terdaftar di registry default
KNOWN = {
    "lockout", "auth_bypass_matrix", "register", "reset_enum", "bola",
    "idor_mass_endpoint", "mass_assign", "api_version_diff", "session_probe",
    "cookie_audit", "priv_matrix", "admin_panel", "laravel_panel", "actuator",
    "wp_probe", "wp_dataexp", "xmlrpc_probe", "traversal", "lfi_read",
    "param_miner", "sqli_probe", "xss_probe",
}


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


class TestEscalationPlanMapping(unittest.TestCase):
    def test_unlocked_by_pattern_memetakan_pola_ke_engine(self):
        plan = escalation.escalation_plan(build_from_world(_rich_world()),
                                          offensive_allowed=True)
        self.assertEqual(plan["fase"], "ESCALATE")
        self.assertIn("login-form", plan["unlocked_by_pattern"])
        self.assertIn("lockout", plan["unlocked_by_pattern"]["login-form"])
        self.assertIn("mass_assign", plan["unlocked_by_pattern"]["json-api-params"])
        self.assertEqual(plan["unlocked_engines"],
                         sorted({e for v in plan["unlocked_by_pattern"].values()
                                 for e in v}))


class TestPlannerEscalation(unittest.TestCase):
    def test_read_only_tetap_pattern_tanpa_step_unlock(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=False, known_tools=KNOWN)
        plan = p.plan(w)
        self.assertEqual(p.escalation_state["fase"], "PATTERN")
        self.assertEqual([s for s in plan if s.hypothesis_id == "H-escalate"], [])
        self.assertTrue(any("escalation" in n for n in w.notes))

    def test_offensive_membuka_engine_sebagai_step(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        plan = p.plan(w)
        self.assertEqual(p.escalation_state["fase"], "ESCALATE")
        esc = [s for s in plan if s.hypothesis_id == "H-escalate"]
        tools = {s.tool for s in esc}
        # engine yang tidak dijadwalkan skeleton _plan_web harus muncul dari unlock
        self.assertIn("mass_assign", tools)
        self.assertIn("api_version_diff", tools)
        self.assertIn("admin_panel", tools)
        for s in esc:
            self.assertEqual(s.phase, "active-testing")
            self.assertGreaterEqual(s.cost, 1)
        # hipotesis masuk ledger budget (budget-aware)
        self.assertIn("H-escalate", p.budget_ledger())
        self.assertTrue(any("escalation unlock" in n for n in w.notes))
        # fase tampil sebagai hipotesis di world
        self.assertTrue(any(h.get("id") == "H-escalate" for h in w.hypotheses))

    def test_dedup_sekali_per_pola_antar_plan(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        plan1 = p.plan(w)
        esc1 = sorted((s.tool, str(sorted(s.args.items())))
                      for s in plan1 if s.hypothesis_id == "H-escalate")
        plan2 = p.plan(w)
        esc2 = sorted((s.tool, str(sorted(s.args.items())))
                      for s in plan2 if s.hypothesis_id == "H-escalate")
        self.assertEqual(esc1, esc2, "plan ulang tidak boleh menduplikasi unlock")
        # pola yang sama tidak membuka gelombang kedua walau graph bertambah
        w.observe_endpoint("https://t.test/admin/users", [], "GET").status = 200
        plan3 = p.plan(w)
        esc3 = {(s.tool, str(sorted(s.args.items())))
                for s in plan3 if s.hypothesis_id == "H-escalate"}
        self.assertEqual(set(esc2), esc3)

    def test_engine_tak_dikenal_difilter_dan_idor_butuh_multisesi(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools={"lockout"})
        plan = p.plan(w)
        esc_tools = {s.tool for s in plan if s.hypothesis_id == "H-escalate"}
        self.assertTrue(esc_tools <= {"lockout"})
        # idor_mass_endpoint butuh >= 2 sesi
        p2 = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        p2.plan(w)
        self.assertNotIn("idor_mass_endpoint",
                         {s.tool for s in p2._schedule})
        p3 = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        p3.account_count = 2
        plan3 = p3.plan(w)
        idor = [s for s in plan3 if s.tool == "idor_mass_endpoint"]
        self.assertTrue(idor)
        self.assertTrue(idor[0].args.get("allow_foreign_probe"))

    def test_prove_menghentikan_unlock_baru(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        p.plan(w)
        w.findings_seen.append({"tool": "sqli_probe", "title": "SQLi",
                                "severity": "high", "status": "confirmed"})
        p.plan(w)
        self.assertEqual(p.escalation_state["fase"], "PROVE")
        self.assertEqual(p.escalation_state["unlocked_engines"], [])

    def test_budget_kecil_tetap_membatasi_alokasi(self):
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN,
                                 request_budget=30)
        p.plan(w)
        ledger = p.budget_ledger()["H-escalate"]
        self.assertLessEqual(ledger["allocated"], 30)
        self.assertTrue(p._schedule)

    def test_step_unlock_terduplikasi_dengan_skeleton_dilewati(self):
        # lockout sudah dijadwalkan _plan_web dengan args identik -> _once
        # menang: tidak ada dua step lockout untuk target yang sama
        w = _rich_world()
        p = DeterministicPlanner(offensive_allowed=True, known_tools=KNOWN)
        plan = p.plan(w)
        lockouts = [s for s in plan if s.tool == "lockout"
                    and s.args.get("url") == w.target]
        self.assertEqual(len(lockouts), 1)


class TestScanSummaryField(unittest.TestCase):
    def test_escalation_field_default_kosong(self):
        s = ScanSummary(target="https://t.test", mode="read-only")
        self.assertEqual(s.escalation, {})


if __name__ == "__main__":
    unittest.main()
