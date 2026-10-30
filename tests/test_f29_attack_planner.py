"""Test F29 — attack planner (fase 2 exploit tier).

Yang dikunci (docs/EXPLOIT-TIER.md, tanpa satu pun request ke target):
  - deterministic core: kategori lead -> playbook + params derivable;
    param yang tidak derivable = blocked (butuh operator), tidak dikarang;
  - slot LLM: output divalidasi keras — playbook tidak di registry,
    param tidak dikenal, param required kurang => ditolak + tercatat;
    JSON cacat => rencana kosong; TIDAK bisa menambah kemampuan baru;
  - config engine yang di-emit SELALU exploit_allowed=false;
  - planner tidak mengeksekusi (tidak ada request target di kodenya).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import attack_planner as ap  # noqa: E402
import exploit_playbooks as ep  # noqa: E402


def _mk_findings(rows: list[dict], tmp: Path) -> Path:
    p = tmp / "f.json"
    p.write_text(json.dumps({"ok": True, "findings": rows}),
                 encoding="utf-8")
    return p


LEAD_SQLI = {"id": "lead-sqli-0001", "tool": "vdp-pipeline",
             "title": "Raw HTML reflection on https://t.local/search param 'q'",
             "severity": "medium", "category": "INJECTION",
             "target_url": "https://t.local/search?q=x",
             "param": "q", "status": "confirmed", "verdict": 2}
LEAD_AUTH = {"id": "lead-auth-0001", "tool": "posture",
             "title": "Reset flow anomaly on https://t.local",
             "severity": "low", "category": "AUTH",
             "target_url": "https://t.local/", "status": "confirmed",
             "verdict": 1}
LEAD_AMAN = {"id": "lead-aman-0001", "tool": "x",
             "title": "No smuggling clue on https://t.local",
             "severity": "info", "category": "AMAN",
             "target_url": "https://t.local/", "status": "confirmed",
             "verdict": 0}


class DeterministicPlannerTest(unittest.TestCase):
    def test_injection_lead_maps_to_playbooks_with_derived_params(self):
        plan = ap.deterministic_plan([LEAD_SQLI], {})
        steps = {s["playbook"]: s for s in plan["steps"]}
        self.assertIn("sqli-products", steps)
        self.assertEqual(steps["sqli-products"]["params"]["path"],
                         "/search")
        self.assertEqual(steps["sqli-products"]["params"]["param"], "q")
        # baseline_value/payload tidak derivable -> blocked
        self.assertIn("baseline_value", steps["sqli-products"]["blocked"])

    def test_operator_param_unblocks_step(self):
        plan = ap.deterministic_plan([LEAD_AUTH], {
            "reset-enum.canary_email": "me@lab.local"})
        steps = {s["playbook"]: s for s in plan["steps"]}
        self.assertIn("reset-enum", steps)
        self.assertEqual(steps["reset-enum"]["blocked"], [])
        self.assertEqual(steps["reset-enum"]["params"]["canary_email"],
                         "me@lab.local")

    def test_missing_operator_param_is_blocked_not_invented(self):
        plan = ap.deterministic_plan([LEAD_AUTH], {})
        steps = {s["playbook"]: s for s in plan["steps"]}
        self.assertIn("canary_email", steps["reset-enum"]["blocked"])

    def test_aman_leads_are_ignored(self):
        plan = ap.deterministic_plan([LEAD_AMAN], {})
        self.assertEqual(plan["steps"], [])

    def test_plan_only_uses_registry_playbooks(self):
        plan = ap.deterministic_plan([LEAD_SQLI, LEAD_AUTH], {})
        for s in plan["steps"]:
            self.assertIn(s["playbook"], ep.PLAYBOOKS)


class LlmSlotTest(unittest.TestCase):
    def _mock_llm(self, content: str):
        resp = {"choices": [{"message": {"content": content}}]}

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return json.dumps(resp).encode()

            @property
            def status(self):
                return 200

        return patch.object(urllib.request, "urlopen", return_value=R())

    def test_valid_llm_plan_is_validated_and_annotated(self):
        content = json.dumps({"steps": [
            {"playbook": "ssti-eval",
             "params": {"path": "/api/render", "param": "tpl"},
             "rationale": "template input terlihat di bukti"},
            {"playbook": "jwt-weak-secret", "params": {},
             "rationale": "postur auth menunjukkan jwt"}]})
        with self._mock_llm(content):
            plan, rej = ap.llm_plan("http://llm.local/v1/chat/completions",
                                    "m", [LEAD_SQLI], {})
        self.assertEqual(rej, [])
        by_pb = {s["playbook"]: s for s in plan["steps"]}
        self.assertIn("ssti-eval", by_pb)
        self.assertIn("[llm]", by_pb["ssti-eval"]["rationale"])
        self.assertIn("jwt-weak-secret", by_pb)

    def test_unknown_playbook_and_params_are_rejected(self):
        content = json.dumps({"steps": [
            {"playbook": "nuke-everything", "params": {}},
            {"playbook": "ssti-eval", "params": {"path": "/x",
                                                 "hax": "on"}}]})
        with self._mock_llm(content):
            plan, rej = ap.llm_plan("http://llm.local/v1", "m",
                                    [LEAD_SQLI], {})
        self.assertEqual(plan["steps"], [])
        self.assertEqual(len(rej), 2)
        self.assertTrue(any("tidak di registry" in r for r in rej))
        self.assertTrue(any("param tidak dikenal" in r for r in rej))

    def test_missing_required_param_needs_operator(self):
        content = json.dumps({"steps": [
            {"playbook": "idor-orders", "params": {}}]})
        with self._mock_llm(content):
            plan, rej = ap.llm_plan("http://llm.local/v1", "m",
                                    [LEAD_SQLI], {})
        self.assertEqual(plan["steps"], [])
        self.assertTrue(any("butuh operator" in r for r in rej))

    def test_broken_json_yields_empty_plan(self):
        with self._mock_llm("saya tidak bisa memutuskan."):
            plan, rej = ap.llm_plan("http://llm.local/v1", "m",
                                    [LEAD_SQLI], {})
        self.assertEqual(plan["steps"], [])
        self.assertTrue(any("JSON" in r for r in rej))


class EmitConfigTest(unittest.TestCase):
    def test_exploit_allowed_always_false(self):
        plan = {"steps": [
            {"playbook": "ssti-eval", "tier": 1,
             "params": {"path": "/api/render", "param": "tpl"},
             "blocked": []},
            {"playbook": "idor-orders", "tier": 1,
             "params": {}, "blocked": ["own_id"]}]}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "exploit.json"
            ap.emit_engine_config(plan,
                                  {"id": "t", "base_url":
                                   "http://127.0.0.1:1",
                                   "credentials": {}},
                                  out)
            cfg = json.loads(out.read_text(encoding="utf-8"))
            t = cfg["targets"][0]
            self.assertFalse(t["exploit_allowed"])
            self.assertEqual(t["mode"], "proof")
            # langkah yang blocked TIDAK masuk config
            self.assertNotIn("idor-orders", cfg["playbooks"])
            self.assertIn("ssti-eval", cfg["playbooks"])


class MainFailClosedTest(unittest.TestCase):
    def test_missing_findings_exit_2(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "attack_planner.py"),
             "--findings", "C:/tidak-ada.json", "--out", "C:/p.json"],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(r.returncode, 2)

    def test_llm_url_requires_model(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _mk_findings([LEAD_SQLI], tmp)
            r = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "attack_planner.py"),
                 "--findings", str(f), "--out", str(tmp / "plan.json"),
                 "--llm-url", "http://llm.local/v1"],
                capture_output=True, text=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(r.returncode, 2)

    def test_deterministic_run_writes_plan_no_network(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _mk_findings([LEAD_SQLI, LEAD_AUTH, LEAD_AMAN], tmp)
            r = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "attack_planner.py"),
                 "--findings", str(f), "--out", str(tmp / "plan.json"),
                 "--param", "reset-enum.canary_email=a@b.c",
                 "--emit-config", str(tmp / "cfg.json"),
                 "--base-url", "http://127.0.0.1:9999"],
                capture_output=True, text=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(r.returncode, 0, r.stderr)
            plan = json.loads((tmp / "plan.json").read_text("utf-8"))
            self.assertGreater(plan["steps_ready"], 0)
            self.assertGreater(plan["steps_blocked"], 0)
            cfg = json.loads((tmp / "cfg.json").read_text("utf-8"))
            self.assertFalse(cfg["targets"][0]["exploit_allowed"])


if __name__ == "__main__":
    unittest.main()
