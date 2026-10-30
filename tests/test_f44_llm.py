"""Test F44 — kelas postur AI/LLM (batch 10, hasil riset topic AI).

NOL jaringan eksternal (lab 127.0.0.1 + bukti sintetis). Yang dikunci:
  - llm-endpoint-surface: marker EKSPLISIT = L1 inventaris; tanpa marker
    = AMAN; kata generik (chat/ai/bot/model) TIDAK PERNAH match (FP-guard);
  - playbook prompt-injection (CWE-1427 terverifikasi katalog): canary
    instruksi benign diikuti endpoint vuln = L3; endpoint kontrol wajib
    menolak (ikut = tidak diklaim); kontrol 404 / baseline rusak =
    fail-closed not_proven; marker tidak boleh muncul di baseline;
  - planner: kategori AI -> prompt-injection; param required tidak
    dikarang (blocked tanpa operator).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import llm_endpoint_surface as les  # noqa: E402
import exploit_engine as ee         # noqa: E402
import exploit_playbooks as ep      # noqa: E402
import lab_target                   # noqa: E402
import attack_planner as ap         # noqa: E402
from findings import validate_finding  # noqa: E402

HTML_AI = """
<html><head><title>Asisten</title></head><body>
<script src="/assets/app.js"></script>
<script>fetch('/v1/chat/completions', {model: 'gpt-4o-mini'})</script>
<div>Ditenagai openai-compatible runtime</div>
</body></html>
"""
HTML_PLAIN = "<html><body><p>chat dengan tim kami, ai powered bot, " \
             "model bisnis kami, machine learning</p></body></html>"
HTML_ALMOST = "<html><body><p>chatgpt klon, llm generik, assistant</p>" \
              "</body></html>"


class LlmEndpointSurfaceTest(unittest.TestCase):
    def test_explicit_markers_are_l1_inventory(self):
        rows, meta = les.audit("https://example.com/app", HTML_AI)
        f = rows[0]
        self.assertEqual(f["verdict"], 1)
        self.assertIn("/v1/chat/completions", f["api_paths"])
        self.assertTrue(any(m.startswith("gpt-") for m in f["models"]))
        self.assertIn("openai", f["frameworks"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_generic_words_never_match(self):
        rows, meta = les.audit("https://example.com/", HTML_PLAIN)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(meta["api_paths"] + meta["models"]
                         + meta["frameworks"], [])

    def test_near_miss_tokens_do_not_match(self):
        # chatgpt (tanpa strip), llm tanpa vendor, assistant = bukan marker
        rows, meta = les.audit("https://example.com/", HTML_ALMOST)
        self.assertEqual(rows[0]["verdict"], 0)

    def test_empty_evidence_is_aman(self):
        rows, meta = les.audit("https://example.com/", "")
        self.assertEqual(rows[0]["verdict"], 0)


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class PromptInjectionE2E(LabTestCase):
    def _run(self, tmp, params, playbooks=("prompt-injection",),
             mode="proof"):
        target = {"id": "lab", "base_url": self.base_url,
                  "exploit_allowed": True, "mode": mode,
                  "params": params}
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({"targets": [target],
                                   "playbooks": list(playbooks)}),
                       encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    def test_proven_l3_cwe1427(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-1427")
            self.assertEqual(rows[0]["category"], "AI")
            self.assertTrue(rows[0]["reportable"])
            self.assertIn("prompt-injection", rows[0]["playbook"])

    def test_control_404_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "safe_path": "/api/tidak-ada"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("kontrol (safe) tidak tersedia",
                          rows[0]["title"])

    def test_control_follows_not_proven(self):
        # kontrol menunjuk endpoint vuln yang sama -> differential invalid
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "safe_path": "/api/llm-chat"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak valid", rows[0]["title"])

    def test_broken_baseline_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "path": "/api/tidak-ada"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("fail-closed", rows[0]["title"])

    def test_never_list_clean(self):
        pb = ep.PLAYBOOKS["prompt-injection"]
        self.assertIsNone(ep.check_never_list(pb))
        self.assertEqual(pb.tier, 1)


class LlmOutputE2E(LabTestCase):
    def _run(self, tmp, params, playbooks, mode="proof"):
        target = {"id": "lab", "base_url": self.base_url,
                  "exploit_allowed": True, "mode": mode,
                  "params": params}
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({"targets": [target],
                                   "playbooks": playbooks}),
                       encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    def test_llm_output_proven_l3_cwe1426(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {}, ["llm-output"])
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-1426")

    def test_llm_output_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"llm-output": {
                "safe_path": "/api/llm-render"}}, ["llm-output"])
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak valid", rows[0]["title"])

    def test_rag_poisoning_proven_tier2_mutate(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {}, ["rag-poisoning"], mode="mutate")
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["tier"], 2)
            # cleanup canary tercatat
            self.assertEqual(len(rows[0]["cleanup"]), 2)

    def test_rag_poisoning_skipped_in_proof_mode(self):
        # tier-2 di atas mode proof = skip engine dengan baris audit
        # (stdout), TANPA findings — tidak ada bukti, tidak ada klaim.
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {}, ["rag-poisoning"], mode="proof")
            self.assertEqual(rows, [])

    def test_rag_poisoning_control_review_not_retrievable(self):
        # kontrol diarahkan ke jalur ingest TANPA review -> differential
        # invalid (dokumen kedua ikut retrievable)
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"rag-poisoning": {
                "review_path": "/api/rag/ingest"}}, ["rag-poisoning"],
                mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak valid", rows[0]["title"])

    def test_never_list_clean_both(self):
        for name in ("llm-output", "rag-poisoning"):
            pb = ep.PLAYBOOKS[name]
            self.assertIsNone(ep.check_never_list(pb), name)



class TrialsProbabilisticTest(PromptInjectionE2E):
    """F59 - target non-deterministik (LLM nyata): N-trial
    probabilistik, verdict MAKSIMAL L2 (REPRODUCED) - L3
    tetap khusus deterministik."""

    def test_trials_deterministic_target_l2(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "trials": "5"}}, ["prompt-injection"])
            self.assertEqual(rows[0]["verdict"], 2)
            self.assertTrue(rows[0]["probabilistic"])
            self.assertEqual(rows[0]["hits"], 5)
            self.assertEqual(rows[0]["trials"], 5)
            self.assertIn("5/5 trial", rows[0]["title"])

    def test_flaky_below_threshold_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "path": "/api/llm-chat-flaky", "trials": "5"}},
                ["prompt-injection"])
            # not_proven = baris L0 (inkonklusif, tanpa klaim)
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("di bawah threshold", rows[0]["title"])

    def test_zero_hits_is_aman(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), {"prompt-injection": {
                "path": "/api/llm-chat-safe", "trials": "5"}},
                ["prompt-injection"])
            self.assertEqual(rows[0]["verdict"], 0)

class PlannerWiringTest(unittest.TestCase):
    LEAD_AI = {"id": "lead-ai-0001", "tool": "manual", "category": "AI",
               "title": "Endpoint generasi LLM pada https://t.local/chat",
               "severity": "low", "target_url": "https://t.local/chat",
               "status": "confirmed", "verdict": 1}

    def test_ai_category_maps_to_playbook_param_blocked(self):
        plan = ap.deterministic_plan([self.LEAD_AI], {})
        steps = [s for s in plan["steps"] if s["playbook"] ==
                 "prompt-injection"]
        self.assertEqual(len(steps), 1)
        # path required dari operator — tidak dikarang
        self.assertIn("path", steps[0]["blocked"])

    def test_operator_param_unblocks(self):
        plan = ap.deterministic_plan(
            [self.LEAD_AI], {"prompt-injection.path": "/chat"})
        steps = [s for s in plan["steps"] if s["playbook"] ==
                 "prompt-injection"]
        self.assertEqual(steps[0]["blocked"], [])
        self.assertEqual(steps[0]["params"]["path"], "/chat")
        # default kontrol ikut tersedia
        self.assertEqual(steps[0]["params"]["safe_path"],
                         "/api/llm-chat-safe")

    def test_spec_in_llm_menu(self):
        menu = {name: spec for name, spec in ap.PARAM_SPECS.items()}
        self.assertIn("prompt-injection", menu)
        self.assertIn("path", menu["prompt-injection"]["required"])


if __name__ == "__main__":
    unittest.main()
