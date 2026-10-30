"""Test F17 — novelty/duplicate-risk, debug-page, rate-limit, impact
narrative, outcome ingest. Semua mocked (nol jaringan)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import novelty_check as nc  # noqa: E402
import debug_page_detector as dpd  # noqa: E402
import rate_limit_validator as rlv  # noqa: E402
import impact_narrative as inp  # noqa: E402


class NoveltyTest(unittest.TestCase):
    def test_email_posture_is_high_duplicate_risk(self):
        # pelajaran triage: DMARC p=none ditolak DUPLIKAT
        flag = nc.classify("DMARC policy p=none on example.id", "posture")
        self.assertEqual(flag["duplicate_risk"], "HIGH")
        self.assertIn("known-list", flag["advice"])

    def test_wp_user_enum_is_high(self):
        flag = nc.classify("WordPress REST API User Enumeration on finance.x",
                           "wp-user-enumeration")
        self.assertEqual(flag["duplicate_risk"], "HIGH")

    def test_debug_page_is_medium(self):
        flag = nc.classify("Verbose Laravel Debug Page on apps.x",
                           "debug-page-exposure")
        self.assertEqual(flag["duplicate_risk"], "MEDIUM")

    def test_chain_finding_is_low(self):
        flag = nc.classify("IDOR via order id 1337 di endpoint spesifik",
                           "idor-specific")
        self.assertEqual(flag["duplicate_risk"], "LOW")

    def test_stamp_ranks_low_risk_first(self):
        rows = [
            {"title": "DMARC policy p=none on x", "finding_class": "posture"},
            {"title": "IDOR spesifik", "finding_class": "idor-specific"},
        ]
        stamped = nc.stamp_report_findings(rows)
        self.assertEqual(stamped[0]["finding_class"], "idor-specific")
        self.assertIn("duplicate_risk", stamped[0]["novelty"])


class DebugPageTest(unittest.TestCase):
    def test_laravel_whoops_detected_l3(self):
        html = "<html><body>Whoops! There was an error. vendor/laravel</body></html>"
        rows, meta = dpd.audit("https://apps.x/", html)
        hit = [r for r in rows if "Laravel Whoops" in r["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["verdict"], 3)  # deterministik, reportable
        self.assertEqual(hit[0]["cwe"], "CWE-489")

    def test_env_secret_is_high(self):
        html = "APP_KEY=base64:AAAAxxxx\nDB_PASSWORD=secret"
        rows, _ = dpd.audit("https://x/", html)
        env = [r for r in rows if "Environment/secret" in r["title"]]
        self.assertEqual(env[0]["severity"], "high")
        self.assertEqual(env[0]["cwe"], "CWE-798")

    def test_no_markers_fail_closed(self):
        rows, _ = dpd.audit("https://x/", "<html>halaman biasa</html>")
        self.assertEqual(rows[0]["category"], "AMAN")
        self.assertEqual(rows[0]["verdict"], 0)


class RateLimitTest(unittest.TestCase):
    def test_no_throttle_is_lead(self):
        res = [{"status": 200, "elapsed_s": 0.1} for _ in range(10)]
        rows, meta = rlv.audit("https://x/login", ["user", "pass"], res)
        lead = [r for r in rows if "No rate limiting" in r["title"]]
        self.assertEqual(len(lead), 1)
        self.assertEqual(lead[0]["verdict"], 1)
        self.assertEqual(lead[0]["cwe"], "CWE-307")
        self.assertEqual(meta["requests"], 10)

    def test_throttle_aman(self):
        res = [{"status": 200, "elapsed_s": 0.1}] * 5 + \
              [{"status": 429, "elapsed_s": 0.1}] * 5
        rows, _ = rlv.audit("https://x/login", ["u", "p"], res)
        aman = [r for r in rows if "ACTIVE" in r["title"]]
        self.assertEqual(len(aman), 1)
        self.assertEqual(aman[0]["category"], "AMAN")

    def test_delay_grows_aman(self):
        res = [{"status": 200, "elapsed_s": 0.1}] * 3 + \
              [{"status": 200, "elapsed_s": 0.6}] * 2
        rows, _ = rlv.audit("https://x/login", ["u", "p"], res)
        self.assertTrue(any("delay" in r["title"] for r in rows))


class ImpactNarrativeTest(unittest.TestCase):
    def test_ssrf_requires_measured_evidence(self):
        d = inp.build("ssrf-amplification", "event.x")
        self.assertTrue(d["ok"])
        blob = " ".join(d["required_evidence"]).lower()
        self.assertIn("amplifikasi", blob)
        self.assertIn("169.254.169.254", blob)
        self.assertIn("doS".lower(), blob)

    def test_unknown_class_fails_closed(self):
        self.assertFalse(inp.build("kelas-ngawur", "x")["ok"])

    def test_email_posture_flags_duplicate_risk(self):
        d = inp.build("email-posture", "example.id")
        self.assertIn("DUPLICATE", " ".join(d["required_evidence"]).upper())

    def test_new_classes_available_with_measurable_evidence(self):
        # kelas baru: semuanya build ok + checklist bukti tidak kosong
        for cls in ("open-redirect", "subdomain-takeover",
                    "cors-misconfig", "secret-leakage"):
            d = inp.build(cls, "lab.local")
            self.assertTrue(d["ok"], f"kelas {cls} harus tersedia")
            self.assertTrue(d["required_evidence"], f"{cls}: checklist kosong")
            self.assertTrue(d["acceptance_hint"], f"{cls}: hint kosong")

    def test_takeover_requires_fingerprint_not_guess(self):
        # zero-FP: takeover tanpa fingerprint layanan = LEAD, bukan klaim
        d = inp.build("subdomain-takeover", "lab.local")
        blob = " ".join(d["required_evidence"]).lower()
        self.assertIn("fingerprint", blob)
        self.assertIn("2 resolver", blob)
        self.assertIn("fail-closed", blob)

    def test_cors_wildcard_is_not_a_finding(self):
        # zero-FP: ACAO * tanpa kredensial tidak boleh dilaporkan
        d = inp.build("cors-misconfig", "lab.local")
        blob = " ".join(d["required_evidence"]).lower()
        self.assertIn("acao: *", blob)
        self.assertIn("bukan temuan", blob)
        self.assertIn("credentials", blob)

    def test_secret_leakage_flags_duplicate_risk(self):
        d = inp.build("secret-leakage", "lab.local")
        blob = " ".join(d["required_evidence"]).upper()
        self.assertIn("DUPLICATE-RISK", blob)
        self.assertIn("PUBLIC-BY-DESIGN", blob)


class OutcomeIngestTest(unittest.TestCase):
    def test_outcomes_learning_shape(self):
        d = json.loads((ROOT / "tests/fixtures/outcomes-fixture.json")
                       .read_text(encoding="utf-8"))
        self.assertEqual(d["score"]["accepted_fixing"], 2)
        self.assertEqual(d["score"]["rejected_duplicate"], 2)
        self.assertEqual(len(d["outcomes"]), 5)
        for o in d["outcomes"]:
            self.assertIn("lesson", o)


if __name__ == "__main__":
    unittest.main(verbosity=2)
