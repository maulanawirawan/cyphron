"""Test tools/target_scout.py — scout murah, tier tenaga berbukti.

Nol jaringan: fetcher disuntik; aturan klasifikasi diuji murni dari
bukti (status/latency/error). Live-verify dilakukan manual ke
tools/lab_target.py (lihat commit message).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import target_scout as scout  # noqa: E402


class NormalizeTargetTest(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(scout.normalize_target("lab.local:8000"),
                         "http://lab.local:8000")

    def test_keeps_https_origin(self):
        self.assertEqual(
            scout.normalize_target("https://staging.internal/app?a=1"),
            "https://staging.internal")

    def test_invalid_returns_none(self):
        self.assertIsNone(scout.normalize_target("   "))
        self.assertIsNone(scout.normalize_target("http://"))


class ClassifyEvidenceTest(unittest.TestCase):
    @staticmethod
    def evidence(status=None, error=None, latency=12.0):
        return {"origin": "http://x", "paths": {"/": {
            "status": status, "latency_ms": latency, "error": error,
            "bytes": 10, "snippet": "hi"}}, "error": None}

    def test_2xx_soft(self):
        verdict = scout.classify_evidence(self.evidence(status=200))
        self.assertEqual(verdict["tier"], "SOFT")
        self.assertIn("tier0 scan penuh", verdict["suggestion"])

    def test_403_guarded(self):
        verdict = scout.classify_evidence(self.evidence(status=403))
        self.assertEqual(verdict["tier"], "GUARDED")

    def test_500_guarded(self):
        verdict = scout.classify_evidence(self.evidence(status=503))
        self.assertEqual(verdict["tier"], "GUARDED")

    def test_timeout_unreachable(self):
        verdict = scout.classify_evidence(
            self.evidence(error="TimeoutError: timed out"))
        self.assertEqual(verdict["tier"], "UNREACHABLE")
        self.assertIn("skip", verdict["suggestion"])


class ScoutSweepTest(unittest.TestCase):
    def fake_fetch(self, url):
        if "soft.local" in url:
            if url.endswith("/robots.txt"):
                raise urllib_error_404()
            return (b"<html><body>lab</body></html>", 200,
                    {"Server": "pytest", "Content-Type": "text/html"})
        if "guarded.local" in url:
            return (b"forbidden", 403, {"Server": "pytest"})
        if "dead.local" in url:
            raise ConnectionError("connection refused")
        raise AssertionError("URL tak terduga: " + url)

    def test_sweep_tiers_and_report_shape(self):
        report = scout.scout(
            ["https://soft.local", "https://guarded.local",
             "dead.local", "://bukan-url"],
            fetch=self.fake_fetch)
        tiers = {r["evidence"]["origin"]: r["tier"]
                 for r in report["results"]}
        self.assertEqual(tiers["https://soft.local"], "SOFT")
        self.assertEqual(tiers["https://guarded.local"], "GUARDED")
        self.assertEqual(tiers["http://dead.local"], "UNREACHABLE")
        self.assertEqual(len(report["skipped"]), 1)  # ://bukan-url
        self.assertEqual(report["tier_counts"],
                         {"SOFT": 1, "GUARDED": 1, "UNREACHABLE": 1})
        json.dumps(report)  # JSON-able tanpa TypeError

    def test_unreachable_does_not_stop_sweep(self):
        report = scout.scout(["dead.local", "soft.local"],
                             fetch=self.fake_fetch)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["results"][1]["tier"], "SOFT")

    def test_error_recorded_as_evidence(self):
        report = scout.scout(["dead.local"], fetch=self.fake_fetch)
        root = report["results"][0]["evidence"]["paths"]["/"]
        self.assertIsNone(root["status"])
        self.assertIn("ConnectionError", root["error"])


class urllib_error_404(Exception):
    """Simulasi 404 — robots.txt memang boleh absen di banyak server."""


if __name__ == "__main__":
    unittest.main()
