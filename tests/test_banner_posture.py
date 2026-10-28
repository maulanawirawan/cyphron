"""Test suite skill banner-posture v2 — body di-mock, NOL jaringan.

Regresi utama:
  - F2: deteksi produk "owa" TIDAK boleh kena substring "reflowApp"
    (kasus nyata halaman login Zimbra, live 2026-10-06).
Kontrak: findings.json satu pintu; version-not-exposed => CVE mapping
TIDAK diklaim.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import banner_posture as bp  # noqa: E402

ZIMBRA_BODY = """
<html><head><title>Zimbra Web Client Sign In</title>
<link href="/css/common,login,zhtml,skin.css?skin=harmony&v=260707094130">
</head><body>
<div class="reflowApp">login form</div>
<script>if(window.zimbraMail){zimbraMail.getAppViewMgr().fitAll()}</script>
</body></html>
"""

HEADERS_OK = {
    "Server": "nginx",
    "X-Frame-Options": "SAMEORIGIN",
    "Strict-Transport-Security": "max-age=15768000",
}


def run_audit(body, headers=None, status=200, url="https://mail.example.id/"):
    result = {"status": status, "headers": headers or {}, "body": body}
    return bp.audit(url, result)


class ProductDetectionTest(unittest.TestCase):
    def test_zimbra_detected_owa_not_falsely_matched(self):
        rows, meta = run_audit(ZIMBRA_BODY, HEADERS_OK)
        self.assertEqual(meta["products"], ["Zimbra Collaboration Suite"])
        titles = [r["title"] for r in rows]
        prod = [t for t in titles if "Product banner" in t]
        self.assertEqual(len(prod), 1)
        self.assertIn("Zimbra", prod[0])
        self.assertNotIn("Outlook", prod[0])  # F2 anti-FP

    def test_outlook_web_app_full_phrase_matches(self):
        rows, meta = run_audit("<title>Outlook Web App</title>")
        self.assertIn("Outlook Web App / Exchange", meta["products"])

    def test_version_marker_found(self):
        _, meta = run_audit(ZIMBRA_BODY, HEADERS_OK)
        self.assertEqual(meta["version_markers"], ["260707094130"])

    def test_version_not_exposed_means_no_cve_claim(self):
        body = ("<html><head><title>Zimbra Web Client Sign In</title></head>"
                "<body>login</body></html>")
        rows, meta = run_audit(body, HEADERS_OK)
        self.assertEqual(meta["version_markers"], [])
        not_claimed = [r for r in rows if "NOT claimed" in r["title"]]
        self.assertEqual(len(not_claimed), 1)
        self.assertEqual(not_claimed[0]["verdict"], 0)


class SecurityHeaderTest(unittest.TestCase):
    def test_present_headers_aman(self):
        rows, _ = run_audit(ZIMBRA_BODY, HEADERS_OK)
        aman = [r for r in rows if r.get("category") == "AMAN"]
        labels = " ".join(r["title"] for r in aman)
        self.assertIn("HSTS", labels)
        self.assertIn("X-Frame-Options", labels)

    def test_absent_headers_are_leads_not_weakness(self):
        rows, _ = run_audit(ZIMBRA_BODY, {"Server": "nginx"})
        absent = [r for r in rows if "absent" in r["title"]]
        self.assertEqual(len(absent), 4)  # HSTS, XFO, CSP, XCTO
        for r in absent:
            self.assertEqual(r["verdict"], 1)
            self.assertEqual(r["severity"], "low")
            self.assertFalse(r["reportable"])
        no_hsts = [r for r in rows if r["title"].startswith("No HSTS")]
        self.assertEqual(len(no_hsts), 1)  # lead tambahan host https tanpa HSTS


class FetchFailureTest(unittest.TestCase):
    def test_fetch_error_recorded_not_silent(self):
        rows, meta = run_audit("__fetch_error__ TimeoutError: t", {},
                               status=None)
        self.assertTrue(meta["error"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "unconfirmed")


class ContractTest(unittest.TestCase):
    def test_request_budget_in_meta(self):
        _, meta = run_audit(ZIMBRA_BODY, HEADERS_OK)
        self.assertEqual(meta["requests"], 1)  # batas 1-request ditegakkan


if __name__ == "__main__":
    unittest.main(verbosity=2)
