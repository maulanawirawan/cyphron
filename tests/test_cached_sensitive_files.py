"""Test suite skill cached-sensitive-files — body di-mock, NOL jaringan.

Regresi utama:
  - Fail-closed: 404 / fetch-error / 200-tanpa-marker => NOL temuan.
  - Marker 'signup-welcome' + pola kredensial => temuan high, confirmed.
  - 200 + marker TANPA pola kredensial => temuan medium (bukan high).
Kontrak: findings.json satu pintu; audit() return (rows, meta) 2-tuple;
batas keras 2 GET.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cached_sensitive_files as csf  # noqa: E402

ACTIVATION_SUCCESS_BODY = """
<html><body>
<h2>Activation complete</h2>
<div id="signup-welcome">
  <p>Your new account is ready.</p>
  <p>Username: <strong>newuser01</strong></p>
  <p>Password: <strong>Xk29!vQzm</strong></p>
  <p><a href="https://site.id/login">Log in</a></p>
</div>
</body></html>
"""

ACTIVATION_FORM_BODY = """
<html><body>
<h2>Activation Key Required</h2>
<form id="signup-form"><input name="key"></form>
</body></html>
"""

PLAIN_PAGE_BODY = "<html><body><h1>Selamat datang</h1></body></html>"


def run_audit(url, result):
    rows, meta = csf.audit(url, result)
    return rows, meta


class TestCachedSensitiveFiles(unittest.TestCase):
    def test_success_page_with_credentials_is_high_confirmed(self):
        rows, meta = run_audit(
            "https://site.id/wp-content/cache/all/wp-activate.php/index.html",
            {"status": 200, "body": ACTIVATION_SUCCESS_BODY})
        self.assertEqual(len(rows), 1)
        f = rows[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(f["cwe"], "CWE-538")
        self.assertEqual(f["verdict"], 3)
        self.assertIn("signup-welcome", f["response"])
        # kontrak meta
        self.assertTrue(meta["cached_page_seen"])
        self.assertEqual(meta["status"], 200)

    def test_success_page_without_credentials_is_medium(self):
        body = ACTIVATION_SUCCESS_BODY.replace(
            "Username: <strong>newuser01</strong>", "Welcome aboard!"
        ).replace("Password: <strong>Xk29!vQzm</strong>", "")
        rows, meta = run_audit("https://site.id/x/index.html",
                               {"status": 200, "body": body})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "medium")
        self.assertTrue(meta["cached_page_seen"])

    def test_activation_form_is_not_a_finding(self):
        # halaman form aktivasi TIDAK memuat blok sukses -> fail-closed
        rows, meta = run_audit("https://site.id/x/index.html",
                               {"status": 200, "body": ACTIVATION_FORM_BODY})
        self.assertEqual(rows, [])
        self.assertFalse(meta["cached_page_seen"])

    def test_plain_page_is_not_a_finding(self):
        rows, meta = run_audit("https://site.id/x/index.html",
                               {"status": 200, "body": PLAIN_PAGE_BODY})
        self.assertEqual(rows, [])

    def test_404_and_fetch_error_are_silent(self):
        rows, meta = run_audit("u", {"status": 404, "body": "Not Found"})
        self.assertEqual(rows, [])
        self.assertEqual(meta["status"], 404)
        rows, meta = run_audit("u", {"status": None, "body": "__fetch_error__ URLError: x"})
        self.assertEqual(rows, [])
        self.assertIsNone(meta["status"])

    def test_cache_paths_shape(self):
        probes = csf.cache_paths("https://site.id/")
        self.assertEqual(len(probes), 2)
        self.assertTrue(probes[0].endswith("/wp-content/cache/all/wp-activate.php/index.html"))
        self.assertIn("/wp-content/cache/supercache/site.id/", probes[1])

    def test_max_live_bound(self):
        self.assertLessEqual(csf.MAX_LIVE, 3)


if __name__ == "__main__":
    unittest.main()
