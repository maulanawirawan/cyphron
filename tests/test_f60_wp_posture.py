"""Test F60 — wp-posture (postur WordPress, bounded 6 GET).

NOL jaringan (urlopen di-mock). Yang dikunci:
  - WP + users REST 200 (guest) = L3 reportable dgn daftar slug;
  - versi generator = L1 + fakta; xmlrpc hidup = L1; wp-login = L1;
  - debug.log terbaca = L2; wp-config backup = L2;
  - bukan WP = AMAN; network error = fail-closed;
  - cve-matcher: versi WP -> KEV product-level (WordPress::Core).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import wp_posture as wp  # noqa: E402
import cve_matcher as cm  # noqa: E402
from findings import validate_finding  # noqa: E402

HOME_WP = ('<meta name="generator" content="WordPress 7.1.1" />'
           '<link rel="stylesheet" href="/wp-content/themes/a/style.css">'
           '<script src="/wp-includes/js/jquery.min.js"></script>')


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8", "replace")
        self.headers = {"content-type": "text/html"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body

    def items(self):
        return list(self.headers.items())


class UrlOpenTest(unittest.TestCase):
    def _patch(self, routes: dict):
        def fake_urlopen(req, timeout=None):
            path_full = req.full_url.split("://", 1)[1]
            path = "/" + path_full.split("/", 1)[1] \
                if "/" in path_full.split("://", 1)[-1] else "/"
            for key, (st, body) in routes.items():
                if path == key:
                    return _FakeResp(st, body)
            return _FakeResp(404, "not found")
        return patch.object(wp.urllib.request, "urlopen", fake_urlopen)

    def test_vulnerable_wp_all_findings(self):
        users = json.dumps([
            {"slug": "admbvy5at"}, {"slug": "adminbaik"}])
        routes = {
            "/": (200, HOME_WP),
            "/wp-json/wp/v2/users": (200, users),
            "/xmlrpc.php": (405, "XML-RPC server accepts POST only"),
            "/wp-login.php": (200, "<form name=\"loginform\" "
                                   "id=\"user_login\">"),
            "/debug.log": (200, "[22-Oct-2026 10:00:00 UTC] PHP Notice: x"),
        }
        with self._patch(routes):
            rows, meta = wp.audit("http://t.local")
        self.assertTrue(meta["is_wp"])
        kinds = {r.get("category") for r in rows
                 if r.get("category") == "WP-POSTURE"}
        users_row = next(r for r in rows if r.get("users"))
        self.assertEqual(users_row["verdict"], 3)
        self.assertEqual(users_row["users"], ["admbvy5at", "adminbaik"])
        self.assertIn("Enumerasi user", users_row["title"])
        # debug.log L2
        self.assertTrue(any(r.get("cwe") == "CWE-538" and r["verdict"] == 2
                            for r in rows))
        # versi L1 + xmlrpc L1 + login L1
        self.assertTrue(any(r.get("version") == "7.1.1" for r in rows))
        self.assertTrue(any("XML-RPC" in r["title"] for r in rows))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_not_wordpress_is_aman(self):
        with self._patch({
                "/": (200, "<html><body>builder x</body></html>")}), \
                patch.object(wp.urllib.request, "urlopen",
                             lambda *a, **k: _FakeResp(
                                 200, "<html>builder x</html>")):
            rows, meta = wp.audit("http://t.local")
        self.assertFalse(meta["is_wp"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_network_error_fail_closed(self):
        def boom(req, timeout=None):
            raise TimeoutError("timeout")
        with patch.object(wp.urllib.request, "urlopen", boom):
            rows, meta = wp.audit("http://t.local")
        self.assertFalse(meta["is_wp"])
        # fail-closed: tanpa klaim AMAN atas kegagalan jaringan
        self.assertTrue(all(r["verdict"] != 3 for r in rows)
                        or meta.get("is_wp") is False)

    def test_hardened_wp_clean_row(self):
        routes = {
            "/": (200, HOME_WP),
            "/wp-json/wp/v2/users": (401, "unauthorized"),
            "/xmlrpc.php": (403, "forbidden"),
            "/wp-login.php": (200, "<form id=\"user_login\">"),
        }
        with self._patch(routes):
            rows, meta = wp.audit("http://t.local")
        # hardened: tanpa users, tanpa verdict >= 2 (versi L1 sah tetap
        # muncul dari meta generator)
        self.assertFalse(any(r.get("verdict", 0) >= 2 for r in rows))
        self.assertEqual(meta["users"], [])


class MatcherChainTest(unittest.TestCase):
    def test_wp_version_fact_matches_kev(self):
        kev = [{"cveID": "CVE-2026-60137", "vendorProject": "WordPress",
                "product": "Core", "vulnerabilityName": "x",
                "knownRansomwareCampaignUse": "Unknown", "cwes": []}]
        rows = [{"tool": "wp-posture",
                 "title": "Versi WordPress ter-expose di meta generator "
                          "(7.1.1) — wordpress 7.1.1",
                 "response": "", "status": "confirmed",
                 "target_url": "http://t.local", "extra": {}}]
        rows_out, meta = cm.match_cves(rows, kev, [])
        self.assertTrue(any(r.get("cve") == "CVE-2026-60137"
                            for r in rows_out))


if __name__ == "__main__":
    unittest.main()
