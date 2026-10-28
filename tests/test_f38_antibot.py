"""Test F38 — skill antibot-posture (posisi pertahanan anti-bot).

NOL jaringan (probe di-mock). Yang dikunci:
  - vendor edge terdeteksi (cf-mitigated/__cf_bm) = AMAN L0 inventaris;
  - header rate-limit ada = AMAN; tidak ada = L1 BOT-DEFENSE (CWE-770);
  - 2 GET identik persis = L1 determinisme (CWE-330); beda = bukan lead;
  - error jaringan = unconfirmed (tanpa klaim);
  - vendor di /login ikut terhitung; budget GET = 3.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import antibot_posture as ab  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://toko.example/"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


def R(status, body="", headers=None, error=None):
    d = {"status": status, "headers": headers or {}, "body": body}
    if error:
        d["error"] = error
    return d


class DeterminismTest(unittest.TestCase):
    def test_deterministic_is_l1_bot_defense(self):
        res = {"main": R(200, "<html>tokosama</html>"),
               "main_repeat": R(200, "<html>tokosama</html>"),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = one(rows, "deterministic")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-330")
        self.assertEqual(meta["deterministic"], True)

    def test_varying_response_not_a_lead(self):
        res = {"main": R(200, "<html>nonce=AAA</html>"),
               "main_repeat": R(200, "<html>nonce=BBB</html>"),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        self.assertIsNone(one(rows, "deterministic"))
        self.assertEqual(meta["deterministic"], False)


class VendorTest(unittest.TestCase):
    def test_cloudflare_marker_is_aman(self):
        res = {"main": R(200, "<html>ok</html>", {
            "cf-mitigated": "challenge",
            "set-cookie": "__cf_bm=abc; path=/"}),
               "main_repeat": R(200, "<html>ok2</html>", {
            "set-cookie": "__cf_bm=def; path=/"}),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        f = one(rows, "Anti-bot/WAF edge detected")
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(meta["vendors"], ["cloudflare"])

    def test_login_page_vendor_counted(self):
        res = {"main": R(200, "<html>tanpa sinyal</html>"),
               "main_repeat": R(200, "<html>tanpa sinyal</html>"),
               "login": R(200, "<script src='https://challenges."
                               "cloudflare.com/turnstile/v0/api.js'>"),
               "gets": 3}
        rows, meta = ab.audit(URL, res)
        self.assertIn("turnstile", meta["vendors"])
        self.assertEqual(meta["requests"], 3)


class RateLimitTest(unittest.TestCase):
    def test_rate_headers_present_aman(self):
        res = {"main": R(200, "x", {"x-ratelimit-remaining": "99"}),
               "main_repeat": R(200, "x", {"x-ratelimit-remaining": "98"}),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        self.assertEqual(meta["rate_headers"], ["x-ratelimit-remaining"])
        self.assertIsNone(one(rows, "No rate-limit"))

    def test_no_rate_headers_is_l1(self):
        res = {"main": R(200, "x"), "main_repeat": R(200, "x"),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        f = one(rows, "No rate-limit headers")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-770")


class FailClosedTest(unittest.TestCase):
    def test_network_error_unconfirmed(self):
        rows, meta = ab.audit(URL, {"main": R(None, error="URLError"),
                                    "gets": 1})
        self.assertTrue(meta.get("error"))
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_contract_shape(self):
        res = {"main": R(200, "x"), "main_repeat": R(200, "x"),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        self.assertIsInstance(rows, list)
        self.assertIsInstance(meta, dict)


if __name__ == "__main__":
    unittest.main()
