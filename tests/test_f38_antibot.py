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


def ntrial_res(statuses, retry_after=None):
    """results dict dgn N-trial sintetis (tanpa jaringan)."""
    trials = []
    for i, st in enumerate(statuses, start=1):
        t = {"i": i, "status": st, "retry_after": None,
             "elapsed_s": 0.01, "error": None}
        if retry_after and i == len(statuses):
            t["retry_after"] = retry_after
        trials.append(t)
    return {"main": R(200, "x"), "main_repeat": R(200, "x"),
            "login": None, "gets": 2 + len(statuses),
            "ntrial": {"path": "/", "n": len(statuses),
                       "trials": trials, "gets": len(statuses)}}


class NtrialTest(unittest.TestCase):
    """F75 — upgrade bukti N-trial (pola F59): unthrottled = L2
    reproduced dgn bukti tersimpan; 429/retry-after = pertahanan
    terbukti (AMAN); inkonklusif = kembali L1 (fail-closed)."""

    def test_unthrottled_l2_reproduced(self):
        rows, meta = ab.audit(URL, ntrial_res([200, 200, 200, 200]))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = one(rows, "No throttling across")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-770")
        self.assertEqual(f["status"], "confirmed")
        # bukti N-trial tersimpan di baris (bukan stdout)
        self.assertIn("4x GET", f["request"])
        self.assertIn("[200,200,200,200]", f["response"])
        self.assertEqual(meta["ntrial"]["outcome"], "unthrottled")
        # baris L1 absensi-header TIDAK ikut terbit (naik kelas)
        self.assertIsNone(one(rows, "No rate-limit headers"))

    def test_throttled_429_is_aman(self):
        rows, meta = ab.audit(URL, ntrial_res([200, 200, 429, 200]))
        f = one(rows, "Throttling behavior observed")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 0)
        self.assertEqual(meta["ntrial"]["outcome"], "throttled")
        self.assertEqual(meta["ntrial"]["at"], 3)
        self.assertIsNone(one(rows, "No rate-limit headers"))

    def test_retry_after_header_is_throttled(self):
        rows, meta = ab.audit(URL, ntrial_res([200, 200, 200],
                                              retry_after="30"))
        self.assertEqual(meta["ntrial"]["outcome"], "throttled")
        self.assertIsNone(one(rows, "No throttling across"))

    def test_inconclusive_falls_back_to_l1(self):
        rows, meta = ab.audit(URL, ntrial_res([200, 404, 200, 200]))
        f = one(rows, "No rate-limit headers")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(meta["ntrial"]["outcome"], "inconclusive")
        self.assertIsNone(one(rows, "No throttling across"))

    def test_error_trial_falls_back_to_l1(self):
        rows, meta = ab.audit(URL, ntrial_res([200, None, 200, 200]))
        f = one(rows, "No rate-limit headers")
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(meta["ntrial"]["outcome"], "error")

    def test_unthrottled_with_vendor_stays_l1(self):
        # vendor WAF terdeteksi: klaim unthrottled kontradiktif
        res = ntrial_res([200, 200, 200, 200])
        res["main"]["headers"]["cf-mitigated"] = "challenge"
        rows, meta = ab.audit(URL, res)
        self.assertIsNone(one(rows, "No throttling across"))
        self.assertEqual(one(rows, "No rate-limit headers")["verdict"], 1)

    def test_no_ntrial_keeps_l1_backward_compat(self):
        res = {"main": R(200, "x"), "main_repeat": R(200, "x"),
               "login": None, "gets": 2}
        rows, meta = ab.audit(URL, res)
        self.assertEqual(one(rows, "No rate-limit headers")["verdict"], 1)
        self.assertIsNone(meta.get("ntrial"))

    def test_ntrial_verdict_unit(self):
        self.assertEqual(
            ab._ntrial_verdict({"trials": [{"i": 1, "status": 200}]}),
            {"outcome": "unthrottled"})
        self.assertEqual(
            ab._ntrial_verdict({"trials": []})["outcome"], "empty")

    def test_probe_ntrial_budget_bounded(self):
        # probe() dengan _get dipalsukan: N dibatasi 3..10, gets dihitung
        calls = []

        def fake_get(url, timeout=15.0):
            calls.append(url)
            return R(200, "ok")

        orig = ab._get
        ab._get = fake_get
        try:
            res = ab.probe(URL, check_login=True, ntrial_n=4)
        finally:
            ab._get = orig
        self.assertEqual(len(calls), 2 + 1 + 4)
        self.assertEqual(res["gets"], 7)
        self.assertEqual(res["ntrial"]["n"], 4)
        self.assertEqual(res["ntrial"]["path"], "/")
        self.assertEqual(
            [t["status"] for t in res["ntrial"]["trials"]],
            [200, 200, 200, 200])

    def test_probe_ntrial_clamped(self):
        def fake_get(url, timeout=15.0):
            return R(200, "ok")

        orig = ab._get
        ab._get = fake_get
        try:
            res = ab.probe(URL, check_login=False, ntrial_n=99)
        finally:
            ab._get = orig
        self.assertEqual(res["ntrial"]["n"], ab.NTRIAL_MAX)


if __name__ == "__main__":
    unittest.main()
