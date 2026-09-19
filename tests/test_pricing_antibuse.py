"""pricing, licensing bertanda tangan, credits, antibuse — kontrak & anti-abuse."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.antibuse import (abuse_verdict, device_fingerprint, ip_abuse_signals,
                              ja3_from_headers, license_sig, license_secret,
                              pow_check, pow_solve, signup_velocity)
from cyphron.credits import CreditLedger
from cyphron.licensing import License, issue_license, TIER_RANK
from cyphron.pricing import MODE_MULTIPLIER, PLANS, estimate_scan_cost, token_cost_for


class TestPricing(unittest.TestCase):
    def test_token_cost_from_risk_tags(self):
        self.assertEqual(token_cost_for({"passive"}), 1)
        self.assertEqual(token_cost_for({"active", "passive"}), 2)
        self.assertEqual(token_cost_for({"aggressive"}), 4)
        self.assertEqual(token_cost_for({"exploit"}), 4)
        self.assertEqual(token_cost_for({"load"}), 3)

    def test_mode_multiplier_applied(self):
        est = estimate_scan_cost([("sqli_probe", {"active"})] * 10, mode="offensive")
        self.assertEqual(est["raw"], 20)
        self.assertEqual(est["total_tokens"], int(20 * MODE_MULTIPLIER["offensive"]))

    def test_plans_complete(self):
        for tier, p in PLANS.items():
            self.assertIn("price_idr", p)
            self.assertIn("token_limit", p)
            self.assertIn("report_mode", p)
        self.assertEqual(PLANS["trial"]["report_mode"], "redacted")
        self.assertLess(PLANS["trial"]["token_limit"], PLANS["basic"]["token_limit"])


class TestLicenseSig(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.lic_path = Path(self.tmp.name) / "license.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_trial_license_valid_and_bound(self):
        payload = issue_license(self.lic_path, licensee="tester@example.com",
                                tier="basic", kind="trial", days=7,
                                token_limit=30, bind_device=True)
        self.assertIn("sig", payload)
        lic = License(self.lic_path)
        self.assertTrue(lic.valid)
        self.assertTrue(lic.is_trial)
        self.assertEqual(lic.token_limit, 30)
        self.assertEqual(lic.device_hash, device_fingerprint())

    def test_tampered_tier_without_sig_invalid(self):
        # license tanpa sig tapi tier god -> anti-tamper: INVALID
        self.lic_path.write_text(json.dumps(
            {"licensee": "x", "tier": "god"}), encoding="utf-8")
        lic = License(self.lic_path)
        self.assertFalse(lic.valid)
        self.assertEqual(lic.tier, "basic")

    def test_editing_signed_license_invalidates(self):
        issue_license(self.lic_path, licensee="tester@example.com", tier="pro")
        data = json.loads(self.lic_path.read_text(encoding="utf-8"))
        data["tier"] = "god"  # edit manual
        self.lic_path.write_text(json.dumps(data), encoding="utf-8")
        lic = License(self.lic_path)
        self.assertFalse(lic.valid)
        self.assertIn("signature", lic.reason)

    def test_device_binding_refuses_other_device(self):
        issue_license(self.lic_path, licensee="tester@example.com", tier="pro")
        data = json.loads(self.lic_path.read_text(encoding="utf-8"))
        data["device_hash"] = "0" * 64  # mesin lain
        self.lic_path.write_text(json.dumps(data), encoding="utf-8")
        lic = License(self.lic_path)
        # device_hash diubah → signature tak cocok lagi ATAU binding gagal
        self.assertFalse(lic.valid)
        self.assertTrue("signature" in lic.reason or "perangkat" in lic.reason)

    def test_expired_license_basic(self):
        self.lic_path.write_text(json.dumps({
            "licensee": "x", "tier": "pro", "kind": "standard",
            "expires": "2020-01-01T00:00:00+00:00"}), encoding="utf-8")
        lic = License(self.lic_path)
        self.assertFalse(lic.valid)

    def test_aliases_map_to_real_engines(self):
        from cyphron.licensing import ENGINE_TIERS, _ENGINE_ALIASES
        # engine inti terdaftar
        for eng in ("http_probe", "dir_probe", "exploitability",
                    "jwt_exploit", "cache_deception_probe"):
            self.assertIn(eng, ENGINE_TIERS)
        # alias legacy menunjuk tool aktual
        for alias, real in _ENGINE_ALIASES.items():
            self.assertIn(real, ENGINE_TIERS)


class TestCreditLedger(unittest.TestCase):
    def test_spend_accumulates_and_persists(self):
        with TemporaryDirectory() as tmp:
            import os
            os.environ["CYPHRON_HOME"] = tmp
            try:
                led = CreditLedger("tester@example.com", mode="active")
                c1 = led.spend("http_probe", {"passive"})
                self.assertEqual(c1, 1)  # 1 x1.0
                c2 = led.spend("sqli_probe", {"active"})
                self.assertEqual(c2, 3)  # 2 x1.5
                self.assertEqual(led.total_spent, 4)
                # ledger baru (restart) membaca total yang sama
                led2 = CreditLedger("tester@example.com", mode="active")
                self.assertEqual(led2.total_spent, 4)
            finally:
                os.environ.pop("CYPHRON_HOME", None)

    def test_trial_limit_blocks(self):
        led = CreditLedger("trial@example.com", mode="active")
        ok, reason, _c = led.can_spend({"aggressive"}, token_limit=30)
        self.assertTrue(ok)
        led.total_spent = 29
        ok, reason, _c = led.can_spend({"aggressive"}, token_limit=30)
        self.assertFalse(ok)
        self.assertIn("token habis", reason)


class TestAntiBuse(unittest.TestCase):
    def test_device_fingerprint_stable_and_distinct(self):
        a = device_fingerprint()
        b = device_fingerprint()
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_ja3_from_headers(self):
        self.assertEqual(ja3_from_headers({"Cf-Ja3-Hash": "abc123"}), "abc123")
        self.assertIsNone(ja3_from_headers({"user-agent": "x"}))

    def test_signup_velocity_bulk(self):
        now = __import__("time").time()
        recs = [{"ts": now, "ip": f"1.2.3.{i}", "device_hash": "d" * 64,
                 "email": f"u{i}@mailinator.com"} for i in range(10)]
        v = signup_velocity(recs)
        self.assertEqual(v["verdict"], "DENY")
        self.assertGreaterEqual(v["score"], 80)

    def test_signup_velocity_normal(self):
        now = __import__("time").time()
        recs = [{"ts": now, "ip": f"10.0.0.{i}", "device_hash": f"d{i}" * 32,
                 "email": f"user{i}@gmail.com"} for i in range(3)]
        v = signup_velocity(recs)
        self.assertEqual(v["verdict"], "ALLOW")

    def test_ip_provider_and_errors(self):
        s = ip_abuse_signals("1.2.3.4", provider=lambda ip: {"hosting": True})
        self.assertTrue(s["hosting"])
        s2 = ip_abuse_signals("1.2.3.4", provider=lambda ip: 1 / 0)
        self.assertEqual(s2["provider"], "error")

    def test_pow_roundtrip(self):
        ch = pow_solve("seed-x", 12)
        self.assertTrue(pow_check("seed-x", ch, 12))
        self.assertFalse(pow_check("seed-y", ch, 12))

    def test_abuse_verdict_matrix(self):
        # user sah di balik VPN: CHALLENGE (PoW), bukan DENY
        v = abuse_verdict("ja3x", {"hosting": True, "proxy": False, "tor": False},
                          {"score": 0})
        self.assertEqual(v["verdict"], "CHALLENGE")
        # device sama klaim trial lagi: DENY
        v2 = abuse_verdict(None, {}, {"score": 0}, trial_claims_same_device=True)
        self.assertEqual(v2["verdict"], "DENY")
        # semua bersih: ALLOW
        v3 = abuse_verdict(None, {}, {"score": 0})
        self.assertEqual(v3["verdict"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
