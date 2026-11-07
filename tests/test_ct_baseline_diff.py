"""Nol jaringan — test ct_baseline_diff (mesin diff baseline CT)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ct_baseline_diff as cbd  # noqa: E402

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


def rec(cn: str, issuer: str = "DigiCert TLS RSA", serial: str = "0101",
        sans: list[str] | None = None, nb: str = "2026-01-01T00:00:00Z",
        na: str = "2026-12-31T00:00:00Z") -> dict:
    return {"common_name": cn, "issuer_name": issuer, "serial_number": serial,
            "sans": sans if sans is not None else [cn],
            "not_before": nb, "not_after": na}


def ts(days_ahead: int, hour: int = 0) -> str:
    t = NOW + timedelta(days=days_ahead, hours=hour)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestRecord(unittest.TestCase):
    def test_name_value_newline_crtsh(self):
        c = cbd.normalize_record({
            "common_name": "www.example.com",
            "name_value": "www.example.com\nexample.com",
            "issuer_name": "R3", "not_before": "2026-01-01",
            "not_after": "2026-04-01 12:00:00", "serial_number": "04ab"})
        self.assertEqual(c.names, ("www.example.com", "example.com"))
        self.assertEqual(c.nb, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(c.na, datetime(2026, 4, 1, 12, tzinfo=timezone.utc))

    def test_record_without_names_is_malformed(self):
        with self.assertRaises(ValueError):
            cbd.normalize_record({"issuer_name": "R3"})

    def test_bad_timestamp_is_malformed(self):
        with self.assertRaises(ValueError):
            cbd.normalize_record(rec("x.com", na="nanti"))

    def test_parse_ts_variants(self):
        for s in ("2026-01-02T03:04:05Z", "2026-01-02 03:04:05",
                  "2026-01-02T03:04:05+00:00", "2026-01-02"):
            self.assertEqual(cbd.parse_ts(s),
                             datetime(2026, 1, 2, 3, 4, 5,
                                      tzinfo=timezone.utc) if ":" in s
                             else datetime(2026, 1, 2, tzinfo=timezone.utc))


class TestPermutations(unittest.TestCase):
    def test_original_excluded_and_sorted(self):
        out = cbd.generate_permutations("example.com")
        self.assertNotIn("example.com", out)
        self.assertEqual(out, sorted(out))
        self.assertIn("exampl.com", out)          # omission
        self.assertIn("exmaple.com", out)          # transposition
        self.assertIn("3xample.com", out)          # homoglyph

    def test_deterministic_and_capped(self):
        a = cbd.generate_permutations("contoh.example-domain.com", cap=50)
        b = cbd.generate_permutations("contoh.example-domain.com", cap=50)
        self.assertEqual(a, b)
        self.assertLessEqual(len(a), 50)

    def test_no_dot_domain(self):
        out = cbd.generate_permutations("intranet")
        self.assertNotIn("intranet", out)
        self.assertTrue(all("." not in p for p in out))


class TestDiffRules(unittest.TestCase):
    def run_diff(self, baseline, current, **kw):
        base = [cbd.normalize_record(r) for r in baseline]
        cur = [cbd.normalize_record(r) for r in current]
        return cbd.diff_ct(base, cur, domains=kw.pop("domains", {"example.com"}),
                           allowlist=kw.pop("allowlist", None), now=NOW, **kw)

    def codes(self, result):
        return [f["code"] for f in result["findings"]]

    def test_identical_baseline_no_new_findings(self):
        r = rec("www.example.com")
        res = self.run_diff([r], [r])
        self.assertEqual(self.codes(res), [])

    def test_new_subdomain(self):
        res = self.run_diff([rec("www.example.com")],
                            [rec("www.example.com", serial="0102"),
                             rec("staging.example.com", serial="0103")])
        self.assertIn("new-subdomain", self.codes(res))
        names = [f["name"] for f in res["findings"]
                 if f["code"] == "new-subdomain"]
        self.assertEqual(names, ["staging.example.com"])

    def test_new_wildcard(self):
        res = self.run_diff([rec("www.example.com")],
                            [rec("*.example.com", serial="0104")])
        self.assertIn("new-wildcard", self.codes(res))

    def test_wildcard_in_baseline_is_quiet(self):
        res = self.run_diff([rec("*.example.com")],
                            [rec("*.example.com", serial="0105")])
        self.assertEqual(self.codes(res), [])

    def test_unauthorized_ca_requires_allowlist(self):
        rogue = rec("pay.example.com", issuer="FreeSSL CA", serial="0106")
        res = self.run_diff([rec("www.example.com")], [rogue])
        self.assertNotIn("unauthorized-ca", self.codes(res))
        res2 = self.run_diff([rec("www.example.com")], [rogue],
                             allowlist={"digicert"})
        self.assertIn("unauthorized-ca", self.codes(res2))

    def test_ca_authorized_substring_direction(self):
        self.assertTrue(cbd.ca_authorized("DigiCert TLS RSA", {"digicert"}))
        self.assertFalse(cbd.ca_authorized("FreeSSL CA", {"digicert"}))

    def test_short_lived_boundary(self):
        res = self.run_diff(
            [rec("a.example.com")],
            [rec("b.example.com", serial="0107",
                 nb="2026-11-07T11:00:00Z", na="2026-11-08T10:00:00Z")])
        self.assertIn("short-lived", self.codes(res))
        res2 = self.run_diff(
            [rec("a.example.com")],
            [rec("c.example.com", serial="0108",
                 nb="2026-11-07T10:00:00Z", na="2026-11-08T10:00:00Z")])
        self.assertNotIn("short-lived", self.codes(res2))

    def test_expiring_soon_dedup_and_boundary(self):
        soon = rec("old.example.com", serial="0109", na=ts(10))
        res = self.run_diff([soon], [soon])
        codes = self.codes(res)
        self.assertEqual(codes.count("expiring-soon"), 1)
        far = rec("far.example.com", serial="0110", na=ts(31))
        res2 = self.run_diff([far], [far])
        self.assertNotIn("expiring-soon", self.codes(res2))
        edge = rec("edge.example.com", serial="0111", na=ts(30))
        res3 = self.run_diff([edge], [edge])
        self.assertIn("expiring-soon", self.codes(res3))
        # sudah kedaluwarsa -> bukan expiring-soon
        past = rec("past.example.com", serial="0112", na=ts(-1))
        res4 = self.run_diff([past], [past])
        self.assertNotIn("expiring-soon", self.codes(res4))

    def test_typosquat(self):
        res = self.run_diff(
            [rec("www.example.com")],
            [rec("secure-login.exarnple.com", issuer="Let's Encrypt",
                 serial="0113")], typosquat=True)
        # exarnple = homoglyph tidak ada; pakai omission exmple
        self.assertNotIn("typosquat-cert", self.codes(res))
        res2 = self.run_diff(
            [rec("www.example.com")],
            [rec("secure-login.exmple.com", issuer="Let's Encrypt",
                 serial="0114")], typosquat=True)
        self.assertIn("typosquat-cert", self.codes(res2))
        res3 = self.run_diff(
            [rec("www.example.com")],
            [rec("www.example.com", serial="0115")], typosquat=True)
        self.assertNotIn("typosquat-cert", self.codes(res3))

    def test_off_domain_names_ignored_for_new_subdomain(self):
        res = self.run_diff([rec("www.example.com")],
                            [rec("unrelated.example.org", serial="0116")])
        self.assertEqual(self.codes(res), [])

    def test_rules_skipped_without_domains(self):
        base = [cbd.normalize_record(rec("a.com"))]
        cur = [cbd.normalize_record(rec("b.com", serial="0117"))]
        res = cbd.diff_ct(base, cur, domains=set(), allowlist=None, now=NOW)
        self.assertIn("new-subdomain (tanpa domain terpantau)",
                      res["meta"]["rules_skipped"])
        self.assertEqual(res["findings"], [])

    def test_order_deterministic(self):
        rogue = rec("pay.example.com", issuer="FreeSSL CA", serial="0118")
        new = rec("staging.example.com", serial="0119")
        res1 = self.run_diff([rec("www.example.com")], [rogue, new],
                             allowlist={"digicert"})
        res2 = self.run_diff([rec("www.example.com")], [new, rogue],
                             allowlist={"digicert"})
        self.assertEqual(res1["findings"], res2["findings"])
        self.assertEqual(res1["findings"][0]["severity"], "critical")


class TestCli(unittest.TestCase):
    def _write(self, tmp, name, payload):
        p = Path(tmp) / name
        p.write_text(json.dumps(payload), encoding="utf-8")
        return str(p)

    def test_fail_closed_missing_and_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write(tmp, "base.json", [rec("www.example.com")])
            rc = cbd.main(["--baseline", base, "--current",
                           str(Path(tmp) / "tidakada.json")])
            self.assertEqual(rc, 2)
            bad = Path(tmp) / "bad.json"
            bad.write_text("{bukan json", encoding="utf-8")
            rc = cbd.main(["--baseline", base, "--current", str(bad)])
            self.assertEqual(rc, 2)
            empty = Path(tmp) / "empty.json"
            empty.write_text("[]", encoding="utf-8")
            rc = cbd.main(["--baseline", base, "--current", str(empty)])
            self.assertEqual(rc, 2)

    def test_fail_on_and_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write(tmp, "base.json", [rec("www.example.com")])
            cur = self._write(tmp, "cur.json",
                              [rec("staging.example.com", serial="0120")])
            out = Path(tmp) / "out.json"
            rc = cbd.main(["--baseline", base, "--current", cur,
                           "--domain", "example.com",
                           "--now", NOW.isoformat(), "--fail-on", "high",
                           "--out", str(out)])
            self.assertEqual(rc, 1)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], cbd.SCHEMA)
            rc = cbd.main(["--baseline", base, "--current", cur,
                           "--domain", "example.com",
                           "--now", NOW.isoformat(), "--fail-on", "critical"])
            self.assertEqual(rc, 0)

    def test_allowlist_text_file_and_bad_now(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._write(tmp, "base.json", [rec("www.example.com")])
            cas = Path(tmp) / "cas.txt"
            cas.write_text("DigiCert\nLet's Encrypt\n", encoding="utf-8")
            rogue = self._write(tmp, "cur.json",
                                [rec("pay.example.com", issuer="FreeSSL CA",
                                     serial="0121")])
            rc = cbd.main(["--baseline", base, "--current", rogue,
                           "--ca-allowlist", str(cas),
                           "--now", NOW.isoformat()])
            self.assertEqual(rc, 0)
            rc = cbd.main(["--baseline", base, "--current", rogue,
                           "--now", "besok"])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
