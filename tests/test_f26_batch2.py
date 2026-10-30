"""Test F26 batch 2 — skill cookie-scope + graphql-schema-map + registry
entries baru. NOL jaringan: introspection fetch di-patch."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import cookie_scope as cs  # noqa: E402
import graphql_schema_map as gsm  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://app.example.com/"


class CookieScopeTest(unittest.TestCase):
    def test_explicit_domain_is_lead(self):
        rows, meta = cs.audit(URL, {"Set-Cookie":
            "sess=abc; Domain=.example.com; Path=/; HttpOnly"})
        lead = next(r for r in rows if "Domain eksplisit" in r["title"])
        self.assertEqual(lead["verdict"], 1)
        self.assertEqual(lead["cwe"], "CWE-1004")
        self.assertTrue(meta["matched"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_sensitive_cookie_path_root_is_lead(self):
        rows, meta = cs.audit(URL, {"Set-Cookie":
            "auth_token=abc; Path=/; Secure; HttpOnly"})
        lead = next(r for r in rows if "Path=/" in r["title"])
        self.assertEqual(lead["verdict"], 1)
        # Path=/ kena karena nama 'auth_token' sensitif — tapi ini bukan
        # domain-lead: satu lead saja
        self.assertEqual(meta["cookies"], 1)

    def test_host_only_specific_path_is_aman_l0(self):
        rows, meta = cs.audit(URL, {"Set-Cookie":
            "sess=abc; Path=/app; Secure; HttpOnly; SameSite=Lax"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")
        self.assertFalse(meta["matched"])

    def test_no_cookie_is_l0_not_lead(self):
        rows, meta = cs.audit(URL, {"Content-Type": "text/html"})
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertIn("AMAN", rows[0]["category"])
        self.assertEqual(meta["cookies"], 0)

    def test_multiple_cookies_with_expires_comma_parsed(self):
        rows, meta = cs.audit(URL, {"Set-Cookie":
            "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/app, "
            "sess=abc; Domain=.example.com; Path=/"})
        self.assertEqual(meta["cookies"], 2)
        # dua lead: Domain eksplisit + Path=/ pada nama sensitif
        leads = [r for r in rows if r["verdict"] == 1]
        self.assertEqual(len(leads), 2)
        self.assertTrue(any("Domain eksplisit" in r["title"] for r in leads))
        self.assertTrue(any("Path=/" in r["title"] for r in leads))


class GraphqlSchemaMapTest(unittest.TestCase):
    def test_open_introspection_is_lead_with_counts(self):
        body = json.dumps({"data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"kind": "OBJECT", "name": "Query",
                 "fields": [{"name": "me"}, {"name": "orders"}]},
                {"kind": "OBJECT", "name": "User",
                 "fields": [{"name": "email"}]},
                {"kind": "SCALAR", "name": "__Type", "fields": None},
            ]}}})
        with patch.object(gsm, "fetch", return_value=(200, body)):
            rows, meta = gsm.audit("https://x.example/graphql")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["verdict"], 1)
        self.assertEqual(r["cwe"], "CWE-200")
        self.assertEqual(r["types"], 2)  # __Type di-skip
        self.assertEqual(r["fields"], 3)
        self.assertTrue(meta["introspection"])
        self.assertEqual(validate_finding(r), [])

    def test_introspection_disabled_is_l0_no_claim(self):
        body = json.dumps({"errors": [{"message": "not allowed"}],
                           "data": None})
        with patch.object(gsm, "fetch", return_value=(200, body)):
            rows, meta = gsm.audit("https://x.example/graphql")
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertIn("AMAN", rows[0]["category"])
        self.assertFalse(meta["introspection"])

    def test_transport_error_is_l0_fail_closed(self):
        with patch.object(gsm, "fetch", return_value=(0, "TimeoutError()")):
            rows, meta = gsm.audit("https://x.example/graphql")
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(meta["requests"], 1)


class RegistryBatch2Test(unittest.TestCase):
    def test_three_new_entries_valid(self):
        reg = json.loads((ROOT / "skills" / "registry.json").read_text(
            encoding="utf-8"))
        by_name = {s["name"]: s for s in reg["skills"]}
        self.assertEqual(by_name["cookie-scope"]["safety_class"], "read-only")
        self.assertTrue(by_name["cookie-scope"]["requires_evidence"])
        self.assertEqual(by_name["graphql-schema-map"]["safety_class"],
                         "1-request")
        rlv = by_name["rate-limit-validator"]
        self.assertEqual(rlv["safety_class"], "active-probe")
        self.assertTrue(rlv.get("lab_only"),
                        "tier0 tidak boleh menjalankan login-probe")
        self.assertIn("--lab", rlv["cmd"],
                      "default registry wajib lab-only fail-closed")
        self.assertGreaterEqual(len(reg["skills"]), 86)


if __name__ == "__main__":
    unittest.main(verbosity=1)
