import unittest
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import (
    AuditLog, AuthorizationDocument, AuthorizationGate, host_port_of)

VALID_DOC = {
    "id": "AUTH-TEST-1",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
    "target": {"name": "lab"},
    "scope": {
        "targets": ["localhost", "*.lab.test"],
        "excluded": ["admin.lab.test"],
        "cidr": ["127.0.0.0/8"],
        "ports": [80, 3000, 8080],
    },
    "authorized_by": {"name": "tester"},
    "restrictions": ["no_dos"],
    "signature": "sig",
}


def make_doc(**overrides):
    doc = {**VALID_DOC, **overrides}
    return AuthorizationDocument.from_dict(doc)


class TestAuthorizationGate(unittest.TestCase):
    def test_no_doc_passive_allowed_active_refused(self):
        gate = AuthorizationGate(None)
        self.assertTrue(gate.evaluate("localhost", 80, {"passive"}).allowed)
        d = gate.evaluate("localhost", 80, {"active"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.mode, "read-only")

    def test_in_scope_active_allowed(self):
        gate = AuthorizationGate(make_doc())
        d = gate.evaluate("localhost", 3000, {"active"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.mode, "offensive")

    def test_cidr_match(self):
        gate = AuthorizationGate(make_doc())
        self.assertTrue(gate.evaluate("127.0.0.1", 80, {"active"}).allowed)
        self.assertFalse(gate.evaluate("10.0.0.5", 80, {"active"}).allowed)

    def test_wildcard_and_exclusion(self):
        gate = AuthorizationGate(make_doc())
        self.assertTrue(gate.evaluate("app.lab.test", 80, {"active"}).allowed)
        self.assertFalse(gate.evaluate("admin.lab.test", 80, {"active"}).allowed)
        self.assertFalse(gate.evaluate("evil.test", 80, {"active"}).allowed)

    def test_port_restriction(self):
        gate = AuthorizationGate(make_doc())
        d = gate.evaluate("localhost", 9999, {"active"})
        self.assertFalse(d.allowed)

    def test_expired(self):
        doc = make_doc(expires_at="2020-01-01T00:00:00Z")
        gate = AuthorizationGate(doc)
        self.assertFalse(gate.evaluate("localhost", 80, {"active"}).allowed)

    def test_restriction_blocks_tag(self):
        doc = make_doc(restrictions=["no_aggressive"])
        gate = AuthorizationGate(doc)
        self.assertFalse(gate.evaluate("localhost", 80, {"active", "aggressive"}).allowed)
        self.assertTrue(gate.evaluate("localhost", 80, {"active"}).allowed)

    def test_missing_signature_rejected(self):
        bad = {**VALID_DOC}
        bad.pop("signature")
        with self.assertRaises(ValueError):
            AuthorizationDocument.from_dict(bad)

    def test_audit_chain_tamper_detection(self):
        log = AuditLog()
        log.append({"kind": "a", "v": 1})
        log.append({"kind": "b", "v": 2})
        ok, note = log.verify()
        self.assertTrue(ok, note)
        log.entries[0]["kind"] = "tampered"
        ok, note = log.verify()
        self.assertFalse(ok)

    def test_host_port(self):
        self.assertEqual(host_port_of("http://localhost:3000/x"), ("localhost", 3000))
        self.assertEqual(host_port_of("https://app.lab.test"), ("app.lab.test", 443))


if __name__ == "__main__":
    unittest.main()
