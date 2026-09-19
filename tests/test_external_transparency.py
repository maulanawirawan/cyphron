"""Kontrak transparansi pihak ketiga (audit 2026-09-19): engine yang mengakses
layanan luar wajib ber-tag 'external', bisa diblokir restriction
no_external_intel, dan laporan menyebut sumbernya."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuthorizationDocument, AuthorizationGate
from cyphron.reporting import TOOLS_EXTERNAL_SOURCES, external_sources_used


class TestExternalIntelContract(unittest.TestCase):
    def test_external_engines_have_external_tag(self):
        for name in TOOLS_EXTERNAL_SOURCES:
            p = Path("cyphron/tools") / f"{name}.py"
            if not p.exists():
                continue
            t = p.read_text(encoding="utf-8", errors="replace")
            self.assertIn("external", t, f"{name} harus ber-tag external")

    def test_no_external_intel_restriction_blocks(self):
        doc = AuthorizationDocument.load(Path("tests/fixtures/auth/full.json")) \
            if Path("tests/fixtures/auth/full.json").exists() else None
        gate = AuthorizationGate(doc) if doc else None
        # buat dokumen inline dengan restriction
        gate = _gate_with_restriction(["no_external_intel"])
        d = gate.evaluate("target.test", 443, {"passive", "external"})
        self.assertFalse(d.allowed, "external harus diblokir no_external_intel")
        d2 = gate.evaluate("target.test", 443, {"passive"})
        self.assertTrue(d2.allowed, "pasif murni tetap boleh")

    def test_external_sources_used_dedup(self):
        self.assertEqual(external_sources_used(["ip_intel", "ip_intel", "crawler"]),
                         ["ipwho.is (intel IP publik)"])


def _gate_with_restriction(restrictions):
    import json, tempfile
    doc = {
        "id": "test-doc", "issued_at": "2020-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "target": {"name": "uji"},
        "scope": {"targets": ["target.test"]},
        "authorized_by": {"name": "owner"},
        "restrictions": restrictions,
        "signature": "test-signature",
    }
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(doc, f)
    f.close()
    return AuthorizationGate(AuthorizationDocument.load(Path(f.name)))


if __name__ == "__main__":
    unittest.main()
