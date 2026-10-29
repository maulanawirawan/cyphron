"""F2 — proof verifier: verifikasi substantif bukti L3+ (kritik A).

Positif: bukti yang benar-benar membuktikan lolos.
Negatif: bukti ADA tapi tidak membuktikan klaim -> ditolak/diturunkan.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, validate_finding  # noqa: E402
from proof_verifier import verify, downgrade  # noqa: E402


def l3(**over):
    base = dict(
        tool="t", title="Refleksi parameter di /cari", severity="high",
        description="Refleksi marker di response (probe echo).",
        target_url="http://x/cari?q=MARKER123abc",
        request="GET /cari?q=MARKER123abc HTTP/1.1",
        response='HTTP/1.1 200 OK ... hasil untuk "MARKER123abc" ...',
        evidence_kind="request-response", confidence=0.9,
        status="confirmed", verdict=3,
    )
    base.update(over)
    return make_finding(**base)


class ProofVerifierTest(unittest.TestCase):
    def test_rv1_refleksi_sah_dengan_marker_terpantul(self):
        ok, reason = verify(l3())
        self.assertTrue(ok, reason)

    def test_rv1_refleksi_tanpa_marker_ditolak(self):
        # bukti ADA (response 200) tapi marker TIDAK terpantul = bukan bukti
        f = l3(response='HTTP/1.1 200 OK ... hasil pencarian kosong ...')
        ok, reason = verify(f)
        self.assertFalse(ok)
        self.assertIn("RV-1", reason)

    def test_rv1_echo_identik_ditolak(self):
        f = l3(response="GET /cari?q=MARKER123abc HTTP/1.1")
        ok, reason = verify(f)
        self.assertFalse(ok)
        self.assertIn("RV-4", reason)

    def test_rv2_versi_klaim_tanpa_versi_di_bukti_ditolak(self):
        f = make_finding(
            tool="t", title="Server version disclosure: 3.2.1",
            severity="info", description="Server header membocorkan versi 3.2.1.",
            target_url="http://x", request="GET / HTTP/1.1",
            response="HTTP/1.1 200 OK Server: GenericServer",
            evidence_kind="request-response", confidence=0.9,
            status="confirmed", verdict=3)
        ok, reason = verify(f)
        self.assertFalse(ok)
        self.assertIn("RV-2", reason)

    def test_rv2_versi_klaim_dengan_versi_di_bukti_lolos(self):
        f = make_finding(
            tool="t", title="Server version disclosure: 3.2.1",
            severity="info", description="Server header membocorkan versi 3.2.1.",
            target_url="http://x", request="GET / HTTP/1.1",
            response="HTTP/1.1 200 OK Server: GenericServer/3.2.1",
            evidence_kind="request-response", confidence=0.9,
            status="confirmed", verdict=3)
        ok, reason = verify(f)
        self.assertTrue(ok, reason)

    def test_rv3_secret_tanpa_format_kuat_ditolak(self):
        f = make_finding(
            tool="t", title="Hardcoded secret ditemukan",
            severity="high", description="Secret ter-hardcode di source.",
            target_url="file:x.py#1", request=None, response="nilai ada di file",
            evidence_kind="file-manifest", confidence=0.9,
            status="confirmed", verdict=3,
            extra={"category": "SECRET-EXPOSURE"})
        ok, reason = verify(f)
        self.assertFalse(ok)
        self.assertIn("RV-3", reason)

    def test_rv3_secret_dengan_format_kuat_lolos(self):
        f = make_finding(
            tool="t", title="Hardcoded secret ditemukan",
            severity="high", description="Secret ter-hardcode di source.",
            target_url="file:x.py#1", request=None,
            response='API_KEY = "AKIAIOSFODNN7SAMPLE0"',
            evidence_kind="file-manifest", confidence=0.9,
            status="confirmed", verdict=3,
            extra={"category": "SECRET-EXPOSURE"})
        ok, reason = verify(f)
        self.assertTrue(ok, reason)

    def test_l1_tidak_diperiksa(self):
        ok, reason = verify(make_finding(
            tool="t", title="lead", severity="low", description="d",
            evidence_kind="header", status="unconfirmed"))
        self.assertTrue(ok)
        self.assertIn("tidak berlaku", reason)

    def test_downgrade_menghasilkan_l1_sah(self):
        f = l3(response="hasil kosong")
        ok, reason = verify(f)
        self.assertFalse(ok)
        down = downgrade(f, reason)
        self.assertEqual(down["verdict"], 1)
        self.assertFalse(down["reportable"])
        self.assertIn("PROOF-VERIFY", down["description"])
        self.assertEqual(validate_finding(down), [])  # hasil turunan tetap sah


if __name__ == "__main__":
    unittest.main()
