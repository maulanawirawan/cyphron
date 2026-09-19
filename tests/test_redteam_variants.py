"""redteam_variants — kontrak zero-FP 3 engine eskalasi variasi:
variant_sweep, method_override_matrix, header_variant_matrix.
Semua pakai fake http_get; temuan hanya bila diferensial terhadap baseline."""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.tools.redteam_variants import (
    HeaderVariantMatrixTool, MethodOverrideMatrixTool, VariantSweepTool)
from cyphron.world.model import WorldModel

_MARKER = "cyphronv7x"


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


def _swap_http(test, fake):
    orig = http_engine.http_get
    http_engine.http_get = fake
    test.addCleanup(setattr, http_engine, "http_get", orig)


class TestVariantSweep(unittest.TestCase):
    def test_raw_reflection_finds(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            # baseline bersih; varian APA PUN memantulkan marker mentah
            body = "error: nilai salah" if "baseline" in url else f"halo {_MARKER}'\"><param>"
            return 200, {}, body, 1
        _swap_http(self, fake)
        tr = VariantSweepTool().run({"url": "https://t.test/x", "param": "q"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].status, "unconfirmed")
        self.assertTrue(tr.data["hits"])

    def test_baseline_hit_means_no_finding(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            # halaman selalu memuat marker (mis. konten statis) -> bukan refleksi
            return 200, {}, f"halaman {_MARKER} statis", 1
        _swap_http(self, fake)
        tr = VariantSweepTool().run({"url": "https://t.test/x", "param": "q"}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertTrue(tr.data["baseline_hit"])

    def test_no_reflection_no_finding(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            return 200, {}, "halaman tanpa refleksi", 1
        _swap_http(self, fake)
        tr = VariantSweepTool().run({"url": "https://t.test/x", "param": "q"}, _ctx())
        self.assertEqual(tr.findings, [])


class TestMethodOverrideMatrix(unittest.TestCase):
    def test_override_changes_status(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            if method == "GET":
                return 200, {}, "ok", 1
            if headers and ("X-HTTP-Method-Override" in headers):
                return 204, {}, "", 1  # override dihormati -> 204
            return 405, {}, "method not allowed", 1
        _swap_http(self, fake)
        tr = MethodOverrideMatrixTool().run({"url": "https://t.test/api"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("override", tr.findings[0].title)

    def test_no_change_no_finding(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            return 200, {}, "sama aja", 1
        _swap_http(self, fake)
        tr = MethodOverrideMatrixTool().run({"url": "https://t.test/"}, _ctx())
        self.assertEqual(tr.findings, [])


class TestHeaderVariantMatrix(unittest.TestCase):
    def test_403_opens_with_xff(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            if headers and "X-Forwarded-For" in headers:
                return 200, {}, "rahasia admin panel isi berbeda", 1
            return 403, {}, "forbidden", 1
        _swap_http(self, fake)
        tr = HeaderVariantMatrixTool().run({"url": "https://t.test/admin"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "low")

    def test_open_endpoint_skipped(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            return 200, {}, "publik", 1
        _swap_http(self, fake)
        tr = HeaderVariantMatrixTool().run({"url": "https://t.test/"}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertIn("tidak terlindungi", tr.data["skipped"])

    def test_spoof_no_open_no_finding(self):
        def fake(url, timeout=8.0, method="GET", data=None, headers=None,
                 follow_redirects=True, **kw):
            return 403, {}, "forbidden", 1
        _swap_http(self, fake)
        tr = HeaderVariantMatrixTool().run({"url": "https://t.test/admin"}, _ctx())
        self.assertEqual(tr.findings, [])


if __name__ == "__main__":
    unittest.main()
