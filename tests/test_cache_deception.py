"""cache_deception_probe — WCD dua-langkah (langkah 1 dengan sesi, langkah 2
tanpa sesi harus mengembalikan konten identik dari cache)."""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.tools.cache_deception_probe import CacheDeceptionProbeTool
from cyphron.world.model import WorldModel

MEMBER_PAGE = ("<html><body>Dashboard user=<b>secret-member</b> "
               "balance confidential</body></html>") + "x" * 300


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50, sessions={"victim": "sid=secret1"})


class _CacheSim:
    """Simulasi CDN: request DENGAN cookie -> member page (mengisi cache bila
    cacheable); request TANPA cookie -> cache hit atau halaman login."""

    def __init__(self, test, cacheable=True, member=True):
        self.cache = {}
        self.cacheable = cacheable
        self.member = member
        self._orig = http_engine.http_get

        def fake_get(url, timeout=8.0, method="GET", data=None, headers=None,
                     max_body=1 << 20, follow_redirects=True):
            has_cookie = bool((headers or {}).get("Cookie"))
            if has_cookie and self.member:
                cc = ("public, max-age=300" if self.cacheable
                      else "private, no-store")
                self.cache[url] = MEMBER_PAGE
                return 200, {"Content-Type": "text/html",
                             "Cache-Control": cc}, MEMBER_PAGE, 1
            if url in self.cache:
                return 200, {"Content-Type": "text/html",
                             "Cache-Control": "public, max-age=300",
                             "cf-cache-status": "HIT"}, self.cache[url], 1
            return 200, {"Content-Type": "text/html"}, "<html>login</html>", 1

        http_engine.http_get = fake_get
        test.addCleanup(setattr, http_engine, "http_get", self._orig)


class TestCacheDeception(unittest.TestCase):
    def setUp(self):
        self.tool = CacheDeceptionProbeTool()

    def test_confirmed_when_cache_serves_member_without_session(self):
        _CacheSim(self, cacheable=True)
        tr = self.tool.run({"url": "https://t.test/dashboard",
                            "member_marker": "secret-member"}, _ctx())
        self.assertEqual(len(tr.findings), 2)  # .css dan .js sama-sama kena
        self.assertTrue(all(f.status == "confirmed" for f in tr.findings))
        self.assertTrue(all(f.severity == "high" for f in tr.findings))
        self.assertEqual(len(tr.data["confirmed"]), 2)

    def test_no_marker_stays_unconfirmed(self):
        # anti-FP: tanpa member_marker, bukti konten member tak ada → kandidat
        _CacheSim(self, cacheable=True)
        tr = self.tool.run({"url": "https://t.test/dashboard"}, _ctx())
        self.assertEqual(len(tr.findings), 2)
        self.assertTrue(all(f.status == "unconfirmed" for f in tr.findings))
        self.assertTrue(all(f.confidence < 0.9 for f in tr.findings))

    def test_no_session_skipped(self):
        # anti-FP: tanpa sesi, dua langkah = dua GET anonim identik → skip
        ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                          world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                          max_requests=50, sessions={})
        _CacheSim(self, cacheable=True)
        tr = self.tool.run({"url": "https://t.test/dashboard"}, ctx)
        self.assertEqual(tr.findings, [])
        self.assertIn("butuh session_cookie", tr.data["note"])

    def test_no_store_blocks(self):
        _CacheSim(self, cacheable=False)
        tr = self.tool.run({"url": "https://t.test/dashboard"}, _ctx())
        self.assertEqual(tr.findings, [], "no-store tidak boleh jadi temuan")
        self.assertEqual(tr.data["candidates"], [])

    def test_uncached_path_not_finding(self):
        # cacheable tapi langkah-2 tanpa sesi = login page (cache miss)
        _CacheSim(self, cacheable=True, member=True)
        # buang cache sebelum langkah 2: pakai server yang tidak cache utk
        # request tanpa cookie -> simulator di atas sudah begitu (cache hanya
        # terisi dari request ber-cookie); path belum pernah diakses ber-cookie
        # tidak menghasilkan kandidat. Uji: marker tidak cocok -> bukan temuan.
        tr = self.tool.run({"url": "https://t.test/dashboard",
                            "member_marker": "NOT-PRESENT-ANYWHERE"}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertEqual(tr.data["candidates"], [])

    def test_requires_args(self):
        tr = self.tool.run({}, _ctx())
        self.assertFalse(tr.ok)


if __name__ == "__main__":
    unittest.main()
