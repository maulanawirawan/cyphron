"""B9-OSINT: username_osint + ip_intel (pasif, gate, tanpa jaringan nyata).

Kontrak yang diuji:
- username_osint: satu GET per platform, hasil = LEAD surface
  (unconfirmed); ambiguitas (403/429) dilaporkan jujur, bukan "tidak ada";
  marker "no such user" mencegah FP pada platform yang balas 200;
- ip_intel: IP privat/reserved dilewati tanpa permintaan; data pasif
  (bukan temuan); gagal layanan = graceful skip;
- semua jaringan di-mock — nol trafik nyata dalam test.
"""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.tools.ip_intel import IpIntelTool
from cyphron.tools.username_osint import UsernameOsintTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


class _FakeServer:
    """Peta URL -> (status, body); URL di luar peta = 404."""

    def __init__(self, test, table):
        self._orig = http_engine.http_get
        self.calls: list[str] = []

        def fake_get(url, **kw):
            self.calls.append(url)
            st, body = table.get(url, (404, ""))
            return st, {}, body, 1

        http_engine.http_get = fake_get
        test.addCleanup(self._restore)

    def _restore(self):
        http_engine.http_get = self._orig


class TestUsernameOsint(unittest.TestCase):
    def setUp(self):
        self.tool = UsernameOsintTool()
        self.u = "brandresmi"

    def test_found_and_not_found(self):
        table = {
            f"https://github.com/{self.u}": (200, "profile page"),
            f"https://gitlab.com/{self.u}": (404, ""),
        }
        _FakeServer(self, table)
        tr = self.tool.run({"username": self.u,
                            "platforms": ["github", "gitlab", "keybase"]},
                           _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual([f["platform"] for f in tr.data["found"]], ["github"])
        self.assertIn("gitlab", tr.data["not_found"])
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].status, "unconfirmed")
        self.assertEqual(tr.findings[0].finding_class, "surface")

    def test_no_such_marker_is_not_found(self):
        table = {
            f"https://news.ycombinator.com/user?id={self.u}":
                (200, "No such user."),
        }
        _FakeServer(self, table)
        tr = self.tool.run({"username": self.u,
                            "platforms": ["hackernews"]}, _ctx())
        self.assertEqual(tr.data["found"], [])
        self.assertIn("hackernews", tr.data["not_found"])
        self.assertEqual(tr.findings, [])

    def test_rate_limited_is_ambiguous_not_absent(self):
        table = {f"https://github.com/{self.u}": (429, "slow down")}
        _FakeServer(self, table)
        tr = self.tool.run({"username": self.u,
                            "platforms": ["github"]}, _ctx())
        self.assertEqual(tr.data["found"], [])
        self.assertEqual(len(tr.data["ambiguous"]), 1)
        self.assertEqual(tr.findings, [])

    def test_one_get_per_platform_and_cap(self):
        _FakeServer(self, {})  # semua 404
        tr = self.tool.run({"username": self.u}, _ctx())
        self.assertEqual(tr.data["platforms_checked"], 10)
        self.assertEqual(len(tr.data["not_found"]), 10)

    def test_username_validation(self):
        for bad in ("", "a", "punya spasi", "user@host.com", "x" * 40,
                    "user<script>"):
            tr = self.tool.run({"username": bad}, _ctx())
            self.assertFalse(tr.ok, bad)

    def test_unknown_platform_rejected(self):
        tr = self.tool.run({"username": self.u, "platforms": ["myspace"]},
                           _ctx())
        self.assertFalse(tr.ok)

    def test_registered_passive(self):
        from cyphron.tools import build_default_registry
        reg = build_default_registry(_ctx())
        names = {t.name for t in reg.all()} if hasattr(reg, "all") else set()
        self.assertIn("username_osint", names)
        self.assertIn("passive", UsernameOsintTool().risk_tags)


class TestIpIntel(unittest.TestCase):
    def setUp(self):
        self.tool = IpIntelTool()

    def test_public_ip_normalized(self):
        import cyphron.tools.ip_intel as mod
        orig = mod.ipwho_lookup
        mod.ipwho_lookup = lambda ip, timeout=15.0: {
            "ip": "93.184.216.34", "success": True, "type": "IPv4",
            "country": "Indonesia", "country_code": "ID",
            "region": "Jakarta", "city": "Jakarta",
            "latitude": -6.2, "longitude": 106.8,
            "connection": {"asn": 7713, "org": "PT Telkom Indonesia",
                           "isp": "Telkom", "domain": "telkom.co.id"},
            "timezone": {"id": "Asia/Jakarta"}, "flag": {"emoji": "🇮🇩"},
        }
        self.addCleanup(setattr, mod, "ipwho_lookup", orig)
        tr = self.tool.run({"ip": "93.184.216.34"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(tr.findings, [])
        self.assertEqual(tr.data["asn"], 7713)
        self.assertEqual(tr.data["country"], "Indonesia")
        self.assertIn("bukan bukti identitas", tr.data["note"])

    def test_private_ip_skipped_without_request(self):
        import cyphron.tools.ip_intel as mod
        calls = []

        def spy(*a, **kw):
            calls.append(a)
            return None
        orig = mod.ipwho_lookup
        mod.ipwho_lookup = spy
        self.addCleanup(setattr, mod, "ipwho_lookup", orig)
        tr = self.tool.run({"ip": "192.168.1.1"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertIn("bukan IP publik", tr.data["skipped"])
        self.assertEqual(calls, [])

    def test_invalid_ip(self):
        tr = self.tool.run({"ip": "bukan.ip"}, _ctx())
        self.assertFalse(tr.ok)

    def test_service_down_graceful(self):
        import cyphron.tools.ip_intel as mod
        orig = mod.ipwho_lookup
        mod.ipwho_lookup = lambda ip, timeout=15.0: None
        self.addCleanup(setattr, mod, "ipwho_lookup", orig)
        tr = self.tool.run({"ip": "8.8.8.8"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertIn("tidak tersedia", tr.data["skipped"])

    def test_service_rejects_payload(self):
        import cyphron.tools.ip_intel as mod
        orig = mod.ipwho_lookup
        mod.ipwho_lookup = lambda ip, timeout=15.0: {"success": False}
        self.addCleanup(setattr, mod, "ipwho_lookup", orig)
        tr = self.tool.run({"ip": "8.8.8.8"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertIn("tidak tersedia", tr.data["skipped"])


if __name__ == "__main__":
    unittest.main()
