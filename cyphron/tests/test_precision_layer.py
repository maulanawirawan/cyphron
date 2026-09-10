"""Unit tests precision layer (2026-09-08) — tiga tugas:

Tugas 2: scope enforcement per-host (takeover sibling + smtp_probe MX).
Tugas 1: semantik temuan CT log (Observation vs Heuristik vs Impact).
Tugas 3: app-liveness classification (stale/orphaned surface candidate).

Semua offline/deterministik: DNS + HTTP dimock, liveness pakai HTTP server
lokal sementara.
"""

from __future__ import annotations

import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.tools import http_engine
from cyphron.guardrails.authorization import AuditLog, AuthorizationDocument, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.roadmap_batch3 import CtLogTool
from cyphron.tools.roadmap_batch4 import SmtpProbeTool
from cyphron.tools.roadmap_bounty import TakeoverTool
from cyphron.tools.liveness_probe import LivenessProbeTool
from cyphron.world.model import WorldModel


def _doc(targets: list[str], excluded: list[str] | None = None,
         ports: list[int] | None = None) -> AuthorizationDocument:
    return AuthorizationDocument.from_dict({
        "id": "AUTH-PRECISION-001", "version": "1.0",
        "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
        "target": {"name": "precision-test"},
        "authorized_by": {"name": "owner"},
        "scope": {"targets": targets, "excluded": excluded or [],
                  "cidr": [], "ports": ports if ports is not None else [80, 443]},
        "restrictions": [], "signature": "test-sig",
    })


# --------------------------------------------------------------- Tugas 2
class TestScopeEnforcement(unittest.TestCase):
    """Kandidat yang ditemukan engine sendiri wajib dicek scope per-destination
    SEBELUM satu pun query DNS/HTTP. Out-of-scope = nol query, lead pasif."""

    def setUp(self):
        self.gai_hosts: list[str] = []
        self.http_urls: list[str] = []
        self.conn_hosts: list[tuple] = []

        def _fake_getaddrinfo(host, *a, **k):
            self.gai_hosts.append(host)
            raise socket.gaierror(8, "test NXDOMAIN")

        def _fake_http_get(url, **k):
            self.http_urls.append(url)
            return 200, {}, "<html><body>generic</body></html>", None

        def _fake_create_connection(addr, **k):
            self.conn_hosts.append(addr)
            raise OSError("test unreachable")

        self._p = [
            mock.patch.object(CtLogTool, "_query_crtsh",
                              return_value=({"app.example.test",
                                             "sibling.example.test",
                                             "secret.example.test"}, "test")),
            mock.patch("cyphron.tools.roadmap_bounty.dns_cname",
                       return_value="dangling.other.test"),
            mock.patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo),
            mock.patch("cyphron.tools.http_engine.http_get",
                       side_effect=_fake_http_get),
        ]
        self._smtp_p = []
        for p in self._p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._p])
        self._patch_conn = mock.patch("socket.create_connection",
                                      side_effect=_fake_create_connection)

    def _ctx(self, doc) -> ToolContext:
        ctx = ToolContext(gate=AuthorizationGate(doc), audit=AuditLog(),
                          world=WorldModel(), rate_limit_s=0.0, timeout_s=1.0)
        self._last_ctx = ctx
        return ctx

    def _takeover(self, ctx):
        return TakeoverTool().run({"url": "https://app.example.test",
                                   "domain": "example.test"}, ctx)

    def test_a_single_host_scope_zero_queries_to_sibling(self):
        res = self._takeover(self._ctx(_doc(["app.example.test"])))
        # NOL query DNS/HTTP ke sibling dan ke host excluded
        for host in ("sibling.example.test", "secret.example.test"):
            self.assertNotIn(host, self.gai_hosts, f"{host} tidak boleh di-resolve")
            self.assertFalse(any(host in u for u in self.http_urls),
                             f"{host} tidak boleh di-HTTP")
        # target host sendiri tetap diuji (in-scope)
        self.assertIn("app.example.test", self.gai_hosts)
        # sibling muncul sebagai passive lead, bukan temuan aktif
        passive = [f for f in res.findings if "diamati pasif" in f.title]
        self.assertEqual(len(passive), 1)
        pf = passive[0]
        self.assertEqual(pf.status, "unconfirmed")
        self.assertEqual(pf.finding_class, "surface")
        self.assertIn("tidak diuji aktif", pf.description)
        self.assertIn("di luar scope", pf.description)
        # audit trail per-host ada
        decisions = {e["host"]: e for e in ctx_audit(self) if e["kind"] == "host-scope-decision"}
        self.assertFalse(decisions["sibling.example.test"]["allowed"])
        self.assertFalse(decisions["secret.example.test"]["allowed"])
        self.assertTrue(decisions["sibling.example.test"]["reason"].startswith("out of scope"))

    def test_b_wildcard_scope_probes_sibling_actively(self):
        res = self._takeover(self._ctx(_doc(["*.example.test"])))
        self.assertIn("sibling.example.test", self.gai_hosts,
                      "wildcard scope: sibling sah diuji aktif")
        # tidak ada passive-lead finding: sibling sudah diuji aktif
        self.assertEqual([f for f in res.findings if "diamati pasif" in f.title], [])

    def test_c_excluded_host_never_touched_nor_reported(self):
        doc = _doc(["*.example.test"], excluded=["secret.example.test"])
        res = self._takeover(self._ctx(doc))
        self.assertNotIn("secret.example.test", self.gai_hosts)
        self.assertFalse(any("secret.example.test" in u for u in self.http_urls))
        decisions = {e["host"]: e for e in ctx_audit(self) if e["kind"] == "host-scope-decision"}
        self.assertIn("excluded", decisions["secret.example.test"]["reason"])
        # excluded tidak dilaporkan sebagai passive lead
        for f in res.findings:
            self.assertNotIn("secret.example.test", f.title + f.description)

    def test_d_smtp_mx_out_of_scope_zero_connection(self):
        self._smtp_p = [
            mock.patch("cyphron.tools.roadmap_batch4.dns_mx",
                       return_value=[(10, "mail.other.com")]),
            self._patch_conn,
        ]
        for p in self._smtp_p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._smtp_p])
        ctx = self._ctx(_doc(["app.example.com"]))
        res = SmtpProbeTool().run({"url": "https://app.example.com",
                                   "domain": "example.com"}, ctx)
        self.assertEqual(self.conn_hosts, [], "MX out-of-scope: NOL koneksi")
        self.assertEqual(res.data.get("skipped"), "mail.other.com")
        self.assertTrue(any("di luar scope" in n for n in ctx.world.notes))
        decisions = [e for e in ctx_audit(self) if e["kind"] == "host-scope-decision"]
        self.assertTrue(decisions and not decisions[-1]["allowed"])

    def test_e_smtp_mx_in_scope_connects(self):
        self._smtp_p = [
            mock.patch("cyphron.tools.roadmap_batch4.dns_mx",
                       return_value=[(10, "mail.other.com")]),
            self._patch_conn,
        ]
        for p in self._smtp_p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._smtp_p])
        ctx = self._ctx(_doc(["*.other.com"], ports=[25, 80, 443]))
        SmtpProbeTool().run({"url": "https://app.example.com",
                             "domain": "example.com"}, ctx)
        self.assertIn(("mail.other.com", 25), self.conn_hosts,
                      "MX wildcard in-scope: koneksi EHLO sah dilakukan")


def ctx_audit(testcase) -> list[dict]:
    """Ambil audit entries dari ctx terakhir yang dipakai test scope."""
    # ToolContext menyimpan audit di ctx.audit.entries; test membuat ctx per test
    # jadi kita ambil dari closure lewat atribut instance.
    return testcase._last_ctx.audit.entries


# --------------------------------------------------------------- Tugas 1
class TestCtSemantics(unittest.TestCase):
    def _run(self, names: set[str]):
        ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                          world=WorldModel(), rate_limit_s=0.0, timeout_s=1.0)
        with mock.patch.object(CtLogTool, "_query_crtsh",
                               return_value=(names, "test")):
            res = CtLogTool().run({"url": "https://app.example.test",
                                   "domain": "example.test"}, ctx)
        self.assertEqual(len(res.findings), 1)
        return res.findings[0]

    def test_sensitive_candidate_marked_as_heuristic(self):
        f = self._run({"app.example.test", "dev.example.test", "admin.example.test"})
        self.assertIsNone(f.cwe)
        self.assertEqual(f.finding_class, "surface")
        self.assertEqual(f.status, "confirmed")
        self.assertEqual(f.severity, "low")
        self.assertTrue(f.title.startswith("Attack surface disclosure"))
        text = (f.title + " " + f.description).lower()
        for banned in ("bocor", "membocorkan", "mungkin", "tidak semestinya"):
            self.assertNotIn(banned, text, f"kata dilarang: {banned}")
        self.assertIn("heuristik", text)
        self.assertIn("kandidat sensitif", text)
        self.assertIn("perlu konfirmasi policy owner", f.description.lower())

    def test_no_sensitive_is_info_and_impact_not_claimed(self):
        f = self._run({"app.example.test", "api.example.test"})
        self.assertEqual(f.severity, "info")
        text = (f.title + " " + f.description).lower()
        for banned in ("bocor", "membocorkan", "mungkin", "tidak semestinya"):
            self.assertNotIn(banned, text)
        self.assertIn("dampak: tidak diklaim", text)
        self.assertIn("policy pemilik domain", text)
        self.assertIn("bukan kerentanan", text)


# --------------------------------------------------------------- Tugas 3
class _LHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        page = self.server.page_for(self.path)
        data = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


_NGINX_DEFAULT = ("<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>"
                  "<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx "
                  "web server is successfully installed and working. Further "
                  "configuration is required.</p></body></html>")
_APP_PAGE = ("<html><head><title>MyApp</title></head><body>"
             "<form action='/login' method='POST'><input name='user'></form>"
             "<script src='/_next/static/chunk.main.js'></script>"
             "<script>window.__NEXT_DATA__={\"page\":\"/\"};</script></body></html>")
_LOGIN_PAGE = ("<html><head><title>Sign in</title></head><body>"
               "<form action='/login' method='POST'><input name='user'>"
               "<input name='password' type='password'></form></body></html>")


class TestLiveness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _LHandler)
        cls.srv.page_for = lambda path: _NGINX_DEFAULT
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _ctx(self) -> ToolContext:
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=WorldModel(), rate_limit_s=0.0, timeout_s=2.0)

    def test_default_page_flags_stale_candidate(self):
        self.srv.page_for = lambda path: _NGINX_DEFAULT
        ctx = self._ctx()
        res = LivenessProbeTool().run({"url": self.base}, ctx)
        self.assertEqual(len(res.findings), 1,
                         "halaman default nginx = kandidat stale muncul")
        f = res.findings[0]
        self.assertIn("Stale/orphaned surface candidate", f.title)
        self.assertEqual(f.finding_class, "surface")
        self.assertEqual(f.status, "unconfirmed")
        self.assertEqual(f.severity, "low")
        self.assertIsNone(f.cwe)
        for must in ("app fingerprint not established", "LAPIS 4",
                     "TIDAK DAPAT DIKONFIRMASI", "bukan klaim backend mati"):
            self.assertIn(must, f.description)
        self.assertIn("app=not established", f.response)

    def test_app_fingerprint_no_stale(self):
        self.srv.page_for = lambda path: _APP_PAGE
        ctx = self._ctx()
        res = LivenessProbeTool().run({"url": self.base}, ctx)
        self.assertEqual(res.findings, [],
                         "aplikasi ber-fingerprint jelas: tidak ada temuan stale")
        self.assertTrue(res.data["layers"]["app"].startswith("established"))

    def test_login_page_counts_as_app_alive(self):
        # halaman utama = default nginx, TETAPI /login menyajikan form:
        # FP-guard: halaman login dihitung aplikasi HIDUP.
        def _route(path: str) -> str:
            return _LOGIN_PAGE if path.startswith("/login") else _NGINX_DEFAULT
        self.srv.page_for = _route
        ctx = self._ctx()
        res = LivenessProbeTool().run({"url": self.base}, ctx)
        self.assertEqual(res.findings, [],
                         "halaman login = aplikasi hidup, bukan stale")
        self.assertTrue(res.data["layers"]["app"].startswith("established"))

    def test_no_success_response_no_conclusion(self):
        # port mati: tidak boleh ada kesimpulan/temuan apa pun
        with mock.patch("cyphron.tools.http_engine.http_get",
                        side_effect=ConnectionError("refused")):
            ctx = self._ctx()
            res = LivenessProbeTool().run({"url": "http://127.0.0.1:9"}, ctx)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.data.get("host_liveness"), "down")


if __name__ == "__main__":
    unittest.main()
