"""Unit tests engine hasil bug bounty BINUS (2026-09-11):

- js_cred_sweep : filter FP (Firebase/MSAL) + decode-gate Basic auth
- wp_probe      : user enumeration (JSON-slug guard) + redaksi nama
- debug_page    : marker kuat + ekstraksi versi
- email_probe   : fallback DoH menutup FP 'false missing' (kasus binus.ac.id)

Semua offline/deterministik: HTTP via server lokal sementara, DNS dimock.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.debug_page import DebugPageTool
from cyphron.tools.email_probe import EmailProbeTool, _doh_txt, dns_txt
from cyphron.tools.js_cred_sweep import JsCredSweepTool, decode_basic, scan_text
from cyphron.tools.wp_probe import WpProbeTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=2.0,
                       max_requests=50)


# --------------------------------------------------------------- js_cred_sweep
class TestJsCredSweepFilters(unittest.TestCase):
    def test_valid_basic_auth_decodes_to_user_pass(self):
        import base64
        token = base64.b64encode(b"binus:binusprogram").decode()
        self.assertEqual(decode_basic(f'Authorization: Basic {token}'),
                         "binus:binusprogram")

    def test_invalid_base64_is_not_confirmed(self):
        # karakter ilegal -> tidak match pattern -> None
        self.assertIsNone(decode_basic("Basic !!!!"))
        # decode "not-user-pass" (tanpa ':') -> invalid -> None (lead, bukan confirmed)
        self.assertIsNone(decode_basic("Basic bm90LXVzZXItcGFzcw=="))

    def test_firebase_and_msal_filtered(self):
        # apiKey Firebase public-by-design -> tidak boleh jadi temuan
        hits = scan_text('let sh=(0,m.Wp)({apiKey:"AIzaSyAWa-QsyAv3hNe8bK0aX6tgEcrsvEL4qOs",'
                         'authDomain:"binus-maya.firebaseapp.com"});')
        self.assertEqual(hits, [])
        # enum MSAL/oidc (kode library) -> tidak boleh jadi temuan
        hits2 = scan_text('e.ACCESS_TOKEN="access_token",e.ID_TOKEN="id_token",'
                          'e.XMS_CC="xms_cc",e.httpSuccess=200')
        self.assertEqual(hits2, [])

    def test_real_basic_auth_survives_filter(self):
        import base64
        token = base64.b64encode(b"binus:binusprogram").decode()
        hits = scan_text(f'"server":"https://x.test/wp-json","auth":"Basic {token}"')
        kinds = {k for k, _m, _s in hits}
        self.assertTrue(any(k.startswith("basic") for k in kinds), kinds)


# --------------------------------------------------------------- wp_probe
class TestWpProbe(unittest.TestCase):
    def setUp(self):
        self._srv = HTTPServer(("127.0.0.1", 0), _WpHandler)
        self._thr = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thr.start()
        self.base = f"http://127.0.0.1:{self._srv.server_port}"

    def tearDown(self):
        self._srv.shutdown()

    def test_user_enumeration_confirmed_and_redacted(self):
        res = WpProbeTool().run({"url": self.base}, _ctx())
        f = [x for x in res.findings if "enumeration" in x.title]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "medium")
        self.assertEqual(f[0].status, "confirmed")
        # nama user TIDAK di-dump utuh di evidence
        self.assertNotIn("barneystinson", f[0].description)
        self.assertIn("***", f[0].description)

    def test_soft404_html_is_not_a_finding(self):
        _WpHandler.mode = "soft404"
        try:
            res = WpProbeTool().run({"url": self.base}, _ctx())
            self.assertFalse([x for x in res.findings if "enumeration" in x.title])
        finally:
            _WpHandler.mode = "users"


class _WpHandler(BaseHTTPRequestHandler):
    mode = "users"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/wp-json/wp/v2/users" and self.mode == "users":
            body = (b'[{"id":3,"name":"Barney Stinson","slug":"barneystinson"},'
                    b'{"id":1,"name":"Site Owner","slug":"siteowner"}]')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # soft-404: HTML biasa
        body = b"<!doctype html><html><body>Page not found</body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --------------------------------------------------------------- debug_page
class TestDebugPage(unittest.TestCase):
    def setUp(self):
        self._srv = HTTPServer(("127.0.0.1", 0), _DebugHandler)
        self._thr = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thr.start()
        self.base = f"http://127.0.0.1:{self._srv.server_port}"

    def tearDown(self):
        self._srv.shutdown()

    def test_ignition_page_confirmed_with_versions(self):
        res = DebugPageTool().run({"url": self.base}, _ctx())
        f = [x for x in res.findings if "debug" in x.title.lower()]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "medium")
        self.assertEqual(f[0].status, "confirmed")
        self.assertIn("6.20.44", f[0].description)
        self.assertIn("8.0.30", f[0].description)

    def test_normal_404_is_not_a_finding(self):
        _DebugHandler.mode = "clean"
        try:
            res = DebugPageTool().run({"url": self.base}, _ctx())
            self.assertEqual([x for x in res.findings
                              if "debug" in x.title.lower()], [])
        finally:
            _DebugHandler.mode = "ignition"

    def test_weak_exception_word_alone_is_not_enough(self):
        # halaman yang hanya memuat kata 'Exception' TANPA marker kuat -> bukan temuan
        _DebugHandler.mode = "weak"
        try:
            res = DebugPageTool().run({"url": self.base}, _ctx())
            self.assertEqual([x for x in res.findings
                              if "debug" in x.title.lower()], [])
        finally:
            _DebugHandler.mode = "ignition"


class _DebugHandler(BaseHTTPRequestHandler):
    mode = "ignition"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.mode in ("ignition", "weak") and "page=abc" in self.path:
            if self.mode == "ignition":
                body = (b"<html><title>Swift_TransportException</title><body>"
                        b"Laravel version 6.20.44 PHP version 8.0.30 "
                        b"vendor/laravel/framework Stack trace "
                        b"/home/rigedutech/public_html/index.php</body></html>")
            else:
                body = (b"<html><body>An Exception occurred in module - "
                        b"please contact support</body></html>")
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<!doctype html><html><body>Not found</body></html>"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --------------------------------------------------------------- email DoH
class TestEmailDohFallback(unittest.TestCase):
    def _dead_network(self):
        """UDP socket gagal total + TCP mock None = simulasi jaringan pembuang DNS."""
        return (mock.patch("cyphron.tools.email_probe.socket.socket",
                           side_effect=OSError("udp-dead")),
                mock.patch("cyphron.tools.email_probe._dns_query_tcp",
                           return_value=None))

    def test_doh_fallback_prevents_false_missing(self):
        """UDP+TCP mati total (jaringan pembuang DNS) -> DoH mengembalikan
        record -> engine TIDAK boleh melaporkan 'No SPF/DMARC' (kasus binus.ac.id)."""
        ctx = _ctx()
        doh_answers = {
            "example.ac.id": ["v=spf1 include:spf.protection.outlook.com ~all"],
            "_dmarc.example.ac.id": ["v=DMARC1; p=none; rua=mailto:dmarc@x"],
        }
        net1, net2 = self._dead_network()
        with net1, net2, mock.patch("cyphron.tools.email_probe._doh_txt",
                                    side_effect=lambda n, t=6.0: doh_answers.get(n, [])):
            res = EmailProbeTool().run({"url": "https://app.example.ac.id"}, ctx)
        titles = " | ".join(f.title for f in res.findings)
        self.assertNotIn("No SPF", titles)
        self.assertNotIn("No DMARC", titles)
        self.assertIn("v=spf1", str(res.data.get("spf")))

    def test_doh_still_reports_real_missing(self):
        """Record memang tidak ada di mana pun (UDP/TCP mati + DoH kosong)
        -> temuan missing sah tetap keluar."""
        ctx = _ctx()
        net1, net2 = self._dead_network()
        with net1, net2, mock.patch("cyphron.tools.email_probe._doh_txt",
                                    return_value=[]):
            res = EmailProbeTool().run({"url": "https://app.example.ac.id"}, ctx)
        titles = " | ".join(f.title for f in res.findings)
        self.assertIn("No SPF", titles)
        self.assertIn("No DMARC", titles)


if __name__ == "__main__":
    unittest.main()
