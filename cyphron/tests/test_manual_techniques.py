"""Unit tests engine hasil promosi teknik manual agent (2026-09-08):
middleware_bypass (CVE-2025-29927), next_image_proxy, cookie_audit, sri_audit.

Semua test pakai HTTP server lokal; gate bukti Next.js disimulasikan lewat
world model.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.nextjs_probe import MiddlewareBypassTool, NextImageProxyTool
from cyphron.tools.client_audit import CookieAuditTool, SriAuditTool
from cyphron.world.model import WorldModel

_MW_HIT = "middleware:middleware:middleware:middleware:middleware"
_DASH_SECRET = ("<html><body>Dashboard internals " + "user data billing admin " * 10
                + "</body></html>")
_EXT_NO_SRI = ("<html><head><script src='https://cdn.example.com/lib.js'>"
               "</script></head><body>ok</body></html>")
_EXT_SRI = ("<html><head><script src='https://cdn.example.com/lib.js' "
            "integrity='sha384-abc'> </script></head><body>ok</body></html>")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookies=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        b = self.server.behavior
        if self.path.startswith("/dashboard"):
            if b == "mw_vulnerable" and \
                    self.headers.get("x-middleware-subrequest") == _MW_HIT:
                self._send(200, _DASH_SECRET)
            else:
                self._send(307, "", cookies=("sid=redirect; Path=/",))
        elif self.path.startswith("/_next/image"):
            low = self.path.lower()
            if b == "img_open" and "url=https%3a%2f%2fwww.google.com" in low:
                self._send(200, "\x89PNG-fake", ctype="image/png")
            else:
                self._send(400, "bad url")
        elif self.path in ("/", "/login"):
            if b == "cookie_bad":
                self._send(200, "<html>app page</html>",
                           cookies=("sid=abc123; Path=/",))
            elif b == "cookie_good":
                self._send(200, "<html>app page</html>",
                           cookies=("sid=abc123; Path=/; HttpOnly; Secure; "
                                    "SameSite=Lax",))
            elif b == "sri_bad":
                self._send(200, _EXT_NO_SRI)
            elif b == "sri_good":
                self._send(200, _EXT_SRI)
            else:
                self._send(200, "<html>app page</html>")
        else:
            self._send(404, "not found")

    do_POST = do_GET


class _Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.srv.behavior = "plain"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _ctx(self, nextjs: bool = True) -> ToolContext:
        w = WorldModel()
        if nextjs:
            ep = w.observe_endpoint(f"{self.base}/_next/static/chunk.js", [],
                                    discovered_by="test")
            ep.status = 200
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=w, rate_limit_s=0.0, timeout_s=2.0)


class TestMiddlewareBypass(_Fixture):
    def test_vulnerable_detected(self):
        self.srv.behavior = "mw_vulnerable"
        res = MiddlewareBypassTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.finding_class, "exploitable")
        self.assertEqual(f.status, "confirmed")
        self.assertIn("x-middleware-subrequest", f.description)
        self.assertIn("CVE-2025-29927", f.title)
        self.assertIn(_MW_HIT, f.poc)

    def test_patched_no_finding(self):
        self.srv.behavior = "plain"  # /dashboard selalu 307
        res = MiddlewareBypassTool().run({"url": self.base}, self._ctx())
        self.assertEqual(res.findings, [])
        self.assertGreater(res.data["checked"], 0)

    def test_no_nextjs_evidence_skips_cleanly(self):
        self.srv.behavior = "mw_vulnerable"
        ctx = self._ctx(nextjs=False)
        before = ctx.world.request_count
        res = MiddlewareBypassTool().run({"url": self.base}, ctx)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.data.get("skipped"), "no-nextjs-evidence")
        self.assertEqual(ctx.world.request_count, before,
                         "tanpa bukti Next.js: NOL request dikirim")


class TestNextImageProxy(_Fixture):
    def test_open_proxy_detected(self):
        self.srv.behavior = "img_open"
        res = NextImageProxyTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.cwe, "CWE-918")
        self.assertEqual(f.finding_class, "exploitable")
        self.assertIn("image/png", f.response)

    def test_patched_no_finding(self):
        self.srv.behavior = "plain"
        res = NextImageProxyTool().run({"url": self.base}, self._ctx())
        self.assertEqual(res.findings, [])

    def test_no_nextjs_evidence_skips_cleanly(self):
        self.srv.behavior = "img_open"
        res = NextImageProxyTool().run({"url": self.base}, self._ctx(nextjs=False))
        self.assertEqual(res.findings, [])
        self.assertEqual(res.data.get("skipped"), "no-nextjs-evidence")


class TestCookieAudit(_Fixture):
    def test_flagless_cookie_detected(self):
        self.srv.behavior = "cookie_bad"
        res = CookieAuditTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.finding_class, "posture")
        self.assertEqual(f.status, "confirmed")
        self.assertIn("HttpOnly-missing", f.response)
        self.assertIn("Secure-missing", f.response)
        # bukti bukan heuristik: nama + flag, nilai cookie tidak dibocorkan
        self.assertNotIn("abc123", f.response + f.description)

    def test_fully_flagged_no_finding(self):
        self.srv.behavior = "cookie_good"
        res = CookieAuditTool().run({"url": self.base}, self._ctx())
        self.assertEqual(res.findings, [])


class TestSriAudit(_Fixture):
    def test_missing_sri_detected(self):
        self.srv.behavior = "sri_bad"
        res = SriAuditTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.finding_class, "posture")
        self.assertEqual(f.severity, "info")
        self.assertIn("cdn.example.com/lib.js", f.response)

    def test_integrity_present_no_finding(self):
        self.srv.behavior = "sri_good"
        res = SriAuditTool().run({"url": self.base}, self._ctx())
        self.assertEqual(res.findings, [])


if __name__ == "__main__":
    unittest.main()
