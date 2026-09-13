"""Unit tests — engine queue round 3 (2026-09-12):

- security_txt : catch-all HTML != valid security.txt; valid file = positif
- cors         : exact-Origin reflection + credentials = temuan; wildcard = bukan
- register     : form registrasi (password+identitas) = temuan; halaman login = FP-guard
- reset_enum   : diff konsisten 3 putaran = temuan; identik = tidak ada
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.cors_probe import CorsProbeTool
from cyphron.tools.register_probe import RegisterProbeTool
from cyphron.tools.reset_enum import ResetEnumTool
from cyphron.tools.security_txt import SecurityTxtTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


class _Router(BaseHTTPRequestHandler):
    routes: dict = {}
    hits: list = []
    bodies: list = []

    def _serve(self, method):
        self.hits.append((method, self.path))
        route = self.routes.get((method, self.path)) \
            or self.routes.get((method, self.path.split("?")[0]))
        if route is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body, headers = route
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        self.bodies.append(self.rfile.read(ln).decode("utf-8", "replace"))
        self._serve("POST")

    def log_message(self, *a):
        pass


def _server(routes):
    handler = type("H", (_Router,), {"routes": routes, "hits": [], "bodies": []})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


LOGIN_PAGE = """<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="_token" value="t">
  <input type="email" name="email">
  <input type="password" name="password">
</form></body></html>"""

RESET_PAGE = """<html><body>
<form method="POST" action="/password/email">
  <input type="hidden" name="_token" value="tok9">
  <input type="email" name="email">
  <input type="email" name="email_confirm" style="display:none">
</form></body></html>"""

REGISTER_PAGE = """<html><body>
<form method="POST" action="/user/sign_up">
  <input type="text" name="user_name">
  <input type="email" name="email">
  <input type="password" name="password">
  <input type="password" name="retype">
</form></body></html>"""


class TestSecurityTxt(unittest.TestCase):
    def test_catchall_html_is_missing(self):
        srv, base = _server({
            ("GET", "/.well-known/security.txt"): (200, "<html>404</html>",
                                                   {"Content-Type": "text/html"}),
            ("GET", "/security.txt"): (200, "<html>404</html>",
                                       {"Content-Type": "text/html"}),
        })
        self.addCleanup(srv.shutdown)
        tr = SecurityTxtTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "info")
        self.assertEqual(tr.findings[0].finding_class, "posture")

    def test_valid_securitytxt_is_positive(self):
        srv, base = _server({
            ("GET", "/.well-known/security.txt"): (
                200, "Contact: mailto:sec@x.test\nExpires: 2027-01-01\n",
                {"Content-Type": "text/plain"}),
        })
        self.addCleanup(srv.shutdown)
        tr = SecurityTxtTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])


class TestCors(unittest.TestCase):
    def test_reflection_with_credentials_is_finding(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {
                "Access-Control-Allow-Origin": "https://cyphron-probe.invalid",
                "Access-Control-Allow-Credentials": "true"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].cwe, "CWE-942")

    def test_wildcard_is_not_reported(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertIn("wildcard", tr.data.get("note", ""))

    def test_legit_allowlist_not_reported(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {"Access-Control-Allow-Origin": "https://app.x.test"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])


class TestRegister(unittest.TestCase):
    def test_open_register_form_is_finding(self):
        srv, base = _server({
            ("GET", "/register"): (200, REGISTER_PAGE, {}),
            ("GET", "/signup"): (404, "", {}),
            ("GET", "/register.html"): (404, "", {}),
            ("GET", "/wp-login.php?action=register"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = RegisterProbeTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].finding_class, "posture")
        self.assertIn("/register", tr.findings[0].request)

    def test_login_page_is_not_register(self):
        srv, base = _server({
            ("GET", "/register"): (200, LOGIN_PAGE, {}),
            ("GET", "/signup"): (404, "", {}),
            ("GET", "/register.html"): (404, "", {}),
            ("GET", "/wp-login.php?action=register"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = RegisterProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "halaman login tidak boleh dihitung registrasi")


class TestResetEnum(unittest.TestCase):
    def test_consistent_diff_is_finding(self):
        # handler dinamis: bedakan known vs fictional dari body
        class Dyn(_Router):
            routes = {}
            hits = []
            bodies = []
            def do_GET(self):
                if self.path == "/password/reset":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(RESET_PAGE)))
                    self.end_headers()
                    self.wfile.write(RESET_PAGE.encode())
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(ln).decode("utf-8", "replace")
                Dyn.bodies.append(body)
                if "known@x.test" in body:
                    self.send_response(500)
                    body_s = "Server Error (reset failed for existing)"
                else:
                    self.send_response(302)
                    body_s = "redirect"
                self.send_header("Content-Length", str(len(body_s)))
                self.end_headers()
                self.wfile.write(body_s.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Dyn)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset",
                                  "known_email": "known@x.test"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].cwe, "CWE-204")
        self.assertEqual(len(tr.data["signatures_known"]), 3)
        self.assertEqual(len(set(tr.data["signatures_known"])), 1)

    def test_identical_response_no_finding(self):
        class Dyn2(_Router):
            routes = {}
            hits = []
            bodies = []
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(RESET_PAGE)))
                self.end_headers()
                self.wfile.write(RESET_PAGE.encode())
            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(ln)
                self.send_response(200)
                body_s = "If that account exists, a link was sent"
                self.send_header("Content-Length", str(len(body_s)))
                self.end_headers()
                self.wfile.write(body_s.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Dyn2)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset",
                                  "known_email": "known@x.test"}, _ctx())
        self.assertEqual(tr.findings, [], "respons identik = postur baik")
        self.assertIn("identik", tr.data.get("note", ""))

    def test_without_known_email_skipped(self):
        srv, base = _server({("GET", "/password/reset"): (200, RESET_PAGE, {})})
        self.addCleanup(srv.shutdown)
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset"}, _ctx())
        self.assertEqual(tr.data.get("skipped"), "known_email-required")


if __name__ == "__main__":
    unittest.main()
