"""Unit tests engine round 2 bug bounty BINUS (2026-09-12):

- lockout_probe   : bounded attempts + statis-vs-dinamis marker guard
                    (pelajaran "Locked!" modal statis) + SPA skip + clamp
- wp_dataexposure : author_email served = high (masked), email di konten =
                    medium (masked), FP-guard image@2x.png, cease-on-data,
                    wp error object = no claim
- wp_probe        : FP atribusi — redirect 302 ke host lain tidak boleh
                    menghasilkan temuan user-enum di host asal

Semua offline/deterministik: HTTP via server lokal sementara.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.lockout_probe import LockoutProbeTool, _parse_login_form
from cyphron.tools.wp_data_exposure import WpDataExposureTool, _mask_email
from cyphron.tools.wp_probe import WpProbeTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=2.0,
                       max_requests=50)


LOGIN_PAGE = """<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="_token" value="tok123">
  <input type="text" name="email">
  <input type="password" name="password">
</form></body></html>"""


class _Router(BaseHTTPRequestHandler):
    routes: dict = {}   # (method, path) -> (status, body, headers)
    hits: list = []

    def _serve(self, method):
        key = (method, self.path)
        self.hits.append(key)
        route = self.routes.get(key) or self.routes.get((method, self.path.split("?")[0]))
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, body, headers = route
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def log_message(self, *a):
        pass


class _RouterServer:
    def __init__(self, routes):
        handler = type("H", (_Router,), {"routes": routes, "hits": []})
        self.srv = HTTPServer(("127.0.0.1", 0), handler)
        self.hits = handler.hits
        self.base = f"http://127.0.0.1:{self.srv.server_port}"
        self._thr = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self._thr.start()

    def stop(self):
        self.srv.shutdown()


# --------------------------------------------------------------- lockout_probe
class TestLockoutProbe(unittest.TestCase):
    def setUp(self):
        self.ported = None

    def _server(self, routes):
        self.s = _RouterServer(routes)
        self.addCleanup(self.s.stop)
        return self.s.base

    def test_no_lockout_finding_when_no_throttle_signals(self):
        base = self._server({
            ("GET", "/login"): (200, LOGIN_PAGE, {}),
            ("POST", "/login"): (200, "These credentials do not match our records.", {}),
        })
        tr = LockoutProbeTool().run({"url": base + "/login", "max_attempts": 4}, _ctx())
        self.assertTrue(tr.findings, "harus menemukan no-lockout")
        f = tr.findings[0]
        self.assertEqual(f.cwe, "CWE-307")
        self.assertEqual(f.severity, "medium")
        self.assertEqual(tr.data["lockout"]["present"], False)

    def test_static_locked_marker_is_not_a_signal(self):
        # pelajaran lapangan: "Locked!" modal statis di template login
        static = "<h2 class=\"modal-title\">Locked!</h2>" + LOGIN_PAGE
        base = self._server({
            ("GET", "/login"): (200, static, {}),
            ("POST", "/login"): (200, "These credentials do not match our records. "
                                      "Locked!", {}),
        })
        tr = LockoutProbeTool().run({"url": base + "/login", "max_attempts": 4}, _ctx())
        self.assertTrue(tr.findings, "marker statis tidak boleh menutup temuan")

    def test_dynamic_throttle_stops_finding(self):
        base = self._server({
            ("GET", "/login"): (200, LOGIN_PAGE, {}),
            ("POST", "/login"): (200, "Too many login attempts. Please try again in 60 seconds.", {}),
        })
        from cyphron.tools.base import ToolContext as _TC
        ctx = _TC(gate=AuthorizationGate(None), audit=AuditLog(), world=WorldModel(),
                  rate_limit_s=0.0, timeout_s=10.0, max_requests=50)
        tr = LockoutProbeTool().run({"url": base + "/login", "max_attempts": 4}, ctx)
        self.assertEqual(tr.findings, [], f"engine data: {tr.data}")
        self.assertEqual(tr.data.get("lockout", {}).get("present"), True,
                         f"engine data: {tr.data}")

    def test_429_stops_finding(self):
        base = self._server({
            ("GET", "/login"): (200, LOGIN_PAGE, {}),
            ("POST", "/login"): (429, "rate limited", {"Retry-After": "60"}),
        })
        tr = LockoutProbeTool().run({"url": base + "/login", "max_attempts": 4}, _ctx())
        self.assertEqual(tr.findings, [])

    def test_spa_without_form_is_skipped(self):
        base = self._server({("GET", "/login"): (200, "<html><body><div id=root></div></body></html>", {})})
        tr = LockoutProbeTool().run({"url": base + "/login"}, _ctx())
        self.assertEqual(tr.data.get("skipped"), "no-html-form")
        self.assertEqual(tr.findings, [])

    def test_attempts_clamped_to_six(self):
        seen = []

        class Counting(_Router):
            def do_POST(self):
                seen.append(1)
                super().do_POST()

        handler = type("H", (Counting,), {"routes": {
            ("GET", "/login"): (200, LOGIN_PAGE, {}),
            ("POST", "/login"): (200, "invalid", {}),
        }, "hits": []})
        srv = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        tr = LockoutProbeTool().run({"url": f"http://127.0.0.1:{srv.server_port}/login",
                                     "max_attempts": 99}, _ctx())
        self.assertLessEqual(len(seen), 6, "hard cap 6 attempt terlampaui")

    def test_parse_login_form_extracts_fields(self):
        form = _parse_login_form(LOGIN_PAGE)
        self.assertIsNotNone(form)
        self.assertEqual(form["user_field"], "email")
        self.assertEqual(form["csrf"], [("_token", "tok123")])


# ------------------------------------------------------------ wp_data_exposure
class TestWpDataExposure(unittest.TestCase):
    def test_author_email_served_is_high_and_masked(self):
        payload = json.dumps([{"id": 1, "author_name": "John Doe",
                               "author_email": "johndoe@gmail.com",
                               "content": {"rendered": "<p>hi</p>"}}])
        base = self._serve({
            ("GET", "/wp-json/wp/v2/comments"): (200, payload, {}),
            ("GET", "/wp-json/wp/v2/media"): (200, "[]", {}),
        })
        tr = WpDataExposureTool().run({"url": base}, _ctx())
        self.assertTrue(tr.findings)
        self.assertEqual(tr.findings[0].severity, "high")
        self.assertNotIn("johndoe@gmail.com", json.dumps(tr.findings[0].response))
        self.assertIn("***", tr.data["collections"]["comments"]["emails"][0]["masked"])

    def test_email_in_comment_content_is_medium(self):
        payload = json.dumps([{"id": 2, "content": {"rendered": "<p>hubungi saya a@mail.com</p>"}}])
        base = self._serve({
            ("GET", "/wp-json/wp/v2/comments"): (200, payload, {}),
            ("GET", "/wp-json/wp/v2/media"): (200, "[]", {}),
        })
        tr = WpDataExposureTool().run({"url": base}, _ctx())
        self.assertTrue(tr.findings)
        self.assertEqual(tr.findings[0].severity, "medium")
        self.assertNotIn("a@mail.com", json.dumps([f.response for f in tr.findings]))

    def test_retina_filename_lookalike_is_not_email(self):
        # FP lapangan: image@2x.png di source_url/guid
        payload = json.dumps([{"id": 3, "source_url": "https://x.test/hero@2x.png",
                               "guid": {"rendered": "https://x.test/hero@3x.jpg"},
                               "caption": {"rendered": ""}}])
        base = self._serve({
            ("GET", "/wp-json/wp/v2/media"): (200, payload, {}),
            ("GET", "/wp-json/wp/v2/comments"): (200, "[]", {}),
        })
        tr = WpDataExposureTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "image@2x.png tidak boleh dihitung email")

    def test_cease_on_data_stops_second_collection(self):
        # comments membocorkan email -> media TIDAK boleh di-fetch lagi
        payload = json.dumps([{"id": 4, "author_email": "x@y.com"}])
        routes = {
            ("GET", "/wp-json/wp/v2/comments"): (200, payload, {}),
            ("GET", "/wp-json/wp/v2/media"): (200, "[]", {}),
        }
        handler = type("H", (_Router,), {"routes": routes, "hits": []})
        srv = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = WpDataExposureTool().run({"url": base}, _ctx())
        self.assertTrue(tr.findings)
        requested = [h[1] for h in handler.hits]
        self.assertFalse(any("media" in p for p in requested),
                         "cease-on-data dilanggar: media masih di-fetch")

    def test_wp_error_object_is_no_claim(self):
        payload = json.dumps({"code": "rest_no_route", "data": {"status": 404}})
        base = self._serve({
            ("GET", "/wp-json/wp/v2/comments"): (404, payload, {}),
            ("GET", "/wp-json/wp/v2/media"): (404, payload, {}),
        })
        tr = WpDataExposureTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])

    def _serve(self, routes):
        self.s = _RouterServer(routes)
        self.addCleanup(self.s.stop)
        return self.s.base


# ------------------------------------------------------------------- wp_probe
class TestWpProbeAttribution(unittest.TestCase):
    def test_redirect_to_other_host_not_attributed(self):
        # FP lapangan: rig-edutech 302 ke research WP -> temuan tidak boleh
        # jatuh ke host asal
        users_json = json.dumps([{"id": 1, "slug": "admin", "name": "Admin"}])
        handler = type("H", (_Router,), {"routes": {
            ("GET", "/wp-json/wp/v2/users"): (302, "", {"Location": "https://other-host.test/wp-json/wp/v2/users"}),
            ("GET", "/?rest_route=/wp/v2/users"): (302, "", {"Location": "https://other-host.test/?rest_route=/wp/v2/users"}),
            ("GET", "/wp-content/debug.log"): (404, "", {}),
            ("GET", "/xmlrpc.php"): (403, "", {}),
        }, "hits": []})
        srv = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = WpProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "respons host lain tidak boleh diatribusikan")
        self.assertTrue(tr.data.get("redirected_to_other_host"))

    def test_same_host_path_redirect_still_attributed(self):
        users_json = json.dumps([{"id": 1, "slug": "admin", "name": "Admin"}])
        handler = type("H", (_Router,), {"routes": {
            ("GET", "/wp-json/wp/v2/users"): (301, "", {"Location": "/wp-json/wp/v2/users/"}),
            ("GET", "/wp-json/wp/v2/users/"): (200, users_json, {"Content-Type": "application/json"}),
            ("GET", "/wp-content/debug.log"): (404, "", {}),
            ("GET", "/xmlrpc.php"): (403, "", {}),
        }, "hits": []})
        srv = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = WpProbeTool().run({"url": base}, _ctx())
        self.assertTrue(tr.findings, "redirect path same-host tetap sah diatribusikan")


if __name__ == "__main__":
    unittest.main()
