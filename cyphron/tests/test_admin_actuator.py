"""Unit tests — admin_panel / laravel_panel / actuator (2026-09-12).

Semua offline HTTPServer; fingerprint + FP-guard diuji:
- admin_panel   : Keycloak ter-expose = HIGH; 401/403 = terproteksi, bukan temuan
- laravel_panel : Telescope 200+marker = HIGH; 404 = bukan
- actuator      : /actuator tanpa _links = gate gagal (tidak ada temuan);
                  /env propertySources = HIGH; /heapdump header-only
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
from cyphron.tools.actuator import ActuatorTool
from cyphron.tools.admin_panel import AdminPanelTool
from cyphron.tools.laravel_panel import LaravelPanelTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=60)


class _Router(BaseHTTPRequestHandler):
    routes: dict = {}

    def _serve(self, method):
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

    def do_HEAD(self):
        self._serve("HEAD")

    def log_message(self, *a):
        pass


def _server(routes):
    handler = type("H", (_Router,), {"routes": routes})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class TestAdminPanel(unittest.TestCase):
    def test_keycloak_exposed_is_high(self):
        srv, base = _server({
            ("GET", "/admin/master/console/"): (200, "<title>Keycloak</title>", {}),
            ("GET", "/admin/"): (200, "<title>Keycloak</title>", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = AdminPanelTool().run({"url": base}, _ctx())
        self.assertTrue(any(f.severity == "high" for f in tr.findings))
        self.assertIn("Keycloak", tr.findings[0].title)

    def test_protected_console_is_not_finding(self):
        srv, base = _server({
            ("GET", "/admin/master/console/"): (403, "", {}),
            ("GET", "/admin/"): (403, "", {}),
            ("GET", "/login"): (403, "", {}),
            ("GET", "/browser/"): (403, "", {}),
            ("GET", "/sessions/new"): (403, "", {}),
            ("GET", "/graph"): (403, "", {}),
            ("GET", "/app/kibana"): (403, "", {}),
            ("GET", "/api/health"): (403, "", {}),
            ("GET", "/api/status"): (403, "", {}),
            ("GET", "/manager/html"): (403, "", {}),
            ("GET", "/#/login"): (403, "", {}),
            ("GET", "/login"): (403, "", {}),
            ("GET", "/api/session/properties"): (403, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = AdminPanelTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "401/403 = terproteksi, bukan temuan")


class TestLaravelPanel(unittest.TestCase):
    def test_telescope_exposed_is_high(self):
        srv, base = _server({
            ("GET", "/telescope"): (200, "<title>Telescope</title> Laravel Telescope", {}),
            ("GET", "/horizon"): (404, "", {}),
            ("GET", "/_ignition/health-check"): (404, "", {}),
            ("GET", "/up"): (200, "OK", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = LaravelPanelTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "high")
        self.assertIn("Telescope", tr.findings[0].title)

    def test_not_present_no_finding(self):
        srv, base = _server({
            ("GET", "/telescope"): (404, "", {}),
            ("GET", "/horizon"): (404, "", {}),
            ("GET", "/_ignition/health-check"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = LaravelPanelTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])


class TestActuator(unittest.TestCase):
    def test_gate_without_links_stops(self):
        srv, base = _server({
            ("GET", "/actuator"): (200, "not-json", {}),
            ("GET", "/actuator/env"): (200, '{"propertySources": [1]}', {}),
        })
        self.addCleanup(srv.shutdown)
        tr = ActuatorTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "gate _links wajib — tanpa itu berhenti")

    def test_env_exposed_is_high(self):
        env_body = json.dumps({"propertySources": [{"name": "x"}],
                               "_links": {"self": {"href": "/"}}})
        srv, base = _server({
            ("GET", "/actuator"): (200, json.dumps({"_links": {"self": {}}}), {}),
            ("GET", "/actuator/env"): (200, env_body, {}),
            ("GET", "/actuator/heapdump"): (404, "", {}),
            ("GET", "/actuator/mappings"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = ActuatorTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "high")

    def test_heapdump_header_only(self):
        heap_headers = {"Content-Type": "application/octet-stream",
                        "Content-Length": "52428800"}
        srv, base = _server({
            ("GET", "/actuator"): (200, json.dumps({"_links": {"self": {}}}), {}),
            ("GET", "/actuator/env"): (404, "", {}),
            ("GET", "/actuator/heapdump"): (200, "", heap_headers),
            ("GET", "/actuator/mappings"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = ActuatorTool().run({"url": base}, _ctx())
        self.assertTrue(any("heapdump" in f.title for f in tr.findings))
        # bukti header-only: tidak ada isi heapdump di evidence
        self.assertFalse(any("WJKBTC" in json.dumps(f.to_dict())
                             for f in tr.findings))


if __name__ == "__main__":
    unittest.main()
