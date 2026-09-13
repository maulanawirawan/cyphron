"""Unit tests roadmap_batch6: sourcemap2 (high-17/18), mq_mgmt (high-16),
dom_xss (high-19), clickj (high-21). VULN fixture = temuan definitif;
CLEAN fixture = 0 temuan (FP-guard)."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.infra_xss_engines import ClickjackTool, DomXssTool, MqMgmtTool, Sourcemap2Tool
from cyphron.world.model import WorldModel

JS_SOURCE = "function handler(){ document.getElementById('x').innerHTML = location.hash.slice(1); }"
MAP_SOURCE = json.dumps({
    "version": 3,
    "sources": ["src/handler.js", "src/config.js"],
    "sourcesContent": [
        JS_SOURCE + "// " + "x" * 950,
        "// config source\n" + "// pad\n" * 20
        + "export const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
        "export const API_KEY = 'abcd1234efgh5678jj';",
    ],
})
APP_JS = "console.log('bundle');"
SETTINGS_HTML = ("<html><body><form action='/settings' method='POST'>"
                 "<input name='email'><button>Save</button></form></body></html>")
RABBIT_JSON = json.dumps({"management_version": "3.12.0", "rabbitmq_version": "3.12.0",
                          "users": [{"name": "admin"}]})


class Batch6VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", xfo=None, csp=None):
        data = body.encode()
        self.send_response(code)
        if xfo:
            self.send_header("X-Frame-Options", xfo)
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/app.js":
            self._send(200, APP_JS, ctype="application/javascript")
        elif p.path == "/app.js.map":
            self._send(200, MAP_SOURCE, ctype="application/json")
        elif p.path == "/sink.js":
            self._send(200, JS_SOURCE, ctype="application/javascript")
        elif p.path == "/api/overview":
            self._send(200, RABBIT_JSON, ctype="application/json")
        elif p.path == "/admin/":
            self._send(200, "<html><title>ActiveMQ Console</title></html>")
        elif p.path == "/settings":
            self._send(200, SETTINGS_HTML)  # tanpa XFO/CSP -> clickj
        else:
            self._send(404, "not found")


class Batch6CleanHandler(Batch6VulnHandler):
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/app.js.map":
            self._send(404, "not found")  # map tidak di-deploy
        elif p.path == "/api/overview" or p.path == "/admin/":
            self._send(401, "unauthorized")  # konsol terlindungi
        elif p.path == "/settings":
            self._send(200, SETTINGS_HTML, xfo="DENY", csp="frame-ancestors 'self'")
        elif p.path == "/app.js" or p.path == "/sink.js":
            self._send(200, "console.log('safe');", ctype="application/javascript")
        else:
            self._send(404, "not found")


class TestRoadmapBatch6(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 0), Batch6VulnHandler)
        cls.clean = HTTPServer(("127.0.0.1", 0), Batch6CleanHandler)
        for srv in (cls.vuln, cls.clean):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.vuln.server_address[1]}"
        cls.cbase = f"http://127.0.0.1:{cls.clean.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.clean.shutdown()

    def _ctx(self, world=None):
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=world or WorldModel(), rate_limit_s=0.0, timeout_s=8.0)

    def test_registry_contains_all_batch6_tools(self):
        reg = build_default_registry(self._ctx())
        names = {t.name for t in reg.all()}
        self.assertTrue({"sourcemap2", "mq_mgmt", "dom_xss", "clickj"} <= names)

    def _world(self, base):
        w = WorldModel()
        for url in (f"{base}/app.js", f"{base}/sink.js"):
            w.observe_response(url, 200, {}, "js", "test")
        w.observe_response(f"{base}/settings", 200, {}, "html", "test")
        return w

    def test_sourcemap2_full_recover_and_secrets(self):
        res = Sourcemap2Tool().run({"url": self.base}, self._ctx(self._world(self.base)))
        titles = [f.title for f in res.findings]
        self.assertEqual(len(res.findings), 2, titles)
        recover = next(f for f in res.findings if "memulihkan" in f.title)
        secrets = next(f for f in res.findings if "kredensial" in f.title)
        self.assertEqual(recover.severity, "high")
        self.assertIn("AWS access key", secrets.response)
        self.assertIn("AKIA", secrets.response)

    def test_mq_mgmt_rabbitmq_and_activemq(self):
        res = MqMgmtTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 2)
        self.assertTrue(all(f.severity == "high" for f in res.findings))
        self.assertIn("RabbitMQ", res.findings[0].title)
        self.assertIn("ActiveMQ", res.findings[1].title)

    def test_dom_xss_sink_lead(self):
        res = DomXssTool().run({"url": self.base}, self._ctx(self._world(self.base)))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.status, "unconfirmed", "dom_xss = lead statis")
        self.assertEqual(f.severity, "high")
        self.assertIn("innerHTML", f.response)

    def test_clickjacking_no_framing_protection(self):
        res = ClickjackTool().run({"url": self.base}, self._ctx(self._world(self.base)))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.cwe, "CWE-1021")
        self.assertIn("X-Frame-Options=absen", f.response)

    def test_clean_fixture_zero_false_positives(self):
        """FP-guard proof: 4 engine batch 6 HARUS 0 temuan di fixture bersih."""
        ctx = self._ctx(self._world(self.cbase))
        results = {
            "sourcemap2": Sourcemap2Tool().run({"url": self.cbase}, ctx),
            "mq_mgmt": MqMgmtTool().run({"url": self.cbase}, ctx),
            "dom_xss": DomXssTool().run({"url": self.cbase}, ctx),
            "clickj": ClickjackTool().run({"url": self.cbase}, ctx),
        }
        for name, res in results.items():
            self.assertTrue(res.ok, f"{name} harus ok")
            self.assertEqual([f.title for f in res.findings], [],
                             f"{name} FP di fixture bersih: {[f.title for f in res.findings]}")


if __name__ == "__main__":
    unittest.main()
