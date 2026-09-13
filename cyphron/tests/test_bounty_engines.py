"""Unit tests roadmap_bounty: param_miner, authz_bypass, takeover, llm_probe."""
from __future__ import annotations
import json, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.bounty_engines import AuthzBypassTool, LlmProbeTool, ParamMinerTool, TakeoverTool, dns_cname
from cyphron.world.model import WorldModel


class BountyHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/":
            hidden = (q.get("debug") or [""])[0]
            body = "<html><body>app home</body></html>"
            if hidden:
                body = "<html><body>app home DEBUG MODE ACTIVE FOR OPERATORS " + hidden + " diagnostics enabled verbose output</body></html>"
            self._send(200, body)
        elif p.path == "/admin" or (p.path != "/" and "admin" in p.path)                 or self.headers.get("X-Original-URL") == "/admin"                 or self.headers.get("X-Rewrite-URL") == "/admin":
            if p.path == "/admin" and "bypass" not in self.path:
                self._send(403, "forbidden page")
            else:
                self._send(200, "<html><body>" + "Admin dashboard user list settings " * 8
                           + "</body></html>")
        elif p.path == "/api/chat":
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
            msg = (data.get("message") or data.get("prompt") or "")
            if "CYPPHRCANARY7F3A" in msg:
                self._send(200, json.dumps({"reply": "CYPPHRCANARY7F3A"}), ctype="application/json")
            else:
                self._send(200, json.dumps({"reply": "how can I help?"}), ctype="application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        self.do_GET()


class TestBounty(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), BountyHandler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _ctx(self):
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=WorldModel(), rate_limit_s=0.0, timeout_s=8.0)

    def test_registry_contains_bounty_tools(self):
        names = {t.name for t in build_default_registry(self._ctx()).all()}
        self.assertTrue({"param_miner", "authz_bypass", "takeover", "llm_probe"} <= names)

    def test_param_miner_finds_hidden_debug(self):
        res = ParamMinerTool().run({"url": self.base, "max_requests": 40}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("debug", res.findings[0].response)

    def test_authz_bypass_path_trick(self):
        res = AuthzBypassTool().run({"url": self.base, "max_requests": 30}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("bypass", res.findings[0].title.lower())

    def test_llm_probe_canary(self):
        world = WorldModel()
        world.observe_response(f"{self.base}/api/chat", 200, {}, "{}", "test")
        res = LlmProbeTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("CYPPHRCANARY7F3A", res.findings[0].response)

    def test_takeover_clean_domain_no_fp(self):
        # domain alive + tanpa CNAME dangling -> 0 temuan
        res = TakeoverTool().run({"url": "https://example.com", "domain": "example.com"},
                                 self._ctx())
        self.assertEqual(res.findings, [])


if __name__ == "__main__":
    unittest.main()
