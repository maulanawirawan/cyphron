"""Unit tests roadmap_batch5: 6 engine baru + ws_probe origin-bypass (medium-22..30).

- VULN fixture : tiap engine menemukan temuan definitifnya
- CLEAN fixture: tiap engine HARUS 0 temuan (FP-guard)
- jwt_crack    : offline HMAC guess terhadap token sintetis (secret 'changeme')"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.header_ws_engines import WsProbeTool
from cyphron.tools.crypto_web_engines import (
    CssInjectionTool, DomClobberTool, JwtCrackTool, JwtHeaderTool,
    ProtoClientTool, ProtoServerTool,
)
from cyphron.world.model import WorldModel

_MARK = "cyphron7f3a"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(secret: str = "changeme") -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64u(json.dumps({"sub": "1", "role": "user"}).encode())
    s = _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"


CLOBBER_HTML = ("<html><body><img id='images'>"
                "<script>var n = document.images.length;</script></body></html>")


class Batch5VulnHandler(BaseHTTPRequestHandler):
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
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/mergepage":  # proto_c: SELURUH query direfleksikan mentah
            self._send(200, f"<html><body>config {p.query}</body></html>")
        elif p.path == "/csspage":  # css_inj: nilai masuk konteks <style> mentah
            style = (q.get("style") or [""])[0]
            self._send(200, f"<html><head><style>body{{color:{style}}}</style></head></html>")
        elif p.path == "/clobber":  # clobber: id menabrak document.images
            self._send(200, CLOBBER_HTML)
        elif p.path == "/api/profile":  # jwt_jku: header jku dipercaya (vuln)
            auth = self.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            parts = token.split(".")
            if len(parts) != 3:
                self._send(401, "unauthorized")
                return
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            except Exception:
                self._send(401, "unauthorized")
                return
            # vuln: percaya header jku/x5u; signature diverifikasi untuk token lain
            expect_sig = _b64u(hmac.new(b"changeme", f"{parts[0]}.{parts[1]}".encode(),
                                        hashlib.sha256).digest())
            if "jku" in header or "x5u" in header:
                self._send(200, '{"profile": "attacker accepted"}')  # vuln: percaya jku
            elif not hmac.compare_digest(parts[2], expect_sig):
                self._send(401, "unauthorized")  # token tempel tanpa jku -> tolak
            else:
                self._send(200, '{"profile": "ok"}')
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        if p.path == "/api/merge":  # proto_s: merge menerima __proto__ (vuln)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._send(400, "bad json")
                return
            merged = payload.get("__proto__") or {}
            self._send(200, json.dumps({"ok": True, "merged": merged}),
                       ctype="application/json")
            return
        self._send(200, "ok")


class Batch5CleanHandler(Batch5VulnHandler):
    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/mergepage":  # tidak merefleksikan query
            self._send(200, "<html><body>fixed page</body></html>")
        elif p.path == "/csspage":  # escape konteks style
            style = (q.get("style") or [""])[0]
            style = style.replace("<", "&lt;").replace(">", "&gt;").replace("}", "&rbrace;")
            self._send(200, f"<html><head><style>body{{color:{style}}}</style></head></html>")
        elif p.path == "/api/profile":  # hanya signature valid (tanpa jku) yang lolos
            auth = self.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            parts = token.split(".")
            if len(parts) != 3 or parts[2] == "TAMPER" or "jku" in parts[0].lower():
                self._send(401, "unauthorized")
                return
            self._send(200, '{"profile": "ok"}')
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        if p.path == "/api/merge":  # strip kunci berbahaya
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._send(400, "bad json")
                return
            payload.pop("__proto__", None)
            payload.pop("constructor", None)
            self._send(200, json.dumps({"ok": True}), ctype="application/json")
            return
        self._send(200, "ok")


class WsOriginServer:
    """Raw socket: upgrade WS dengan origin asing = 101, origin lain = 400."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(10)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                if b"origin: https://evil-cyphron.example" in data.lower():
                    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                else:
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


class TestRoadmapBatch5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 0), Batch5VulnHandler)
        cls.clean = HTTPServer(("127.0.0.1", 0), Batch5CleanHandler)
        for srv in (cls.vuln, cls.clean):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.vuln.server_address[1]}"
        cls.cbase = f"http://127.0.0.1:{cls.clean.server_address[1]}"
        cls.ws = WsOriginServer()
        cls.token = make_jwt()

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.clean.shutdown()

    def _ctx(self, world=None):
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=world or WorldModel(), rate_limit_s=0.0, timeout_s=8.0)

    def _world(self, base):
        w = WorldModel()
        w.observe_endpoint(f"{base}/mergepage", ["q"], discovered_by="test")
        w.observe_endpoint(f"{base}/csspage", ["style"], discovered_by="test")
        w.observe_endpoint(f"{base}/api/merge", [], method="POST", discovered_by="test")
        return w

    def test_registry_contains_all_batch5_tools(self):
        reg = build_default_registry(self._ctx())
        names = {t.name for t in reg.all()}
        self.assertTrue({"jwt_jku", "jwt_crack", "proto_c", "proto_s",
                         "clobber", "css_inj"} <= names)

    def test_jwt_header_jku_accepted(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/profile", [], discovered_by="test")
        res = JwtHeaderTool().run({"url": self.base, "token": self.token}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("jku", f.title)
        self.assertEqual(f.status, "confirmed")

    def test_jwt_crack_weak_hmac(self):
        res = JwtCrackTool().run({"url": self.base, "token": self.token}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("changeme", f.response)
        self.assertEqual(f.confidence, 1.0)

    def test_jwt_crack_skips_non_hmac(self):
        token = _b64u(json.dumps({"alg": "RS256"}).encode()) + ".x.y"
        res = JwtCrackTool().run({"url": self.base, "token": token}, self._ctx())
        self.assertEqual(res.findings, [])
        self.assertEqual(res.data.get("alg"), "RS256")

    def test_ws_origin_bypass(self):
        world = WorldModel()
        world.note("ws target")
        res = WsProbeTool().run({"url": f"http://127.0.0.1:{self.ws.port}",
                                 "max_requests": 12}, self._ctx(world))
        titles = [f.title for f in res.findings]
        self.assertGreaterEqual(len(res.findings), 1, titles)
        self.assertTrue(all("origin bypass" in t for t in titles), titles)

    def test_proto_client_reflection(self):
        res = ProtoClientTool().run({"url": self.base}, self._ctx(self._world(self.base)))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("Prototype pollution", res.findings[0].title)

    def test_proto_server_merge(self):
        res = ProtoServerTool().run({"url": self.base}, self._ctx(self._world(self.base)))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("cyphronpoll", res.findings[0].response)

    def test_dom_clobbering_lead(self):
        world = self._world(self.base)
        world.observe_endpoint(f"{self.base}/clobber", [], discovered_by="test")
        res = DomClobberTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].status, "unconfirmed", "clobber = lead statis")

    def test_css_injection_breakout(self):
        res = CssInjectionTool().run({"url": self.base}, self._ctx(self._world(self.base)))
        self.assertGreaterEqual(len(res.findings), 1)
        f = next(x for x in res.findings if x.param == "style")
        self.assertIn("CSS injection", f.title)
        self.assertEqual(f.status, "confirmed")

    def test_clean_fixture_zero_false_positives(self):
        """FP-guard proof: semua engine batch 5 HARUS 0 temuan di fixture bersih."""
        ctx = self._ctx(self._world(self.cbase))
        strong_token = make_jwt("6f8d0a2c9b1e47d38fa05c2b9e7d1a4f3c8b6d2e9f0a7c5b1d3e8f2a6c9b4d7e")
        results = {
            "jwt_jku": JwtHeaderTool().run({"url": self.cbase, "token": self.token}, ctx),
            "jwt_crack": JwtCrackTool().run({"url": self.cbase, "token": strong_token}, ctx),
            "proto_c": ProtoClientTool().run({"url": self.cbase}, ctx),
            "proto_s": ProtoServerTool().run({"url": self.cbase}, ctx),
            "clobber": DomClobberTool().run({"url": self.cbase}, ctx),
            "css_inj": CssInjectionTool().run({"url": self.cbase}, ctx),
        }
        for name, res in results.items():
            self.assertTrue(res.ok, f"{name} harus ok")
            self.assertEqual([f.title for f in res.findings], [],
                             f"{name} FP di fixture bersih: {[f.title for f in res.findings]}")


if __name__ == "__main__":
    unittest.main()
