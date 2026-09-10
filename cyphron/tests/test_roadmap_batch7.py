"""Unit tests roadmap_batch7: multi-akun god mode — bola (high-02/28),
priv_matrix (high-03), ws unauth-message (high-06), helper auth_login.

- VULN fixture : alice/bob/admin, objek user-scoped bocor lintas akun
- CLEAN fixture: otorisasi per-objek benar -> 0 temuan"""

from __future__ import annotations

import base64
import json
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.auth_login import login
from cyphron.tools.base import ToolContext
from cyphron.tools.roadmap_batch2 import WsProbeTool
from cyphron.tools.roadmap_batch7 import BolaTool, PrivMatrixTool
from cyphron.world.model import WorldModel

ORDER_ALICE = "Order #1 of alice: 2x keyboard, total $150, ship to Jl. Melati 12"


class Batch7VulnHandler(BaseHTTPRequestHandler):
    enforce_owner = False

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookie=None,
              location=None):
        data = body.encode()
        self.send_response(code)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _user_of(cookie: str | None) -> str | None:
        if not cookie:
            return None
        m = cookie.split("=")
        if len(m) == 2 and m[0].strip() == "session" and m[1].endswith("-sid"):
            return m[1][:-4]
        return None

    def do_GET(self):
        p = urlparse(self.path)
        user = self._user_of(self.headers.get("Cookie"))
        if p.path == "/" and user:
            self._send(200, f"<html><body><h1>Hub {user}</h1>"
                            "<a href='/api/order?id=1'>Order 1</a>"
                            "<a href='/admin'>Admin</a></body></html>")
            return
        if p.path == "/api/order":
            if user is None:  # anonim DITOLAK (prasyarat predikat BOLA)
                self._send(302, "", location="/login")
            elif self.enforce_owner and user != "alice":
                self._send(403, "forbidden")
            elif (parse_qs(p.query).get("id") or [""])[0] == "1":
                self._send(200, f"<html><body>{ORDER_ALICE}</body></html>")
            else:
                self._send(404, "not found")
        elif p.path == "/admin":
            if user is None:
                self._send(302, "", location="/login")
            elif self.enforce_owner and user != "admin":
                self._send(403, "forbidden")
            else:
                self._send(200, "<html><body><h1>Admin panel</h1>"
                                "<table><tr><td>user list</td></tr>"
                                "<tr><td>system settings</td></tr></table></body></html>")
        elif p.path == "/login":
            self._send(200, "<html><body><form action='/login' method='POST'>"
                            "<input name='email'><input type='password' name='password'>"
                            "</form></body></html>")
        else:
            self._send(302, "", location="/login")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode())
        if p.path == "/login":
            creds = {"alice": "alicepass", "bob": "bobpass", "admin": "adminpass"}
            email = (form.get("email") or [""])[0].split("@")[0]
            if creds.get(email) == (form.get("password") or [""])[0]:
                self._send(302, "welcome", cookie=f"session={email}-sid; Path=/")
                return
        self._send(200, "login failed")


class Batch7CleanHandler(Batch7VulnHandler):
    enforce_owner = True  # otorisasi per-objek benar


class WsEchoServer:
    """WS tanpa auth + echo frame (server memproses pesan anonim)."""

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
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            # baca frame client (masked), echo balik unmasked
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            ln = hdr[1] & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", conn.recv(2))[0]
            mask = conn.recv(4)
            payload = bytearray(conn.recv(ln or 1024))
            for i in range(len(payload)):
                payload[i] ^= mask[i % 4]
            conn.sendall(bytes([0x81, len(payload)]) + bytes(payload))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class TestRoadmapBatch7(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 0), Batch7VulnHandler)
        cls.clean = HTTPServer(("127.0.0.1", 0), Batch7CleanHandler)
        for srv in (cls.vuln, cls.clean):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.vuln.server_address[1]}"
        cls.cbase = f"http://127.0.0.1:{cls.clean.server_address[1]}"
        cls.ws = WsEchoServer()
        cls.sessions = {"alice": "session=alice-sid", "bob": "session=bob-sid"}
        cls.sessions_admin = {"alice": "session=alice-sid", "admin": "session=admin-sid"}

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.clean.shutdown()

    def _ctx(self, world=None, sessions=None):
        ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                          world=world or WorldModel(), rate_limit_s=0.0, timeout_s=8.0)
        if sessions:
            ctx.sessions = dict(sessions)
        return ctx

    def test_registry_contains_batch7_tools(self):
        reg = build_default_registry(self._ctx())
        names = {t.name for t in reg.all()}
        self.assertTrue({"bola", "priv_matrix"} <= names)

    def test_login_helper_form_flow(self):
        cookie = login(self.base, "alice@example.test", "alicepass", timeout=8)
        self.assertIsNotNone(cookie)
        self.assertEqual(cookie, "session=alice-sid")
        self.assertIsNone(login(self.base, "alice@example.test", "salah", timeout=8))

    def test_bola_cross_account_read(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/order", ["id"], discovered_by="test")
        res = BolaTool().run({"url": self.base}, self._ctx(world, self.sessions))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertIn("bob", f.title)
        self.assertIn("alice", f.title)
        self.assertIn("anon: 302", f.response)

    def test_bola_noop_with_single_session(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/order", ["id"], discovered_by="test")
        res = BolaTool().run({"url": self.base},
                             self._ctx(world, {"alice": "session=alice-sid"}))
        self.assertEqual(res.findings, [])

    def test_priv_matrix_user_sees_admin(self):
        res = PrivMatrixTool().run({"url": self.base},
                                   self._ctx(WorldModel(), self.sessions_admin))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("alice", f.title)
        self.assertIn("admin", f.title)
        self.assertEqual(f.cwe, "CWE-285")

    def test_ws_unauth_message_processed(self):
        res = WsProbeTool().run({"url": f"http://127.0.0.1:{self.ws.port}",
                                 "max_requests": 12}, self._ctx())
        titles = [f.title for f in res.findings]
        self.assertTrue(any("diproses tanpa autentikasi" in t for t in titles), titles)
        self.assertTrue(any(t.startswith("WebSocket handshake diterima tanpa")
                            for t in titles), titles)

    def test_clean_fixture_zero_false_positives(self):
        """FP-guard: otorisasi per-objek benar -> bola & priv_matrix 0 temuan."""
        world = WorldModel()
        world.observe_endpoint(f"{self.cbase}/api/order", ["id"], discovered_by="test")
        results = {
            "bola": BolaTool().run({"url": self.cbase}, self._ctx(world, self.sessions)),
            "priv_matrix": PrivMatrixTool().run({"url": self.cbase},
                                                self._ctx(WorldModel(),
                                                          self.sessions_admin)),
        }
        for name, res in results.items():
            self.assertTrue(res.ok, f"{name} harus ok")
            self.assertEqual([f.title for f in res.findings], [],
                             f"{name} FP: {[f.title for f in res.findings]}")


if __name__ == "__main__":
    unittest.main()
