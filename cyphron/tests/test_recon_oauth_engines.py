"""Unit tests untuk roadmap_batch3: 8 engine baru (10 slot tier2).

Dua fixture dijalankan berdampingan:
- VULN fixture : tiap engine menemukan temuan definitifnya (hit by construction)
- CLEAN fixture: tiap engine HARUS 0 temuan (bukti FP-guard bekerja)

Plus raw-socket server untuk uji smuggle (timing divergence CL.TE)."""

from __future__ import annotations

import json
import re
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.recon_oauth_engines import (
    CacheDecTool, CtLogTool, IdSeqTool, JsonInjTool, OAuthTool, PuzzleTool,
    SmuggleTool, WaybackTool,
)
from cyphron.world.model import WorldModel

ACCOUNT_HTML = ("<html><body><h1>Account: alice</h1>"
                "<p>email alice@example.test — order #4711 — plan pro</p></body></html>")
ID_TOKEN_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.cyphronsig"


class Batch3VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", location=None):
        data = body.encode()
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/cdx":  # mock Wayback CDX (rows merujuk Host fixture)
            host = self.headers.get("Host")
            rows = [["original", "statuscode"],
                    [f"http://{host}/admin-old", "200"],
                    [f"http://{host}/live-page", "200"]]
            self._send(200, json.dumps(rows), ctype="application/json")
        elif p.path.rstrip("/") == "/crt":  # mock crt.sh (engine pakai suffix "/?q=")
            self._send(200, json.dumps([
                {"name_value": "dev.example.test\nvpn.example.test\nwww.example.test"},
                {"name_value": "api.example.test"},
            ]), ctype="application/json")
        elif p.path in ("/account", "/account.css"):  # cache deception: isi identik
            self._send(200, ACCOUNT_HTML)
        elif p.path == "/live-page":
            self._send(200, "<html><body>live page</body></html>")
        elif p.path == "/item":
            item_id = (q.get("id") or [""])[0]
            bodies = {"1": "Item one details: alpha inventory",
                      "2": "Item two details: beta inventory"}
            if item_id in bodies:
                self._send(200, f"<html><body>{bodies[item_id]}</body></html>")
            elif len(item_id) >= 8 and item_id.isdigit():
                self._send(404, "<html><body>missing</body></html>")
            else:
                self._send(200, f"<html><body>Item {item_id}</body></html>")
        elif p.path == "/api/search":  # JSON dibangun dengan string concat (vuln)
            qs = (q.get("q") or [""])[0]
            self._send(200, '{"query": "' + qs + '", "results": []}',
                       ctype="application/json")
        elif p.path == "/oauth/authorize":  # OAuth longgar: any client, no state
            uri = (q.get("redirect_uri") or [""])[0]
            if (q.get("response_type") or [""])[0] == "id_token":
                self._send(302, "", location=f"{uri}#id_token={ID_TOKEN_VALUE}")
            else:
                self._send(302, "", location=f"{uri}?code=cyphroncode123")
        elif p.path == "/login":
            self._send(200, "<html><body><form action='/login' method='POST'>"
                            "<input name='email'><input type='password' name='password'>"
                            "<button>Login</button></form></body></html>")
        else:
            self._send(404, "<html><body>not found generic</body></html>")

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self._send(200, "ok")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode())
        if "password[]" in form:
            # type confusion (emulasi PHP strcmp: array -> NULL -> bypass)
            self._send(302, "Welcome to dashboard", location="/dashboard")
        elif (form.get("password") or [""])[0] == "admin123":
            self._send(302, "Welcome to dashboard", location="/dashboard")
        else:
            self._send(200, "login failed")


class Batch3CleanHandler(Batch3VulnHandler):
    """Fixture BAIK: semua perilaku vuln hilang; engine wajib 0 temuan."""

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/cdx":
            self._send(200, json.dumps([["original", "statuscode"]]),
                       ctype="application/json")
        elif p.path.rstrip("/") == "/crt":
            self._send(200, json.dumps([{"name_value": "www.example.test"}]),
                       ctype="application/json")
        elif p.path == "/account":
            self._send(200, ACCOUNT_HTML)
        elif p.path == "/item":  # body identik + kontrol 200 -> guard id_seq gagal
            self._send(200, "<html><body>Same item body</body></html>")
        elif p.path == "/api/search":  # json.dumps -> ter-escape benar
            self._send(200, json.dumps({"query": (q.get("q") or [""])[0], "results": []}),
                       ctype="application/json")
        elif p.path == "/oauth/authorize":  # redirect ketat ke callback sama-origin
            self._send(302, "", location="/callback?code=xyz")
        elif p.path == "/login":
            self._send(200, "<html><body><form action='/login' method='POST'>"
                            "<input name='email'><input type='password' name='password'>"
                            "<button>Login</button></form></body></html>")
        else:
            self._send(404, "<html><body>not found generic</body></html>")

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self._send(200, "ok")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        form = parse_qs(self.rfile.read(length).decode())
        if (form.get("password") or [""])[0] == "admin123":
            self._send(302, "Welcome to dashboard", location="/dashboard")
        else:
            self._send(200, "login failed")  # password[] diabaikan: tidak rentan


class SmuggleRawServer:
    """Back-end yang menghormati TE secara ketat: chunk-stream rusak = hang.

    CL.TE probe (body `1\\r\\nZ\\r\\nQ\\r\\n`): chunk `1` valid, lalu size line
    `Q` tidak valid -> back-end menunggu -> client timeout (divergensi).
    Baseline CL-only dan TE.CL probe (`0\\r\\n\\r\\nX`) selesai normal."""

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
            conn.settimeout(15)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            headers = head.decode("latin-1").lower()
            if "transfer-encoding:" in headers:
                buf = rest
                while True:
                    while b"\r\n" not in buf:
                        buf += conn.recv(4096)
                    line, _, buf = buf.partition(b"\r\n")
                    try:
                        size = int(line.strip()[:16] or "zz", 16)
                    except ValueError:
                        time.sleep(120)  # desync: back-end diam menunggu
                        return
                    if size == 0:
                        break
                    while len(buf) < size + 2:
                        buf += conn.recv(4096)
                    buf = buf[size + 2:]
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            else:
                m = re.search(r"content-length:\s*(\d+)", headers)
                need = int(m.group(1)) if m else 0
                while len(rest) < need:
                    rest += conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class TestRoadmapBatch3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 0), Batch3VulnHandler)
        cls.clean = HTTPServer(("127.0.0.1", 0), Batch3CleanHandler)
        for srv in (cls.vuln, cls.clean):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.vuln.server_address[1]}"
        cls.cbase = f"http://127.0.0.1:{cls.clean.server_address[1]}"
        cls.smuggle = SmuggleRawServer()

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.clean.shutdown()

    def _ctx(self, world=None):
        return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                           world=world or WorldModel(), rate_limit_s=0.0, timeout_s=8.0)

    def test_registry_contains_all_batch3_tools(self):
        reg = build_default_registry(self._ctx())
        names = {t.name for t in reg.all()}
        self.assertTrue({"wayback", "id_seq", "ct_log", "smuggle", "cache_dec",
                         "oauth", "puzzle", "json_inj"} <= names)

    def test_wayback_lost_routes(self):
        ctx = self._ctx()
        res = WaybackTool().run({"url": self.base, "cdx_base": f"{self.base}/cdx"}, ctx)
        self.assertTrue(res.ok)
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("rute historis", f.title)
        self.assertIn("/admin-old", f.description)
        self.assertNotIn("/live-page", f.response)

    def test_wayback_skips_private_host(self):
        res = WaybackTool().run({"url": "http://127.0.0.1:1"}, self._ctx())
        self.assertEqual(res.findings, [])
        self.assertEqual(res.data.get("skipped"), "private-host")

    def test_id_seq_enumerable_with_failing_control(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/item", ["id"], discovered_by="test")
        res = IdSeqTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("sekuensial", f.title)
        self.assertEqual(f.param, "id")
        self.assertIn("99999999", f.response)

    def test_ct_log_subdomains(self):
        res = CtLogTool().run({"url": self.base, "domain": "example.test",
                               "crt_base": f"{self.base}/crt"}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f.severity, "low", "dev/vpn harus dinaikkan ke low")
        self.assertIn("dev.example.test", f.response)
        self.assertIn("vpn.example.test", f.response)
        self.assertNotIn("www.example.test", f.response, "www/apex tidak dilaporkan")

    def test_smuggle_cl_te_divergence(self):
        res = SmuggleTool().run({"url": f"http://127.0.0.1:{self.smuggle.port}"},
                                self._ctx())
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("CL.TE", f.title)
        self.assertEqual(f.status, "confirmed")
        self.assertIn("timeout 2/2", f.response)

    def test_cache_deception(self):
        world = WorldModel()
        world.observe_response(f"{self.base}/account", 200, {}, ACCOUNT_HTML, "test")
        res = CacheDecTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("/account.css", f.title)
        self.assertEqual(f.cwe, "CWE-525")

    def test_oauth_state_redirect_nonce(self):
        res = OAuthTool().run({"url": self.base}, self._ctx())
        titles = " | ".join(f.title for f in res.findings)
        self.assertEqual(len(res.findings), 3, titles)
        self.assertIn("state", titles)
        self.assertIn("redirect_uri", titles)
        self.assertIn("nonce", titles)

    def test_puzzle_type_confusion(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/login", [], method="POST",
                               form_fields=["email", "password"], discovered_by="test")
        res = PuzzleTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("puzzling", res.findings[0].title)

    def test_json_injection_marker(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/search", ["q"], discovered_by="test")
        res = JsonInjTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("JSON injection", f.title)
        self.assertEqual(f.status, "confirmed")
        self.assertEqual(f.param, "q")

    def test_clean_fixture_zero_false_positives(self):
        """FP-guard proof: semua 8 engine HARUS 0 temuan pada fixture bersih."""
        world = WorldModel()
        world.observe_response(f"{self.cbase}/account", 200, {}, ACCOUNT_HTML, "test")
        world.observe_endpoint(f"{self.cbase}/item", ["id"], discovered_by="test")
        world.observe_endpoint(f"{self.cbase}/api/search", ["q"], discovered_by="test")
        world.observe_endpoint(f"{self.cbase}/login", [], method="POST",
                               form_fields=["email", "password"], discovered_by="test")
        ctx = self._ctx(world)
        results = {
            "wayback": WaybackTool().run({"url": self.cbase, "cdx_base": f"{self.cbase}/cdx"}, ctx),
            "id_seq": IdSeqTool().run({"url": self.cbase}, ctx),
            "ct_log": CtLogTool().run({"url": self.cbase, "domain": "example.test",
                                       "crt_base": f"{self.cbase}/crt"}, ctx),
            "smuggle": SmuggleTool().run({"url": self.cbase, "max_requests": 6}, ctx),
            "cache_dec": CacheDecTool().run({"url": self.cbase}, ctx),
            "oauth": OAuthTool().run({"url": self.cbase}, ctx),
            "puzzle": PuzzleTool().run({"url": self.cbase}, ctx),
            "json_inj": JsonInjTool().run({"url": self.cbase}, ctx),
        }
        for name, res in results.items():
            self.assertTrue(res.ok, f"{name} harus ok")
            self.assertEqual([f.title for f in res.findings], [],
                             f"{name} tidak boleh menemukan apa pun di fixture bersih")


if __name__ == "__main__":
    unittest.main()
