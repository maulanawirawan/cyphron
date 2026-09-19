"""Unit tests — High-class engine batch (2026-09-12):

- traversal : /etc/passwd marker (root: + :/bin/) = HIGH; FP 1-marker = bukan
- ssrf_oob  : tanpa OOB = lead (bukan finding); OOB capture>0 = HIGH;
              capture 0 = tidak ada
- crlf      : header marker terinjeksi di HEADERS = temuan; echo body = bukan
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.crlf_probe import CrlfProbeTool
from cyphron.tools.ssrf_oob import SsrfOobTool
from cyphron.tools.traversal_probe import TraversalTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class TestTraversal(unittest.TestCase):
    def _srv(self, vulnerable):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                p = (q.get("file") or q.get("path") or [""])[0]
                if vulnerable and "etc/passwd" in p:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(PASSWD)))
                    self.end_headers()
                    self.wfile.write(PASSWD.encode())
                else:
                    self.send_response(200)
                    body = "root documentation page"
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}"

    def test_traversal_confirmed(self):
        base = self._srv(vulnerable=True)
        tr = TraversalTool().run({"url": base, "path": "/download",
                                  "params": ["file", "path"]}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        f = tr.findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.cwe, "CWE-22")
        self.assertNotIn("root:x:", f.response, "isi file tidak boleh di-dump")

    def test_single_marker_is_not_enough(self):
        # body memuat "root:" saja (tanpa :/bin/) -> FP guard menolak
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                body = "the root: of all evil documentation"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = TraversalTool().run({"url": base, "params": ["file"]}, _ctx())
        self.assertEqual(tr.findings, [])


class TestSsrfOob(unittest.TestCase):
    def test_without_oob_is_lead_not_finding(self):
        srv, base = _server_ok()
        self.addCleanup(srv.shutdown)
        tr = SsrfOobTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertIn("UNCONFIRMED", tr.data.get("lead", ""))

    def test_oob_capture_confirmed(self):
        # oob_check server: hitung capture >0
        class OobCheck(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"count": 1, "data": [
                    {"ip": "10.0.0.5", "user_agent": "python-urllib"}]})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        oob_srv = HTTPServer(("127.0.0.1", 0), OobCheck)
        threading.Thread(target=oob_srv.serve_forever, daemon=True).start()
        self.addCleanup(oob_srv.shutdown)
        srv, base = _server_ok()
        self.addCleanup(srv.shutdown)
        tr = SsrfOobTool().run({
            "url": base,
            "params": ["url"],
            "oob_url": f"http://127.0.0.1:{oob_srv.server_port}/capture",
            "oob_check_url": f"http://127.0.0.1:{oob_srv.server_port}/check"},
            _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "high")
        self.assertEqual(tr.data["oob_capture_count"], 1)

    def test_oob_zero_capture_no_finding(self):
        class OobZero(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"count": 0, "data": []})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        oob_srv = HTTPServer(("127.0.0.1", 0), OobZero)
        threading.Thread(target=oob_srv.serve_forever, daemon=True).start()
        self.addCleanup(oob_srv.shutdown)
        srv, base = _server_ok()
        self.addCleanup(srv.shutdown)
        tr = SsrfOobTool().run({
            "url": base, "params": ["url"],
            "oob_url": f"http://127.0.0.1:{oob_srv.server_port}/capture",
            "oob_check_url": f"http://127.0.0.1:{oob_srv.server_port}/check"},
            _ctx())
        self.assertEqual(tr.findings, [])


class TestCrlf(unittest.TestCase):
    def test_header_injection_detected(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                payload = (q.get("id") or [""])[0]
                self.send_response(200)
                # simulasi server rentan: CRLF di payload memisahkan baris
                # -> tiap baris berformat 'Name: value' menjadi header sungguhan
                for line in payload.split("\r\n"):
                    if ":" in line and line.strip():
                        name, _, val = line.partition(":")
                        self.send_header(name.strip(), val.strip())
                body = "ok"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = CrlfProbeTool().run({"url": base, "params": ["id"]}, _ctx())
        # marker per-run acak -> engine harus menemukan header yang MENGANDUNG
        # nama markernya di headers (simulasi injeksi berhasil)
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].cwe, "CWE-93")

    def test_body_echo_is_not_finding(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                payload = (q.get("id") or [""])[0]
                self.send_response(200)
                body = f"you typed: {payload}"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = CrlfProbeTool().run({"url": base, "params": ["id"]}, _ctx())
        self.assertEqual(tr.findings, [], "echo di body bukan injeksi header")


def _server_ok():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            body = "ok"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


if __name__ == "__main__":
    unittest.main()
