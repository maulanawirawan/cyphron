"""Unit tests xmlrpc_probe (engine #67) — generik, protocol-level.

Server XML-RPC lokal dimock; mencakup:
- interface terbuka + multicall proof (2 hasil / 1 request) -> confirmed medium
- amplifikasi credential-testing (3 faultCode / 1 request, kredensial fiktif)
- pingback: tanpa OOB -> unconfirmed; dengan oob_check konfirmasi -> high confirmed
- interface tertutup (403) / respons non-XML -> nol temuan
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.xmlrpc_probe import XmlRpcProbeTool
from cyphron.world.model import WorldModel

LIST_METHODS = ("<?xml version='1.0'?><methodResponse><params><param><value><array>"
                "<data>" + "".join(
                    f"<value><string>{m}</string></value>"
                    for m in ("system.listMethods", "system.multicall", "demo.sayHello",
                              "pingback.ping", "wp.getUsersBlogs")) +
                "</data></array></value></param></params></methodResponse>")
MULTI_OK = ("<?xml version='1.0'?><methodResponse><params><param><value><array><data>"
            "<value><array><data><value><string>Hello!</string></value></data></array></value>"
            "<value><array><data><value><string>Hello!</string></value></data></array></value>"
            "</data></array></value></param></params></methodResponse>")
FAULTS3 = ("<?xml version='1.0'?><methodResponse><params><param><value><array><data>" +
           ("<value><struct><member><name>faultCode</name><value><int>801</int></value>"
            "</member></struct></value>" * 3) +
           "</data></array></value></param></params></methodResponse>")
PINGBACK_FAULT = ("<?xml version='1.0'?><methodResponse><fault><value><struct>"
                  "<member><name>faultCode</name><value><int>0</int></value></member>"
                  "</struct></value></fault></methodResponse>")


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=2.0,
                       max_requests=50)


class _RpcHandler(BaseHTTPRequestHandler):
    mode = "open"

    def log_message(self, *a):
        pass

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(ln).decode("utf-8", "replace")
        if self.mode == "closed":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.mode == "plain":
            body_out = b"<html>hello</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return
        if "system.listMethods" in body:
            out = LIST_METHODS.encode()
        elif "system.multicall" in body and "wp.getUsersBlogs" in body:
            out = FAULTS3.encode()
        elif "system.multicall" in body:
            out = MULTI_OK.encode()
        elif "pingback.ping" in body:
            out = PINGBACK_FAULT.encode()
        else:
            out = b"<?xml version='1.0'?><methodResponse></methodResponse>"
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class TestXmlRpcProbe(unittest.TestCase):
    def setUp(self):
        _RpcHandler.mode = "open"
        self._srv = HTTPServer(("127.0.0.1", 0), _RpcHandler)
        self._thr = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thr.start()
        self.base = f"http://127.0.0.1:{self._srv.server_port}"

    def tearDown(self):
        self._srv.shutdown()

    def test_open_interface_finds_multicall_and_unconfirmed_pingback(self):
        res = XmlRpcProbeTool().run({"url": self.base}, _ctx())
        titles = [f.title for f in res.findings]
        self.assertTrue(any("multicall" in t and "amplification" in t for t in titles))
        mc = [f for f in res.findings if "multicall" in f.title][0]
        self.assertEqual(mc.status, "confirmed")
        self.assertEqual(mc.severity, "medium")
        self.assertIn("3 pengecekan kredensial", mc.description)
        pb = [f for f in res.findings if "SSRF" in f.title]
        self.assertEqual(len(pb), 1)
        self.assertEqual(pb[0].status, "unconfirmed")
        self.assertEqual(pb[0].severity, "medium")

    def test_oob_confirmation_upgrades_to_high_confirmed(self):
        with mock.patch("cyphron.tools.xmlrpc_probe.urllib.request.urlopen") as ur:
            ur.return_value.__enter__.return_value.read.return_value = \
                b'{"total": 1, "data": [{"ip": "127.0.0.1"}]}'
            res = XmlRpcProbeTool().run(
                {"url": self.base,
                 "oob_url": "https://webhook.site/test-uuid",
                 "oob_check_url": "https://webhook.site/token/test-uuid/requests"},
                _ctx())
        pb = [f for f in res.findings if "SSRF" in f.title]
        self.assertEqual(len(pb), 1)
        self.assertEqual(pb[0].status, "confirmed")
        self.assertEqual(pb[0].severity, "high")

    def test_closed_interface_no_findings(self):
        _RpcHandler.mode = "closed"
        res = XmlRpcProbeTool().run({"url": self.base}, _ctx())
        self.assertEqual(res.findings, [])

    def test_plain_html_is_not_xmlrpc(self):
        _RpcHandler.mode = "plain"
        res = XmlRpcProbeTool().run({"url": self.base}, _ctx())
        self.assertEqual(res.findings, [])
        self.assertIn("closed/not-xmlrpc", str(res.data.get("xmlrpc", "")) or "")


if __name__ == "__main__":
    unittest.main()
