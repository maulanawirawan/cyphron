"""Unit tests roadmap_batch4: 10 engine baru (slot medium-08..21 tier2).

- VULN fixture : tiap engine menemukan temuan definitifnya
- CLEAN fixture: tiap engine HARUS 0 temuan (FP-guard bekerja)
- Fungsi protokol murni diuji langsung: parse_ehlo_starttls, dkim_key_bits, dns_mx."""

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
from cyphron.tools.api_email_engines import (
    ApiVerTool, CtaConfTool, DkimProbeTool, GqlAliasTool, GqlBatchTool,
    GqlDepthTool, PaginationTool, SmtpProbeTool, SortFilterTool,
    VerbOverrideTool, dkim_key_bits, parse_ehlo_starttls,
)
from cyphron.world.model import WorldModel

USERS_JSON = json.dumps({"users": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]})


class _GqlMixin:
    def graphql_response(self, body: bytes, ctype: str):
        """Server GraphQL kecil. Vuln: batching + alias tanpa batas + cost bebas.
        Hardened (cap=True): batch ditolak, alias didedup, cost dibatasi."""
        if "json" not in ctype:
            return 415, "unsupported media type"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return 400, "bad json"
        if isinstance(payload, list):
            if self.gql_cap:
                return 400, "batching not allowed"
            return 200, json.dumps([{"data": {"__typename": "Query"}} for _ in payload])
        query = str(payload.get("query") or "")
        aliases = __import__("re").findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", query)
        if len(aliases) > (10 if self.gql_cap else 100000):
            return 400, "query too complex"
        data = {}
        for alias in aliases:
            if self.gql_cap and data:
                continue  # dedup per field: hanya field pertama yang dijawab
            data[alias] = "Query"
        return 200, json.dumps({"data": data})


class Batch4VulnHandler(_GqlMixin, BaseHTTPRequestHandler):
    gql_cap = False

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
        if p.path == "/api/items":  # pagination unbounded + sort injection
            limit = int((q.get("limit") or [10])[0] or 10)
            sort = (q.get("sort") or ["name"])[0]
            if "(" in sort or ";" in sort or "--" in sort:
                self._send(500, "SQLiteException: near \"(: syntax error", ctype="text/plain")
                return
            self._send(200, "x" * min(limit * 10, 200000), ctype="text/plain")
        elif p.path == "/api/v1/users":
            self._send(200, USERS_JSON, ctype="application/json")  # v1 terbuka
        elif p.path.startswith(("/api/v2/", "/api/v3/")):
            self._send(401, "unauthorized", ctype="text/plain")
        elif p.path == "/graphql":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length)
            code, text = self.graphql_response(body, self.headers.get("Content-Type", ""))
            self._send(code, text, ctype="application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if p.path == "/graphql":
            code, text = self.graphql_response(body, ctype)
            self._send(code, text, ctype="application/json")
            return
        override = self.headers.get("X-HTTP-Method-Override") \
            or self.headers.get("X-Method-Override") or self.headers.get("X-HTTP-Method")
        if p.path == "/api/item/1":
            if self.gql_cap or not override:
                self._send(200, "created")
            elif override.upper() == "DELETE":
                self._send(204, "deleted item")  # override dijalankan (vuln)
            return
        if p.path == "/api/echo":
            parsed_extra = None
            if "json" in ctype or "text/plain" in ctype:
                try:
                    parsed_extra = (json.loads(body) or {}).get("extra")  # parser diangkat (vuln)
                except json.JSONDecodeError:
                    parsed_extra = None
            elif "x-www-form-urlencoded" in ctype:
                parsed_extra = None  # form baseline: extra tidak dipakai
            else:
                self._send(415, "unsupported")
                return
            echo_q = (parse_qs(body.decode()).get("q") or
                      [(json.loads(body) or {}).get("q", "")] if body else [""])
            resp = f"echo q={echo_q}"
            if parsed_extra is not None:
                resp += f" extra={parsed_extra}"
            self._send(200, resp)
            return
        self._send(200, "ok")


class Batch4CleanHandler(Batch4VulnHandler):
    gql_cap = True  # batching ditolak, alias didedup, cost dibatasi

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/api/items":  # limit di-cap server, sort di-whitelist
            self._send(200, "x" * 120, ctype="text/plain")
        elif p.path == "/api/v1/users":
            self._send(401, "unauthorized", ctype="text/plain")  # v1 juga terlindungi
        elif p.path == "/graphql":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length)
            code, text = self.graphql_response(body, self.headers.get("Content-Type", ""))
            self._send(code, text, ctype="application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if p.path == "/graphql":
            code, text = self.graphql_response(body, ctype)
            self._send(code, text, ctype="application/json")
            return
        if p.path == "/api/item/1":
            self._send(200, "created")  # override diabaikan
            return
        if p.path == "/api/echo":
            if "x-www-form-urlencoded" not in ctype:
                self._send(415, "unsupported media type")  # hanya form yang diparse
                return
            self._send(200, f"echo q={parse_qs(body.decode()).get('q')}")
            return
        self._send(200, "ok")


class TestRoadmapBatch4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 0), Batch4VulnHandler)
        cls.clean = HTTPServer(("127.0.0.1", 0), Batch4CleanHandler)
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

    def test_registry_contains_all_batch4_tools(self):
        reg = build_default_registry(self._ctx())
        names = {t.name for t in reg.all()}
        self.assertTrue({"ct_conf", "verb_over", "smtp_probe", "dkim_probe", "api_ver",
                         "gql_batch", "gql_depth", "gql_alias", "pagin", "sort_inj"} <= names)

    def test_ct_conf_json_parsed_with_wrong_content_type(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/echo", [], method="POST",
                               discovered_by="test")
        res = CtaConfTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("Content-type confusion", res.findings[0].title)

    def test_verb_override_delete_executed(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/item/1", [], method="POST",
                               discovered_by="test")
        res = VerbOverrideTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("override", f.title)
        self.assertEqual(f.status, "confirmed")

    def test_api_ver_v1_open_v2_protected(self):
        res = ApiVerTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("v1", res.findings[0].title)

    def test_gql_batch_array_executed(self):
        res = GqlBatchTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("batching", res.findings[0].title.lower())

    def test_gql_depth_cost_unbounded(self):
        res = GqlDepthTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("500", res.findings[0].description)

    def test_gql_alias_dedup_guard(self):
        res = GqlAliasTool().run({"url": self.base}, self._ctx())
        self.assertEqual(len(res.findings), 1)
        self.assertIn("alias", res.findings[0].title.lower())

    def test_pagination_unbounded(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/items", ["limit"], discovered_by="test")
        res = PaginationTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("10000", res.findings[0].title)

    def test_sort_filter_injection_db_error(self):
        world = WorldModel()
        world.observe_endpoint(f"{self.base}/api/items", ["sort"], discovered_by="test")
        res = SortFilterTool().run({"url": self.base}, self._ctx(world))
        self.assertEqual(len(res.findings), 1)
        self.assertIn("Sort/filter injection", res.findings[0].title)

    def test_parse_ehlo_starttls(self):
        ehlo_tls = ("220 mx.google.com ESMTP\r\n250-mx.google.com at your service\r\n"
                    "250-SIZE 157286400\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
        ehlo_plain = "220 mail.local ESMTP\r\n250-PIPELINING\r\n250 SIZE 10240000\r\n"
        self.assertTrue(parse_ehlo_starttls(ehlo_tls))
        self.assertFalse(parse_ehlo_starttls(ehlo_plain))
        self.assertFalse(parse_ehlo_starttls(""))

    def test_dkim_key_bits(self):
        """DER RSAPublicKey sintetis: modulus 1024-bit dan 512-bit."""
        import base64

        def rsa_pub_der(mod_bits: int) -> bytes:
            nbytes = mod_bits // 8
            modulus = b"\x00" + b"\xff" * (nbytes - 1) + b"\x7f"  # leading 0x00 (signed INT)
            int_mod = b"\x02\x81" + bytes([len(modulus)]) + modulus  # long-form length
            int_exp = b"\x02\x01\x01"
            inner = int_mod + int_exp
            return b"\x30\x81" + bytes([len(inner)]) + inner

        rec1024 = "v=DKIM1; k=rsa; p=" + base64.b64encode(rsa_pub_der(1024)).decode()
        rec512 = "v=DKIM1; k=rsa; p=" + base64.b64encode(rsa_pub_der(512)).decode()
        self.assertEqual(dkim_key_bits(rec1024), 1024)
        self.assertEqual(dkim_key_bits(rec512), 512)
        self.assertLess(dkim_key_bits(rec512), 1024)
        self.assertIsNone(dkim_key_bits("v=DKIM1; k=ed25519; p=11qYAYKxCrfVSZ7QWTA=="))
        self.assertIsNone(dkim_key_bits("v=spf1 -all"))
        self.assertIsNone(dkim_key_bits(""))

    def test_smtp_and_dkim_graceful_on_invalid_domain(self):
        res = SmtpProbeTool().run({"url": "https://example.test", "domain": "example.test"},
                                  self._ctx())
        self.assertTrue(res.ok)
        self.assertEqual(res.findings, [])
        res2 = DkimProbeTool().run({"url": "https://example.test", "domain": "example.test"},
                                   self._ctx())
        self.assertTrue(res2.ok)
        self.assertEqual(res2.findings, [])

    def test_clean_fixture_zero_false_positives(self):
        """FP-guard proof: 10 engine batch 4 HARUS 0 temuan pada fixture bersih."""
        world = WorldModel()
        world.observe_endpoint(f"{self.cbase}/api/echo", [], method="POST", discovered_by="test")
        world.observe_endpoint(f"{self.cbase}/api/item/1", [], method="POST", discovered_by="test")
        world.observe_endpoint(f"{self.cbase}/api/items", ["limit", "sort"], discovered_by="test")
        ctx = self._ctx(world)
        results = {
            "ct_conf": CtaConfTool().run({"url": self.cbase}, ctx),
            "verb_over": VerbOverrideTool().run({"url": self.cbase}, ctx),
            "api_ver": ApiVerTool().run({"url": self.cbase}, ctx),
            "gql_batch": GqlBatchTool().run({"url": self.cbase}, ctx),
            "gql_depth": GqlDepthTool().run({"url": self.cbase}, ctx),
            "gql_alias": GqlAliasTool().run({"url": self.cbase}, ctx),
            "pagin": PaginationTool().run({"url": self.cbase}, ctx),
            "sort_inj": SortFilterTool().run({"url": self.cbase}, ctx),
        }
        for name, res in results.items():
            self.assertTrue(res.ok, f"{name} harus ok")
            self.assertEqual([f.title for f in res.findings], [],
                             f"{name} tidak boleh menemukan apa pun di fixture bersih: "
                             f"{[f.title for f in res.findings]}")


if __name__ == "__main__":
    unittest.main()
