"""Unit tests — engine queue round 3 (2026-09-12):

- security_txt : catch-all HTML != valid security.txt; valid file = positif
- cors         : exact-Origin reflection + credentials = temuan; wildcard = bukan
- register     : form registrasi (password+identitas) = temuan; halaman login = FP-guard
- reset_enum   : diff konsisten 3 putaran = temuan; identik = tidak ada
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
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.tools.cors_probe import CorsProbeTool
from cyphron.tools.register_probe import RegisterProbeTool
from cyphron.tools.reset_enum import ResetEnumTool
from cyphron.tools.security_txt import SecurityTxtTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


class _Router(BaseHTTPRequestHandler):
    routes: dict = {}
    hits: list = []
    bodies: list = []

    def _serve(self, method):
        self.hits.append((method, self.path))
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

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        self.bodies.append(self.rfile.read(ln).decode("utf-8", "replace"))
        self._serve("POST")

    def log_message(self, *a):
        pass


def _server(routes):
    handler = type("H", (_Router,), {"routes": routes, "hits": [], "bodies": []})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


LOGIN_PAGE = """<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="_token" value="t">
  <input type="email" name="email">
  <input type="password" name="password">
</form></body></html>"""

RESET_PAGE = """<html><body>
<form method="POST" action="/password/email">
  <input type="hidden" name="_token" value="tok9">
  <input type="email" name="email">
  <input type="email" name="email_confirm" style="display:none">
</form></body></html>"""

REGISTER_PAGE = """<html><body>
<form method="POST" action="/user/sign_up">
  <input type="text" name="user_name">
  <input type="email" name="email">
  <input type="password" name="password">
  <input type="password" name="retype">
</form></body></html>"""


class TestSecurityTxt(unittest.TestCase):
    def test_catchall_html_is_missing(self):
        srv, base = _server({
            ("GET", "/.well-known/security.txt"): (200, "<html>404</html>",
                                                   {"Content-Type": "text/html"}),
            ("GET", "/security.txt"): (200, "<html>404</html>",
                                       {"Content-Type": "text/html"}),
        })
        self.addCleanup(srv.shutdown)
        tr = SecurityTxtTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "info")
        self.assertEqual(tr.findings[0].finding_class, "posture")

    def test_valid_securitytxt_is_positive(self):
        srv, base = _server({
            ("GET", "/.well-known/security.txt"): (
                200, "Contact: mailto:sec@x.test\nExpires: 2027-01-01\n",
                {"Content-Type": "text/plain"}),
        })
        self.addCleanup(srv.shutdown)
        tr = SecurityTxtTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])


class TestCors(unittest.TestCase):
    def test_reflection_with_credentials_is_finding(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {
                "Access-Control-Allow-Origin": "https://cyphron-probe.invalid",
                "Access-Control-Allow-Credentials": "true"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].cwe, "CWE-942")

    def test_wildcard_is_not_reported(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])
        self.assertIn("wildcard", tr.data.get("note", ""))

    def test_legit_allowlist_not_reported(self):
        srv, base = _server({
            ("GET", "/"): (200, "ok", {"Access-Control-Allow-Origin": "https://app.x.test"}),
        })
        self.addCleanup(srv.shutdown)
        tr = CorsProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [])


class TestRegister(unittest.TestCase):
    def test_open_register_form_is_finding(self):
        srv, base = _server({
            ("GET", "/register"): (200, REGISTER_PAGE, {}),
            ("GET", "/signup"): (404, "", {}),
            ("GET", "/register.html"): (404, "", {}),
            ("GET", "/wp-login.php?action=register"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = RegisterProbeTool().run({"url": base}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].finding_class, "posture")
        self.assertIn("/register", tr.findings[0].request)

    def test_login_page_is_not_register(self):
        srv, base = _server({
            ("GET", "/register"): (200, LOGIN_PAGE, {}),
            ("GET", "/signup"): (404, "", {}),
            ("GET", "/register.html"): (404, "", {}),
            ("GET", "/wp-login.php?action=register"): (404, "", {}),
        })
        self.addCleanup(srv.shutdown)
        tr = RegisterProbeTool().run({"url": base}, _ctx())
        self.assertEqual(tr.findings, [], "halaman login tidak boleh dihitung registrasi")


class TestResetEnum(unittest.TestCase):
    def test_consistent_diff_is_finding(self):
        # handler dinamis: bedakan known vs fictional dari body
        class Dyn(_Router):
            routes = {}
            hits = []
            bodies = []
            def do_GET(self):
                if self.path == "/password/reset":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(RESET_PAGE)))
                    self.end_headers()
                    self.wfile.write(RESET_PAGE.encode())
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(ln).decode("utf-8", "replace")
                Dyn.bodies.append(body)
                if "known@x.test" in body:
                    self.send_response(500)
                    body_s = "Server Error (reset failed for existing)"
                else:
                    self.send_response(302)
                    body_s = "redirect"
                self.send_header("Content-Length", str(len(body_s)))
                self.end_headers()
                self.wfile.write(body_s.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Dyn)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset",
                                  "known_email": "known@x.test"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].cwe, "CWE-204")
        self.assertEqual(len(tr.data["signatures_known"]), 3)
        self.assertEqual(len(set(tr.data["signatures_known"])), 1)

    def test_identical_response_no_finding(self):
        class Dyn2(_Router):
            routes = {}
            hits = []
            bodies = []
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(RESET_PAGE)))
                self.end_headers()
                self.wfile.write(RESET_PAGE.encode())
            def do_POST(self):
                ln = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(ln)
                self.send_response(200)
                body_s = "If that account exists, a link was sent"
                self.send_header("Content-Length", str(len(body_s)))
                self.end_headers()
                self.wfile.write(body_s.encode())
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Dyn2)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset",
                                  "known_email": "known@x.test"}, _ctx())
        self.assertEqual(tr.findings, [], "respons identik = postur baik")
        self.assertIn("identik", tr.data.get("note", ""))

    def test_without_known_email_skipped(self):
        srv, base = _server({("GET", "/password/reset"): (200, RESET_PAGE, {})})
        self.addCleanup(srv.shutdown)
        tr = ResetEnumTool().run({"url": base, "reset_path": "/password/reset"}, _ctx())
        self.assertEqual(tr.data.get("skipped"), "known_email-required")


class TestSubdomainBrute(unittest.TestCase):
    """FP-guard inti: liveness WAJIB konsisten 2x; DNS flaky = tidak dilapor."""

    def _run(self):
        from cyphron.tools.subdomain_brute import SubdomainBruteTool
        return SubdomainBruteTool().run(
            {"domains": ["contoh.id"], "prefixes": ["api"], "max_prefixes": 1},
            _ctx())

    def test_live_host_verified_twice(self):
        from cyphron.tools import subdomain_brute as sb
        calls: list[str] = []
        orig = sb._doh_a
        sb._doh_a = lambda name, timeout=6.0: calls.append(name) or "1.2.3.4"
        try:
            tr = self._run()
        finally:
            sb._doh_a = orig
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["live_count"], 1)
        self.assertEqual(tr.data["live"][0]["host"], "api.contoh.id")
        self.assertEqual(tr.data["live"][0]["ip"], "1.2.3.4")
        # FP-guard: 2x resolve per kandidat
        self.assertEqual(calls, ["api.contoh.id", "api.contoh.id"])

    def test_flaky_dns_never_reported(self):
        from cyphron.tools import subdomain_brute as sb
        seq = ["1.2.3.4", None]  # hidup lalu hilang = flaky, bukan temuan
        orig = sb._doh_a
        sb._doh_a = lambda name, timeout=6.0: seq.pop(0) if seq else None
        try:
            tr = self._run()
        finally:
            sb._doh_a = orig
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["live_count"], 0)

    def test_requires_domains(self):
        from cyphron.tools.subdomain_brute import SubdomainBruteTool
        tr = SubdomainBruteTool().run({"prefixes": ["api"]}, _ctx())
        self.assertFalse(tr.ok)
        self.assertIn("domains", tr.error or "")


class TestPassiveDns(unittest.TestCase):
    def test_staging_flag_and_scope_split(self):
        from cyphron.tools import passive_dns as pd
        orig_otx, orig_res = pd.otx_hostnames, pd.resolve_verified
        pd.otx_hostnames = lambda dom, timeout=30.0: {
            "api.contoh.id", "staging.contoh.id", "stg.contoh.id"}
        pd.resolve_verified = lambda name, rounds=2, timeout=6.0: "5.6.7.8"
        try:
            tr = pd.PassiveDnsTool().run({"domains": ["contoh.id"]}, _ctx())
        finally:
            pd.otx_hostnames, pd.resolve_verified = orig_otx, orig_res
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["names_total"], 3)
        self.assertEqual(tr.data["live_total"], 3)
        hosts = [h["host"] for h in tr.data["live_in_scope"]]
        self.assertEqual(hosts, ["api.contoh.id"])
        self.assertEqual(sorted(tr.data["staging_flagged"]),
                         ["staging.contoh.id", "stg.contoh.id"])

    def test_requires_domains(self):
        from cyphron.tools.passive_dns import PassiveDnsTool
        tr = PassiveDnsTool().run({}, _ctx())
        self.assertFalse(tr.ok)
        self.assertIn("domains", tr.error or "")


PAGE = '<html><script src="/static/app.js"></script></html>'
APPJS = ('fetch("/api/v1/users");'
         'fetch("/api/v1/orders/123/update");'
         'const h={};h["x-appversion"]="1";')

SERVER_ROUTES = {
    ("GET", "/"): (200, PAGE, {"Content-Type": "text/html"}),
    ("GET", "/static/app.js"): (200, APPJS, {"Content-Type": "application/javascript"}),
    ("GET", "/api/v1/users"): (200, '{"data":[{"email":"a@b.c","name":"Ani"}]}',
                               {"Content-Type": "application/json"}),
    ("GET", "/api/v1/orders/123/update"): (200, '{"ok":true}',
                                           {"Content-Type": "application/json"}),
}


class TestApiSurfaceProbe(unittest.TestCase):
    def _run(self, routes, max_probe=8):
        from cyphron.tools.api_surface_probe import ApiSurfaceProbeTool
        srv, base = _server(routes)
        self.addCleanup(srv.shutdown)
        return ApiSurfaceProbeTool().run({"url": base, "max_probe": max_probe}, _ctx())

    def test_unauth_personal_data_is_finding(self):
        tr = self._run(SERVER_ROUTES)
        self.assertTrue(tr.ok)
        titles = [f.title for f in tr.findings]
        self.assertTrue(any("/api/v1/users" in t for t in titles))
        self.assertIn("x-appversion", tr.data["custom_headers"])
        # FP-guard: path mutasi TIDAK diprobe
        self.assertNotIn("/api/v1/orders/123/update",
                         [p["path"] for p in tr.data["probed"]])

    def test_version_page_is_not_finding(self):
        routes = dict(SERVER_ROUTES)
        routes[("GET", "/api/v1/users")] = (
            200, '{"version":"1.2.3"}', {"Content-Type": "application/json"})
        tr = self._run(routes)
        self.assertEqual(tr.findings, [])
        self.assertEqual(tr.data["probed"][0]["classified"],
                         "json-tanpa-data-personal (bukan temuan)")

    def test_sensitive_dump_stops_probing(self):
        routes = dict(SERVER_ROUTES)
        routes[("GET", "/static/app.js")] = (
            200, 'fetch("/api/v1/debug");fetch("/api/v1/users");',
            {"Content-Type": "application/javascript"})
        routes[("GET", "/api/v1/debug")] = (
            200, '{"root_password":"supersecret99"}',
            {"Content-Type": "application/json"})
        tr = self._run(routes)
        self.assertTrue(tr.data["stopped_early"])
        self.assertEqual(len(tr.data["probed"]), 1)
        self.assertTrue(any("sensitive credentials" in f.title
                            for f in tr.findings))


class TestApkSurfaceProbe(unittest.TestCase):
    """Guard APK: PEM template kosong tidak kena; 'protection' tidak jadi
    kredensial; Google key = NON-CLAIM; private key asli = finding."""

    def _make_apk(self, path: Path):
        import zipfile
        pem_body = ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w"
                    "cXJzdHV2d3h5ejEK" * 2)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("classes.dex",
                       'L"{\\"root_token\\":\\"abcdef\\"}";api.contoh.com;'
                       "https://api.contoh.com/v1/x\n"
                       "-----BEGIN PRIVATE KEY-----\\n" + pem_body +
                       "\\n-----END PRIVATE KEY-----\n")
            z.writestr("assets/cfg.json",
                       '{"key":"AIzaSyA1234567890abcdefghijklmnopqrstu",'
                       '"ip":"192.168.18.185"}')
            z.writestr("assets/x.js", 'h="Basic cHJvdGVjdGlvbg=="')  # "protection"
            z.writestr("assets/cred.js", 'h="Basic dXNlcjpwYXNzMTIzNDU="')  # user:pass
            z.writestr("res/logo.png", b"\x89PNG\r\n\x1a\nAKIAIOSFODNN7EXAMPLE")

    def test_guards_and_finding(self):
        import tempfile
        from cyphron.tools.apk_surface_probe import ApkSurfaceProbeTool
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "fake.apk"
            self._make_apk(apk)
            tr = ApkSurfaceProbeTool().run({"path": str(apk)}, _ctx())
        self.assertTrue(tr.ok)
        self.assertIn(("api.contoh.com", ), [
            (h, ) for h, _n in tr.data["top_hosts"]])
        labels = {(c["file"], c["label"], c["verdict"][:8])
                  for c in tr.data["candidates"]}
        # Google key = NON-CLAIM
        self.assertTrue(any(c["label"] == "Google API key"
                            and "NON-CLAIM" in c["verdict"]
                            for c in tr.data["candidates"]))
        # "protection" TIDAK jadi kandidat kredensial (guard printable+colon)
        self.assertFalse(any(c["label"] == "basic-auth literal"
                             and c["file"] == "x.js"
                             for c in tr.data["candidates"]))
        # user:pass12345 lolos guard
        self.assertTrue(any(c["label"] == "basic-auth literal"
                            and c["file"] == "cred.js"
                            for c in tr.data["candidates"]))
        # PEM template tidak kena; private key asli = 1 finding
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("private key", tr.findings[0].title)
        # dev-leftover IP tercatat sebagai info
        self.assertTrue(any(c["label"] == "private IP hardcoded"
                            for c in tr.data["candidates"]))

    def test_missing_file_error(self):
        from cyphron.tools.apk_surface_probe import ApkSurfaceProbeTool
        tr = ApkSurfaceProbeTool().run({"path": "Z:/tidak/ada.apk"}, _ctx())
        self.assertFalse(tr.ok)


class TestErrorOracle(unittest.TestCase):
    """Protokol Gojek 13 Sep: baseline id sendiri + malformed + id asing."""

    def _routes_authz(self):
        return {
            ("GET", "/api/orders/F-1"): (200, '{"number":"F-1"}',
                                         {"Content-Type": "application/json"}),
            ("GET", "/api/orders/F-00000ZZZ999"): (
                200, "5 NOT_FOUND: Can't find the transaction",
                {"Content-Type": "text/plain"}),
            ("GET", "/api/orders/F-2"): (200, "7 PERMISSION_DENIED: customer unauthorized",
                                         {"Content-Type": "text/plain"}),
        }

    def test_authz_fail_closed_no_finding(self):
        from cyphron.tools.error_oracle import ErrorOracleTool
        srv, base = _server(self._routes_authz())
        self.addCleanup(srv.shutdown)
        tr = ErrorOracleTool().run({
            "url": base + "/api/orders", "id_template": "/{id}",
            "own_id": "F-1", "foreign_id": "F-2",
            "allow_foreign_probe": True}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["verdict"], "authz-fail-closed")
        self.assertEqual(len(tr.findings), 0)

    def test_foreign_data_is_idor_finding(self):
        from cyphron.tools.error_oracle import ErrorOracleTool
        routes = self._routes_authz()
        routes[("GET", "/api/orders/F-2")] = (
            200, '{"email":"orang-lain@contoh.id"}',
            {"Content-Type": "application/json"})
        srv, base = _server(routes)
        self.addCleanup(srv.shutdown)
        tr = ErrorOracleTool().run({
            "url": base + "/api/orders", "id_template": "/{id}",
            "own_id": "F-1", "foreign_id": "F-2",
            "allow_foreign_probe": True}, _ctx())
        self.assertTrue(tr.data["cease_on_data"])
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("IDOR", tr.findings[0].title)
        # cease-on-data: nilai PII TIDAK disimpan
        self.assertIn("nilai redacted", tr.findings[0].response)

    def test_foreign_requires_explicit_flag(self):
        from cyphron.tools.error_oracle import ErrorOracleTool
        srv, base = _server(self._routes_authz())
        self.addCleanup(srv.shutdown)
        tr = ErrorOracleTool().run({
            "url": base + "/api/orders/", "own_id": "F-1",
            "foreign_id": "F-2"}, _ctx())
        self.assertFalse(tr.ok)
        self.assertIn("allow_foreign_probe", tr.error or "")

    def test_stack_trace_leak_reported(self):
        from cyphron.tools.error_oracle import ErrorOracleTool
        routes = self._routes_authz()
        routes[("GET", "/api/orders/F-00000ZZZ999")] = (
            200, 'Traceback (most recent call last): File "app.py", line 42',
            {"Content-Type": "text/plain"})
        srv, base = _server(routes)
        self.addCleanup(srv.shutdown)
        tr = ErrorOracleTool().run({
            "url": base + "/api/orders", "id_template": "/{id}",
            "own_id": "F-1"}, _ctx())
        self.assertTrue(any("Stack trace" in f.title for f in tr.findings))


class TestGithubOsint(unittest.TestCase):
    def test_skip_without_token(self):
        import os
        from cyphron.tools.github_osint import GithubOsintTool
        env_bak = {k: os.environ.pop(k) for k in ("GITHUB_TOKEN", "GH_TOKEN")
                   if k in os.environ}
        try:
            tr = GithubOsintTool().run({"domain": "contoh.ac.id"}, _ctx())
        finally:
            os.environ.update(env_bak)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["skipped"], "token-tidak-ada")

    def test_verified_lead_becomes_finding(self):
        import os
        from cyphron.tools import github_osint as gh
        from cyphron.tools.github_osint import GithubOsintTool
        os.environ["GITHUB_TOKEN"] = "dummy"
        orig_json, orig_raw = gh._gh_json, gh._fetch_raw
        calls = {"n": 0}

        def fake_json(url, token, timeout=15.0):
            calls["n"] += 1
            if calls["n"] == 1:  # hanya query pertama yang ketemu
                return {"items": [{"repository": {"full_name": "user/repo",
                                                  "pushed_at": "2026-09-01"},
                                   "path": "cfg.py",
                                   "url": "https://api.github.com/raw/1"}]}, {}
            return {"items": []}, {}

        gh._gh_json = fake_json
        gh._fetch_raw = lambda raw_url, token, timeout=15.0: "password = 'hunter2hunter2'"
        try:
            tr = GithubOsintTool().run({"domain": "contoh.ac.id"}, _ctx())
        finally:
            gh._gh_json, gh._fetch_raw = orig_json, orig_raw
            os.environ.pop("GITHUB_TOKEN", None)
        self.assertTrue(tr.ok)
        self.assertEqual(tr.data["verified_leads"], 1)
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("user/repo", tr.findings[0].title)


class TestExploitPack(unittest.TestCase):
    """Engine eksploitasi = mesin bukti dampak: differential + cease-on-data."""

    def test_sqli_extract_confirmed(self):
        from cyphron.tools.sqli_extract import SqliExtractTool
        # server: baseline "item 1"; payload UNION -> respons versi DB
        srv, base = _server({("GET", "/item"): (200, "item 1", {})})
        self.addCleanup(srv.shutdown)

        class PatchedTool(SqliExtractTool):
            def run(self, args, ctx):
                orig = http_engine.http_get

                def fake_get(url, **kw):
                    if "UNION" in url and "%40%40version" in url:
                        # bukti versi MARIADB sesuai evidence payload mysql
                        return 200, {}, "10.4.32-MariaDB-ub2404-log (mysql)", 1
                    return orig(url, **kw)

                http_engine.http_get = fake_get
                try:
                    return super().run(args, ctx)
                finally:
                    http_engine.http_get = orig
        tr = PatchedTool().run({
            "url": base + "/item?{payload}", "param": "id",
            "baseline_value": "1"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "critical")
        self.assertIn("cease-on-data", tr.findings[0].description)

    def test_ssti_no_evidence_on_static_server(self):
        from cyphron.tools.ssti_rce import SstiRceTool
        srv, base = _server({("GET", "/page"): (200, "tpl", {})})
        self.addCleanup(srv.shutdown)
        tr = SstiRceTool().run({"url": base + "/page?{payload}"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(tr.findings, [])

    def test_lfi_cease_on_data(self):
        from cyphron.tools.lfi_read import LfiReadTool
        srv, base = _server({("GET", "/read"): (200, "cyphron.txt tidak ada", {})})
        self.addCleanup(srv.shutdown)

        class PatchedLfi(LfiReadTool):
            def run(self, args, ctx):
                orig = http_engine.http_get

                def fake_get(url, **kw):
                    # server rentan: isi /etc/passwd hanya bila traversal passwd
                    if "passwd" in url:
                        return 200, {}, "root:x:0:0:root:/root:/bin/bash", 1
                    return orig(url, **kw)

                http_engine.http_get = fake_get
                try:
                    return super().run(args, ctx)
                finally:
                    http_engine.http_get = orig
        tr = PatchedLfi().run({"url": base + "/read?f={payload}"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("root:x:0:0", tr.findings[0].response)

    def test_auth_bypass_none_on_always_403(self):
        from cyphron.tools.auth_bypass_matrix import AuthBypassMatrixTool
        srv, base = _server({("GET", "/admin"): (403, "denied" + "x" * 100, {})})
        self.addCleanup(srv.shutdown)
        tr = AuthBypassMatrixTool().run({"url": base + "/admin"}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(tr.findings, [])

    def test_auth_bypass_skips_open_path(self):
        from cyphron.tools.auth_bypass_matrix import AuthBypassMatrixTool
        srv, base = _server({("GET", "/admin"): (200, "ADMIN CONTENT", {})})
        self.addCleanup(srv.shutdown)
        tr = AuthBypassMatrixTool().run({"url": base + "/admin"}, _ctx())
        self.assertIn("sudah terbuka", tr.data.get("skipped", ""))


class TestExploitBatch2(unittest.TestCase):
    """proto_pollution, xxe, nosql, host header poison — kondisional server."""

    def _patch(self, responder):
        from cyphron.tools import http_engine
        orig = http_engine.http_get

        def fake_get(url, **kw):
            body = b""
            if isinstance(kw.get("data"), (bytes, bytearray)):
                body = kw["data"]
            method = kw.get("method", "GET")
            return responder(url, method, body, kw)

        http_engine.http_get = fake_get
        self.addCleanup(setattr, http_engine, "http_get", orig)

    def test_proto_pollution_double_differential(self):
        from cyphron.tools.proto_pollution import ProtoPollutionTool

        def resp(url, method, body, kw):
            b = body.decode() if body else ""
            if "__proto__" in b and "isAdmin" in b:
                return 200, {}, '{"ok":1,"admin":true}', 1
            return 200, {}, '{"ok":1}', 1

        self._patch(resp)
        tr = ProtoPollutionTool().run({
            "url": "http://t.test/profile", "body": {"user": "aku"}}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "critical")

    def test_proto_pollution_decoy_blocks_fp(self):
        from cyphron.tools.proto_pollution import ProtoPollutionTool

        def resp(url, method, body, kw):
            b = body.decode() if body else ""
            # echo semua isi body (decoy juga berubah) -> bukan pollusi
            return 200, {}, b or "{}", 1

        self._patch(resp)
        tr = ProtoPollutionTool().run({
            "url": "http://t.test/profile", "body": {"user": "aku"}}, _ctx())
        self.assertEqual(tr.findings, [])

    def test_xxe_error_based(self):
        from cyphron.tools.xxe_probe import XxeProbeTool

        def resp(url, method, body, kw):
            b = body.decode() if body else ""
            if "<!DOCTYPE" in b and "&xxe;" in b:
                return 200, {}, 'error: root:x:0:0:root:/root (line 1)', 1
            return 200, {}, "ok", 1

        self._patch(resp)
        tr = XxeProbeTool().run({"url": "http://t.test/xml"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "critical")

    def test_nosqli_bypass(self):
        from cyphron.tools.nosqli_probe import NosqliProbeTool

        def resp(url, method, body, kw):
            b = body.decode() if body else "{}"
            j = json.loads(b)
            pw = j.get("password")
            if isinstance(pw, dict) or pw == "benar":
                return 200, {}, '{"msg":"welcome"}', 1
            return 401, {}, '{"msg":"denied"}', 1

        self._patch(resp)
        tr = NosqliProbeTool().run({
            "url": "http://t.test/login", "username": "aku",
            "password": "benar", "success_hint": "welcome"}, _ctx())
        self.assertTrue(tr.data["bypass"])
        self.assertEqual(len(tr.findings), 1)
        self.assertEqual(tr.findings[0].severity, "high")

    def test_host_header_poison_link(self):
        from cyphron.tools.host_header_poison import HostHeaderPoisonTool

        def resp(url, method, body, kw):
            fwd = (kw.get("headers") or {}).get("X-Forwarded-Host", "")
            if fwd == "cyphron-oob.example":
                return 200, {}, 'cek: https://cyphron-oob.example/reset?token=abc', 1
            return 200, {}, "check your email", 1

        self._patch(resp)
        tr = HostHeaderPoisonTool().run({
            "url": "http://t.test/reset", "email": "aku@contoh.id"}, _ctx())
        self.assertEqual(len(tr.findings), 1)
        self.assertIn("cyphron-oob.example", tr.findings[0].response)


if __name__ == "__main__":
    unittest.main()
