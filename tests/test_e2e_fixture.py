"""End-to-end test: Cyphron scans a local, self-owned vulnerable fixture.

Proves the whole chain: skill registry -> planner -> authorization gate
(read-only refuses active tools) -> own engines find real issues -> verifier
-> reports + SQLite + audit chain."""

import json
import sys
import threading
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.findings import Finding
from cyphron.orchestrator import ScanOptions, run_scan
from cyphron.tools.secret_scan import SecretScanTool
from cyphron.tools.base import ToolContext
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.world.model import WorldModel

PAGE = """<html><head><title>Lab</title></head><body>
<h1>Cyphron fixture</h1>
<a href="/search?q=laptop">Search</a>
<a href="/item?id=3">Item 3</a>
<form action="/login" method="POST">
  <input type="text" name="username"><input type="password" name="password">
  <button type="submit">Login</button>
</form>
</body></html>"""


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test noise
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path
        if path.startswith("/search"):
            from urllib.parse import parse_qs, urlparse
            q = (parse_qs(urlparse(path).query).get("q") or [""])[0]
            # VULNERABLE: raw reflection, no encoding
            self._send(200, f"<html><body>Results for {q}</body></html>")
        elif path.startswith("/item"):
            from urllib.parse import parse_qs, urlparse
            item_id = (parse_qs(urlparse(path).query).get("id") or [""])[0]
            if "'" in item_id:
                if "1'='1" in item_id or "1'='2" in item_id:
                    if "1'='1" in item_id:
                        self._send(200, "<html><body><table><tr><td>Row A</td></tr>"
                                        "<tr><td>Row B</td></tr></table></body></html>")
                    else:
                        self._send(200, "<html><body><table></table></body></html>")
                    return
                # VULNERABLE: raw DB error surfaces
                self._send(500, "<html><body>SQLiteException: incomplete input</body></html>")
            else:
                self._send(200, f"<html><body><table><tr><td>Item {item_id}</td></tr></table></body></html>")
        elif path == "/.env":
            # VULNERABLE: secrets file exposed
            self._send(200, "DB_PASSWORD=supersecret123\nAPI_KEY=abcd1234efgh5678\n",
                       content_type="text/plain")
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", content_type="text/plain")
        elif path == "/" or path == "":
            self._send(200, PAGE)
        else:
            self._send(404, "<html><body>not found</body></html>")


AUTH_DOC = {
    "id": "AUTH-E2E-1",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
    "target": {"name": "fixture"},
    "scope": {
        "targets": ["localhost", "127.0.0.1"],
        "excluded": [],
        "cidr": ["127.0.0.0/8"],
        "ports": [],
    },
    "authorized_by": {"name": "tester"},
    "restrictions": ["no_dos", "no_data_exfiltration", "no_persistence"],
    "signature": "test-sig",
}


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), VulnerableHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _opts(self, auth):
        return ScanOptions(
            target=self.base, auth_path=auth, rate_limit_s=0.0,
            max_steps=60, max_time_s=60,
        )

    def test_read_only_refuses_active_and_still_audits(self):
        run = run_scan(self._opts(None), verbose=False)
        s = run.summary
        self.assertEqual(s.mode, "read-only")
        tools_active = [e for e in run.audit.entries
                        if e["kind"] == "tool-run" and e["tool"] in ("sqli_probe", "xss_probe", "dir_probe")]
        self.assertEqual(tools_active, [], "no active tool may run without authorization")
        # kontrak verdict ladder: temuan ber-evidence HEADER (CSP missing) kini
        # LEAD (unconfirmed), bukan "confirmed" — audit pasif tetap dilaporkan
        titles = ([f.title for f in s.confirmed]
                  + [f.title for f in s.unconfirmed])
        self.assertTrue(any("Content-Security-Policy" in t for t in titles),
                        "passive header audit must still run and report")
        ok, note = run.audit.verify()
        self.assertTrue(ok, note)

    def test_authorized_run_finds_real_vulns(self):
        with tempfile.TemporaryDirectory() as td:
            auth_path = Path(td) / "auth.json"
            auth_path.write_text(json.dumps(AUTH_DOC), encoding="utf-8")
            run = run_scan(self._opts(auth_path), verbose=False)
        s = run.summary
        self.assertEqual(s.mode, "offensive")
        titles = [f.title for f in s.confirmed]

        self.assertTrue(any("SQL injection (error-based" in t for t in titles),
                        f"expected error-based SQLi finding; got {titles}")
        sqli = next(f for f in s.confirmed if "SQL injection" in f.title)
        self.assertEqual(sqli.cwe, "CWE-89")
        self.assertIn("curl", sqli.poc)

        self.assertTrue(any("Reflected XSS" in t for t in titles),
                        f"expected reflected XSS finding; got {titles}")
        xss = next(f for f in s.confirmed if "Reflected XSS" in f.title)
        self.assertEqual(xss.cwe, "CWE-79")

        self.assertTrue(any("/.env" in t for t in titles), "dir_probe must catch /.env")
        self.assertTrue(any("/.git/HEAD" in t for t in titles), "dir_probe must catch /.git/HEAD")

        self.assertEqual(sqli.severity, "critical")
        self.assertEqual(xss.severity, "high")
        self.assertEqual(s.confirmed[0].severity, "critical", "sorted by severity first")

        ok, note = run.audit.verify()
        self.assertTrue(ok, note)
        self.assertTrue(any(e["kind"] == "authorization-loaded" for e in run.audit.entries))
        self.assertEqual(s.auth_id, "AUTH-E2E-1")

    def test_out_of_scope_authorization_blocks_active_tools(self):
        doc = dict(AUTH_DOC)
        doc["scope"] = {"targets": ["example.test"], "excluded": [], "cidr": [],
                        "ports": []}
        with tempfile.TemporaryDirectory() as td:
            auth_path = Path(td) / "auth.json"
            auth_path.write_text(json.dumps(doc), encoding="utf-8")
            run = run_scan(self._opts(auth_path), verbose=False)
        self.assertEqual(run.summary.mode, "read-only")
        refusals = [e for e in run.audit.entries if e["kind"] == "authorization-refusal"]
        self.assertTrue(refusals, "active tools must be refused for out-of-scope target")

    def test_secret_scanner_local(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            (repo / "config.py").write_text(
                'DB_URL="postgres://admin:P@ss"\n'
                'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
            (repo / "safe.py").write_text("x = 1\n", encoding="utf-8")
            ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                              world=WorldModel(), rate_limit_s=0.0)
            tool = SecretScanTool()
            result = tool.run({"path": str(repo)}, ctx)
            titles = [f.title for f in result.findings]
            self.assertTrue(any("AWS access key" in t for t in titles))
            aws = next(f for f in result.findings if "AWS" in f.title)
            self.assertEqual(aws.file_path, str(repo / "config.py"))
            self.assertIn("***[redacted]", aws.response, "secret value must be redacted in evidence")

    def test_secret_scanner_pem_template_fp_guard(self):
        """PEM markers bersebelahan tanpa isi (template string-pool DEX)
        tidak boleh dianggap private key — FP lesson 2026-09-13."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            body = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAK" * 3
            (repo / "template.txt").write_text(
                "-----BEGIN PRIVATE KEY----- -----END PRIVATE KEY-----\n", encoding="utf-8")
            (repo / "real.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n",
                encoding="utf-8")
            ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                              world=WorldModel(), rate_limit_s=0.0)
            tool = SecretScanTool()
            result = tool.run({"path": str(repo)}, ctx)
            hits = [f for f in result.findings if "private key block" in f.title]
            self.assertEqual(len(hits), 1, "only the real key block may match, not the template")
            self.assertTrue(hits[0].file_path.endswith("real.pem"))


if __name__ == "__main__":
    unittest.main()
