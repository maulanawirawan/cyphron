"""U10: ownership proof (well-known/DNS TXT fail-closed), usage ledger,
safe-update script, dan konsistensi landing v2."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuthorizationDocument
from cyphron.ledger import record_scan, summarize
from cyphron.orchestrator import ScanOptions, run_scan
from cyphron.ownership import ownership_token, verify_ownership

_REPO = Path(__file__).resolve().parents[1]

TOKEN = ownership_token("127.0.0.1", "AUTH-U10", "2026-01-01T00:00:00Z")

AUTH = {
    "id": "AUTH-U10",
    "issued_at": "2026-01-01T00:00:00Z",
    "expires_at": "2030-01-01T00:00:00Z",
    "target": {"name": "fixture"},
    "scope": {"targets": ["localhost", "127.0.0.1"], "excluded": [],
              "cidr": ["127.0.0.0/8"], "ports": []},
    "authorized_by": {"name": "tester"},
    "restrictions": ["no_dos"],
    "signature": "sig",
    "require_ownership": True,
    "ownership_channel": "auto",
}

PAGE = """<html><head><title>lab</title></head><body><h1>ok</h1></body></html>"""


class _OwnerHandler(BaseHTTPRequestHandler):
    token = TOKEN
    log_message = lambda self, *a: None

    def do_GET(self):
        if self.path == "/.well-known/cyphron-verify.txt":
            body = (self.token + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class TestOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _OwnerHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _doc(self):
        with __import__("tempfile").TemporaryDirectory() as td:
            pass
        return AuthorizationDocument.from_dict(dict(AUTH))

    def test_token_deterministik(self):
        t1 = ownership_token("127.0.0.1", "AUTH-U10", "2026-01-01T00:00:00Z")
        t2 = ownership_token("127.0.0.1", "AUTH-U10", "2026-01-01T00:00:00Z")
        t3 = ownership_token("127.0.0.1", "AUTH-LAIN", "2026-01-01T00:00:00Z")
        t4 = ownership_token("127.0.0.1", "AUTH-U10", "2027-01-01T00:00:00Z")
        self.assertEqual(t1, t2)
        self.assertNotEqual(t1, t3)
        self.assertNotEqual(t1, t4, "ganti dokumen = ganti token")
        self.assertTrue(t1.startswith("cyphron-verify="))
        self.assertEqual(len(t1), len("cyphron-verify=") + 32)

    def test_wellknown_cocok(self):
        doc = self._doc()
        ok, detail = verify_ownership(self.base, doc, channel="wellknown")
        self.assertTrue(ok, detail)
        self.assertEqual(detail["method"], "wellknown")

    def test_wellknown_mismatch_gagal(self):
        _OwnerHandler.token = "cyphron-verify=" + "b" * 32
        try:
            doc = self._doc()
            ok, _ = verify_ownership(self.base, doc, channel="wellknown")
            self.assertFalse(ok)
        finally:
            _OwnerHandler.token = TOKEN

    def test_run_scan_fail_closed_tanpa_bukti(self):
        _OwnerHandler.token = "cyphron-verify=" + "c" * 32
        try:
            run = run_scan(ScanOptions(target=self.base,
                                       auth_path=self._write_auth(),
                                       rate_limit_s=0.0, max_steps=3,
                                       max_time_s=20), verbose=False)
        finally:
            _OwnerHandler.token = TOKEN
        self.assertEqual(run.summary.mode, "read-only",
                         "ownership gagal wajib fail-closed")
        kinds = [e["kind"] for e in run.audit.entries]
        self.assertIn("ownership-check", kinds)
        self.assertIn("ownership proof GAGAL",
                      " | ".join(run.world.notes))

    def test_run_scan_offensive_dengan_bukti(self):
        run = run_scan(ScanOptions(target=self.base,
                                   auth_path=self._write_auth(),
                                   rate_limit_s=0.0, max_steps=3,
                                   max_time_s=20), verbose=False)
        self.assertEqual(run.summary.mode, "offensive")
        self.assertTrue(any("ownership proof OK" in n
                            for n in run.world.notes))

    def _write_auth(self):
        import tempfile
        td = tempfile.mkdtemp(prefix="cyphron-u10-")
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        p = Path(td) / "auth.json"
        p.write_text(json.dumps(AUTH), encoding="utf-8")
        return p


class TestLedger(unittest.TestCase):
    def test_record_dan_summarize(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td)
            data = {
                "target": "https://t.test", "mode": "offensive",
                "authorization": "AUTH-1", "steps": 20,
                "world": {"request_count": 88},
                "confirmed": [{"id": "a"}], "unconfirmed": [{"id": "b"}],
                "refused_actions": 2, "elapsed_s": 55.0,
            }
            (src / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
            row1 = record_scan(src)
            self.assertEqual(row1["requests"], 88)
            self.assertEqual(row1["confirmed"], 1)
            record_scan(src)
            s = summarize(src)
            self.assertEqual(s["scans"], 2)
            self.assertEqual(s["requests"], 176)
            self.assertEqual(s["per_target"]["https://t.test"]["scans"], 2)


class TestSafeUpdateScript(unittest.TestCase):
    def test_sintaks_bash_valid(self):
        script = _REPO / "scripts" / "safe-update.sh"
        self.assertTrue(script.exists())
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash tidak tersedia")
        r = subprocess.run([bash, "-n", str(script)], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode())


class TestLandingV2(unittest.TestCase):
    def test_landing_menyebut_kapabilitas_inti(self):
        html = (_REPO / "landing" / "index.html").read_text(
            encoding="utf-8").lower()
        for word in ("verdict", "lead", "benchmark", "knowledge base"):
            self.assertIn(word, html, f"landing v2 harus menyebut {word}")


if __name__ == "__main__":
    unittest.main()
