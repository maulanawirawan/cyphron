"""dir_probe anti-soft-404 (pelajaran pay.kredivo.com 2026-09-19).

Host catch-all di balik load balancer membalas 200 HTML hampir identik
untuk SEMUA path (baseline garbage kebetulan dibalas node lain dengan 404).
Kontrak baru:
- SPA catch-all (body mirip baseline ATAU miss-kedua mirip kandidat)
  TIDAK menghasilkan temuan;
- file sungguhan (PK/SQLite magic, content-type biner) TETAP tertangkap;
- .env teks nyata tetap tertangkap walau content-type text/plain;
- /admin catch-all tidak lagi jadi "candidate".
"""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import http_engine
from cyphron.tools.base import ToolContext
from cyphron.tools.dir_probe import DirProbeTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=200)


_SHELL = ("<!DOCTYPE html><html><head><title>App</title></head><body>"
          "<div id=\"root\"></div><script src=\"/app.js\"></script>"
          "<p>Path: {path}</p></body></html>")


class _Server:
    """route(path) -> (status, headers, body); garbage path juga lewat route."""

    def __init__(self, test, route):
        self._orig = http_engine.http_get

        def fake_get(url, **kw):
            path = url.split("/", 3)[-1] if url.count("/") >= 3 else url
            st, hd, body = route(url, path)
            return st, hd, body, 1

        http_engine.http_get = fake_get
        test.addCleanup(setattr, http_engine, "http_get", self._orig)


def _hd(ct=None):
    return {"Content-Type": ct} if ct else {}


class TestDirProbeSoft404(unittest.TestCase):
    def setUp(self):
        self.tool = DirProbeTool()

    def test_spa_catchall_zero_finding(self):
        """Node LB: baseline garbage PERTAMA -> 404; semua berikutnya ->
        200 HTML shell dengan path tertanam (body beda dikit).
        Kasus pay.kredivo.com: engine lama melempar 41 temuan palsu."""

        calls = {"garbage": 0}

        def route(url, path):
            if "cx-zz-not-a-real-path" in path:
                calls["garbage"] += 1
                if calls["garbage"] == 1:
                    return 404, _hd(), "404 not found"
                return 200, _hd("text/html"), _SHELL.format(path=path)
            return 200, _hd("text/html"), _SHELL.format(path=path)

        _Server(self, route)
        tr = self.tool.run({"url": "https://t.test"}, _ctx())
        self.assertEqual(tr.findings, [], "catch-all SPA tidak boleh bertemuan")
        self.assertGreater(tr.data["soft404_blocked"], 0)

    def test_real_zip_and_sqlite_still_caught(self):
        def route(url, path):
            if "cx-zz-not-a-real-path" in path:
                return 404, _hd(), "404 not found"
            if path == "backup.zip":
                return 200, _hd("application/zip"), "PK\x03\x04 binarydata"
            if path == "db.sqlite3":
                return 200, _hd("application/octet-stream"), \
                    "SQLite format 3\x00data"
            return 404, _hd(), "404 not found"

        _Server(self, route)
        tr = self.tool.run({"url": "https://t.test"}, _ctx())
        titles = {f.title for f in tr.findings}
        self.assertTrue(any("backup.zip" in t for t in titles), titles)
        self.assertTrue(any("db.sqlite3" in t for t in titles), titles)

    def test_real_env_text_still_caught(self):
        def route(url, path):
            if "cx-zz-not-a-real-path" in path:
                return 404, _hd(), "404 not found"
            if path == ".env":
                return 200, _hd("text/plain"), "DB_PASSWORD=hunter2secret\n"
            return 404, _hd(), "404 not found"

        _Server(self, route)
        tr = self.tool.run({"url": "https://t.test"}, _ctx())
        titles = {f.title for f in tr.findings}
        self.assertTrue(any(".env" in t for t in titles), titles)

    def test_html_file_with_zip_ext_blocked(self):
        """/backup.zip berupa HTML (catch-all) -> diblok walau baseline
        404 sempurna: content-type tidak masuk akal + miss kedua mirip."""

        def route(url, path):
            if "cx-zz-not-a-real-path" in path:
                return 404, _hd("text/html"), "not found page"
            return 200, _hd("text/html"), _SHELL.format(path=path)

        _Server(self, route)
        tr = self.tool.run({"url": "https://t.test"}, _ctx())
        self.assertEqual([f for f in tr.findings
                          if "backup.zip" in f.title], [])


if __name__ == "__main__":
    unittest.main()
