"""U4: browser_scout — CDP headless scout. Offline via monkeypatch; live
opt-in dengan env CYPHRON_BSCOUT_LIVE=1 (butuh Edge/Chrome + node di mesin)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.planner import DeterministicPlanner
from cyphron.tools import browser_scout as bs
from cyphron.tools.browser_scout import BrowserScoutTool
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel

REPORT = {
    "pages": [
        {"url": "https://t.test/", "final_url": "https://t.test/",
         "status": 200,
         "dom": ("<html><body><a href='/search?q=1'>s</a>"
                 "<form action='/login' method='POST'>"
                 "<input name='password'></form></body></html>"),
         "requests": [
             {"url": "https://t.test/api/session", "method": "GET",
              "type": "XHR", "status": 200, "mime": "application/json",
              "host": "t.test", "in_scope": True,
              "set_cookie": "sid=abc; Path=/"},
             {"url": "https://tracker.example/pixel", "method": "GET",
              "type": "Image", "status": 200, "host": "tracker.example",
              "in_scope": False, "set_cookie": ""},
         ],
         "cookies": [
             {"name": "sid", "domain": ".t.test", "path": "/",
              "http_only": False, "secure": False,
              "same_site": "unspecified", "session": True},
             {"name": "ok", "domain": ".t.test", "path": "/",
              "http_only": True, "secure": True,
              "same_site": "strict", "session": False},
         ],
         "third_party_blocked": 3, "errors": []},
        {"url": "https://t.test/login", "final_url": "https://evil.example/x",
         "status": 302, "dom": "", "requests": [], "cookies": [],
         "third_party_blocked": 0, "errors": []},
    ],
    "errors": ["https://t.test/timeout: ws-timeout"],
}


def _ctx(world: WorldModel | None = None) -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=world or WorldModel(), rate_limit_s=0.0,
                       timeout_s=5.0, max_requests=50)


class _FakeProc:
    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class TestBrowserScoutOffline(unittest.TestCase):
    def test_ingest_dom_trafik_cookie(self):
        w = WorldModel()
        w.target = "https://t.test"
        ctx = _ctx(w)
        tool = BrowserScoutTool()
        res = tool._ingest(json.loads(json.dumps(REPORT)), ctx, "t.test")
        self.assertTrue(res.ok)
        # DOM -> endpoint link + form
        self.assertIn("https://t.test/search?q=1", w.endpoints)
        self.assertIn("https://t.test/login", w.endpoints)
        self.assertTrue(w.endpoints["https://t.test/login"].form_fields)
        # subresource same-host tercatat dengan status
        self.assertEqual(w.endpoints["https://t.test/api/session"].status, 200)
        # pihak ketiga TIDAK masuk world
        self.assertNotIn("https://tracker.example/pixel", w.endpoints)
        # cookie finding: hanya 'sid' (deterministik dari atribut)
        titles = [f.title for f in res.findings]
        self.assertEqual(len(titles), 1)
        self.assertIn("'sid'", titles[0])
        self.assertIn("Secure", titles[0])
        self.assertEqual(res.findings[0].finding_class, "posture")
        self.assertEqual(res.findings[0].status, "unconfirmed")
        self.assertEqual(res.findings[0].cwe, "CWE-1004")
        # halaman dengan redirect keluar scope di-skip
        self.assertEqual(len(res.data["pages"]), 1)
        self.assertEqual(res.data["third_party_blocked"], 3)
        self.assertGreaterEqual(w.request_count, 2)

    def test_no_browser_graceful(self):
        _orig = bs._find_browser
        bs._find_browser = lambda: None
        self.addCleanup(setattr, bs, "_find_browser", _orig)
        w = WorldModel()
        w.target = "https://t.test"
        res = BrowserScoutTool().run({"url": "https://t.test"}, _ctx(w))
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("skipped"), "no-browser")

    def test_no_node_bridge_graceful(self):
        _orig_fb = bs._find_browser
        bs._find_browser = lambda: "C:/fake/browser.exe"
        self.addCleanup(setattr, bs, "_find_browser", _orig_fb)
        _orig_which = bs.shutil.which
        bs.shutil.which = lambda name: None
        self.addCleanup(setattr, bs.shutil, "which", _orig_which)
        w = WorldModel()
        w.target = "https://t.test"
        res = BrowserScoutTool().run({"url": "https://t.test"}, _ctx(w))
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("skipped"), "no-node-bridge")

    def test_bounded_pages_dan_args_bridge(self):
        captured = {}

        def fake_bridge(self, node, port, urls, host):
            captured["urls"] = list(urls)
            captured["host"] = host
            return {"pages": [], "errors": []}

        _orig_fb = BrowserScoutTool._run_bridge
        BrowserScoutTool._run_bridge = fake_bridge
        self.addCleanup(setattr, BrowserScoutTool, "_run_bridge", _orig_fb)
        _orig_fb2 = bs._find_browser
        bs._find_browser = lambda: "C:/fake/browser.exe"
        self.addCleanup(setattr, bs, "_find_browser", _orig_fb2)
        _orig_wait = bs._wait_cdp
        bs._wait_cdp = lambda port, deadline: True
        self.addCleanup(setattr, bs, "_wait_cdp", _orig_wait)
        _orig_popen = bs.subprocess.Popen
        bs.subprocess.Popen = lambda *a, **k: _FakeProc()
        self.addCleanup(setattr, bs.subprocess, "Popen", _orig_popen)

        w = WorldModel()
        w.target = "https://t.test"
        res = BrowserScoutTool().run({"url": "https://t.test",
                                      "max_pages": 99}, _ctx(w))
        self.assertTrue(res.ok)
        self.assertLessEqual(len(captured["urls"]), 8, "max_pages wajib ter-clamp")
        self.assertTrue(all(u.startswith("https://t.test") for u in captured["urls"]))
        self.assertEqual(captured["host"], "t.test")

    def test_budget_habis_melewati_browser(self):
        w = WorldModel()
        w.target = "https://t.test"
        w.request_count = 49
        ctx = _ctx(w)  # max_requests 50
        _orig_fb = bs._find_browser
        bs._find_browser = lambda: "C:/fake/browser.exe"
        self.addCleanup(setattr, bs, "_find_browser", _orig_fb)
        res = BrowserScoutTool().run({"url": "https://t.test"}, ctx)
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("skipped"), "budget")

    def test_planner_menjadwalkan_browser_scout(self):
        w = WorldModel()
        w.target = "https://t.test"
        w.observe_endpoint("https://t.test/", []).status = 200
        p = DeterministicPlanner(offensive_allowed=False)
        plan = p.plan(w)
        steps = [s for s in plan if s.tool == "browser_scout"]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].phase, "discovery")
        self.assertEqual(steps[0].args.get("max_pages"), 5)


class TestBridgeScript(unittest.TestCase):
    def test_bridge_sintaks_valid(self):
        node = None
        import shutil as _sh
        node = _sh.which("node")
        if not node:
            self.skipTest("node tidak tersedia")
        bridge = Path(bs.__file__).with_name("browser_scout_bridge.js")
        r = subprocess.run([node, "--check", str(bridge)], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode())


LIVE_PAGE = """<html><head><title>scout-live</title></head><body>
<script>
fetch('/api/data').then(r => r.json()).then(d => {
  document.body.setAttribute('data-loaded', 'yes');
  const el = document.createElement('p'); el.id = 'out';
  el.textContent = 'loaded:' + d.ok; document.body.appendChild(el);
}).catch(() => {});
</script></body></html>"""


class _LiveHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, headers=None, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/data"):
            self._send(200, '{"ok":true}',
                       headers={"Set-Cookie": "sid=1; Path=/"},
                       ctype="application/json")
        elif self.path == "/":
            self._send(200, LIVE_PAGE)
        else:
            self._send(404, "nope")


@unittest.skipUnless(os.environ.get("CYPHRON_BSCOUT_LIVE"),
                     "live CDP test opt-in: set CYPHRON_BSCOUT_LIVE=1")
class TestBrowserScoutLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import shutil as _sh
        if not _sh.which("node"):
            raise unittest.SkipTest("node tidak tersedia")
        r = subprocess.run(["node", "-e",
                            "console.log(typeof WebSocket)"],
                           capture_output=True)
        if r.stdout.decode().strip() != "function":
            raise unittest.SkipTest("WebSocket global node tidak tersedia")
        if not bs._find_browser():
            raise unittest.SkipTest("Edge/Chrome tidak tersedia")
        cls.server = HTTPServer(("127.0.0.1", 0), _LiveHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_capture_dom_trafik_cookie_live(self):
        w = WorldModel()
        w.target = self.base
        ctx = _ctx(w)
        res = BrowserScoutTool().run({"url": self.base, "max_pages": 2}, ctx)
        self.assertTrue(res.ok, res.error)
        self.assertTrue(res.data.get("pages"), "minimal satu halaman terscan")
        # fetch() SPA same-host tertangkap di trafik
        self.assertIn(f"{self.base}/api/data", w.endpoints)
        # cookie tanpa Secure/HttpOnly/SameSite -> temuan posture deterministik
        sid = [f for f in res.findings if "'sid'" in f.title]
        self.assertTrue(sid, f"cookie sid harus tertangkap; findings={res.findings}")
        self.assertIn(f"{self.base}/", [p["url"] for p in res.data["pages"]])


if __name__ == "__main__":
    unittest.main()
