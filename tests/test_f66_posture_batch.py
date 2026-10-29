"""Test F66 — batch agresif pasca-Black October (5 skill baru).

NOL jaringan (urlopen di-mock). Yang dikunci:
  - php-posture: versi PHP = L1 + fakta tech; easter-egg GIF89a = L1;
    phpinfo tiga-signature = L2; bukan PHP = AMAN; network = no-claim.
  - brotli-stack-surface: Content-Encoding br = L0; marker Express =
    L1 stack Node.js (token watchlist); tanpa marker = AMAN.
  - wp-plugin-surface: readme bricksforge = fakta versi + ringkasan L1;
    bukan WP = AMAN; network = no-claim.
  - magento-surface: /magento_version = versi + L1; tanpa marker =
    AMAN; network = no-claim.
  - agent-instruction-exposure: AGENTS.md/.mcp.json = L2; fallback HTML
    ditolak; tanpa marker = AMAN; network = no-claim.
  - registry: 5 entri baru (count 88) + cve-matcher allowlist memuat
    tool baru dan watchlist token bricksforge ter-match.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import agent_instruction_exposure as aie  # noqa: E402
import brotli_stack_surface as bss  # noqa: E402
import cve_matcher as cm  # noqa: E402
import magento_surface as ms  # noqa: E402
import php_posture as pp  # noqa: E402
import wp_plugin_surface as wps  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "http://t.local"
EASTER = pp.EASTER_EGG


class _FakeResp:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = (body.encode("utf-8", "replace")
                      if isinstance(body, str) else body)
        self.headers = headers if headers is not None else {
            "Content-Type": "text/html"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body


def _patch(module, routes):
    """routes: {path: (status, body, headers)} atau 'boom'."""
    def fake_urlopen(req, timeout=None):
        full = req.full_url
        rest = full.split("://", 1)[1]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        entry = routes.get(path, (404, "not found", {}))
        if entry == "boom":
            raise OSError("conn refused")
        st, body, headers = entry
        resp = _FakeResp(st, body, headers)
        return resp
    return patch.object(module.urllib.request, "urlopen", fake_urlopen)


def _boom(module):
    def fake(req, timeout=None):
        raise OSError("conn refused")
    return patch.object(module.urllib.request, "urlopen", fake)


class PhpPostureTest(unittest.TestCase):
    def test_version_easter_egg_and_phpinfo(self):
        routes = {
            "/": (200, "<html><body>ok</body></html>",
                  {"X-Powered-By": "PHP/8.2.34",
                   "Set-Cookie": "PHPSESSID=abc"}),
            EASTER: (200, "GIF89a" + "0" * 40,
                     {"Content-Type": "image/gif"}),
            "/phpinfo.php": (200, "phpinfo() PHP Version 8.2.34 "
                                   "php.ini System",
                             {"Content-Type": "text/html"}),
            "/info.php": (404, "nope", {}),
        }
        with _patch(pp, routes):
            rows, meta = pp.audit(URL)
        self.assertTrue(meta["is_php"])
        self.assertEqual(meta["version"], "8.2.34")
        self.assertTrue(meta["expose_php"])
        self.assertEqual(meta["phpinfo"], ["/phpinfo.php"])
        self.assertEqual(meta["requests"], 4)
        ver = next(r for r in rows if r.get("version") == "8.2.34")
        self.assertEqual(ver["verdict"], 1)
        self.assertEqual(ver["cwe"], "CWE-200")
        self.assertIn("php 8.2.34", ver["tech"])
        phpinfo = next(r for r in rows if r["title"].startswith("phpinfo()"))
        self.assertEqual(phpinfo["verdict"], 2)
        self.assertEqual(phpinfo["cwe"], "CWE-538")
        self.assertTrue(any("expose_php" in r["title"] for r in rows))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_not_php_is_aman(self):
        routes = {"/": (200, "<html>plain</html>", {}),
                  EASTER: (404, "nope", {}),
                  "/phpinfo.php": (404, "nope", {}),
                  "/info.php": (404, "nope", {})}
        with _patch(pp, routes):
            rows, meta = pp.audit(URL)
        self.assertFalse(meta["is_php"])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_network_fail_closed(self):
        with _boom(pp):
            rows, meta = pp.audit(URL)
        self.assertFalse(meta["is_php"])
        self.assertTrue(rows[0].get("network_error"))
        self.assertEqual(rows[0]["verdict"], 0)


class BrotliStackTest(unittest.TestCase):
    def test_brotli_and_node_marker(self):
        routes = {"/": (200, "<html>app</html>",
                        {"Content-Encoding": "br",
                         "X-Powered-By": "Express"})}
        with _patch(bss, routes):
            rows, meta = bss.audit(URL)
        self.assertTrue(meta["brotli"])
        self.assertIn("node.js", meta["stack"])
        self.assertIn("br", next(r for r in rows
                                 if "Brotli aktif" in r["title"])
                      ["response"])
        node = next(r for r in rows if "Stack Node.js" in r["title"])
        self.assertEqual(node["verdict"], 1)
        self.assertTrue(node["tech"].startswith("node.js"))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_no_marker_is_aman(self):
        routes = {"/": (200, "<html>plain</html>",
                        {"Content-Encoding": "gzip",
                         "Server": "nginx"})}
        with _patch(bss, routes):
            rows, meta = bss.audit(URL)
        self.assertFalse(meta["brotli"])
        self.assertEqual(meta["stack"], [])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_network_fail_closed(self):
        with _boom(bss):
            rows, meta = bss.audit(URL)
        self.assertTrue(rows[0].get("network_error"))


class WpPluginSurfaceTest(unittest.TestCase):
    WP_HOME = ('<link rel="stylesheet" '
               'href="/wp-content/themes/a/style.css">'
               '<script src="/wp-includes/js/x.js"></script>')

    def test_bricksforge_readme_version_fact(self):
        routes = {
            "/": (200, self.WP_HOME, {}),
            "/wp-content/plugins/bricksforge/readme.txt":
                (200, "=== Bricksforge ===\nStable tag: 3.1.8.9\n"
                     "Requires at least: 6.0\n", {}),
        }
        with _patch(wps, routes):
            rows, meta = wps.audit(URL)
        self.assertTrue(meta["is_wp"])
        self.assertEqual(meta["plugins"], {"bricksforge": "3.1.8.9"})
        fact = next(r for r in rows if r["title"].startswith("Plugin"))
        self.assertIn("bricksforge 3.1.8.9", fact["tech"])
        summary = next(r for r in rows if r["verdict"] == 1)
        self.assertIn("Versi plugin publik", summary["title"])
        self.assertEqual(summary["cwe"], "CWE-200")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_not_wordpress_is_aman(self):
        routes = {"/": (200, "<html>builder</html>", {})}
        with _patch(wps, routes):
            rows, meta = wps.audit(URL)
        self.assertFalse(meta["is_wp"])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_network_fail_closed(self):
        with _boom(wps):
            rows, meta = wps.audit(URL)
        self.assertTrue(rows[0].get("network_error"))


class MagentoSurfaceTest(unittest.TestCase):
    def test_magento_version_detected(self):
        routes = {
            "/magento_version": (200, "Magento/2.4.7 (Community)", {}),
            "/customer/account/login/": (404, "nope", {}),
            "/downloader/": (404, "nope", {}),
        }
        with _patch(ms, routes):
            rows, meta = ms.audit(URL)
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["2.4.7"])
        det = next(r for r in rows if "terdeteksi" in r["title"])
        self.assertEqual(det["verdict"], 1)
        self.assertIn("magento 2.4.7", det["tech"])
        self.assertTrue(any("Versi Magento ter-expose" in r["title"]
                            and r["verdict"] == 1 for r in rows))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_no_marker_is_aman(self):
        routes = {p: (404, "nope", {}) for p in ms.PROBES}
        with _patch(ms, routes):
            rows, meta = ms.audit(URL)
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_network_fail_closed(self):
        with _boom(ms):
            rows, meta = ms.audit(URL)
        self.assertTrue(rows[0].get("network_error"))


class AgentInstructionExposureTest(unittest.TestCase):
    def test_agents_and_mcp_are_l2(self):
        routes = {
            "/AGENTS.md": (200, "# AGENTS\nagent instructions: never "
                                "use production keys", {}),
            "/.mcp.json": (200, '{"mcpServers": {"x": {}}}', {}),
            "/CLAUDE.md": (404, "nope", {}),
            "/.cursorrules": (404, "nope", {}),
            "/.windsurfrules": (404, "nope", {}),
        }
        with _patch(aie, routes):
            rows, meta = aie.audit(URL)
        self.assertEqual(sorted(meta["exposed"]),
                         ["/.mcp.json", "/AGENTS.md"])
        self.assertTrue(all(r["verdict"] == 2 for r in rows))
        self.assertTrue(all(r["cwe"] == "CWE-538" for r in rows))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_html_fallback_rejected(self):
        routes = {"/AGENTS.md": (200, "<!doctype html><html>app</html>",
                                 {})}
        with _patch(aie, routes):
            rows, meta = aie.audit(URL)
        self.assertEqual(meta["exposed"], [])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_network_fail_closed(self):
        with _boom(aie):
            rows, meta = aie.audit(URL)
        self.assertTrue(rows[0].get("network_error"))


class RegistryAndMatcherTest(unittest.TestCase):
    def test_registry_batch_f66(self):
        import json
        reg = json.loads((ROOT / "skills" / "registry.json").read_text(
            encoding="utf-8"))
        by_name = {s["name"]: s for s in reg["skills"]}
        expect = {
            "php-posture": "bounded-requests",
            "brotli-stack-surface": "1-request",
            "wp-plugin-surface": "bounded-requests",
            "magento-surface": "bounded-requests",
            "agent-instruction-exposure": "bounded-requests",
        }
        for name, cls in expect.items():
            self.assertIn(name, by_name)
            self.assertEqual(by_name[name]["safety_class"], cls)
            self.assertEqual(by_name[name]["needs"], "target")
        self.assertGreaterEqual(len(reg["skills"]), 86)

    def test_cve_matcher_allowlist_and_watchlist_chain(self):
        for tool in ("php-posture", "brotli-stack-surface",
                     "wp-plugin-surface", "magento-surface"):
            self.assertIn(tool, cm.ALLOWED_SOURCE_TOOLS)
        wl = [{"cve": "CVE-2026-85097", "vendor": "Bricksforge",
               "product": "Bricksforge (WordPress plugin)",
               "_tokens": ["bricksforge"], "_product": "bricksforge",
               "source_url": "https://example.com/bricksforge"}]
        rows = [{"tool": "wp-plugin-surface",
                 "title": "Plugin bricksforge 3.1.8.9 terdeteksi",
                 "response": "", "status": "confirmed",
                 "target_url": "http://t.local", "extra": {}}]
        out, meta = cm.match_cves(rows, [], [], [], None, wl)
        wl_rows = [r for r in out if r.get("via") == "watchlist"]
        self.assertEqual(len(wl_rows), 1)
        self.assertEqual(wl_rows[0]["cve"], "CVE-2026-85097")
        self.assertEqual(wl_rows[0]["verdict"], 1)
        self.assertFalse(wl_rows[0]["version_claim"])
        self.assertTrue(all(validate_finding(r) == [] for r in out))


if __name__ == "__main__":
    unittest.main(verbosity=1)
