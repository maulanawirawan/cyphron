"""Test F64+F65 — vllm-posture, openwebui-posture, supplychain-check.

NOL jaringan (urlopen di-mock; blocklist via tmp). Yang dikunci:
  - vllm-posture: metrik 'vllm:*' di /metrics = L1 + fakta versi;
    shape generik OpenAI /v1/models SAJA = BUKAN marker (anti-FP
    antar-gateway); tanpa marker = AMAN; gagal jaringan = tanpa klaim;
  - openwebui-posture: token 'open-webui' = L1 + fakta; shape version
    generik SAJA = bukan marker; tanpa marker = AMAN;
  - supplychain-check: (ecosystem,package,version) kena blocklist =
    lead HIGH; tanpa-pin = LOW; pin tanpa hash = LOW; baris komentar
    dilewati; blocklist entri cacat ditolak; blocklist hilang =
    fail-closed (dilewati, bukan klaim bersih); parser npm scoped.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import vllm_posture as vp  # noqa: E402
import openwebui_posture as ow  # noqa: E402
import supplychain_check as sc  # noqa: E402
from findings import validate_finding  # noqa: E402


class _FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self.getvalue()[:n] if n > 0 else self.getvalue()

    def items(self):
        return list(self.headers.items())


def _patch_urlopen(skill, bodies, status=200):
    def fake_urlopen(req, timeout=None):
        path = req.full_url.split("://", 1)[1]
        path = "/" + path.split("/", 1)[1] if "/" in \
            path.split("://", 1)[-1] else "/"
        for key, body in bodies.items():
            if path.startswith(key):
                resp = _FakeResp(body.encode())
                resp.status = status
                resp.headers = {"content-type": "text/plain"}
                return resp
        resp = _FakeResp(b"not found")
        resp.status = 404
        resp.headers = {}
        return resp
    return patch.object(skill.urllib.request, "urlopen", fake_urlopen)


# ------------------------------------------------------- vllm-posture

class VllmPostureTest(unittest.TestCase):
    def test_metrics_token_is_l1_with_version(self):
        bodies = {"/metrics": '# HELP vllm:request_success_total x\n'
                              'vllm:request_success_total{model="m"} 1\n',
                  "/version": '{"version":"0.6.4"}',
                  "/v1/models": '{"object":"list","data":'
                                '[{"id":"m1"},{"id":"m2"}]}'}
        with _patch_urlopen(vp, bodies):
            rows, meta = vp.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["0.6.4"])
        self.assertEqual(meta["models_count"], 2)
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("vllm 0.6.4", rows[1]["title"].lower())
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_generic_openai_shape_alone_not_marker(self):
        bodies = {"/metrics": "http_requests_total 5\n",
                  "/version": "404",
                  "/v1/models": '{"object":"list","data":'
                                '[{"id":"gpt-x"}]}'}
        with _patch_urlopen(vp, bodies):
            rows, meta = vp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_all_network_error_no_aman_claim(self):
        def fake_urlopen(req, timeout=None):
            raise OSError("conn refused")
        with patch.object(vp.urllib.request, "urlopen", fake_urlopen):
            rows, meta = vp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertTrue(rows[0].get("network_error"))


# -------------------------------------------------- openwebui-posture

class OpenwebuiPostureTest(unittest.TestCase):
    def test_token_marker_with_version(self):
        bodies = {"/api/config": '{"name":"Open WebUI","version":'
                                 '"0.6.5"}',
                  "/api/version": '{"version":"0.6.5"}',
                  "/health": '{"status":true}'}
        with _patch_urlopen(ow, bodies):
            rows, meta = ow.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["0.6.5"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("open-webui 0.6.5", rows[1]["title"].lower())
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_generic_version_shape_alone_not_marker(self):
        bodies = {"/api/config": "404",
                  "/api/version": '{"version":"1.2.3"}',
                  "/health": "ok"}
        with _patch_urlopen(ow, bodies):
            rows, meta = ow.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_no_marker_is_aman(self):
        bodies = {"/api/config": "404", "/api/version": "404",
                  "/health": "404"}
        with _patch_urlopen(ow, bodies):
            rows, meta = ow.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)


# ------------------------------------------------- supplychain-check

BLOCKLIST = {"entries": [
    {"ecosystem": "pypi", "package": "litellm",
     "versions": ["1.82.8", "1.107.0"], "campaign": "test-campaign",
     "note": "rilis beracun", "source_url": "https://example.com/x",
     "added": "2026-10-26"},
    {"ecosystem": "npm", "package": "@tensorlake/tensorlake",
     "versions": ["0.5.144"], "campaign": "worm",
     "note": "self-spreading", "source_url": "https://example.com/y",
     "added": "2026-10-26"},
    {"ecosystem": "pypi", "package": "cacat",
     "note": "tanpa versions/source_url"},  # ditolak fail-closed
]}

REQ_PYPI = """# requirements
litellm==1.82.8 --hash=sha256:abc
requests==2.31.0
flask
"""

REQ_NPM = """// package list
@tensorlake/tensorlake@0.5.144
lodash@4.17.21
left-pad
"""


class SupplychainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f65-"))
        self.bl = self.tmp / "blocklist.json"
        self.bl.write_text(json.dumps(BLOCKLIST), encoding="utf-8")
        self.old = sc.BLOCKLIST_PATH
        sc.BLOCKLIST_PATH = self.bl

    def tearDown(self):
        sc.BLOCKLIST_PATH = self.old
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_poisoned_unpinned_nohash(self):
        blocklist, rejected = sc.load_blocklist()
        self.assertEqual(len(blocklist), 2)
        self.assertEqual(len(rejected), 1)
        rows, meta = sc.check(REQ_PYPI, "pypi", blocklist)
        self.assertEqual(meta["poisoned"], 1)
        self.assertEqual(meta["unpinned"], 1)
        self.assertEqual(meta["no_hash"], 1)  # requests; litellm ber-hash
        high = [r for r in rows if r["severity"] == "high"]
        self.assertEqual(len(high), 1)
        self.assertIn("litellm==1.82.8", high[0]["title"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_npm_scoped_exact_match(self):
        blocklist, _ = sc.load_blocklist()
        rows, meta = sc.check(REQ_NPM, "npm", blocklist)
        self.assertEqual(meta["poisoned"], 1)
        high = [r for r in rows if r["severity"] == "high"]
        self.assertIn("tensorlake/tensorlake==0.5.144", high[0]["title"])
        self.assertEqual(meta["unpinned"], 1)  # left-pad

    def test_missing_blocklist_is_fail_closed(self):
        sc.BLOCKLIST_PATH = self.tmp / "tidak-ada.json"
        blocklist, rejected = sc.load_blocklist()
        self.assertEqual(blocklist, [])
        self.assertTrue(rejected)
        rows, meta = sc.check("requests==2.31.0\n", "pypi", [])
        self.assertEqual(meta["poisoned"], 0)  # tanpa blocklist = tidak
        # diklaim bersih — poisoned_hits nol karena memang dilewati
        self.assertEqual(meta["blocklist_entries"], 0)

    def test_parse_line_variants(self):
        self.assertIsNone(sc.parse_line("# comment", "pypi"))
        self.assertIsNone(sc.parse_line("", "pypi"))
        p = sc.parse_line("flask[async]==2.3.0", "pypi")
        self.assertEqual((p["package"], p["version"]), ("flask", "2.3.0"))
        p = sc.parse_line("@scope/name@1.0.0", "npm")
        self.assertEqual((p["package"], p["version"]),
                         ("scope/name", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
