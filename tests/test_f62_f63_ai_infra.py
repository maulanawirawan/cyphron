"""Test F62+F63 — mcp-exposure + ollama-posture + rantai KB Probllama.

NOL jaringan (urlopen di-mock). Yang dikunci:
  - mcp-exposure: /sse endpoint-event = L1; /mcp JSON-RPC error shape =
    L1; token 'mcp' word-boundary dihitum, tanpa marker = AMAN; semua
    probe gagal jaringan = tanpa klaim AMAN;
  - ollama-posture: /api/version + /api/tags = L1 + fakta "ollama
    <versi>" bersebelahan; shape /api/tags tanpa token = kandidat;
    nama model TIDAK dimuat (jumlah saja); tanpa marker = AMAN;
  - rantai KB Probllama CVE-2024-37032: ollama 0.1.33 in-range = lead
    terikat versi; 0.1.34 / 0.3.4 patched = tanpa klaim KB (zero-FP);
  - kontrak findings.json valid di SEMUA baris.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import mcp_exposure as mx  # noqa: E402
import ollama_posture as op  # noqa: E402
import cve_matcher as cm  # noqa: E402
from findings import validate_finding  # noqa: E402

KB = json.load(open(ROOT / "assets/intel/cve-kb.json",
                    encoding="utf-8"))["entries"]


def kb_valid():
    out = []
    for e in KB:
        fixed = cm.parse_version(str(e["fixed"]))
        if fixed is None:
            continue
        out.append({**e, "_product": cm.norm_text(e["product"]),
                    "_fixed": fixed,
                    "_introduced": (cm.parse_version(e["introduced"])
                                    if e.get("introduced") else None)})
    return out


def _fact_row(tool: str, text: str):
    return {"tool": tool, "response": text, "title": text,
            "status": "confirmed", "target_url": "http://t.local",
            "extra": {}}


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


class _UrlOpenMixin:
    def _patch(self, skill, bodies, status=200):
        def fake_urlopen(req, timeout=None):
            path = req.full_url.split("://", 1)[1]
            path = "/" + path.split("/", 1)[1] if "/" in \
                path.split("://", 1)[-1] else "/"
            for key, body in bodies.items():
                if path.startswith(key):
                    resp = _FakeResp(body.encode())
                    resp.status = status
                    resp.headers = {"content-type": "text/html"}
                    return resp
            resp = _FakeResp(b"not found")
            resp.status = 404
            resp.headers = {}
            return resp
        return patch.object(skill.urllib.request, "urlopen",
                            fake_urlopen)


# ------------------------------------------------------- mcp-exposure

class McpExposureTest(_UrlOpenMixin, unittest.TestCase):
    def test_sse_endpoint_event_is_l1(self):
        bodies = {"/sse": "event: endpoint\r\ndata: /messages/?session_id"
                          "=abc123\r\n\r\n",
                  "/mcp": "404", "/messages": "405"}
        with self._patch(mx, bodies):
            rows, meta = mx.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["category"], "AI")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_jsonrpc_error_shape_on_mcp_is_candidate(self):
        bodies = {"/sse": "404",
                  "/mcp": '{"jsonrpc":"2.0","error":{"code":-32600,'
                          '"message":"Not Allowed"}}',
                  "/messages": "405"}
        with self._patch(mx, bodies):
            rows, meta = mx.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 1)

    def test_no_marker_is_aman(self):
        bodies = {"/sse": "<html>plain page</html>",
                  "/mcp": "<html>nothing</html>",
                  "/messages": "<html>x</html>"}
        with self._patch(mx, bodies):
            rows, meta = mx.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_all_network_error_no_aman_claim(self):
        def fake_urlopen(req, timeout=None):
            raise OSError("conn refused")
        with patch.object(mx.urllib.request, "urlopen", fake_urlopen):
            rows, meta = mx.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertTrue(rows[0].get("network_error"))
        self.assertNotIn("AMAN/inventaris", rows[0]["description"])


# ----------------------------------------------------- ollama-posture

class OllamaPostureTest(_UrlOpenMixin, unittest.TestCase):
    def test_version_and_tags_detected_with_fact(self):
        bodies = {"/api/version": '{"version":"0.1.33"}',
                  "/api/tags": '{"models":[{"name":"llama3:latest",'
                               '"digest":"sha256:abc","size":1}]}',
                  }
        with self._patch(op, bodies):
            rows, meta = op.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["0.1.33"])
        self.assertEqual(meta["models_count"], 1)
        self.assertEqual(rows[0]["verdict"], 1)
        # fakta bersebelahan utk version_near_token
        self.assertIn("ollama 0.1.33", rows[1]["title"].lower())
        # nama model TIDAK dimuat (jumlah saja)
        self.assertNotIn("llama3", rows[0]["title"])
        self.assertNotIn("llama3", rows[0]["description"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_shape_only_without_token_is_candidate(self):
        bodies = {"/api/version": "404",
                  "/api/tags": '{"models":[{"name":"qwen2:7b",'
                               '"digest":"sha256:def","size":2}]}',
                  }
        with self._patch(op, bodies):
            rows, meta = op.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], [])

    def test_no_marker_is_aman(self):
        bodies = {"/api/version": "404", "/api/tags": "404"}
        with self._patch(op, bodies):
            rows, meta = op.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_kb_probllama_in_range_and_patched(self):
        valid = [e for e in kb_valid() if e["cve"] == "CVE-2024-37032"]
        self.assertEqual(len(valid), 1)

        def probe(version):
            rows = [_fact_row("ollama-posture",
                              f"ollama {version} API terdeteksi di t")]
            out, _ = cm.match_cves(rows, [], valid)
            return [r for r in out if r.get("via") == "operator-kb"]

        self.assertEqual(len(probe("0.1.33")), 1)   # rentan
        self.assertEqual(probe("0.1.34"), [])       # fix zero-FP
        self.assertEqual(probe("0.3.4"), [])        # fix jauh di atas
        self.assertEqual(len(probe("0.0.1")), 1)    # legacy


if __name__ == "__main__":
    unittest.main()
