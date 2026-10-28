"""Test F56 — litellm-posture + rantai cve-matcher (KB operator + KEV).

NOL jaringan (urlopen di-mock). Yang dikunci:
  - marker eksplisit 'litellm' / shape /version (status+version) =
    L1 lead + fakta versi; tanpa marker = AMAN (3 GET);
  - rantai: baris litellm-posture -> cve-matcher: KEV BerriAI::
    LiteLLM (product-level) + KB operator CVE-2026-42208
    (1.81.16 <= v < 1.83.7) versi-in-range = lead terikat versi;
  - versi di luar rentang = tanpa klaim KB (zero-FP).
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

import litellm_posture as lp  # noqa: E402
import cve_matcher as cm  # noqa: E402
from findings import validate_finding  # noqa: E402


class _FakeResp(io.BytesIO):
    status = 200
    headers = {"content-type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self.getvalue()[:n] if n > 0 else self.getvalue()

    def items(self):
        return list(self.headers.items())


class UrlOpenTest(unittest.TestCase):
    def _patch(self, bodies: dict[str, str]):
        def fake_urlopen(req, timeout=None):
            path = req.full_url.split("://", 1)[1]
            path = "/" + path.split("/", 1)[1] if "/" in \
                path.split("://", 1)[-1] else "/"
            for key, body in bodies.items():
                if path.startswith(key) or (key == "/" and path == "/"):
                    return _FakeResp(body.encode())
            return _FakeResp(b"{}")
        return patch.object(lp.urllib.request, "urlopen", fake_urlopen)

    def test_litellm_token_marker_detected(self):
        bodies = {"/version": '{"status":"ok","version":"1.82.3",'
                              '"litellm_version":"1.82.3"}',
                  "/health/liveliness": '{"status":"healthy"}',
                  "/v1/models": "unauthorized"}
        with self._patch(bodies):
            rows, meta = lp.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["1.82.3"])
        lead = rows[0]
        self.assertEqual(lead["verdict"], 1)
        self.assertEqual(lead["category"], "AI")
        # baris fakta (rows[1]) membawa 'litellm <versi>' bersebelahan
        # utk cve-matcher (version_near_token)
        self.assertIn("litellm 1.82.3", rows[1]["title"].lower())
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_version_shape_alone_is_candidate(self):
        bodies = {"/version": '{"status":"ok","version":"1.83.2"}',
                  "/health/liveliness": "404",
                  "/v1/models": "404"}
        with self._patch(bodies):
            rows, meta = lp.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["1.83.2"])

    def test_no_marker_is_aman(self):
        bodies = {"/version": "404", "/health/liveliness": "404",
                  "/v1/models": "404"}
        with self._patch(bodies):
            rows, meta = lp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)


KEV_LITELLM = [
    {"cveID": "CVE-2026-42271", "vendorProject": "BerriAI",
     "product": "LiteLLM", "vulnerabilityName": "RCE",
     "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-78"]},
]


class MatcherChainTest(unittest.TestCase):
    def _rows(self, version):
        return [{"tool": "litellm-posture",
                 "title": f"litellm {version} proxy terdeteksi di t",
                 "response": "", "status": "confirmed",
                 "target_url": "http://t.local", "extra": {}}]

    def test_kb_version_in_range_binds_claim(self):
        kb = [{"product": "litellm", "cve": "CVE-2026-42208",
               "introduced": "1.81.16", "fixed": "1.83.7",
               "source_url": "https://example.com/advisory"}]
        valid = [{**e, "_product": cm.norm_text(e["product"]),
                  "_fixed": cm.parse_version(e["fixed"]),
                  "_introduced": cm.parse_version(e["introduced"])}
                 for e in kb]
        rows, meta = cm.match_cves(self._rows("1.82.3"), KEV_LITELLM,
                                   valid)
        kb_row = next(r for r in rows if r.get("via") == "operator-kb")
        self.assertEqual(kb_row["verdict"], 1)
        self.assertEqual(kb_row["version_detected"], "1.82.3")
        kev_rows = [r for r in rows if r.get("cve") == "CVE-2026-42271"]
        self.assertEqual(len(kev_rows), 1)

    def test_version_above_fixed_no_kb_claim(self):
        kb = [{"product": "litellm", "cve": "CVE-2026-42208",
               "introduced": "1.81.16", "fixed": "1.83.7",
               "source_url": "https://example.com/advisory"}]
        valid = [{**e, "_product": cm.norm_text(e["product"]),
                  "_fixed": cm.parse_version(e["fixed"]),
                  "_introduced": cm.parse_version(e["introduced"])}
                 for e in kb]
        rows, meta = cm.match_cves(self._rows("1.83.7"), KEV_LITELLM,
                                   valid)
        self.assertEqual(
            [r for r in rows if r.get("via") == "operator-kb"], [])
        # KEV product-level lead tetap muncul (fakta, bukan klaim rentang)
        self.assertTrue(any(r.get("cve") == "CVE-2026-42271"
                            for r in rows))


if __name__ == "__main__":
    unittest.main()
