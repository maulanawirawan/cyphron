"""Test F27 — VDP pipeline + xss-reflect-check (jalur lapor resmi).

Pipa recon klasik (subfinder/httpx/katana/dalfox) versi Cyphron:
policy-gated, bounded, zero-FP. Yang dikunci (mock, NOL jaringan):
  - xss-reflect-check: marker mentah di HTML = L2 lead; escaped /
    konteks non-HTML / error = bukan temuan; --scope-ack wajib;
  - alive inventory: host hidup tanpa header proteksi = lead postur,
    host mati tercatat (padanan split mati/hidup);
  - pipa: fail-closed tanpa program; stage xss DITOLAK tanpa
    --scope-ack dan untuk program belum accepted.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import xss_reflect_check as xrc          # noqa: E402
import vdp_pipeline as vp                # noqa: E402

URL = "https://lab.local/search"
MARKER = "xss-canary-abcdef123456"
REG = json.loads((ROOT / "skills" / "registry.json").read_text("utf-8"))


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


def _res(status=200, ctype="text/html; charset=utf-8", body="x"):
    return {"status": status, "content_type": ctype, "body": body}


class XssReflectCheckTest(unittest.TestCase):
    def test_raw_reflection_in_html_is_l2_lead(self):
        res = {"q": _res(body=f"<p>hasil: <{MARKER}></p>")}
        rows, meta = xrc.audit(URL, res, MARKER)
        f = one(rows, "Raw HTML reflection")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-79")
        self.assertFalse(f["reportable"], "L2 lead = belum reportable")
        self.assertEqual(meta["reflected"], ["q"])
        self.assertEqual(meta["requests"], 1)

    def test_escaped_or_non_html_is_not_lead(self):
        res = {"q": _res(body=f"<p>hasil: &lt;{MARKER}&gt;</p>"),
               "page": _res(ctype="application/json",
                            body=f'{{"q": "<{MARKER}>"}}'),
               "f": _res(status=404, body="")}
        rows, meta = xrc.audit(URL, res, MARKER)
        self.assertIsNone(one(rows, "Raw HTML reflection"))
        self.assertEqual(meta["reflected"], [])
        self.assertEqual(one(rows, "posture")["verdict"], 0)

    def test_transport_error_fail_closed(self):
        res = {"q": {"status": None, "error": "URLError",
                     "content_type": "", "body": ""}}
        rows, _ = xrc.audit(URL, res, MARKER)
        self.assertEqual(one(rows, "Probe failed")["title"],
                         f"Probe failed on {URL} param 'q'")

    def test_scope_ack_required_fail_closed(self):
        import subprocess
        import tempfile
        out = Path(tempfile.gettempdir()) / "xrc-scope-test.json"
        r = subprocess.run(
            [sys.executable, str(ROOT / "skills" / "xss_reflect_check.py"),
             "--url", URL, "--param", "q", "--out", str(out)],
            capture_output=True, text=True, timeout=30, cwd=str(ROOT))
        self.assertEqual(r.returncode, 3)
        self.assertIn("scope-ack", (r.stderr or ""))

    def test_registry_entry(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        s = next(x for x in REG["skills"]
                 if x["name"] == "xss-reflect-check")
        self.assertEqual(s["safety_class"], "active-probe")
        self.assertTrue(s.get("lab_only"), "tier0 tidak boleh menjalankan")
        self.assertIn("--scope-ack", s["cmd"])
        self.assertTrue((ROOT / s["cmd"][1]).exists())


class InventoryAuditTest(unittest.TestCase):
    def test_alive_without_headers_is_lead_and_dead_recorded(self):
        results = {
            "a." + "lab.local": {"alive": True, "status": 200,
                                 "hsts": True, "xfo": True, "csp": True,
                                 "server": "nginx", "content_type": ""},
            "b." + "lab.local": {"alive": True, "status": 200,
                                 "hsts": False, "xfo": False, "csp": False,
                                 "server": "nginx", "content_type": ""},
            "c." + "lab.local": {"alive": False, "error": "URLError"},
        }
        rows, meta = vp.audit_inventory("lab.local", results)
        self.assertEqual(set(meta["alive"]),
                         {"a." + "lab.local", "b." + "lab.local"})
        self.assertEqual(meta["dead"], ["c." + "lab.local"])
        f = one(rows, "Security headers missing")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertIn("b." + "lab.local", f["target_url"])
        self.assertEqual(meta["requests"], 3)

    def test_all_protected_is_no_lead(self):
        results = {"a.lab.local": {"alive": True, "status": 200,
                                   "hsts": True, "xfo": True, "csp": True,
                                   "server": "", "content_type": ""}}
        rows, meta = vp.audit_inventory("lab.local", results)
        self.assertEqual([r for r in rows if r["verdict"] >= 1], [])
        self.assertEqual(meta["alive"], ["a.lab.local"])


class ExtractCandidatesTest(unittest.TestCase):
    def test_json_array_and_meta_and_wildcard(self):
        doc = {"findings": [{"response": '["*.x.go.id", "api.x.go.id", '
                                         '"nope.example.com"]'}],
               "data": {"hostnames": ["cms.x.go.id", "*.x.go.id"]}}
        cands = vp._extract_candidates(doc, "x.go.id")
        self.assertEqual(cands, ["api.x.go.id", "cms.x.go.id"])


class PipelineGateTest(unittest.TestCase):
    def test_unknown_program_fails_closed(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "vdp_pipeline.py"),
             "--program", "tidak-ada"],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fail-closed", (r.stdout + r.stderr))

    def test_discover_params_bounds_and_filters(self):
        html = ('<form><input name="q"><input name="csrf">'
                '<input name="password">'
                '<input name="page"><a href="/x?ref=abc&ref2=def">a</a>'
                "</form>")
        params = vp.discover_params("https://h/", html)
        self.assertNotIn("csrf", params)
        self.assertNotIn("password", params)
        self.assertIn("q", params)
        self.assertIn("page", params)
        self.assertLessEqual(len(params), vp.MAX_XSS_PARAMS)


if __name__ == "__main__":
    unittest.main()
