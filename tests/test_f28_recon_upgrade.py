"""Test F28 — upgrade ekosistem 2026: 4 skill baru dari riset tools
terkini (Arjun / waymore-gau / Subzy / smuggler), dibangun clean-room
lewat pipeline wajib. Mock, NOL jaringan; yang dikunci:
  - param-probe: kontrol ganda (baseline+random) — identik = bukan
    temuan; refleksi L2; perubahan perilaku L1; kontrol gagal = stop;
  - archive-url: klasifikasi murni string; live-check hanya faktum
    status; L2 hanya pola sensitif masih 200;
  - takeover-fingerprint: L2 hanya bila signature persis; 404 generik
    bukan temuan;
  - smuggling-clue: CL duplikat/CL+TE/TE aneh = lead; konsisten = L0;
    NOL request (pasif).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import param_probe_checker as ppc          # noqa: E402
import archive_url_checker as auc          # noqa: E402
import takeover_fingerprint_checker as tfc  # noqa: E402
import smuggling_clue_checker as scc       # noqa: E402

URL = "https://lab.local/api"
REG = json.loads((ROOT / "skills" / "registry.json").read_text("utf-8"))
MARKER = "pp-0123456789abcdef"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


def _r(status, body, length=None):
    return {"status": status, "len": len(body) if length is None else length,
            "body": body}


class ParamProbeTest(unittest.TestCase):
    def test_reflected_param_is_l2(self):
        base = _r(200, "<html>ok</html>")
        res = {"baseline": base,
               "control": dict(base),
               "debug": _r(200, f"<html>ok {MARKER}</html>")}
        rows, meta = ppc.audit(URL, res, MARKER)
        f = one(rows, "accepted+reflected")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-471")
        self.assertEqual(meta["reflected"] if "reflected" in meta
                         else [a["param"] for a in meta["accepted"]], ["debug"])

    def test_identical_to_baseline_or_control_is_not_lead(self):
        base = _r(200, "<html>ok</html>")
        res = {"baseline": base,
               "control": dict(base),
               "debug": dict(base),          # identik baseline
               "admin": _r(200, "wildcard-page", length=1)}  # identik ctrl panjang? buat eksplisit
        res["admin"] = {"status": 200, "len": base["len"],
                        "body": "wildcard-same-length"}
        rows, meta = ppc.audit(URL, res, MARKER)
        self.assertIsNone(one(rows, "Hidden param"))
        self.assertEqual(meta["accepted"], [])

    def test_wildcard_control_reflection_downgrades_leads(self):
        res = {"baseline": _r(200, "<html>ok</html>"),
               "control": _r(200, f"<html>echo {MARKER}</html>"),
               "debug": _r(200, f"<html>ok {MARKER}</html>"),
               "admin": _r(200, f"<html>ok {MARKER}</html>")}
        rows, meta = ppc.audit(URL, res, MARKER)
        self.assertIsNone(one(rows, "accepted+reflected"),
                          "wildcard: klaim per-param harus batal")
        self.assertIsNone(one(rows, "changes behavior"))
        w = one(rows, "Wildcard query reflection")
        self.assertIsNotNone(w)
        self.assertEqual(w["verdict"], 1)
        self.assertEqual(meta["accepted"], [])

    def test_control_failed_stops_fail_closed(self):
        res = {"baseline": _r(200, "ok"),
               "control": {"status": None, "len": 0, "error": "URLError",
                           "body": ""},
               "debug": _r(200, f"x {MARKER}")}
        rows, meta = ppc.audit(URL, res, MARKER)
        self.assertIsNone(one(rows, "Hidden param"))
        self.assertTrue(meta.get("error"))
        self.assertEqual(one(rows, "Control failed")["verdict"], 1)

    def test_behavior_change_is_l1(self):
        base = _r(200, "<html>ok</html>")
        res = {"baseline": base,
               "control": dict(base),
               "internal": {"status": 500, "len": 40, "body": "err"},
               "role": {"status": 302, "len": 0, "body": ""}}
        rows, meta = ppc.audit(URL, res, MARKER)
        self.assertEqual(len([r for r in rows if r["verdict"] == 1
                              and "changes behavior" in r["title"]]), 2)
        self.assertIsNone(one(rows, "accepted+reflected"))


class ArchiveUrlTest(unittest.TestCase):
    CDX = {"ok": True, "urls": [
        "https://lab.local/api/v1/users",
        "https://lab.local/admin/panel",
        "https://lab.local/.env.bak",
        "https://lab.local/db.sql",
        "https://lab.local/normal/page",
    ]}

    def test_classification_is_string_only(self):
        c = auc.classify(self.CDX["urls"])
        self.assertTrue(any("/api/" in u for u in c["api-surface"]))
        self.assertEqual(len(c["config-secret"]), 1)
        self.assertEqual(len(c["backup-dump"]), 2)  # .env.bak masuk dua kelas
        self.assertNotIn("https://lab.local/normal/page",
                         [u for v in c.values() for u in v])

    def test_sensitive_pattern_is_l1_and_live_200_is_l2(self):
        rows, meta = auc.audit("lab.local", self.CDX,
                               auc.classify(self.CDX["urls"]),
                               {"https://lab.local/.env.bak":
                                {"status": 200}})
        self.assertEqual(len([r for r in rows if r["verdict"] == 1
                              and "pattern in archive" in r["title"]]), 2)
        f = one(rows, "still live")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(meta["live_checked"], 1)

    def test_cdx_failure_is_fail_closed(self):
        rows, meta = auc.audit("lab.local", {"ok": False, "error": "X"},
                               {}, None)
        self.assertTrue(meta.get("error"))
        self.assertEqual(one(rows, "CDX fetch failed")["verdict"], 1)
        self.assertEqual(len(rows), 1)


class TakeoverFingerprintTest(unittest.TestCase):
    def test_github_pages_signature_is_l2(self):
        probe = {"requests": 1, "responses": [
            {"scheme": "https", "status": 404,
             "body_head": "There isn't a GitHub Pages site here."}]}
        rows, meta = tfc.audit("sub.lab.local", probe)
        f = one(rows, "Unclaimed service fingerprint")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-350")
        self.assertEqual(meta["matched"], "github-pages")

    def test_generic_404_is_not_a_claim(self):
        probe = {"requests": 1, "responses": [
            {"scheme": "https", "status": 404,
             "body_head": "<html><body>404 Not Found nginx</body></html>"}]}
        rows, meta = tfc.audit("sub.lab.local", probe)
        self.assertIsNone(one(rows, "Unclaimed"))
        self.assertIsNone(meta["matched"])
        self.assertEqual(one(rows, "No unclaimed")["verdict"], 0)


class SmugglingClueTest(unittest.TestCase):
    def test_cl_te_combo_is_lead(self):
        rows, meta = scc.audit(URL, {"Content-Length": "5",
                                     "Transfer-Encoding": "chunked"})
        f = one(rows, "smuggling clue")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-444")
        self.assertEqual(meta["requests"], 0)

    def test_duplicate_cl_conflict_is_lead(self):
        rows, _ = scc.audit(URL, {"Content-Length": ["5", "7"]})
        self.assertIsNotNone(one(rows, "smuggling clue"))

    def test_consistent_headers_is_l0(self):
        rows, meta = scc.audit(URL, {"Content-Length": "5"})
        self.assertEqual(one(rows, "No smuggling clue")["verdict"], 0)
        self.assertEqual(meta["clues"], [])


class RateLimitCliTest(unittest.TestCase):
    def test_cli_smoke_local_fail_fast(self):
        import subprocess
        import tempfile
        out = Path(tempfile.mkdtemp()) / "rl.json"
        r = subprocess.run(
            [sys.executable, str(ROOT / "skills" / "rate_limit_validator.py"),
             "--url", "http://127.0.0.1:1/login", "--attempts", "1",
             "--lab", "--out", str(out)],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(doc["ok"])
        self.assertIn("requests", json.dumps(doc["data"]))


class RdapTransferLockFpTest(unittest.TestCase):
    """FP regression 2026-10-18: PIR menulis status dengan spasi —
    skill pernah salah klaim 'NOT locked' untuk domain TERKUNCI."""

    def test_pir_space_style_is_locked_aman(self):
        import rdap_whois as rw
        doc = {"status": ["client delete prohibited",
                          "client transfer prohibited"],
               "events": [], "nameservers": []}
        rows, _ = rw.audit("lab.local", doc=doc)
        f = [r for r in rows if "transfer" in r["title"].lower()]
        self.assertTrue(any("NOT locked" not in r["title"] and
                            "terkunci" in (r["description"] or "")
                            for r in f), [r["title"] for r in f])
        self.assertFalse(any("NOT locked" in r["title"] for r in f))

    def test_camelcase_still_detected(self):
        import rdap_whois as rw
        doc = {"status": ["clientTransferProhibited"], "events": [],
               "nameservers": []}
        rows, _ = rw.audit("lab.local", doc=doc)
        self.assertFalse(any("NOT locked" in r["title"]
                             for r in rows))


class RegistryF28Test(unittest.TestCase):
    def test_four_new_entries_valid(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        by_name = {s["name"]: s for s in REG["skills"]}
        for name, cls in (("param-probe-checker", "bounded-requests"),
                          ("archive-url-checker", "bounded-requests"),
                          ("takeover-fingerprint-checker",
                           "bounded-requests"),
                          ("smuggling-clue-checker", "read-only")):
            s = by_name[name]
            self.assertEqual(s["safety_class"], cls)
            self.assertTrue((ROOT / s["cmd"][1]).exists(), s["cmd"][1])


if __name__ == "__main__":
    unittest.main()
