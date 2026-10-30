"""Test F35 — batch 8 (penutup antrian konsolidasi): 4 playbook
(oauth-state, lockout-canary tier-2, session-fixation, sqli-time) +
3 skill (api-version-surface, cloud-bucket-exposure, github-leak-check).

NOL jaringan eksternal (lab 127.0.0.1 + mock). Yang dikunci:
  - oauth-state: state arbitrer diterima + sesi terbentuk = L3 (CWE-352);
    callback state-benar = baseline wajib; kontrol strict menerima
    state asal -> L0; state ditegakkan -> L0;
  - lockout-canary (tier-2, akun canary milik sendiri): login benar
    tetap sukses setelah N gagal = L3 (CWE-307); kontrol locked ikut
    menerima -> L0; threshold > 10 = fail-closed;
  - session-fixation: sid paksaan tetap autentik = L3 (CWE-384);
    baseline sid belum aktif wajib; kontrol meregenerasi; kontrol
    ikut-menerima -> L0;
  - sqli-time: guard FP timing ganda — 2 trial payload lambat + 2
    baseline cepat + kontrol safe = L3 (CWE-89); delta tidak konsisten
    -> L0; kontrol ikut tertunda -> L0;
  - skill: inventaris L1 / AMAN L0 / unconfirmed; github-leak-check
    tanpa token = dilewati (opt-in, nol request).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import api_version_surface as avs   # noqa: E402
import cloud_bucket_exposure as cbe  # noqa: E402
import github_leak_check as glc     # noqa: E402
import exploit_engine as ee         # noqa: E402
import exploit_playbooks as ep      # noqa: E402
import lab_target                   # noqa: E402
from findings import validate_finding  # noqa: E402

REG = json.loads((ROOT / "skills" / "registry.json")
                 .read_text(encoding="utf-8"))
URL = "https://lab.local/"
CREDS = {"username": "alice", "password": "alicepass"}


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class RegistryTest(unittest.TestCase):
    def test_entries(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        self.assertEqual(len(ep.PLAYBOOKS), 38)
        by = {s["name"]: s for s in REG["skills"]}
        for n in ("api-version-surface", "cloud-bucket-exposure",
                  "github-leak-check"):
            self.assertEqual(by[n]["safety_class"], "bounded-requests", n)
        pb = ep.PLAYBOOKS["lockout-canary"]
        self.assertEqual(pb.tier, 2)
        for name in ("oauth-state", "lockout-canary", "session-fixation",
                     "sqli-time"):
            self.assertFalse(ep.PLAYBOOKS[name].techniques & ep.NEVER_LIST,
                             name)


class ApiVersionSurfaceTest(unittest.TestCase):
    def test_alive_versions_l1(self):
        rows, meta = avs.audit(URL, {"/api/": {"status": 404, "body": ""},
                                     "/api/v1/": {"status": 200,
                                                  "body": "{}"},
                                     "/api/v2/": {"status": 401,
                                                  "body": "{}"}})
        self.assertEqual(meta["alive"], ["v1", "v2"])
        self.assertEqual(rows[0]["verdict"], 1)

    def test_404_is_not_alive(self):
        rows, meta = avs.audit(URL, {"/api/v1/": {"status": 404,
                                                  "body": ""}})
        self.assertEqual(meta["alive"], [])
        self.assertEqual(one(rows, "version surface")["verdict"], 0)

    def test_no_versions_aman(self):
        rows, meta = avs.audit(URL, {"/api/": {"status": 410,
                                               "body": ""}})
        self.assertEqual(meta["alive"], [])
        self.assertEqual(one(rows, "version surface")["verdict"], 0)

    def test_network_error_not_alive(self):
        rows, meta = avs.audit(URL, {"/api/": {"status": None,
                                               "error": "URLError",
                                               "body": ""}})
        self.assertEqual(meta["alive"], [])


class CloudBucketTest(unittest.TestCase):
    def test_listable_bucket_l1(self):
        rows, meta = cbe.audit("lab.example", {"results": {
            "https://lab-com.s3.amazonaws.com/": {
                "status": 200,
                "body": "<ListBucketResult><Key>a</Key></"
                        "ListBucketResult>"},
            "x": {"status": 404, "body": ""}}})
        self.assertEqual(meta["listable"],
                         ["https://lab-com.s3.amazonaws.com/"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertFalse(rows[0]["ownership_verified"])

    def test_not_listable_aman(self):
        rows, meta = cbe.audit("lab.example", {"results": {
            "https://lab-com.s3.amazonaws.com/": {"status": 403,
                                                  "body": ""}}})
        self.assertEqual(meta["listable"], [])
        self.assertEqual(one(rows, "posture")["verdict"], 0)

    def test_network_error_unconfirmed(self):
        rows, meta = cbe.audit("lab.example", {"results": {
            "https://lab-com.s3.amazonaws.com/": {
                "status": None, "error": "URLError", "body": ""}}})
        self.assertEqual(one(rows, "posture")["status"], "unconfirmed")

    def test_candidates_derive_from_domain(self):
        cands = cbe.bucket_candidates("www.lab.example")
        self.assertIn("lab-example", cands)
        self.assertIn("lab.example", cands)


class GithubLeakTest(unittest.TestCase):
    def test_skip_without_token(self):
        rows, meta = glc.audit("lab.example",
                               {"skipped": "opt-in: tanpa token",
                                "items": []})
        self.assertTrue(meta["skipped"])
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_hits_are_l1_leads(self):
        rows, meta = glc.audit("lab.example", {"skipped": None, "items": [
            {"html_url": "https://cfg.example/x", "repository": "a/b",
             "path": "config.py"}]})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["cwe"], "CWE-798")

    def test_no_hits_aman(self):
        rows, meta = glc.audit("lab.example", {"skipped": None, "items": []})
        self.assertEqual(one(rows, "no public hits")["verdict"], 0)


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class Batch8E2E(LabTestCase):
    def _run(self, tmp, playbooks, params, credentials=CREDS, mode="proof"):
        target = {"id": "lab", "base_url": self.base_url,
                  "exploit_allowed": True, "mode": mode,
                  "params": params}
        if credentials:
            target["credentials"] = credentials
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({"targets": [target],
                                   "playbooks": playbooks}),
                       encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    # --- oauth-state ------------------------------------------------------

    def test_oauth_state_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["oauth-state"], {"oauth-state": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-352")
            self.assertTrue(rows[0]["reportable"])

    def test_oauth_state_enforced_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["oauth-state"],
                             {"oauth-state": {
                                 "callback_path": "/oauth/callback-strict",
                                 "strict_callback_path":
                                 "/oauth/callback-strict"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("state ditegakkan", rows[0]["title"])

    def test_oauth_state_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["oauth-state"],
                             {"oauth-state": {
                                 "strict_callback_path":
                                 "/oauth/callback"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])

    # --- lockout-canary ---------------------------------------------------

    def test_lockout_canary_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["lockout-canary"],
                             {"lockout-canary": {}}, mode="mutate")
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-307")
            self.assertEqual(rows[0]["threshold"], 5)

    def test_lockout_control_enforced_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["lockout-canary"],
                             {"lockout-canary": {"login_path":
                                                 "/login-locked"}},
                             mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("lockout ditegakkan", rows[0]["title"])

    def test_lockout_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["lockout-canary"],
                             {"lockout-canary": {"locked_path": "/login"}},
                             mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])

    def test_lockout_over_bound_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["lockout-canary"],
                             {"lockout-canary": {"threshold": 11}},
                             mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("bounded", rows[0]["title"])

    # --- session-fixation -------------------------------------------------

    def test_session_fixation_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-fixation"],
                             {"session-fixation": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-384")
            self.assertTrue(rows[0]["reportable"])

    def test_session_fixation_secure_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-fixation"],
                             {"session-fixation": {"login_path": "/login"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("regenerasi ditegakkan", rows[0]["title"])

    def test_session_fixation_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-fixation"],
                             {"session-fixation": {
                                 "safe_login_path": "/login-fixated"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])

    # --- sqli-time ----------------------------------------------------------

    def test_sqli_time_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-time"], {"sqli-time": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-89")
            self.assertTrue(rows[0]["reportable"])
            self.assertEqual(rows[0]["category"], "SQLI")

    def test_sqli_time_no_delay_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["sqli-time"],
                             {"sqli-time": {"path": "/api/search-sleep-safe",
                                            "safe_path":
                                            "/api/search-sleep-safe"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("guard FP timing", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
