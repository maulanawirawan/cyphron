"""Test F36 — batch 9 (penutup sisa antrian yang bisa dikerjakan):
2 playbook (api-version-auth, session-invalidation tier-2) + skill
favicon-fingerprint (mmh3 stdlib clean-room).

NOL jaringan eksternal (lab 127.0.0.1 + mock). Yang dikunci:
  - mmh3_x86_32: vektor TERVERIFIKASI terhadap referensi resmi
    (mmh3 5.3.1, sesi riset — kosong=0, hello=613153351, seed 42,
    tail 11/12 byte) + properti (deterministik, seed-sensitif);
  - favicon-fingerprint: 200 = L1 inventaris hash; 404 = AMAN;
    gagal jaringan = unconfirmed;
  - api-version-auth: versi lama terbuka + versi baru menolak + marker
    owner = L3 (CWE-284); semua terbuka -> L0 (bukan regresi antar
    versi); semua menolak -> L0 (auth ditegakkan); path <2 / >bounded
    -> fail-closed; marker tidak muncul -> L0;
  - session-invalidation (tier-2): sid lama tetap hidup setelah logout
    = L3 (CWE-613); kontrol secure mematikan sesi; kontrol ikut
    meninggalkan sesi -> L0; logout yang mengakhiri sesi -> L0.
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

import favicon_fingerprint as ff   # noqa: E402
import exploit_engine as ee        # noqa: E402
import exploit_playbooks as ep     # noqa: E402
import lab_target                  # noqa: E402
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
        # F44+F46: +1 skill (llm-endpoint-surface) + 3 playbook
        # (prompt-injection, llm-output, rag-poisoning) -> 75 / 38
        self.assertGreaterEqual(len(REG["skills"]), 86)
        self.assertEqual(len(ep.PLAYBOOKS), 38)
        by = {s["name"]: s for s in REG["skills"]}
        self.assertEqual(by["favicon-fingerprint"]["safety_class"],
                         "1-request")
        self.assertEqual(ep.PLAYBOOKS["session-invalidation"].tier, 2)
        for name in ("api-version-auth", "session-invalidation"):
            self.assertFalse(ep.PLAYBOOKS[name].techniques & ep.NEVER_LIST,
                             name)


class Mmh3Test(unittest.TestCase):
    """Vektor terverifikasi terhadap referensi resmi (pip mmh3 5.3.1
    dipakai SEKALI di sesi riset untuk mencatat nilai; kode produk
    stdlib murni, tanpa dependensi)."""

    def test_reference_vectors(self):
        self.assertEqual(ff.mmh3_x86_32(b""), 0)
        self.assertEqual(ff.mmh3_x86_32(b"hello"), 613153351)
        self.assertEqual(ff.mmh3_x86_32(b"hello", 42), -488910111)
        self.assertEqual(ff.mmh3_x86_32(b"abc"), -1277324294)
        self.assertEqual(ff.mmh3_x86_32(b"1234567890a"), 236820539)
        self.assertEqual(ff.mmh3_x86_32(b"1234567890ab"), -2041382245)
        self.assertEqual(ff.favicon_hash(b"\x89PNG fake icon data here"),
                         1187273902)

    def test_properties(self):
        self.assertEqual(ff.mmh3_x86_32(b"abc"), ff.mmh3_x86_32(b"abc"))
        self.assertNotEqual(ff.mmh3_x86_32(b"abc", 1),
                            ff.mmh3_x86_32(b"abc", 0))
        self.assertNotEqual(ff.mmh3_x86_32(b"x"), ff.mmh3_x86_32(b"y"))
        self.assertEqual(ff.mmh3_x86_32(b"\x00" * 4),
                         ff.mmh3_x86_32(b"\x00" * 4))


class FaviconFingerprintTest(unittest.TestCase):
    def test_200_is_l1_inventory(self):
        rows, meta = ff.audit(URL, {"status": 200,
                                    "content_type": "image/x-icon",
                                    "body": b"\x00\x00\x01\x00icon"})
        self.assertEqual(meta["hash"], ff.favicon_hash(b"\x00\x00\x01\x00icon"))
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["category"], "SURFACE")

    def test_404_is_aman(self):
        rows, meta = ff.audit(URL, {"status": 404, "body": b"",
                                    "content_type": ""})
        self.assertIsNone(meta["hash"])
        self.assertEqual(one(rows, "tidak ada favicon")["verdict"], 0)

    def test_network_error_unconfirmed(self):
        rows, meta = ff.audit(URL, {"status": None, "body": b"",
                                    "error": "URLError"})
        self.assertTrue(meta.get("error"))
        self.assertEqual(rows[0]["status"], "unconfirmed")


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class Batch9E2E(LabTestCase):
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

    # --- api-version-auth ------------------------------------------------

    def test_api_version_auth_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v1/orders/1002",
                                           "/api/v2/orders/1002"],
                                 "marker": "bob@example.com"}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-284")
            self.assertTrue(rows[0]["reportable"])
            self.assertEqual(rows[0]["open_paths"],
                             ["/api/v1/orders/1002"])
            self.assertEqual(rows[0]["protected_paths"],
                             ["/api/v2/orders/1002"])

    def test_api_version_auth_all_open_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v1/orders/1002",
                                           "/api/v1/orders/1002"],
                                 "marker": "bob@example.com"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("bukan regresi", rows[0]["title"])

    def test_api_version_auth_all_protected_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v2/orders/1002",
                                           "/api/v2/orders/1002"],
                                 "marker": "bob@example.com"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("auth ditegakkan", rows[0]["title"])

    def test_api_version_auth_single_path_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v1/orders/1002"],
                                 "marker": "bob@example.com"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn(">=2 path", rows[0]["title"])

    def test_api_version_auth_over_bound_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v1/orders/1002"] * 5,
                                 "marker": "bob@example.com"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("bounded", rows[0]["title"])

    def test_api_version_auth_marker_missing_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["api-version-auth"],
                             {"api-version-auth": {
                                 "paths": ["/api/v1/orders/1002",
                                           "/api/v2/orders/1002"],
                                 "marker": "bukan-marker-apa-pun"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak sesuai asumsi", rows[0]["title"])

    # --- session-invalidation ---------------------------------------------

    def test_session_invalidation_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-invalidation"],
                             {"session-invalidation": {}}, mode="mutate")
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-613")
            self.assertTrue(rows[0]["reportable"])

    def test_session_invalidation_secure_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-invalidation"],
                             {"session-invalidation": {
                                 "logout_path": "/logout-secure"}},
                             mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("invalidasi ditegakkan", rows[0]["title"])

    def test_session_invalidation_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["session-invalidation"],
                             {"session-invalidation": {
                                 "safe_logout_path": "/logout"}},
                             mode="mutate")
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
