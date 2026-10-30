"""Test F34 — batch 7 (antrian konsolidasi): 4 playbook (ssrf-chain,
xxe-file, cache-poison, idor-mass) + perluasan cors-checker
wildcard-subdomain.

NOL jaringan eksternal (lab 127.0.0.1 + mock). Yang dikunci:
  - ssrf-chain: marker unik ter-echo service internal VIA fetch (L3);
    kontrol fetch-safe menolak internal; kontrol ikut-menjangkau -> L0;
  - xxe-file: isi canary terbaca in-band via entity file:// (L3);
    baseline tanpa entity wajib bersih; kontrol parser aman menolak
    DOCTYPE; safe-ikut-mengembalikan canary -> L0;
  - cache-poison: header unkeyed direfleksikan lalu dilayani cache ke
    request tanpa header (L3); cleanup evict terdaftar; kontrol safe
    invarian header; refleksi tidak tersimpan -> L0;
  - idor-mass: >=2 endpoint dengan bug ownership sama (L4); 1 endpoint
    -> L0 (pakai idor-orders); bounded 8 endpoint (fail-closed);
  - cors-checker: suffix trust + credentials = L2; tanpa refleksi =
    AMAN; tanpa suffix = perilaku lama utuh (backward compatible).
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

import cors_checker as cc        # noqa: E402
import exploit_engine as ee      # noqa: E402
import exploit_playbooks as ep   # noqa: E402
import lab_target                # noqa: E402
from findings import validate_finding  # noqa: E402

REG = json.loads((ROOT / "skills" / "registry.json")
                 .read_text(encoding="utf-8"))
URL = "https://lab.local/"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class RegistryTest(unittest.TestCase):
    def test_entries(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        self.assertEqual(len(ep.PLAYBOOKS), 38)
        for name in ("ssrf-chain", "xxe-file", "cache-poison", "idor-mass"):
            pb = ep.PLAYBOOKS[name]
            self.assertEqual(pb.tier, 1, name)
            self.assertFalse(pb.techniques & ep.NEVER_LIST, name)


class CorsSuffixTest(unittest.TestCase):
    def test_subdomain_trust_with_credentials_is_l2(self):
        res = {"status": 200, "headers": {},
               "sub": {"origin": "https://evil-probe.lab.local",
                       "status": 200,
                       "headers": {
                           "access-control-allow-origin":
                           "https://evil-probe.lab.local",
                           "access-control-allow-credentials": "true"}}}
        rows, meta = cc.audit(URL, res, origin_suffix="lab.local")
        self.assertTrue(meta["subdomain_reflected"])
        self.assertEqual(meta["requests"], 2)
        f = one(rows, "subdomain wildcard")
        self.assertEqual(f["verdict"], 2)
        self.assertEqual(f["cwe"], "CWE-942")

    def test_no_reflection_is_aman(self):
        res = {"status": 200, "headers": {},
               "sub": {"origin": "https://evil-probe.lab.local",
                       "status": 200, "headers": {}}}
        rows, meta = cc.audit(URL, res, origin_suffix="lab.local")
        self.assertFalse(meta["subdomain_reflected"])
        self.assertEqual(one(rows, "not trusted")["verdict"], 0)

    def test_backward_compatible_without_suffix(self):
        rows, meta = cc.audit(URL, {"status": 200, "headers": {}})
        self.assertNotIn("subdomain_reflected", meta)
        self.assertEqual(meta["requests"], 1)


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class Batch7E2E(LabTestCase):
    def _run(self, tmp, playbooks, params, credentials=None):
        target = {"id": "lab", "base_url": self.base_url,
                  "exploit_allowed": True, "mode": "proof",
                  "params": params}
        if credentials:
            target["credentials"] = credentials
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps({
            "targets": [target],
            "playbooks": playbooks}), encoding="utf-8")
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    # --- ssrf-chain -----------------------------------------------------

    def test_ssrf_chain_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["ssrf-chain"], {"ssrf-chain": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-918")
            self.assertTrue(rows[0]["reportable"])
            self.assertIn("ssrf-chain-", rows[0]["request"])

    def test_ssrf_chain_control_leaks_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["ssrf-chain"],
                             {"ssrf-chain": {"safe_fetch_path": "/fetch"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak dapat dipercaya", rows[0]["title"])

    # --- xxe-file ---------------------------------------------------------

    def test_xxe_file_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["xxe-file"],
                             {"xxe-file": {"path": "/api/xml2",
                                           "safe_path": "/api/xml2-safe",
                                           "entity": "file://canary-lfi.txt",
                                           "canary_content":
                                           lab_target.LFI_CANARY}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-611")
            self.assertTrue(rows[0]["reportable"])
            self.assertIn(lab_target.LFI_CANARY, rows[0]["response"])

    def test_xxe_file_safe_parser_control_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["xxe-file"],
                             {"xxe-file": {"path": "/api/xml2-safe",
                                           "safe_path": "/api/xml2-safe",
                                           "entity": "file://canary-lfi.txt",
                                           "canary_content":
                                           lab_target.LFI_CANARY}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])

    def test_xxe_file_wrong_canary_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["xxe-file"],
                             {"xxe-file": {"path": "/api/xml2",
                                           "entity": "file://canary-lfi.txt",
                                           "canary_content": "bukan-isi"}})
            self.assertEqual(rows[0]["verdict"], 0)

    # --- cache-poison -----------------------------------------------------

    def test_cache_poison_proven_l3(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["cache-poison"],
                             {"cache-poison": {}})
            self.assertEqual(rows[0]["verdict"], 3)
            self.assertEqual(rows[0]["cwe"], "CWE-444")
            self.assertTrue(rows[0]["reportable"])
            self.assertEqual(rows[0]["category"], "CACHE")

    def test_cache_poison_no_reflection_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["cache-poison"],
                             {"cache-poison": {"path_prefix":
                                               "/cache-safe-header/"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("tidak direfleksikan", rows[0]["title"])

    # --- idor-mass --------------------------------------------------------

    def test_idor_mass_proven_l4(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["idor-mass"],
                             {"idor-mass": {
                                 "endpoints": ["/api/orders/{id}",
                                               "/api/tickets/{id}"],
                                 "own_id": "1001", "other_id": "1002",
                                 "other_owner_email": "bob@example.com"}},
                             credentials={"username": "alice",
                                          "password": "alicepass"})
            self.assertEqual(rows[0]["verdict"], 4)
            self.assertEqual(rows[0]["cwe"], "CWE-639")
            self.assertEqual(len(rows[0]["endpoints"]), 2)
            self.assertFalse(rows[0]["unauthenticated"])

    def test_idor_mass_single_endpoint_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["idor-mass"],
                             {"idor-mass": {
                                 "endpoints": ["/api/orders/{id}"],
                                 "own_id": "1001", "other_id": "1002",
                                 "other_owner_email": "bob@example.com"}},
                             credentials={"username": "alice",
                                          "password": "alicepass"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("idor-orders", rows[0]["title"])

    def test_idor_mass_over_bound_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            eps = ["/api/orders/{id}"] * 9
            rows = self._run(Path(td), ["idor-mass"],
                             {"idor-mass": {"endpoints": eps,
                                            "own_id": "1001",
                                            "other_id": "1002",
                                            "other_owner_email":
                                            "bob@example.com"}},
                             credentials={"username": "alice",
                                          "password": "alicepass"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("bounded", rows[0]["title"])

    def test_idor_mass_no_hit_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            rows = self._run(Path(td), ["idor-mass"],
                             {"idor-mass": {
                                 "endpoints": ["/api/profile/{id}"],
                                 "own_id": "1001", "other_id": "1002",
                                 "other_owner_email": "bob@example.com"}},
                             credentials={"username": "alice",
                                          "password": "alicepass"})
            self.assertEqual(rows[0]["verdict"], 0)


if __name__ == "__main__":
    unittest.main()
