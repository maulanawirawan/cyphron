"""Test F26 — konsolidasi katalog batch 1 (docs/CATALOG-CONSOLIDATION.md).

Port playbook terbukti dari Cyphron-legacy lewat pipeline wajib:
ssti-eval (CWE-1336), lfi-traversal (CWE-22), nosqli-login (CWE-943).
NOL jaringan eksternal — lawan uji lab_target 127.0.0.1 port ephemeral.
Yang dikunci:
  - 3 playbook terbukti L3 di lab via engine (kontrak findings valid);
  - FP-guard: target tak sesuai asumsi -> L0 "not proven", bukan temuan;
  - ssti: echo biasa TIDAK dihitung evaluasi (differensial 49/56);
  - lfi: file tak ada -> 404 -> L0; baseline wajib terbaca dulu;
  - nosqli: kredensial salah tetap 401 (kontrol); sesi = akun canary;
  - canary LFI hanya di luar root served (tidak menyentuh fs lain).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_engine as ee  # noqa: E402
import exploit_playbooks as ep  # noqa: E402
import lab_target  # noqa: E402
from findings import validate_finding  # noqa: E402

NEW_PLAYBOOKS = ["ssti-eval", "lfi-traversal", "nosqli-login"]


def _params() -> dict:
    return {
        "ssti-eval": {"path": "/api/render", "param": "tpl"},
        "lfi-traversal": {"path": "/download", "param": "file",
                          "baseline_file": "report.txt",
                          "traversal_payload": "../canary-lfi.txt",
                          "canary_content": lab_target.LFI_CANARY},
        "nosqli-login": {"path": "/api/nosqli-login",
                         "whoami_path": "/api/whoami",
                         "canary_user": "svc-canary"},
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
                     "params": params}],
        "playbooks": playbooks}), encoding="utf-8")
    return p


def _http(base: str, method: str, path: str, body: bytes | None = None,
          headers: dict | None = None) -> tuple[int, dict, str]:
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
    def test_batch1_registered_and_clean(self):
        for name in NEW_PLAYBOOKS:
            self.assertIn(name, ep.PLAYBOOKS)
            pb = ep.PLAYBOOKS[name]
            self.assertFalse(pb.techniques & ep.NEVER_LIST,
                             "teknik never-list tidak boleh lolos registry")
            self.assertEqual(pb.tier, 1, "batch 1 semua tier-1 (proof)")
        self.assertEqual(len(ep.PLAYBOOKS), 38)


class LabEndpointTest(LabTestCase):
    def test_download_baseline_and_traversal_and_missing(self):
        st, _, body = _http(self.base_url, "GET",
                            "/download?file=report.txt")
        self.assertEqual(st, 200)
        self.assertIn("lab report", body)
        st, _, body = _http(self.base_url, "GET",
                            "/download?file="
                            + urllib.parse.quote("../canary-lfi.txt", safe=""))
        self.assertEqual(st, 200)
        self.assertIn(lab_target.LFI_CANARY, body)
        st, _, _ = _http(self.base_url, "GET",
                         "/download?file=../no-such-file.txt")
        self.assertEqual(st, 404)

    def test_render_evaluates_arithmetic_only(self):
        st, _, body = _http(self.base_url, "GET",
                            "/api/render?tpl=" + urllib.parse.quote("{{7*7}}"))
        self.assertEqual(st, 200)
        self.assertIn("49", body)
        st, _, body = _http(self.base_url, "GET",
                            "/api/render?tpl=" + urllib.parse.quote("{{8*7}}"))
        self.assertIn("56", body)
        self.assertNotIn("49", body)
        # echo biasa: non-aritmetika TIDAK dievaluasi (FP-guard bentuk)
        st, _, body = _http(self.base_url, "GET", "/api/render?tpl=hello")
        self.assertIn("hello", body)
        self.assertNotIn("49", body)

    def test_nosqli_login_flow_canary(self):
        # kontrol: kredensial salah ditolak
        st, _, _ = _http(self.base_url, "POST", "/api/nosqli-login",
                         body=json.dumps({"username": "svc-canary",
                                          "password": "wrong"}).encode(),
                         headers={"Content-Type": "application/json"})
        self.assertEqual(st, 401)
        # operator $ne lolos
        st, hdr, _ = _http(self.base_url, "POST", "/api/nosqli-login",
                           body=json.dumps({"username": {"$ne": ""},
                                            "password": {"$ne": ""}}).encode(),
                           headers={"Content-Type": "application/json"})
        self.assertEqual(st, 200)
        sid = hdr.get("Set-Cookie", "").split(";")[0]
        self.assertTrue(sid.startswith("sid="))
        st, _, body = _http(self.base_url, "GET", "/api/whoami",
                            headers={"Cookie": sid})
        self.assertEqual(st, 200)
        self.assertIn("svc-canary", body)


class Batch1ProvenE2E(LabTestCase):
    def test_three_playbooks_proven_l3_contract_valid(self):
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
            ssti = by_pb["ssti-eval"]
            self.assertEqual(ssti["verdict"], 3)
            self.assertEqual(ssti["cwe"], "CWE-1336")
            self.assertEqual(ssti["severity"], "critical")
            lfi = by_pb["lfi-traversal"]
            self.assertEqual(lfi["verdict"], 3)
            self.assertEqual(lfi["cwe"], "CWE-22")
            # canary LFI memang muncul sebagai bukti; yang wajib bebas
            # dari bukti = kredensial
            self.assertNotIn("alicepass", json.dumps(doc))
            nos = by_pb["nosqli-login"]
            self.assertEqual(nos["verdict"], 3)
            self.assertEqual(nos["cwe"], "CWE-943")
            self.assertIn("svc-canary", nos["response"])
            # kredensial salah tak pernah bocor di bukti mana pun
            self.assertNotIn("canary-pass-9f3", json.dumps(doc))


class Batch1FpGuard(LabTestCase):
    """FP-guard: target yang tidak sesuai asumsi WAJIB L0, bukan temuan."""

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

    def test_ssti_echo_only_is_not_proven(self):
        # endpoint tanpa evaluasi (download 400) -> bukan temuan
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["ssti-eval"],
                                 {"ssti-eval": {"path": "/download",
                                                "param": "tpl"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])
            self.assertFalse(rows[0]["reportable"])

    def test_lfi_missing_canary_is_not_proven(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["lfi-traversal"],
                                 {"lfi-traversal":
                                  {"traversal_payload":
                                   "../no-such-file.txt"}})
            self.assertEqual(rows[0]["verdict"], 0)

    def test_lfi_baseline_missing_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["lfi-traversal"],
                                 {"lfi-traversal":
                                  {"baseline_file": "ghost.txt"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("asumsi", rows[0]["title"])

    def test_nosqli_wrong_canary_user_is_not_proven(self):
        # sesi pasca-injeksi = svc-canary; klaim canary_user lain -> L0
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run_one(tmp, ["nosqli-login"],
                                 {"nosqli-login": {"canary_user": "alice"}})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
