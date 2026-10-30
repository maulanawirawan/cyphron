"""Test F31 — batch 4 playbook: jwt-alg-confusion (CWE-347).

Port kelas terbukti dari legacy (jwt_exploit: alg:none) lewat pipeline
wajib. NOL jaringan eksternal — lawan uji lab_target 127.0.0.1.
Yang dikunci:
  - forged token alg:none TANPA signature diterima endpoint loose
    (L3), endpoint strict pada aplikasi yang sama MENOLAK (kontrol);
  - FP-guard: target strict-only -> L0 not proven; kontrol ikut
    menerima -> L0 (konteks tak dapat dipercaya).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import exploit_engine as ee  # noqa: E402
import exploit_playbooks as ep  # noqa: E402
import lab_target  # noqa: E402
from findings import validate_finding  # noqa: E402


def _config(tmp: Path, base_url: str, params_override: dict | None = None) \
        -> Path:
    params = {"jwt-alg-confusion": {"path": "/api/profile-loose",
                                    "strict_path": "/api/profile"}}
    for k, v in (params_override or {}).items():
        params["jwt-alg-confusion"][k] = v
    p = tmp / "exploit.json"
    p.write_text(json.dumps({
        "targets": [{"id": "lab", "base_url": base_url,
                     "exploit_allowed": True, "mode": "proof",
                     "params": params}],
        "playbooks": ["jwt-alg-confusion"]}), encoding="utf-8")
    return p


class LabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)


class RegistryTest(unittest.TestCase):
    def test_registered_tier1_clean(self):
        pb = ep.PLAYBOOKS["jwt-alg-confusion"]
        self.assertEqual(pb.tier, 1)
        self.assertFalse(pb.techniques & ep.NEVER_LIST)
        self.assertEqual(len(ep.PLAYBOOKS), 38)


class ProvenE2E(LabTestCase):
    def test_alg_none_proven_l3_contract_valid(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, self.base_url)
            out = tmp / "findings.json"
            rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(all(validate_finding(r) == []
                                for r in doc["findings"]))
            row = doc["findings"][0]
            self.assertEqual(row["playbook"], "jwt-alg-confusion")
            self.assertEqual(row["verdict"], 3)
            self.assertEqual(row["cwe"], "CWE-347")
            self.assertEqual(row["severity"], "high")
            self.assertTrue(row["reportable"])
            # bukti menyebut kontrol strict menolak
            self.assertIn("strict", row["response"])


class FpGuard(LabTestCase):
    def _run(self, tmp: Path, params_override: dict) -> list[dict]:
        cfg = _config(tmp, self.base_url, params_override)
        out = tmp / "f.json"
        rc = ee.main_with_args(["--config", str(cfg), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(all(validate_finding(r) == []
                            for r in doc["findings"]))
        return doc["findings"]

    def test_strict_only_target_is_not_proven(self):
        # arahkan ke endpoint strict (verifikasi HS256) -> alg:none ditolak
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run(tmp, {"path": "/api/profile",
                                   "strict_path": "/api/profile"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])
            self.assertFalse(rows[0]["reportable"])

    def test_control_accepting_token_is_not_proven(self):
        # kontrol "strict" ikut menerima -> konteks tak dapat dipercaya
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rows = self._run(tmp, {"strict_path": "/api/profile-loose"})
            self.assertEqual(rows[0]["verdict"], 0)
            self.assertIn("not proven", rows[0]["title"])


if __name__ == "__main__":
    unittest.main()
