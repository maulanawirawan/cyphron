"""Nol jaringan eksternal — test audit_phases (lawan = lab_target lokal).

Yang dikunci:
  - fase surface: target hidup = LIVE; target mati = exit 2 + report tetap;
  - probe: playbook registry jalan end-to-end di lab (IDOR terbukti L3+);
  - error satu playbook tidak membunuh audit (tercatat di ledger);
  - verify: confirmed TANPA bukti diturunkan unconfirmed (fail-closed);
  - tier-2 butuh flag; tier-3 TIDAK PERNAH dijalankan;
  - non-loopback tanpa --confirm-external = refuse sebelum request;
  - coverage PARTIAL dengan gaps tercatat jujur;
  - semua baris findings lulus kontrak validate_finding.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import audit_phases as ap  # noqa: E402
import exploit_playbooks as ep  # noqa: E402
import lab_target  # noqa: E402
from findings import validate_finding  # noqa: E402


class BaseLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base_url = lab_target.start_lab()

    @classmethod
    def tearDownClass(cls):
        lab_target.stop_lab(cls.server)

    def _audit(self, playbooks, **kw):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: None)  # tmp di tempdir sistem, biarkan
        params = {
            "idor-orders": {"own_id": "1001", "other_id": "1002",
                            "other_owner_email": "bob@example.com"},
            "admin-access": {"admin_path": "/admin/panel",
                             "marker": "admin-panel-secret-marker"},
        }
        params.update(kw.pop("params", {}))
        return ap.run_audit(
            self.base_url, playbooks, params,
            {"username": "alice", "password": "alicepass"},
            tmp, **kw)


class TestAuditPhases(BaseLab):
    """Nol jaringan — audit end-to-end di lab lokal."""

    def test_idor_terbukti_dan_coverage_partial(self):
        res = self._audit(["idor-orders"])
        l3 = [f for f in res["findings"] if f.get("verdict") == 3
              or (f.get("verdict") == 4)]
        self.assertTrue(l3, "IDOR harus terbukti di lab")
        cov = res["coverage"]
        self.assertEqual(cov["status"], "PARTIAL")
        self.assertIn("admin-access", cov["gaps"])
        for f in res["findings"]:
            self.assertEqual(validate_finding(f), [])

    def test_dua_playbook_error_tetap_lanjut(self):
        # playbook dengan params kosong = KeyError di dalam run -> error
        # tercatat di ledger, audit TIDAK crash, findings playbook lain tetap.
        res = self._audit(["idor-orders", "admin-access"],
                          params={"idor-orders": {}})
        ledger = {m["playbook"]: m["status"] for m in
                  res["coverage"]["ledger"]}
        self.assertEqual(ledger["admin-access"], "run")
        self.assertEqual(ledger["idor-orders"], "error")
        self.assertIn("error", ledger["idor-orders"] or "error")

    def test_playbook_tidak_dikenal_tercatat(self):
        res = self._audit(["idor-orders", "playbook-fantasi"])
        cov = res["coverage"]
        self.assertIn("playbook-fantasi", cov["unknown_requested"])

    def test_surface_live(self):
        res = self._audit([])
        self.assertTrue(res["surface_live"])
        # lab merespons / dengan 404 — cukup bukti server hidup
        self.assertTrue(res["surface_detail"].startswith("GET / -> "))


class TestVerifyPhase(unittest.TestCase):
    """Nol jaringan — fase verify fail-closed pada bukti."""

    def test_confirmed_tanpa_bukti_diturunkan(self):
        finding = {"tool": "x", "title": "tanpa bukti", "severity": "high",
                   "status": "confirmed", "verdict": 4,
                   "evidence_kind": "poc-exploit", "request": "",
                   "response": "", "poc": ""}
        out = ap._verify_phase([finding])[0]
        self.assertEqual(out["status"], "unconfirmed")
        self.assertEqual(out["verdict"], 1)
        self.assertIn("fail-closed", out["extra"]["audit_verify_note"])

    def test_confirmed_dengan_bukti_dipertahankan(self):
        finding = {"tool": "x", "title": "dengan bukti", "severity": "high",
                   "status": "confirmed", "verdict": 3,
                   "evidence_kind": "request-response",
                   "request": "GET / -> 200", "response": "marker",
                   "poc": "curl ..."}
        out = ap._verify_phase([dict(finding)])[0]
        self.assertEqual(out["status"], "confirmed")
        self.assertEqual(out["verdict"], 3)

    def test_info_not_proven_tak_disentuh(self):
        finding = {"tool": "x", "title": "not proven", "severity": "info",
                   "status": "confirmed", "verdict": 0,
                   "evidence_kind": "poc-exploit"}
        out = ap._verify_phase([dict(finding)])[0]
        self.assertEqual(out["status"], "confirmed")  # verdict 0 < 2 → biarkan
        self.assertEqual(out["verdict"], 0)


class TestTierGate(unittest.TestCase):
    """Nol jaringan — tangga tier fail-closed."""

    def _dummy(self, t):
        from exploit_playbooks import BasePlaybook

        class Dummy(BasePlaybook):
            name = f"dummy-t{t}"
            tier = t
            techniques = frozenset({"lab-only"})

            def run(self, ctx):
                return []
        return Dummy()

    def test_tier3_tidak_pernah_dipilih(self):
        selected = ap._select_playbooks(["dummy-t3"], allow_tier2=True)
        self.assertEqual(selected, [])

    def test_tier2_butuh_flag(self):
        with unittest.mock.patch.dict(ep.PLAYBOOKS, {"dummy-t2": self._dummy(2)}):
            self.assertEqual(ap._select_playbooks(["dummy-t2"], False), [])
            self.assertEqual(len(ap._select_playbooks(["dummy-t2"], True)), 1)

    def test_tier1_default_dipilih(self):
        with unittest.mock.patch.dict(ep.PLAYBOOKS, {"dummy-t1": self._dummy(1)}):
            self.assertEqual(len(ap._select_playbooks(["dummy-t1"], False)), 1)


class TestGateExternal(unittest.TestCase):
    """Nol jaringan — gerbang non-loopback."""

    def test_non_loopback_ditolak_tanpa_flag(self):
        rc = ap.main(["--target", "https://example.com", "--out",
                      tempfile.mkdtemp()])
        self.assertEqual(rc, 2)

    def test_non_http_ditolak(self):
        rc = ap.main(["--target", "ftp://127.0.0.1", "--out",
                      tempfile.mkdtemp()])
        self.assertEqual(rc, 2)


class TestTargetDown(unittest.TestCase):
    """Nol jaringan — target mati: exit 2, report tetap ditulis."""

    def test_target_mati(self):
        # port di 127.0.0.1 yang pasti tidak terpakai
        tmp = Path(tempfile.mkdtemp())
        rc = ap.main(["--target", "http://127.0.0.1:1", "--out", str(tmp)])
        self.assertEqual(rc, 2)
        self.assertTrue((tmp / "REPORT.md").is_file())


if __name__ == "__main__":
    unittest.main()
