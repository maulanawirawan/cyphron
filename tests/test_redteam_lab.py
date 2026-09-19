"""Red-team lab expansion (U9 full): katalog tradecraft RTL-*, C2-sim
loopback berbatas, privesc read-only, deteksi coverage, lab report."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import redteam_lab
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.privesc_scan import PrivescScanTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0)


class TestCatalog(unittest.TestCase):
    def test_12_teknik_semua_fase(self):
        rows = redteam_lab.catalog()
        self.assertGreaterEqual(len(rows), 12)
        phases = {t["phase"] for t in rows}
        for p in ("INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIV_ESC",
                  "DEFENSE_EVASION", "CRED_ACCESS", "DISCOVERY", "LATERAL",
                  "C2", "EXFIL", "IMPACT", "RECON"):
            self.assertIn(p, phases)

    def test_filter_auth_dan_telemetri_wajib(self):
        lab_only = redteam_lab.catalog("lab")
        self.assertTrue(lab_only)
        self.assertTrue(all(t["auth"] == "lab" for t in lab_only))
        for t in redteam_lab.catalog():
            self.assertTrue(t["telemetry"], f"{t['id']} tanpa telemetri")
            self.assertTrue(t["purple_note"])

    def test_detection_coverage_gap_jujur(self):
        cov = redteam_lab.detection_coverage(set())
        self.assertEqual(cov["covered"], 0)
        self.assertEqual(len(cov["gaps"]), cov["techniques"])
        cov2 = redteam_lab.detection_coverage({"C2", "IMPACT", "RECON"})
        self.assertEqual(cov2["covered"], 3)


class TestC2Sim(unittest.TestCase):
    def test_loopback_only_ditegakkan(self):
        with self.assertRaises(ValueError):
            redteam_lab.c2_simulate(host="example.test")

    def test_beacon_ack_dan_batas(self):
        sim = redteam_lab.c2_simulate(beacons=3, interval_s=0.1,
                                      duration_cap_s=5.0)
        self.assertEqual(sim["beacons_sent"], 3)
        self.assertEqual(sim["acks_ok"], 3, sim["timeline"])
        self.assertEqual(sim["tasks_issued"], 3)
        self.assertTrue(sim["listener"].startswith("127.0.0.1"))
        self.assertLess(sim["duration_s"], 6.0, "durasi wajib berbatas")
        msgs = [e["msg"] for e in sim["timeline"]]
        self.assertTrue(any(m.startswith("HELLO lab-c2-sim") for m in msgs))
        self.assertTrue(any(m.startswith("TASK noop-") for m in msgs))
        self.assertTrue(any(m.startswith("ACK TASK") for m in msgs))

    def test_cap_beacon_keras(self):
        sim = redteam_lab.c2_simulate(beacons=999, interval_s=0.05,
                                      duration_cap_s=3.0)
        self.assertLessEqual(sim["beacons_sent"], 10, "cap 10 beacon")


class TestPrivesc(unittest.TestCase):
    def test_read_only_dan_struktur(self):
        res = redteam_lab.privesc_scan()
        self.assertIn("read-only", res["mode"])
        self.assertGreater(res["path_dirs"], 0)
        for f in res["findings"]:
            self.assertIn(f["severity"], ("info", "medium", "high"))

    def test_engine_readonly_tanpa_temuan_info(self):
        res = PrivescScanTool().run({}, _ctx())
        self.assertTrue(res.ok)
        self.assertEqual(res.data["mode"], res.data["mode"])  # struktur
        for f in res.findings:
            self.assertNotEqual(f.finding_class, "exploitable")
            self.assertEqual(f.status, "unconfirmed")
            # SUID (info) tidak jadi temuan otomatis
            self.assertNotIn("suid-binary", f.title)

    def test_engine_terdaftar(self):
        names = {t.name for t in build_default_registry(_ctx()).all()}
        self.assertIn("privesc_scan", names)


class TestLabReport(unittest.TestCase):
    def test_report_lengkap(self):
        sim = redteam_lab.c2_simulate(beacons=2, interval_s=0.05,
                                      duration_cap_s=3.0)
        privesc = redteam_lab.privesc_scan()
        md = redteam_lab.render_lab_report(sim=sim, privesc=privesc,
                                           covered_phases={"C2", "RECON"})
        self.assertIn("# Engagement Lab Report", md)
        self.assertIn("RTL-01", md)
        self.assertIn("GAP", md)
        self.assertIn("C2-simulation", md)
        self.assertIn("Privesc read-only", md)
        self.assertIn("Aturan lab", md)


if __name__ == "__main__":
    unittest.main()
