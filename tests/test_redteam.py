"""U9: redteam — MITRE-lite tag per engine, coverage matrix, deteksi-hint,
engagement report dari folder hasil scan."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import redteam
from cyphron.tools import build_default_registry
from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel

_REPO = Path(__file__).resolve().parents[1]


def _all_engine_names() -> list[str]:
    ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                      world=WorldModel(), rate_limit_s=0.0)
    return sorted(t.name for t in build_default_registry(ctx).all())


class TestMitreLite(unittest.TestCase):
    def test_setiap_fase_adalah_bagian_taksonomi(self):
        for name, ent in redteam.ENGINE_MITRE.items():
            for p in ent["phases"]:
                self.assertIn(p, redteam.PHASES, f"{name}: fase {p} tak sah")

    def test_engine_inti_tertag_eksplisit(self):
        for name in ("sqli_probe", "xss_probe", "bola", "browser_scout",
                     "identity_matrix", "business_logic", "lockout",
                     "load_probe", "cve_matcher"):
            self.assertIn(name, redteam.ENGINE_MITRE, f"{name} harus ter-tag")

    def test_semua_engine_registry_tercakup_fase(self):
        names = _all_engine_names()
        for name in names:
            phases = redteam.phases_for(name)
            self.assertTrue(phases, f"{name} tanpa fase")
            for p in phases:
                self.assertIn(p, redteam.PHASES)

    def test_coverage_tag_eksplisit_majoritas(self):
        m = redteam.coverage_matrix(_all_engine_names())
        self.assertEqual(m["engines"], len(_all_engine_names()))
        self.assertGreaterEqual(m["tagged"], m["engines"] // 2,
                                "mayoritas engine wajib ter-tag eksplisit")
        self.assertIn("RECON", m["coverage"])
        self.assertTrue(m["coverage"]["RECON"])
        self.assertTrue(m["coverage"]["CRED_ACCESS"])

    def test_fallback_heuristik_deterministik(self):
        self.assertEqual(redteam.phases_for("wp_probe"),
                         ["DISCOVERY", "INITIAL_ACCESS"])
        self.assertEqual(redteam.phases_for("engine_baru_hokus_pokus"),
                         ["DISCOVERY"])


class TestHintsAndReport(unittest.TestCase):
    def _scan_dir(self, td: Path) -> Path:
        findings = {
            "target": "https://t.test", "mode": "offensive",
            "authorization": "AUTH-1", "steps": 12,
            "world": {"request_count": 40},
            "confirmed": [
                {"id": "f1", "title": "SQL injection", "tool": "sqli_probe"},
                {"id": "f2", "title": "Cookie tanpa HttpOnly",
                 "tool": "cookie_audit"},
            ],
            "unconfirmed": [],
        }
        audit = [
            {"kind": "tool-run", "tool": "sqli_probe"},
            {"kind": "tool-run", "tool": "dir_probe"},
            {"kind": "tool-done", "tool": "sqli_probe", "ok": True},
        ]
        (td / "findings.json").write_text(json.dumps(findings),
                                          encoding="utf-8")
        (td / "audit.jsonl").write_text(
            "\n".join(json.dumps(e) for e in audit), encoding="utf-8")
        return td

    def test_detection_hints(self):
        hints = redteam.detection_hints([
            {"id": "f1", "title": "SQL injection", "tool": "sqli_probe"},
            {"id": "f1", "title": "SQL injection", "tool": "sqli_probe"},
        ])
        self.assertEqual(len(hints), 1, "dedup per finding id")
        self.assertEqual(hints[0]["phases"], ["INITIAL_ACCESS", "COLLECTION"])
        self.assertIn("access log", hints[0]["hint"].lower())

    def test_engagement_report_struktur(self):
        with tempfile.TemporaryDirectory() as td:
            src = self._scan_dir(Path(td))
            report = redteam.engagement_report(src)
            md = report["markdown"]
            self.assertIn("# Engagement Report", md)
            self.assertIn("AUTH-1", md)
            self.assertIn("SQL injection", md)
            self.assertIn("pembersihan", md.lower())
            # kontrak baru: coverage hanya engine dengan tool-done ok —
            # dir_probe punya tool-run TANPA tool-done => tidak dihitung
            self.assertNotIn("dir_probe", report["executed_engines"])
            self.assertIn("sqli_probe", report["executed_engines"])
            # coverage matrix mencakup fase dari engine yang dieksekusi
            self.assertIn("sqli_probe", report["matrix"]["coverage"]["INITIAL_ACCESS"])

    def test_engagement_report_cli_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            src = self._scan_dir(Path(td))
            report = redteam.engagement_report(src)
            out = Path(td) / "ENGAGEMENT-REPORT.md"
            out.write_text(report["markdown"], encoding="utf-8")
            self.assertTrue(out.exists())
            self.assertGreater(out.stat().st_size, 500)


if __name__ == "__main__":
    unittest.main()
