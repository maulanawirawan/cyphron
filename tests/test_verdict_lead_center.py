"""Verdict enforcement lanjutan (STATUS-MASTER §10 item 2): label LEAD
terpusat di semua permukaan laporan — meta cover, callout JAMINAN VERDICT,
ringkasan eksekutif, matriks verdict, tabel observasi (PDF), ringkasan/detail/
observasi (MD), dan findings.json. Dulu label level hanya tampil sebagai chip
per-temuan di PDF detail; bucket sudah ditegakkan verifier, kini labelnya
wajib terbaca di permukaan sentral."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import reporting, verdicts
from cyphron.findings import Finding
from cyphron.guardrails.authorization import AuditLog
from cyphron.orchestrator import ScanOptions, ScanSummary
from cyphron.world.model import WorldModel


def _confirmed() -> Finding:
    f = Finding(tool="sqli_probe", title="SQL injection (error-based)",
                severity="critical", description="marker terlihat",
                target_url="https://t.test/item", param="id",
                confidence=0.95, status="confirmed", cwe="CWE-89",
                request="GET /item?id=1", response="Row A")
    f.attach_evidence("probe-pair", {"url": "x"})
    return f


def _lead() -> Finding:
    f = Finding(tool="security_headers", title="CSP missing",
                severity="low", description="header tidak ada",
                confidence=0.4, status="unconfirmed", evidence_kind="header")
    return f


def _rejected() -> Finding:
    return Finding(tool="xss_probe", title="XSS tersangka",
                   severity="medium", description="terbukti false-positive",
                   confidence=0.2, status="false-positive")


def _summary() -> ScanSummary:
    return ScanSummary(target="https://t.test", mode="offensive",
                       steps_executed=5, confirmed=[_confirmed()],
                       unconfirmed=[_lead(), _rejected()])


def _doc():
    w = WorldModel()
    w.target = "https://t.test"
    opts = ScanOptions(target="https://t.test")
    blocks = reporting._build_blocks(opts, _summary(), w, AuditLog())
    return blocks, reporting._build_doc(opts, _summary(), w, AuditLog(), blocks)


class TestVerdictTag(unittest.TestCase):
    def test_tag_satu_sumber(self):
        self.assertEqual(verdicts.tag(0), "L0 OBSERVED - LEAD")
        self.assertEqual(verdicts.tag(1), "L1 SUSPECTED - LEAD")
        self.assertEqual(verdicts.tag(2), "L2 REPRODUCED - LEAD")
        self.assertEqual(verdicts.tag(3), "L3 DETERMINISTICALLY VERIFIED")
        self.assertEqual(verdicts.tag(4), "L4 IMPACT VERIFIED")
        self.assertEqual(verdicts.tag(5), "L5 BLIND VALIDATED")
        self.assertEqual(verdicts.tag(verdicts.REJECTED), "L-x REJECTED")

    def test_lead_selalu_berlabel(self):
        for lv in (0, 1, 2):
            self.assertTrue(verdicts.tag(lv).endswith("- LEAD"),
                            f"level {lv} wajib berlabel LEAD")
        for lv in (3, 4, 5):
            self.assertNotIn("LEAD", verdicts.tag(lv),
                             f"level {lv} adalah TEMUAN, bukan LEAD")


class TestDocLabelTerpusat(unittest.TestCase):
    def test_meta_cover_menyebut_lead(self):
        _, doc = _doc()
        meta = dict(doc["meta"])
        obs = next(v for k, v in meta.items() if k.startswith("Observasi"))
        self.assertIn("REJECTED:1", obs, "kandidat FP harus terhitung di meta")
        self.assertIn("L1:", obs)

    def test_callout_dan_exec_box_menyebut_lead(self):
        _, doc = _doc()
        self.assertIn("LEAD", doc["callout"]["text"])
        box = next(sec for sec in doc["sections"]
                   if sec["no"] == "01")["blocks"][0][1]
        self.assertIn("berstatus LEAD", box)
        self.assertIn("1 kandidat", box)

    def test_matriks_verdict_membawa_ladder(self):
        _, doc = _doc()
        row = next(sec for sec in doc["sections"]
                   if sec["no"] == "02")["rows"][0]
        self.assertTrue(row[2].startswith("ADA (terkonfirmasi) - L3"),
                        "matriks verdict wajib memuat level ladder temuan")

    def test_tabel_observasi_berlabel_per_level(self):
        _, doc = _doc()
        rows = next(sec for sec in doc["sections"]
                    if sec["no"] == "07")["rows"]
        verdicts_cells = [r[1] for r in rows]
        self.assertTrue(any("L1 SUSPECTED - LEAD" in v for v in verdicts_cells))
        self.assertTrue(any("L-x REJECTED" in v for v in verdicts_cells))
        self.assertTrue(all("tidak dihitung sebagai temuan" in v
                            for v in verdicts_cells))


class TestMdDanJson(unittest.TestCase):
    def test_md_ringkasan_dan_observasi_berlabel(self):
        blocks, _ = _doc()
        md = reporting._render_md(blocks)
        self.assertIn("observasi berstatus LEAD", md)
        self.assertIn("- Verdict: L3 DETERMINISTICALLY VERIFIED", md)
        self.assertIn("L-x REJECTED", md)
        self.assertIn("L1 SUSPECTED - LEAD", md)

    def test_findings_json_membawa_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            reporting.write_reports(out, ScanOptions(target="https://t.test"),
                                    _summary(), WorldModel(), AuditLog())
            data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(data["confirmed"][0]["verdict"], 3)
        self.assertEqual(data["confirmed"][0]["verdict_tag"],
                         "L3 DETERMINISTICALLY VERIFIED")
        unconfirmed_tags = {f["verdict_tag"] for f in data["unconfirmed"]}
        self.assertIn("L1 SUSPECTED - LEAD", unconfirmed_tags)
        self.assertIn("L-x REJECTED", unconfirmed_tags)


if __name__ == "__main__":
    unittest.main()
