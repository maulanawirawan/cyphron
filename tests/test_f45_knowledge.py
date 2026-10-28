"""Test F45 — lapisan pengetahuan di orkestrator (nightrun/report_pack).

NOL jaringan: scan disimulasikan (pola F23); KEV + katalog CWE dari
FIXTURE (bukan intel nyata — pelajaran F40). Yang dikunci:
  - enrich_findings_doc: salinan + baris CVE-MATCH, doc asli UTUH
    (state scan & drift stabil);
  - nightrun: findings-knowledge.json + summary cve_matches; state
    findings.json tetap scan-only; KEV hilang = 'skipped' fail-closed;
    --no-knowledge mematikan semuanya;
  - cwe-check sekali per run -> cwe-check.json (unknown = lead).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import nightrun as nr  # noqa: E402
import cve_matcher as cm  # noqa: E402
import cwe_check as cc  # noqa: E402
import intel_sync  # noqa: E402

KEV_FIXTURE = {"vulnerabilities": [
    {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
     "product": "HTTP Server", "vulnerabilityName": "path traversal",
     "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-22"]},
]}
CATALOG_CSV = ("CWE-ID,Name,Weakness Abstraction,Status,Description\n"
               "125,Out-of-bounds Read,Base,Stable,x\n")


def _finding(i: str, tool: str = "mock", title: str = "t",
             verdict: int = 1) -> dict:
    return {"id": i, "title": title, "severity": "low", "verdict": verdict,
            "tool": tool, "target_url": "https://example.com/",
            "status": "confirmed"}


def _scan_row() -> dict:
    """Baris server-version-disclosure dgn fakta versi Apache."""
    return {"id": "svd-1", "tool": "server-version-disclosure",
            "title": "Version leak via header",
            "response": "Server: Apache/2.4.49 (Win64)",
            "severity": "low", "verdict": 1, "status": "confirmed",
            "target_url": "https://a.example/", "extra": {}}


class _FakeScan:
    def __init__(self, per_domain: dict[str, list[dict]]):
        self.per_domain = per_domain

    def __call__(self, argv, timeout=600):
        out = Path(argv[argv.index("--out") + 1])
        domain = argv[argv.index("--domain") + 1]
        out.mkdir(parents=True, exist_ok=True)
        rows = self.per_domain[domain]
        (out / "findings.json").write_text(json.dumps({
            "ok": True, "data": {"total_findings": len(rows)},
            "findings": rows, "requests": 2,
        }, ensure_ascii=False), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class EnrichTest(unittest.TestCase):
    def test_enrich_appends_rows_original_untouched(self):
        doc = {"ok": True, "findings": [_scan_row()]}
        enriched, meta = cm.enrich_findings_doc(doc, KEV_FIXTURE[
            "vulnerabilities"])
        self.assertEqual(meta["matches"], 1)
        self.assertEqual(len(enriched["findings"]), 2)
        # doc asli UTUH — state scan tidak tersentuh
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(enriched["findings"][1]["tool"], "cve-matcher")
        self.assertEqual(enriched["findings"][1]["verdict"], 1)

    def test_no_facts_no_rows(self):
        doc = {"ok": True, "findings": [_finding("x-1")]}
        enriched, meta = cm.enrich_findings_doc(
            doc, KEV_FIXTURE["vulnerabilities"])
        self.assertEqual(meta["matches"], 0)
        self.assertEqual(len(enriched["findings"]), 1)


class KnowledgeOrchestratorTest(unittest.TestCase):
    """Harness: KEV + katalog CWE dari fixture (intel nyata tidak boleh
    memengaruhi hasil test — pelajaran F40)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        (self.tmp / "kev.json").write_text(
            json.dumps(KEV_FIXTURE), encoding="utf-8")
        intel_dir = self.tmp / "assets" / "intel"
        intel_dir.mkdir(parents=True)
        (intel_dir / "cwe-1000.csv").write_text(CATALOG_CSV,
                                                encoding="utf-8")
        skills = self.tmp / "skills"
        skills.mkdir()
        (skills / "a.py").write_text('x = "CWE-125"\ny = "CWE-99999"\n',
                                     encoding="utf-8")
        p_kev = patch.object(cm, "KEV_PATH", self.tmp / "kev.json")
        p_cat = patch.object(intel_sync, "INTEL", intel_dir)
        p_root = patch.object(cc, "ROOT", self.tmp)
        for p in (p_kev, p_cat, p_root):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, progs, rows, extra_args=()):
        cfg = self.tmp / "cfg.json"
        cfg.write_text(json.dumps({"programs": progs}), encoding="utf-8")
        out = self.tmp / "nr"
        fake = _FakeScan({p["domain"]: rows for p in progs})
        with patch.object(nr, "run_cmd", fake), \
             patch.object(nr, "resolve_exe", lambda: Path("scan.exe")), \
             patch.object(nr, "render_pdf", return_value={"ok": True}), \
             patch.object(nr.egress_preflight, "run_preflight",
                          return_value={"all_ok": True, "checks": [],
                                        "blocked": [], "impact": []}):
            rc = nr.main_with_args(["--config", str(cfg), "--out", str(out),
                                    "--run-id", "2026-01-01", *extra_args])
        self.assertEqual(rc, 0)
        return out

    def test_knowledge_merge_and_state_scan_only(self):
        out = self._run([{"id": "a", "domain": "a.example", "budget": 10}],
                        [_scan_row()])
        pid_dir = out / "state" / "a"
        # state findings.json tetap scan-only (drift stabil)
        state = json.loads((pid_dir / "findings.json").read_text(
            encoding="utf-8"))
        self.assertEqual(len(state["findings"]), 1)
        # salinan pengetahuan membawa baris cve-matcher
        kn = json.loads((pid_dir / "findings-knowledge.json").read_text(
            encoding="utf-8"))
        self.assertEqual(len(kn["findings"]), 2)
        self.assertEqual(kn["findings"][1]["tool"], "cve-matcher")
        # summary mencatat hitungan
        summary = json.loads((out / "2026-01-01" /
                              "nightrun-summary.json").read_text(
            encoding="utf-8"))
        prog = summary["programs"][0]
        self.assertEqual(prog["cve_matches"], 1)
        self.assertEqual(summary["cwe_check"]["unknown"], 1)
        self.assertTrue((out / "2026-01-01" / "cwe-check.json").exists())

    def test_missing_kev_is_skipped_not_clean(self):
        (self.tmp / "kev.json").unlink()
        out = self._run([{"id": "a", "domain": "a.example", "budget": 10}],
                        [_scan_row()])
        summary = json.loads((out / "2026-01-01" /
                              "nightrun-summary.json").read_text(
            encoding="utf-8"))
        self.assertIn("skipped", str(summary["programs"][0]["cve_matches"]))
        # state findings tetap ada (scan berjalan normal)
        self.assertTrue((out / "state" / "a" / "findings.json").exists())
        self.assertFalse((out / "state" / "a" /
                          "findings-knowledge.json").exists())

    def test_no_knowledge_flag_disables_layer(self):
        out = self._run([{"id": "a", "domain": "a.example", "budget": 10}],
                        [_scan_row()], extra_args=["--no-knowledge"])
        self.assertFalse((out / "state" / "a" /
                          "findings-knowledge.json").exists())
        self.assertFalse((out / "2026-01-01" / "cwe-check.json").exists())
        summary = json.loads((out / "2026-01-01" /
                              "nightrun-summary.json").read_text(
            encoding="utf-8"))
        self.assertNotIn("cwe_check", summary)
        self.assertNotIn("cve_matches", summary["programs"][0])

    def test_clean_audit_single_aman(self):
        (self.tmp / "skills" / "a.py").write_text('x = "CWE-125"\n',
                                                  encoding="utf-8")
        out = self._run([{"id": "a", "domain": "a.example", "budget": 10}],
                        [_finding("m-1")])
        summary = json.loads((out / "2026-01-01" /
                              "nightrun-summary.json").read_text(
            encoding="utf-8"))
        self.assertEqual(summary["cwe_check"]["unknown"], 0)
        self.assertEqual(summary["cwe_check"]["clean"], 1)


if __name__ == "__main__":
    unittest.main()
