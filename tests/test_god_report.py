"""Unit tests — GOD-TIER batch 4: god_report + CLI god-report + hook planner.

Semua offline: scan folder dummy (findings.json ala hasil reporting) + KB
sementara (feed NVD fixture + CSV EDB fixture).
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIX = Path(__file__).resolve().parent / "fixtures" / "kb"

from cyphron import god_report
from cyphron.cli import main


def _make_scan_dir(tmp: Path) -> Path:
    scan = tmp / "scan_out"
    scan.mkdir(parents=True)
    data = {
        "target": "https://bim.example.ac.id",
        "confirmed": [
            {"tool": "server_banner_soft", "severity": "info",
             "title": "Server banner discloses product version (X-Powered-By)",
             "status": "confirmed", "finding_class": "posture",
             "confidence": 1.0, "cwe": "CWE-200",
             "response": "X-Powered-By: PHP/8.1.34"},
            {"tool": "nuclei_bridge", "severity": "low",
             "title": "[nuclei:git-config-exposure] Git Configuration File "
                      "Exposure",
             "status": "confirmed", "finding_class": "weakness",
             "confidence": 0.9, "cwe": "CWE-538"},
        ],
        "unconfirmed": [],
        "world": {"technologies": {
            "Server: nginx/1.24.0": "header on /",
            "generator: Open Journal Systems 3.4.0.7": "meta tag on /"}},
    }
    (scan / "findings.json").write_text(json.dumps(data), encoding="utf-8")
    return scan


def _make_kb(tmp: Path) -> Path:
    kb = tmp / "kb"
    nvd = kb / "nvd"
    nvd.mkdir(parents=True)
    (nvd / "nvdcve-1.1-2026.json.gz").write_bytes(gzip.compress(
        (FIX / "nvd" / "nvdcve-1.1-mini-2026.json").read_bytes()))
    edb = kb / "edb"
    edb.mkdir(parents=True)
    (edb / "files_exploits.csv").write_bytes(
        (FIX / "edb" / "files_exploits.csv").read_bytes())
    from cyphron.kb import nvd_sqlite
    nvd_sqlite.build_sqlite(kb)
    return kb


class TestGodReport(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.scan = _make_scan_dir(self.tmp)
        self.kb = _make_kb(self.tmp)

    def test_collect_technologies_pulls_world_and_findings(self):
        data = god_report.load_scan_data(self.scan / "findings.json")
        texts = god_report.collect_technologies(data, ["manual: Leconfe 1.4.0"])
        joined = "\n".join(texts)
        for needle in ("nginx/1.24.0", "Open Journal Systems 3.4.0.7",
                       "PHP/8.1.34", "Leconfe 1.4.0"):
            self.assertIn(needle, joined)

    def test_build_produces_full_report(self):
        data = god_report.load_scan_data(self.scan / "findings.json")
        texts = god_report.collect_technologies(data)
        md, stats = god_report.build(data["target"],
                                     data["confirmed"], texts,
                                     kb_dir=self.kb)
        # bagian wajib
        for heading in ("## 1. Temuan live", "## 2. CVE exposure",
                        "## 3. Referensi exploit publik",
                        "## 4. Metodologi & disclaimer"):
            self.assertIn(heading, md)
        # temuan live + temuan nuclei tampil
        self.assertIn("[nuclei:git-config-exposure]", md)
        self.assertIn("SERVER_BANNER_SOFT", md.upper())
        # CVE lead pasif (nginx wildcard + ojs wildcard dari fixture)
        self.assertIn("CVE-2026-6666", md)   # nginx all versions
        self.assertIn("CVE-2026-2222", md)   # OJS all versions
        self.assertIn("LEAD", md)
        # referensi EDB utk nginx 1.24.0
        self.assertIn("EDB-10004", md)
        self.assertIn("TIDAK dieksekusi", md)
        # disclaimer metodologi
        self.assertIn("skema severity program", md)
        self.assertIn("Penolakan ambiguitas", md)
        # statistik konsisten
        self.assertGreaterEqual(stats["cve_rows"], 2)
        self.assertGreaterEqual(stats["edb_products"], 1)
        self.assertEqual(stats["sev_counts"]["info"], 1)
        self.assertEqual(stats["sev_counts"]["low"], 1)

    def test_cli_writes_report_file(self):
        out = self.tmp / "GOD-REPORT.md"
        rc = main(["god-report", "--from", str(self.scan),
                   "--kb-dir", str(self.kb), "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        text = out.read_text(encoding="utf-8")
        self.assertIn("Laporan GOD-TIER", text)
        self.assertIn("CVE exposure", text)

    def test_cli_missing_findings_returns_1(self):
        rc = main(["god-report", "--from", str(self.tmp / "nggak-ada"),
                   "--kb-dir", str(self.kb)])
        self.assertEqual(rc, 1)

    def test_kb_empty_report_is_honest(self):
        data = god_report.load_scan_data(self.scan / "findings.json")
        texts = god_report.collect_technologies(data)
        md, stats = god_report.build(data["target"], data["confirmed"],
                                     texts, kb_dir=self.tmp / "kosong")
        self.assertIn("belum tersinkron", md)
        self.assertEqual(stats["cve_rows"], 0)


if __name__ == "__main__":
    unittest.main()
