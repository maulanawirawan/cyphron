"""U6: benchmark (Precision/Recall/F1, CPE & version resolution, ambiguity
rejection) di atas fixture KB sqlite nyata + sweep bahasa klaim di produk."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import benchmark
from cyphron.kb import nvd_sqlite
from cyphron.kb.nvd_sqlite import _SCHEMA

_REPO = Path(__file__).resolve().parents[1]


def _build_fixture_kb(db_path: Path) -> None:
    """KB kecil dengan CVE publik nyata (batas versi dari feed NVD) untuk
    mengukur pipeline pencocokan secara offline dan deterministik."""
    con = sqlite3.connect(str(db_path))
    con.executescript(_SCHEMA)
    con.execute("INSERT OR IGNORE INTO cve VALUES "
                "('CVE-2024-4439','2024-11-01','2024-11-02',6.5,"
                "'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N','CWE-79',"
                "'Stored XSS in WordPress')")
    con.execute("INSERT OR IGNORE INTO cve_cpe VALUES "
                "('CVE-2024-4439',"
                "'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',"
                "NULL,'6.4.3',NULL,NULL)")
    con.execute("INSERT OR IGNORE INTO cpe VALUES "
                "('cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',"
                "'wordpress','wordpress','*','*')")
    con.execute("INSERT OR IGNORE INTO cve VALUES "
                "('CVE-2022-24181','2022-02-01','2022-02-03',7.5,"
                "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N','CWE-79',"
                "'OJS XSS')")
    con.execute("INSERT OR IGNORE INTO cve_cpe VALUES "
                "('CVE-2022-24181',"
                "'cpe:2.3:a:public_knowledge_project:open_journal_systems:*:"
                "*:*:*:*:*:*:*',NULL,'3.3.0',NULL,NULL)")
    con.execute("INSERT OR IGNORE INTO cpe VALUES "
                "('cpe:2.3:a:public_knowledge_project:open_journal_systems:*:"
                "*:*:*:*:*:*:*','public_knowledge_project',"
                "'open_journal_systems','*','*')")
    # CVE dengan batas versi yang TIDAK mencakup nginx 1.20.1 (end 1.20.0):
    # uji sisi true-negative dan penolakan over-claim
    con.execute("INSERT OR IGNORE INTO cve VALUES "
                "('CVE-2021-23017','2021-06-01','2021-06-03',9.4,"
                "'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H','CWE-909',"
                "'nginx resolver 1-byte memory overwrite')")
    con.execute("INSERT OR IGNORE INTO cve_cpe VALUES "
                "('CVE-2021-23017',"
                "'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*',"
                "'0.6.18','1.20.0',NULL,NULL)")
    con.execute("INSERT OR IGNORE INTO cpe VALUES "
                "('cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*','f5','nginx','*','*')")
    # CVE versi-eksak: hanya versi identik yang cocok
    con.execute("INSERT OR IGNORE INTO cve VALUES "
                "('CVE-2020-99999','2020-01-01','2020-01-02',8.0,"
                "'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H','CWE-502',"
                "'exact-version fixture CVE')")
    con.execute("INSERT OR IGNORE INTO cve_cpe VALUES "
                "('CVE-2020-99999',"
                "'cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*',"
                "NULL,NULL,NULL,NULL)")
    con.commit()
    con.close()


class TestBenchmarkMetrics(unittest.TestCase):
    def test_precision_recall_f1_pure(self):
        m = benchmark.precision_recall_f1({"CVE-1", "CVE-2"},
                                          {"CVE-2", "CVE-3"})
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)
        self.assertAlmostEqual(m["precision"], 0.5)
        self.assertAlmostEqual(m["recall"], 0.5)
        self.assertAlmostEqual(m["f1"], 0.5)
        # tanpa prediksi dan tanpa gold = sempurna (bukan 0/0 crash)
        m0 = benchmark.precision_recall_f1(set(), set())
        self.assertEqual(m0["f1"], 1.0)

    def test_cpe_resolution(self):
        gold = {"WordPress 6.4.3": ("wordpress", "wordpress"),
                "nginx/1.20.1": ("f5", "nginx")}
        res = benchmark.cpe_resolution(
            {"WordPress 6.4.3": ("wordpress", "wordpress"),
             "nginx/1.20.1": ("f5", "nginx")}, gold)
        self.assertEqual(res["accuracy"], 1.0)
        res_bad = benchmark.cpe_resolution(
            {"WordPress 6.4.3": None, "nginx/1.20.1": ("nginx", "nginx")},
            gold)
        self.assertEqual(res_bad["accuracy"], 0.0)

    def test_exploit_validation_rate(self):
        r = benchmark.exploit_validation_rate(
            {"CVE-2024-4439", "CVE-X"}, {"CVE-2024-4439"})
        self.assertAlmostEqual(r["rate"], 0.5)
        self.assertEqual(r["verified"], 1)


class TestBenchmarkPipeline(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.kb = Path(self._td.name)
        _build_fixture_kb(self.kb / "cpe.sqlite")
        self.results = benchmark.run_cve_benchmark(kb_dir=self.kb)

    def test_precision_sempurna_dan_ambigu_ditolak(self):
        m = self.results["matching"]
        self.assertEqual(m["fp"], 0, "tanpa over-claim pada fixture")
        self.assertEqual(m["precision"], 1.0)
        # semua gold tertangkap (WordPress 6.4.3 + OJS 3.3.0)
        self.assertEqual(m["fn"], 0)
        self.assertEqual(m["recall"], 1.0)
        self.assertGreaterEqual(self.results["ambiguous_rejected"], 0)

    def test_cpe_dan_version_resolution(self):
        c = self.results["cpe_resolution"]
        v = self.results["version_resolution"]
        self.assertEqual(c["accuracy"], 1.0,
                         str(self.results["cases"]))
        self.assertEqual(v["accuracy"], 1.0)
        # true-negative terjaga: nginx 1.20.1 & OJS 3.4.0.7 tidak diklaim
        by_text = {r["text"]: r for r in self.results["cases"]}
        self.assertEqual(by_text["nginx/1.20.1"]["predicted"], [])
        self.assertEqual(by_text["Open Journal Systems 3.4.0.7"]["predicted"], [])
        # fingerprint tanpa versi = tidak berklaim (versioned False)
        self.assertFalse(by_text["WordPress"]["versioned"])

    def test_case_baris_menunjukkan_cocok_eksemplar(self):
        by_text = {r["text"]: r for r in self.results["cases"]}
        self.assertIn("CVE-2024-4439", by_text["WordPress 6.4.3"]["predicted"])
        self.assertIn("CVE-2022-24181",
                      by_text["Open Journal Systems 3.3.0"]["predicted"])

    def test_render_markdown_mengandung_angka(self):
        md = benchmark.render_markdown(self.results)
        self.assertIn("Precision", md)
        self.assertIn("ambiguity rejection", md)
        self.assertIn("CVE-2024-4439", md)

    def test_benchmark_butuh_kb(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                benchmark.run_cve_benchmark(kb_dir=td)


class TestClaimLanguage(unittest.TestCase):
    """Bahasa klaim disiplin (ROADMAP-UNITY §4): CVE = deterministic
    matching with ambiguity rejection; TANPA jualan angka mentah/klaim
    absolut di narasi produk."""

    BANNED = ("zero false positive", "zero false positives",
              "100% secure", "temuan terjamin", "guaranteed",
              "53 paths", "40 engines")

    def _texts(self):
        read = lambda p: (p.read_text(encoding="utf-8", errors="replace")
                          if p.exists() else "")
        return {
            "README.md": read(_REPO / "README.md"),
            "landing": read(_REPO / "landing" / "index.html"),
            "god_report": read(_REPO / "cyphron" / "god_report.py"),
            "reporting": read(_REPO / "cyphron" / "reporting.py"),
        }

    def test_tanpa_klaim_absolut_di_narasi_produk(self):
        for name, text in self._texts().items():
            low = text.lower()
            for banned in self.BANNED:
                self.assertNotIn(banned, low,
                                 f"{name} memuat klaim terlarang: {banned!r}")

    def test_readme_menyebut_benchmark_dan_klaim_cve(self):
        readme = (_REPO / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("benchmark", readme)
        self.assertIn("ambiguity rejection", readme)


if __name__ == "__main__":
    unittest.main()
