"""Nol jaringan — test sarif_ingest (SARIF 2.1.0 -> findings.json).

Fixture dibangun inline mengikuti struktur SARIF 2.1.0 (OASIS); perilaku
resolusi level diuji terhadap contoh spesifikasi (result.level opsional,
CodeQL menaruh severity di rule). Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import sarif_ingest as si  # noqa: E402
from findings import validate_finding  # noqa: E402


def _run(results: list[dict], rules: list[dict] | None = None,
         driver: str = "CodeQL") -> dict:
    run: dict = {"tool": {"driver": {"name": driver}}, "results": results}
    if rules is not None:
        run["tool"]["driver"]["rules"] = rules
    return run


def _doc(runs: list[dict]) -> dict:
    return {"version": "2.1.0", "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}


def _res(rule_id: str = "py/audit", **kw) -> dict:
    r: dict = {"ruleId": rule_id, "message": {"text": "temuan uji"}}
    r.update(kw)
    return r


class TestResolveLevel(unittest.TestCase):
    """Resolusi severity — SARIF 2.1.0 §3.27.10."""

    def test_kind_pass_adalah_none(self):
        self.assertEqual(si.resolve_level(_res(kind="pass"), _run([])), "none")

    def test_level_eksplisit_di_result(self):
        self.assertEqual(
            si.resolve_level(_res(level="error"), _run([])), "error")

    def test_codeql_style_severity_di_rule_via_ruleindex(self):
        """Result TANPA level + rule defaultConfiguration.level=error."""
        run = _run([_res(ruleIndex=0)],
                   rules=[{"id": "py/audit",
                           "defaultConfiguration": {"level": "error"}}])
        self.assertEqual(si.resolve_level(run["results"][0], run), "error")

    def test_join_via_ruleid_bila_ruleindex_hilang(self):
        run = _run([_res("py/audit")],
                   rules=[{"id": "py/audit",
                           "defaultConfiguration": {"level": "warning"}}])
        self.assertEqual(si.resolve_level(run["results"][0], run), "warning")

    def test_tanpa_rule_dan_tanpa_level_default_warning(self):
        self.assertEqual(si.resolve_level(_res(), _run([])), "warning")


class TestNormalizePath(unittest.TestCase):
    def test_file_scheme_dan_percent(self):
        self.assertEqual(si.normalize_path("file:///src/a%20b.py"),
                         "/src/a b.py")

    def test_base_relasikan(self):
        self.assertEqual(si.normalize_path("/src/pkg/mod.py", base="/src"),
                         "pkg/mod.py")

    def test_backslash_dan_windows_drive(self):
        self.assertEqual(si.normalize_path("file:///C:/x/y.py"),
                         "C:/x/y.py")
        self.assertEqual(si.normalize_path("a\\b.py"), "a/b.py")


class TestFingerprint(unittest.TestCase):
    def test_fp_tool_diutamakan(self):
        r = _res(fingerprints={"a/1": "xyz"})
        self.assertEqual(si.compute_fingerprint(r, "p.py", 3),
                         "fingerprints:a/1=xyz")

    def test_fallback_hash_path_utuh(self):
        """Rule+line sama di dua file berbeda-bedapath = fingerprint beda."""
        a = si.compute_fingerprint(_res(), "auth/login.py", 10)
        b = si.compute_fingerprint(_res(), "admin/login.py", 10)
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("hash:"))


class TestIngest(unittest.TestCase):
    def test_ingest_codeql_style_end_to_end(self):
        """Run CodeQL-gaya (severity di rule) -> findings.json sah kontrak."""
        run = _run([_res(ruleIndex=0,
                         locations=[{"physicalLocation": {
                             "artifactLocation": {"uri": "file:///src/app.py"},
                             "region": {"startLine": 42}}}])],
                   rules=[{"id": "py/sql-injection",
                           "defaultConfiguration": {"level": "error"}}])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "codeql.sarif"
            src.write_text(json.dumps(_doc([run])), encoding="utf-8")
            findings, meta = si.ingest([str(src)])
            self.assertEqual(meta["emitted"], 1)
            self.assertEqual(meta["rejected_level"], 0)
            f = findings[0]
            self.assertEqual(f["severity"], "high")          # error -> high
            self.assertEqual(f["verdict"], 0)                # statis = lead
            self.assertEqual(f["verdict_tag"], "L0 OBSERVED - LEAD")
            self.assertEqual(f["file_path"], "/src/app.py")
            self.assertEqual(f["line_start"], 42)
            self.assertEqual(validate_finding(f), [])

    def test_dedup_lintas_run_fp_tool(self):
        """Dua run, fingerprint sama -> satu temuan; severity tertinggi menang."""
        fp = {"fingerprints": {"x/1": "ABC"}}
        run_a = _run([_res(level="note", **fp)])
        run_b = _run([_res(level="error", **fp)], driver="Semgrep")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "multi.sarif"
            src.write_text(json.dumps(_doc([run_a, run_b])), encoding="utf-8")
            findings, meta = si.ingest([str(src)])
            self.assertEqual(meta["dedup_dropped"], 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "high")
            self.assertEqual(findings[0]["tool"], "sarif:Semgrep")

    def test_min_level_filter_dan_histogram(self):
        run = _run([_res("r/low", level="note"),
                    _res("r/high", level="error")])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.sarif"
            src.write_text(json.dumps(_doc([run])), encoding="utf-8")
            _, meta = si.ingest([str(src)], min_level="warning")
            self.assertEqual(meta["emitted"], 1)
            self.assertEqual(meta["level_histogram"], {"error": 1})

    def test_kind_pass_dilewati_bukan_diemisikan(self):
        run = _run([_res(kind="pass"), _res(kind="notApplicable")])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.sarif"
            src.write_text(json.dumps(_doc([run])), encoding="utf-8")
            findings, meta = si.ingest([str(src)])
            self.assertEqual(findings, [])
            self.assertEqual(meta["skipped_not_fail"], 2)

    def test_level_eksplisit_tidak_sah_ditolak(self):
        """Level di luar enum SARIF -> result ditolak, BUKAN diam-diam lolos."""
        run = _run([_res(level="fatal")])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.sarif"
            src.write_text(json.dumps(_doc([run])), encoding="utf-8")
            findings, meta = si.ingest([str(src)])
            self.assertEqual(findings, [])
            self.assertEqual(meta["rejected_level"], 1)

    def test_semua_file_gagal_fail_closed(self):
        with self.assertRaises(ValueError):
            si.ingest([str(ROOT / "tests" / "TIDAK-ADA.sarif")])

    def test_version_bukan_2x_ditolak(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "v1.sarif"
            src.write_text(json.dumps({"version": "1.0.0", "runs": []}),
                           encoding="utf-8")
            with self.assertRaises(ValueError):
                si.ingest([str(src)])


class TestCLI(unittest.TestCase):
    def test_main_end_to_end_tulis_findings(self):
        run = _run([_res(ruleIndex=0,
                         locations=[{"physicalLocation": {
                             "artifactLocation": {"uri": "src/auth.py"},
                             "region": {"startLine": 7}}}])],
                   rules=[{"id": "js/xss",
                           "defaultConfiguration": {"level": "warning"}}])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.sarif"
            out = Path(td) / "out" / "findings.json"
            src.write_text(json.dumps(_doc([run])), encoding="utf-8")
            rc = si.main(["--sarif", str(src), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(doc["ok"])
            self.assertEqual(len(doc["findings"]), 1)
            self.assertEqual(doc["findings"][0]["severity"], "medium")
            self.assertEqual(validate_finding(doc["findings"][0]), [])
            self.assertEqual(doc["data"]["emitted"], 1)

    def test_main_input_hancur_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "bad.sarif"
            src.write_text("bukan json {{{", encoding="utf-8")
            rc = si.main(["--sarif", str(src),
                          "--out", str(Path(td) / "o.json")])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
