"""Test F23 — night-run orchestrator + drift detection. NOL jaringan:
`cyphron scan` disimulasikan lewat mock run_cmd yang menulis
findings.json kontrak ke --out yang diminta (pola test orchestrator).
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

import nightrun as nr  # noqa: E402


def _finding(i: str, title: str, verdict: int = 1) -> dict:
    return {"id": i, "title": title, "severity": "low", "verdict": verdict,
            "tool": "mock", "target_url": "https://example.com/"}


class _FakeScan:
    """Simulasi `cyphron scan`: tulis findings.json ke dir --out."""

    def __init__(self, per_domain: dict[str, list[dict]], fail_domains=()):
        self.per_domain = per_domain
        self.fail_domains = set(fail_domains)
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout=600):
        self.calls.append(argv)
        out = Path(argv[argv.index("--out") + 1])
        domain = argv[argv.index("--domain") + 1]
        if domain in self.fail_domains:
            return SimpleNamespace(returncode=1, stdout="", stderr="boom")
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings.json").write_text(json.dumps({
            "ok": True, "data": {"total_findings": len(self.per_domain[domain])},
            "findings": self.per_domain[domain], "requests": 2,
        }, ensure_ascii=False), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _config(tmp: Path, progs: list[dict]) -> Path:
    p = tmp / "nightrun.json"
    p.write_text(json.dumps({"programs": progs}, ensure_ascii=False),
                 encoding="utf-8")
    return p


class ArchiveCompareEgressTest(unittest.TestCase):
    """F37 — arsip findings per run + --compare otomatis + preflight."""

    def test_second_run_archives_and_compares(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "a", "domain": "a.example",
                                 "budget": 10}])
            out = tmp / "nr"
            f1 = [_finding("id-1", "temuan lama", 1),
                  _finding("id-2", "temuan aman", 0)]
            f2 = [_finding("id-1", "temuan lama", 1),
                  _finding("id-3", "temuan baru", 2)]
            fake = _FakeScan({"a.example": f1})
            with patch.object(nr, "run_cmd", fake),                  patch.object(nr, "resolve_exe", lambda: Path("scan.exe")),                  patch.object(nr, "render_pdf",
                              return_value={"ok": True}) as rpdf,                  patch.object(nr.egress_preflight, "run_preflight",
                              return_value={"all_ok": True, "checks": [],
                                            "blocked": [], "impact": [],
                                            "note": "ok"}):
                nr.main_with_args(["--config", str(cfg), "--out", str(out),
                                   "--run-id", "2026-10-20"])
            # arsip run pertama
            a1 = out / "state" / "a" / "runs" / "2026-10-20.json"
            self.assertTrue(a1.exists())
            self.assertEqual(len(json.loads(a1.read_text(
                encoding="utf-8"))["findings"]), 2)
            # run kedua: state findings.json sudah tertimpa scan baru
            fake2 = _FakeScan({"a.example": f2})
            with patch.object(nr, "run_cmd", fake2),                  patch.object(nr, "resolve_exe", lambda: Path("scan.exe")),                  patch.object(nr, "render_pdf",
                              return_value={"ok": True}) as rpdf2,                  patch.object(nr.egress_preflight, "run_preflight",
                              return_value={"all_ok": True, "checks": [],
                                            "blocked": [], "impact": [],
                                            "note": "ok"}):
                nr.main_with_args(["--config", str(cfg), "--out", str(out),
                                   "--run-id", "2026-10-21"])
            a2 = out / "state" / "a" / "runs" / "2026-10-21.json"
            self.assertTrue(a2.exists())
            # render dipanggil dengan --compare gabungan dokumen lama
            kw = rpdf2.call_args.kwargs
            self.assertIsNotNone(kw.get("compare_path"))
            cold = json.loads(kw["compare_path"].read_text(
                encoding="utf-8"))
            self.assertEqual([r["id"] for r in cold["findings"]],
                             ["id-1", "id-2"])
            self.assertIsNotNone(kw.get("egress_path"))

    def test_first_run_no_compare(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "a", "domain": "a.example",
                                 "budget": 10}])
            out = tmp / "nr"
            fake = _FakeScan({"a.example": [_finding("id-1", "x", 1)]})
            with patch.object(nr, "run_cmd", fake),                  patch.object(nr, "resolve_exe", lambda: Path("scan.exe")),                  patch.object(nr, "render_pdf", return_value={"ok": True}) as rpdf,                  patch.object(nr.egress_preflight, "run_preflight",
                              return_value={"all_ok": True, "checks": [],
                                            "blocked": [], "impact": [],
                                            "note": "ok"}):
                nr.main_with_args(["--config", str(cfg), "--out", str(out),
                                   "--run-id", "2026-10-20"])
            kw = rpdf.call_args.kwargs
            self.assertIsNone(kw.get("compare_path"))
            self.assertIsNotNone(kw.get("egress_path"))


class ConfigValidationTest(unittest.TestCase):
    def test_valid_config_passes(self):
        with tempfile.TemporaryDirectory() as td:
            progs = nr.load_config(_config(Path(td), [
                {"id": "a", "domain": "a.example", "budget": 10},
                {"id": "b", "domain": "b.example", "target": "https://b.example/"},
            ]))
        self.assertEqual([p["id"] for p in progs], ["a", "b"])

    def test_duplicate_id_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(nr.ConfigError):
                nr.load_config(_config(Path(td), [
                    {"id": "a", "domain": "a.example"},
                    {"id": "a", "domain": "b.example"}]))

    def test_missing_domain_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(nr.ConfigError):
                nr.load_config(_config(Path(td), [{"id": "a"}]))

    def test_negative_budget_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(nr.ConfigError):
                nr.load_config(_config(Path(td), [
                    {"id": "a", "domain": "a.example", "budget": -1}]))

    def test_unknown_key_hard_error(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(nr.ConfigError):
                nr.load_config(_config(Path(td), [
                    {"id": "a", "domain": "a.example", "bugdet": 10}]))
            # dan key top-level tak dikenal:
            p = Path(td) / "c.json"
            p.write_text(json.dumps({"program": []}), encoding="utf-8")
            with self.assertRaises(nr.ConfigError):
                nr.load_config(p)

    def test_missing_config_file_hard_error(self):
        with self.assertRaises(nr.ConfigError):
            nr.load_config(Path("TIDAK/ADA.json"))


class DriftDiffTest(unittest.TestCase):
    def test_first_run_is_baseline_not_noise(self):
        d = nr.drift_diff(None, {"findings": [_finding("a", "x")]})
        self.assertTrue(d["first_run"])
        self.assertEqual(d["added"], [])
        self.assertEqual(d["total_now"], 1)

    def test_added_removed_verdict_up_down(self):
        old = {"mtime": 100, "ids": {
            "persist1": _finding("persist1", "tetap", 1),
            "gone1": _finding("gone1", "hilang", 1),
            "up1": _finding("up1", "menguat", 1),
            "down1": _finding("down1", "melemah", 3),
        }}
        new_doc = {"findings": [
            _finding("persist1", "tetap", 1),
            _finding("new1", "baru", 3),
            _finding("up1", "menguat", 3),   # naik 1 -> 3
            _finding("down1", "melemah", 0),  # turun 3 -> 0
        ]}
        d = nr.drift_diff(old, new_doc)
        self.assertEqual(d["added_count"], 1)
        self.assertEqual(d["removed_count"], 1)
        self.assertEqual(d["verdict_up_count"], 1)
        self.assertEqual(d["verdict_down_count"], 1)
        self.assertEqual(d["verdict_up"][0]["to"], 3)
        self.assertEqual(d["verdict_down"][0]["from"], 3)
        self.assertEqual(d["persist"], 3)

    def test_same_verdict_no_change(self):
        old = {"mtime": 0, "ids": {"a": _finding("a", "x", 3)}}
        d = nr.drift_diff(old, {"findings": [_finding("a", "x", 3)]})
        self.assertEqual(d["verdict_up_count"], 0)
        self.assertEqual(d["verdict_down_count"], 0)


class OrchestrationTest(unittest.TestCase):
    def test_run_twice_drift_and_weekly_accumulate(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [
                {"id": "p1", "domain": "p1.example", "budget": 8},
                {"id": "p0", "domain": "p0.example", "budget": 0},  # skip
            ])
            fake = _FakeScan({
                "p1.example": [_finding("f1", "satu", 1)],
            })
            with patch.object(nr, "run_cmd", fake), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                rc = nr.main_with_args(["--config", str(cfg), "--out",
                                        str(tmp / "nr"), "--no-pdf"])
            self.assertEqual(rc, 0)
            # skip budget 0 tercatat dengan baris audit, bukan senyap
            # run-id default = hari ini; baca satu-satunya run dir
            run_dirs = [d for d in (tmp / "nr").iterdir() if d.is_dir()]
            self.assertEqual(len(run_dirs), 2)  # state/ + <run-id>/
            run_dir = next(d for d in run_dirs if d.name != "state")
            doc = json.loads((run_dir / "nightrun-summary.json")
                             .read_text(encoding="utf-8"))
            self.assertEqual(doc["scanned"], 1)
            self.assertEqual(doc["skipped"], 1)
            self.assertEqual(doc["failed"], 0)
            self.assertTrue(doc["programs"][1]["skipped"] == "budget=0")
            self.assertTrue(doc["programs"][0]["drift"]["first_run"])
            # state + drift.json per program
            st = tmp / "nr" / "state" / "p1"
            self.assertTrue((st / "findings.json").exists())
            drift = json.loads((st / "drift.json").read_text(encoding="utf-8"))
            self.assertEqual(drift["added_count"], 0)  # first run = baseline
            # weekly terakumulasi
            wk = json.loads((tmp / "nr" / "weekly-summary.json")
                            .read_text(encoding="utf-8"))
            self.assertEqual(list(wk["weeks"].values())[0]["runs"], 1)
            # run kedua: temuan baru -> drift added_count == 1
            fake2 = _FakeScan({
                "p1.example": [_finding("f1", "satu", 1),
                               _finding("f2", "dua", 3)],
            })
            with patch.object(nr, "run_cmd", fake2), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                nr.main_with_args(["--config", str(cfg), "--out",
                                   str(tmp / "nr"), "--no-pdf"])
            drift2 = json.loads((st / "drift.json").read_text(encoding="utf-8"))
            self.assertEqual(drift2["added_count"], 1)
            self.assertFalse(drift2["first_run"])
            wk2 = json.loads((tmp / "nr" / "weekly-summary.json")
                             .read_text(encoding="utf-8"))
            week = list(wk2["weeks"].values())[0]
            self.assertEqual(week["runs"], 2)
            self.assertEqual(week["added_total"], 1)
            self.assertEqual(week["by_program"]["p1"]["added"], 1)

    def test_budget_passed_to_scan_argv(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "p1", "domain": "p1.example",
                                 "budget": 8}])
            fake = _FakeScan({"p1.example": []})
            with patch.object(nr, "run_cmd", fake), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                nr.main_with_args(["--config", str(cfg), "--out",
                                   str(tmp / "nr"), "--no-pdf"])
            argv = fake.calls[0]
            self.assertIn("--max-requests", argv)
            self.assertEqual(argv[argv.index("--max-requests") + 1], "8")
            self.assertIn("--mode", argv)
            self.assertEqual(argv[argv.index("--mode") + 1], "tier0")

    def test_scan_failure_is_recorded_and_exit_1(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "p1", "domain": "p1.example",
                                 "budget": 8}])
            fake = _FakeScan({}, fail_domains={"p1.example"})
            with patch.object(nr, "run_cmd", fake), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                rc = nr.main_with_args(["--config", str(cfg), "--out",
                                        str(tmp / "nr"), "--no-pdf"])
            self.assertEqual(rc, 1)
            run_dir = next(d for d in (tmp / "nr").iterdir()
                           if d.is_dir() and d.name != "state")
            doc = json.loads((run_dir / "nightrun-summary.json")
                             .read_text(encoding="utf-8"))
            self.assertEqual(doc["failed"], 1)
            self.assertIn("boom", doc["programs"][0]["error"])

    def test_config_error_raises_and_no_scan(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "a", "domain": "a.example"},
                                {"id": "a", "domain": "b.example"}])
            fake = _FakeScan({})
            with patch.object(nr, "run_cmd", fake), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                with self.assertRaises(nr.ConfigError):
                    nr.main_with_args(["--config", str(cfg), "--out",
                                       str(tmp / "nr"), "--no-pdf"])
            self.assertEqual(fake.calls, [])
            # CLI entry memetakan ConfigError -> exit 2 (fail-closed)
            with patch.object(sys, "argv",
                              ["nightrun.py", "--config", str(cfg),
                               "--out", str(tmp / "nr2"), "--no-pdf"]):
                self.assertEqual(nr.main(), 2)

    def test_dry_run_prints_plan_without_scan(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = _config(tmp, [{"id": "p1", "domain": "p1.example",
                                 "budget": 4}])
            fake = _FakeScan({})
            with patch.object(nr, "run_cmd", fake), \
                 patch.object(nr, "resolve_exe", lambda: Path("fake-exe")):
                rc = nr.main_with_args(["--config", str(cfg), "--out",
                                        str(tmp / "nr"), "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
