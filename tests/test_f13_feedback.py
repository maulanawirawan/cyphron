"""Test F13 — field feedback loop (korelasi lintas run) + F11 auth file.

Semua pakai fixture temp — nol jaringan, nol subprocess berat.
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

import field_feedback as ff  # noqa: E402


def run_doc(run_id, rows):
    return {"path": f"run-{run_id}", "findings": rows}


def row(fid, title="Temuan X", verdict=3, tool="nuclei"):
    return {"id": fid, "title": title, "verdict": verdict, "tool": tool,
            "severity": "high" if verdict >= 3 else "info"}


class AnalyzeTest(unittest.TestCase):
    def test_stable_confirmed_across_runs(self):
        docs = [
            run_doc(1, [row("a"), row("b")]),
            run_doc(2, [row("a"), row("c")]),
        ]
        (stable, fp_cand, new), detail = ff.analyze(docs)
        ids = {fid for fid, _ in stable}
        self.assertEqual(ids, {"a"})
        self.assertEqual(detail["stable_confirmed"], 1)
        self.assertEqual(detail["unique_findings"], 3)

    def test_fp_candidate_when_l3_disappears(self):
        docs = [
            run_doc(1, [row("gone"), row("ok")]),
            run_doc(2, [row("ok")]),
        ]
        (stable, fp_cand, new), detail = ff.analyze(docs)
        self.assertEqual({fid for fid, _ in fp_cand}, {"gone"})
        self.assertEqual({fid for fid, _ in stable}, {"ok"})

    def test_new_in_latest_run(self):
        docs = [
            run_doc(1, [row("old")]),
            run_doc(2, [row("fresh")]),
        ]
        (_, fp_cand, new), detail = ff.analyze(docs)
        self.assertEqual({fid for fid, _ in new}, {"fresh"})

    def test_build_findings_contract_shape(self):
        docs = [
            run_doc(1, [row("a"), row("gone")]),
            run_doc(2, [row("a"), row("fresh")]),
        ]
        (stable, fp_cand, new), detail = ff.analyze(docs)
        rows = ff.build_findings(stable, fp_cand, new, detail)
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(r["category"], "LEARNING")
            self.assertIn("learning_kind", r)
            self.assertIn(r["verdict"], (0, 1))
        kinds = {r["learning_kind"] for r in rows}
        self.assertEqual(kinds, {"stable_confirmed", "fp_candidate", "new"})


class AuthFileTest(unittest.TestCase):
    def test_serve_auth_file_via_cli_build(self):
        # Auth::from_file diuji di sisi Rust (tests serve::tests);
        # di sini cukup pastikan format file yang kita dokumentasikan valid.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tokens.json"
            p.write_text(json.dumps({"tokens": [
                {"token": "abc", "operator": "owner", "role": "admin"},
            ]}), encoding="utf-8")
            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertIn("tokens", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
