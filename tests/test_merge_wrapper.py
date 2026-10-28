"""Test merge_findings.py sebagai thin wrapper `cyphron merge`.

Dua jalur wajib setara:
  - binary `cyphron merge` (validasi kontrak + dedup_by_id Rust);
  - fallback python murni (binary tidak ada — export OSS).
Flag lama dipertahankan: --run, --dedup-id, skip input hilang/ok=false,
meta output bentuk kontrak (run label + sources dict + requests jumlahan).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import merge_findings as mf  # noqa: E402
from findings import make_finding  # noqa: E402

EXE = ROOT / "core-rs" / "target" / "release" / "cyphron.exe"
EXE_OK = EXE.exists()


def _write_doc(p: Path, rows: list[dict], requests: int = 0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"ok": True,
                             "data": {"requests": requests},
                             "findings": rows}, ensure_ascii=False),
                 encoding="utf-8")


def _write_fixtures(a: Path, b: Path, req_a: int = 3, req_b: int = 4):
    """a: [X, A1]  b: [X, B1] — X id identik antar file (dedup), A1/B1 unik."""
    x = make_finding(tool="t", title="sama", severity="low", description="d",
                     target_url="x.example", evidence_kind="dns",
                     finding_class="posture", status="confirmed", verdict=0)
    a1 = make_finding(tool="t", title="unik-a", severity="low", description="d",
                      target_url="x.example", evidence_kind="dns",
                      finding_class="posture", status="confirmed", verdict=0)
    b1 = make_finding(tool="t", title="unik-b", severity="low", description="d",
                      target_url="x.example", evidence_kind="dns",
                      finding_class="posture", status="confirmed", verdict=0)
    _write_doc(a, [x, a1], requests=req_a)
    _write_doc(b, [x, b1], requests=req_b)


class FallbackPythonTest(unittest.TestCase):
    def test_fallback_dedup_and_meta_contract(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            a, b = td / "a.json", td / "b.json"
            _write_fixtures(a, b)
            out = td / "merged.json"
            argv = ["mf.py", str(a), str(b), "--out", str(out),
                    "--run", "label-uji", "--dedup-id"]
            with patch.dict(os.environ, {"CYPHRON_EXE": str(td / "nope.exe")}):
                rc = _main(argv)
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["run"], "label-uji")
            self.assertEqual(doc["data"]["total_findings"], 3)
            self.assertEqual(doc["data"]["dedup"]["duplicates_dropped"], 1)
            self.assertEqual(doc["requests"], 7)
            self.assertEqual(len(doc["data"]["sources"]), 2)
            self.assertEqual(doc["data"]["sources"][0]["file"], str(a))
            self.assertEqual(doc["findings"][0]["dup_count"], 2)

    def test_missing_and_ok_false_inputs_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            a = td / "a.json"
            _write_doc(a, [make_finding(tool="t", title="u1", severity="low",
                                        description="d",
                                        target_url="x.example",
                                        evidence_kind="dns",
                                        finding_class="posture",
                                        status="confirmed", verdict=0)],
                       requests=1)
            bad = td / "bad.json"
            bad.write_text('{"ok": false, "findings": []}', encoding="utf-8")
            out = td / "merged.json"
            argv = ["mf.py", str(a), str(td / "hilang.json"), str(bad),
                    "--out", str(out)]
            with patch.dict(os.environ, {"CYPHRON_EXE": str(td / "nope.exe")}):
                rc = _main(argv)
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["data"]["total_findings"], 1)
            self.assertEqual(len(doc["data"]["sources"]), 1)

    def test_no_usable_input_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            argv = ["mf.py", str(Path(td) / "hilang.json"),
                    "--out", str(Path(td) / "o.json")]
            with patch.dict(os.environ, {"CYPHRON_EXE": str(Path(td) / "n.exe")}):
                self.assertEqual(_main(argv), 2)


def _main(argv: list[str]) -> int:
    """main() dengan argv injeksi (tanpa sys.argv trick)."""
    old_argv = sys.argv
    sys.argv = argv
    try:
        return mf.main()
    finally:
        sys.argv = old_argv


@unittest.skipUnless(EXE_OK, "binary cyphron belum di-build")
class BinaryPathTest(unittest.TestCase):
    def test_binary_path_matches_fallback_output(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            a, b = td / "a.json", td / "b.json"
            _write_fixtures(a, b)
            out_bin, out_py = td / "out-bin.json", td / "out-py.json"
            common = ["--run", "label-uji", "--dedup-id"]
            with patch.dict(os.environ, {"CYPHRON_EXE": str(EXE)}):
                rc1 = _main(["mf.py", str(a), str(b), "--out",
                             str(out_bin)] + common)
            with patch.dict(os.environ, {"CYPHRON_EXE": str(td / "nope.exe")}):
                rc2 = _main(["mf.py", str(a), str(b), "--out",
                             str(out_py)] + common)
            self.assertEqual((rc1, rc2), (0, 0))
            d1 = json.loads(out_bin.read_text(encoding="utf-8"))
            d2 = json.loads(out_py.read_text(encoding="utf-8"))
            # findings + dedup + run + requests identik antar jalur
            self.assertEqual(
                [(f["id"], f.get("dup_count")) for f in d1["findings"]],
                [(f["id"], f.get("dup_count")) for f in d2["findings"]])
            self.assertEqual(d1["data"]["dedup"], d2["data"]["dedup"])
            self.assertEqual(d1["data"]["run"], d2["data"]["run"])
            self.assertEqual(d1["requests"], d2["requests"])
            self.assertEqual(d1["data"]["sources"], d2["data"]["sources"])

    def test_binary_rejects_contract_invalid_input_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bad = td / "bad.json"
            bad.write_text(json.dumps({"ok": True, "data": {}, "findings": [
                {"tool": "t", "title": "x", "severity": "TIDAK-VALID",
                 "description": "d", "confidence": 0.5, "status": "confirmed",
                 "verdict": 0, "id": "x", "reportable": False}]}),
                encoding="utf-8")
            out = td / "o.json"
            with patch.dict(os.environ, {"CYPHRON_EXE": str(EXE)}):
                rc = _main(["mf.py", str(bad), "--out", str(out)])
            self.assertEqual(rc, 1, "input kontrak-invalid harus exit 1 "
                                    "(bukan fallback senyap)")
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=1)
