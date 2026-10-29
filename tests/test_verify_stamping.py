"""Test F19 — stamping integritas evidence di verify_findings.

evidence_hash Python harus replikasi persis fao.rs (empatis terverifikasi
saat stamping 11 program: 0 HASH_MISMATCH = parity Rust/Python OK).
NOL jaringan.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import verify_findings as vf  # noqa: E402


class EvidenceHashTest(unittest.TestCase):
    def test_known_vector_and_normalization(self):
        row = {"request": "GET  /   HTTP/1.1",  # spasi ganda -> collapse
               "response": "HTTP/1.1 200 OK", "poc": ""}
        basis = "GET / HTTP/1.1|HTTP/1.1 200 OK|"
        self.assertEqual(vf.evidence_hash(row),
                         hashlib.sha256(basis.encode()).hexdigest())
        self.assertEqual(len(vf.evidence_hash(row)), 64)

    def test_non_string_value_compact_json_like_rust(self):
        row = {"response": {"a": 1, "b": "x"}}
        expected = hashlib.sha256(
            b'|{"a":1,"b":"x"}|').hexdigest()
        self.assertEqual(vf.evidence_hash(row), expected)

    def test_hash_changes_with_evidence(self):
        a = vf.evidence_hash({"response": "x"})
        b = vf.evidence_hash({"response": "y"})
        self.assertNotEqual(a, b)


class StampEvidenceTest(unittest.TestCase):
    def _row(self, **over):
        row = {"tool": "t", "title": "x", "response": "resp-1",
               "request": "", "poc": "",
               "evidence_hash": hashlib.sha256(b"|resp-1|").hexdigest()}
        row.update(over)
        return row

    def test_intact_when_hash_matches_and_file_exists(self):
        with tempfile.TemporaryDirectory() as td:
            ev = Path(td) / "banner.html"
            ev.write_text("<html></html>", encoding="utf-8")
            stamped, s = vf.stamp_evidence([self._row()], str(ev))
        self.assertEqual(s, {"intact": 1, "hash_mismatch": 0,
                             "no_evidence_data": 0, "evidence_missing": 0})
        self.assertEqual(stamped[0]["cross_verification"]["verdict"],
                         "EVIDENCE_INTACT")
        self.assertEqual(stamped[0]["cross_verification"]["method"],
                         "evidence-integrity")

    def test_hash_mismatch_detected(self):
        with tempfile.TemporaryDirectory() as td:
            ev = Path(td) / "banner.html"
            ev.write_text("<html></html>", encoding="utf-8")
            stamped, s = vf.stamp_evidence(
                [self._row(evidence_hash="deadbeefdeadbeef")], str(ev))
        self.assertEqual(s["hash_mismatch"], 1)

    def test_evidence_missing_and_no_data(self):
        stamped, s = vf.stamp_evidence(
            [self._row(), self._row(response="", evidence_hash=None)],
            str(Path(td_none) / "absen.html") if False else "Z:/tidak/ada.html")
        self.assertEqual(s["evidence_missing"], 1)
        self.assertEqual(s["no_evidence_data"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
