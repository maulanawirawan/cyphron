"""Riset oss-scanner — threat_model loader per program Cyphron.

Fail-closed: opsional (tidak ada = None), bounded 64 KB, path WAJIB di
dalam programs/ (symlink/traversal keluar = ditolak), output ber-hash.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import threat_model  # noqa: E402


def make_programs(tmp: Path, layout: dict):
    """Bangun folder programs/ sementara dgn index + file opsional."""
    pdir = tmp / "programs"
    pdir.mkdir()
    index = {"version": 1, "programs": layout.get("programs", [])}
    import json
    (pdir / "index.json").write_text(
        json.dumps(index, ensure_ascii=False), encoding="utf-8")
    for rel, content in layout.get("files", {}).items():
        f = pdir / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content.encode("utf-8"))  # tanpa newline translation
    return pdir


class ThreatModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_tidak_ada_file(self):
        pdir = make_programs(self.tmp, {"programs": [
            {"id": "p1", "name": "P1"}]})
        out = threat_model.load_for_program(
            {"id": "p1"}, programs_dir=pdir, root=self.tmp)
        self.assertIsNone(out)  # opsional — bukan error

    def test_muat_normal_dengan_hash_dan_sections(self):
        content = ("# Threat model: P2\n\n"
                   "## Where untrusted input enters\nhttp API.\n\n"
                   "## How you rate severity\nhigh+critical only.\n")
        pdir = make_programs(self.tmp, {
            "programs": [{"id": "p2"}],
            "files": {"p2/threat_model.md": content}})
        out = threat_model.load_for_program({"id": "p2"}, programs_dir=pdir,
                                            root=self.tmp)
        self.assertIsNotNone(out)
        self.assertEqual(out["title"], "Threat model: P2")
        self.assertEqual(len(out["sections"]), 2)
        self.assertEqual(out["bytes"], len(content.encode()))
        self.assertEqual(len(out["sha256"]), 16)
        self.assertIn("severity", out["text"])

    def test_ukuran_lebih_dari_bound_ditolak(self):
        pdir = make_programs(self.tmp, {
            "programs": [{"id": "p3"}],
            "files": {"p3/threat_model.md": "x" * (threat_model.MAX_BYTES + 1)}})
        out = threat_model.load_for_program({"id": "p3"}, programs_dir=pdir,
                                            root=self.tmp)
        self.assertIsNotNone(out)
        self.assertIn("ditolak", out.get("rejected", ""))

    def test_field_path_luar_programs_ditolak(self):
        pdir = make_programs(self.tmp, {"programs": [
            {"id": "p4", "threat_model": "findings/rahasia/tm.md"}]})
        out = threat_model.load_for_program(
            {"id": "p4", "threat_model": "findings/rahasia/tm.md"},
            programs_dir=pdir, root=self.tmp)
        self.assertIsNotNone(out)
        self.assertIn("di luar programs/", out.get("rejected", ""))

    def test_traversal_keluar_ditolak(self):
        pdir = make_programs(self.tmp, {"programs": [
            {"id": "p5", "threat_model": "programs/../secrets/tm.md"}]})
        # buat file target di luar programs/
        target = self.tmp / "secrets"
        target.mkdir()
        (target / "tm.md").write_text("# secret", encoding="utf-8")
        out = threat_model.load_for_program(
            {"id": "p5", "threat_model": "programs/../secrets/tm.md"},
            programs_dir=pdir, root=self.tmp)
        self.assertIsNotNone(out)
        self.assertIn("di luar programs/", out.get("rejected", ""))

    def test_symlink_keluar_ditolak(self):
        pdir = make_programs(self.tmp, {"programs": [{"id": "p6"}]})
        target = self.tmp / "outside.md"
        target.write_text("# rahasia", encoding="utf-8")
        link = pdir / "p6"
        link.mkdir()
        try:
            (link / "threat_model.md").symlink_to(target)
        except OSError:
            self.skipTest("symlink tidak didukung di lingkungan ini")
        out = threat_model.load_for_program({"id": "p6"}, programs_dir=pdir,
                                            root=self.tmp)
        self.assertIn("di luar programs/", out.get("rejected", ""))

    def test_summarize_pendek(self):
        meta = {"title": "TM X", "sections": ["A", "B"],
                "text": "# TM X\n\n## A\n\n## B\n"}
        s = threat_model.summarize(meta)
        self.assertIn("TM X", s)
        self.assertIn("A; B", s)
        self.assertIsNone(threat_model.summarize(None))
        self.assertIsNone(threat_model.summarize({"rejected": "x"}))


if __name__ == "__main__":
    unittest.main()
