"""Test evtx_hunt — NOL jaringan, EVTX-like binary di-mock in-memory.

Kontrak yang dikunci:
  - magic `ElfFile\\x00` wajib; bukan EVTX -> error (exit 2 via main);
  - string UTF-16LE di chunk ter-carve dan indikator terdeteksi per
    kategori (tooling/persistence/lateral);
  - EVTX-like tanpa indikator = clean, zero-FP;
  - output = indicator lead (bukan klaim event forensik utuh).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import evtx_hunt as eh  # noqa: E402


def _u16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _evtx(chunks: list[bytes]) -> bytes:
    out = bytearray(b"ElfFile\x00")
    out += b"\x00" * 32
    for i, body in enumerate(chunks):
        out += b"ElfChnk\x00"
        out += i.to_bytes(4, "little")
        out += body
    return bytes(out)


CHUNK_CLEAN = b"\x00" * 128 + _u16("Microsoft-Windows-Security-Auditing")
CHUNK_MIMI = b"\x00" * 16 + _u16("mimikatz.exe # seksek privilege::debug")
CHUNK_PERSIST = b"\x00" * 16 + _u16("schtasks /create /tn Update /sc onlogon")
CHUNK_LATERAL = b"\x00" * 16 + _u16("copy payload.dll \\\\host\\IPC$")


class HuntTest(unittest.TestCase):
    def test_clean_evtx_is_clean(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.evtx"
            p.write_bytes(_evtx([CHUNK_CLEAN]))
            res = eh.hunt_file(p)
            self.assertTrue(res["clean"])
            self.assertEqual(res["finding_count"], 0)
            self.assertEqual(res["chunks_detected"], 1)

    def test_tooling_and_persistence_and_lateral_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.evtx"
            p.write_bytes(_evtx([CHUNK_MIMI, CHUNK_PERSIST, CHUNK_LATERAL]))
            res = eh.hunt_file(p)
            cats = {f["category"]: f for f in res["findings"]}
            self.assertIn("tooling", cats)
            self.assertIn("persistence", cats)
            self.assertIn("lateral", cats)
            self.assertEqual(cats["tooling"]["severity"], "high")
            self.assertIn("mimikatz", cats["tooling"]["evidence"])

    def test_samples_are_lowercased_and_capped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.evtx"
            p.write_bytes(_evtx([CHUNK_MIMI]))
            res = eh.hunt_file(p)
            f0 = res["findings"][0]
            self.assertLessEqual(len(f0["evidence"]), 400)


class FailClosedTest(unittest.TestCase):
    def test_not_evtx_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.evtx"
            p.write_bytes(b"PK\x03\x04 bukan evtx")
            with self.assertRaises(ValueError):
                eh.hunt_file(p)

    def test_main_exit_2_on_not_evtx(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.evtx"
            p.write_bytes(b"random bytes here")
            rc = eh.main(["--file", str(p)])
            self.assertEqual(rc, 2)

    def test_main_exit_2_on_missing_file(self):
        rc = eh.main(["--file", str(ROOT / ".tmp" / "nope.evtx")])
        self.assertEqual(rc, 2)

    def test_main_writes_single_json_line(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.evtx"
            p.write_bytes(_evtx([CHUNK_CLEAN]))
            out = Path(td) / "o.json"
            rc = eh.main(["--file", str(p), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "secai.evtx-hunt/1")
            self.assertTrue(doc["read_only"])
            self.assertIn("BUKAN parser EVTX penuh", doc["note"])


if __name__ == "__main__":
    unittest.main()
