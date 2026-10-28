"""Test tools/atomic.py — tulis atomik + kunci satu penulis.

Nol jaringan; lock diuji lintas thread (proses kedua = ThreadPool).
"""
from __future__ import annotations

import concurrent.futures
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from atomic import atomic_write_bytes, atomic_write_text, single_writer_lock  # noqa: E402


class AtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_atomic_"))

    def test_write_and_read_back(self):
        p = self.tmp / "sub" / "out.json"
        atomic_write_text(p, '{"ok": true}')
        self.assertEqual(p.read_text(encoding="utf-8"), '{"ok": true}')

    def test_overwrite_replaces_content(self):
        p = self.tmp / "out.json"
        atomic_write_text(p, "lama")
        atomic_write_text(p, "baru")
        self.assertEqual(p.read_text(encoding="utf-8"), "baru")

    def test_bytes_roundtrip(self):
        p = self.tmp / "bin.dat"
        atomic_write_bytes(p, b"\x00\x01\xff")
        self.assertEqual(p.read_bytes(), b"\x00\x01\xff")

    def test_no_tmp_leftover_on_success(self):
        p = self.tmp / "out.json"
        atomic_write_text(p, "data")
        leftovers = list(self.tmp.glob("out.json.*.tmp"))
        self.assertEqual(leftovers, [], "file tmp harus ter-replace")

    def test_concurrent_writers_leave_valid_json(self):
        # 8 penulis paralel ke SATU path: replace atomik menjamin file
        # utuh — setelah semua selesai, isi adalah SALAH SATU versi
        # lengkap (tidak pernah setengah/korup). Catatan Windows:
        # open() yang bersamaan dengan replace bisa gagal sesaat
        # (sharing violation) — itu artefak OS, bukan korupsi file;
        # pembaca CLI berumur pendek tidak melihatnya di praktik.
        p = self.tmp / "out.json"
        atomic_write_text(p, json.dumps({"gen": 0}))

        def write(i):
            atomic_write_text(p, json.dumps({"gen": i}))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(write, range(8)))
        doc = json.loads(p.read_text(encoding="utf-8"))
        self.assertTrue(0 <= doc["gen"] < 8)


class SingleWriterLockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron_lock_"))
        self.lock = self.tmp / ".lock"

    def test_acquire_and_release(self):
        with single_writer_lock(self.lock):
            pass  # berhasil kunci + lepas tanpa error
        # re-acquire setelah lepas harus berhasil
        with single_writer_lock(self.lock):
            pass

    def test_second_writer_fails_fast(self):
        with single_writer_lock(self.lock):
            with self.assertRaises(RuntimeError) as ctx:
                with single_writer_lock(self.lock):
                    pass
            self.assertIn("fail-closed", str(ctx.exception))

    def test_lock_holds_pid_info(self):
        import os
        with single_writer_lock(self.lock):
            with self.assertRaises(RuntimeError) as ctx:
                with single_writer_lock(self.lock):
                    pass
            self.assertIn(f"pid={os.getpid()}", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
