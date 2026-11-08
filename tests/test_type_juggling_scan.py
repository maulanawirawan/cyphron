"""Test type_juggling_scan (#0512) — nol jaringan, fixture PHP inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import type_juggling_scan as tjs


def _write_php(tmp: "tempfile.TemporaryDirectory", name: str, code: str) -> Path:
    p = Path(tmp.name) / name
    p.write_text(code, encoding="utf-8")
    return p


class TestChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, extra: "list[str] | None" = None):
        rc = tjs.main(["--source", self.tmp.name, "--out",
                       str(Path(self.tmp.name) / "r.json")] + (extra or []))
        return rc, json.loads(
            (Path(self.tmp.name) / "r.json").read_text(encoding="utf-8"))

    def test_loose_hash_compare(self):
        _write_php(self.tmp, "a.php",
                   "<?php\nif (md5($input) == $stored) { login(); }\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        checks = [f["check"] for f in rep["findings"]]
        self.assertIn("loose-hash-compare", checks)
        f = next(f for f in rep["findings"]
                 if f["check"] == "loose-hash-compare")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["line"], 2)

    def test_strict_compare_clean(self):
        _write_php(self.tmp, "b.php",
                   "<?php\nif (md5($input) === $stored) { login(); }\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["findings"], 0)

    def test_magic_literal(self):
        _write_php(self.tmp, "c.php",
                   "<?php\nif ($token == '0e462097431906509019562988736854')"
                   " { grant(); }\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        checks = [f["check"] for f in rep["findings"]]
        self.assertIn("magic-literal-compare", checks)

    def test_strcmp_superglobal(self):
        _write_php(self.tmp, "d.php",
                   "<?php\nif (0 == strcmp($_POST['pw'], $real)) ok();\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        checks = [f["check"] for f in rep["findings"]]
        self.assertIn("strcmp-superglobal", checks)

    def test_in_array_loose_and_strict(self):
        _write_php(self.tmp, "e.php",
                   "<?php\n"
                   "if (in_array($otp, $codes)) allow();\n"
                   "if (in_array($otp, $codes, true)) allow2();\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        hits = [f for f in rep["findings"]
                if f["check"] == "in-array-loose-auth"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 2)

    def test_in_array_nonauth_ignored(self):
        _write_php(self.tmp, "f.php",
                   "<?php\nif (in_array($fruit, $basket)) eat();\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["findings"], 0)

    def test_auth_eq_zero(self):
        _write_php(self.tmp, "g.php",
                   "<?php\nif ($pin == 0) verify();\n"
                   "if (true == $password) grant();\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        hits = [f for f in rep["findings"]
                if f["check"] == "auth-eq-zero-coercion"]
        self.assertEqual(len(hits), 2)

    def test_superglobal_loose(self):
        _write_php(self.tmp, "h.php",
                   "<?php\nif ($_GET['role'] == $required) act();\n")
        rc, rep = self._run()
        self.assertEqual(rc, 1)
        checks = [f["check"] for f in rep["findings"]]
        self.assertIn("loose-superglobal-compare", checks)

    def test_comments_skipped(self):
        _write_php(self.tmp, "i.php",
                   "<?php\n// md5($x) == $y contoh komentar\n"
                   "/* *\n * sha1($a) == $b juga komentar\n */\n$ok = 1;\n")
        rc, rep = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["findings"], 0)

    def test_dedup_same_line(self):
        _write_php(self.tmp, "j.php",
                   "<?php\nif (md5($_POST['p']) == $h) login();\n")
        rc, rep = self._run()
        # dua check boleh menyala di baris sama (hash + superglobal),
        # tapi TIDAK ada duplikat (check,file,line) identik
        keys = [(f["check"], f["file"], f["line"]) for f in rep["findings"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreaterEqual(len(keys), 2)


class TestModes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "r.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_allow_check(self):
        p = Path(self.tmp.name) / "a.php"
        p.write_text("<?php\nif (md5($i) == $s) x();\n", encoding="utf-8")
        rc = tjs.main(["--source", str(p), "--out", str(self.out),
                       "--allow-check", "loose-hash-compare"])
        rep = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["findings"], 0)
        self.assertTrue(any("disaring" in n for n in rep["notes"]))

    def test_no_php_files_exit2(self):
        Path(self.tmp.name, "readme.txt").write_text("halo")
        rc = tjs.main(["--source", self.tmp.name])
        self.assertEqual(rc, 2)

    def test_missing_source_exit2(self):
        rc = tjs.main(["--source", str(Path(self.tmp.name) / "nope")])
        self.assertEqual(rc, 2)

    def test_no_args_exit2(self):
        rc = tjs.main([])
        self.assertEqual(rc, 2)

    def test_verify_hash_magic_table(self):
        rc = tjs.main(["--verify-hash",
                       "0e462097431906509019562988736854,plain-text"])
        self.assertEqual(rc, 0)  # mode verify selalu 0, output di stdout

    def test_verify_table_preimages_are_magic(self):
        rows = tjs.verify_hashes(["0e1"])
        tail = rows[-1]
        self.assertTrue(tail["magic"])
        # deterministik: md5("240610708") memang 0e...
        d = next(r for r in rows if r["input"] == 'md5("240610708")')
        self.assertTrue(d["magic"])
        self.assertEqual(d["digest"], "0e462097431906509019562988736854")

    def test_fail_on_low_includes_medium(self):
        p = Path(self.tmp.name) / "a.php"
        p.write_text("<?php\nif ($pin == 0) v();\n", encoding="utf-8")
        rc = tjs.main(["--source", str(p), "--out", str(self.out),
                       "--fail-on", "low"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
