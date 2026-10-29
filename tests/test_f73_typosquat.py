"""F73 — typosquat-watch: permutasi deterministik + drift CT (mock)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import typosquat_watch as tw  # noqa: E402


class PermutationTest(unittest.TestCase):
    def test_deterministic_sorted_bounded(self):
        a = tw.permutations("brandku.com")
        b = tw.permutations("brandku.com")
        self.assertEqual(a, b)
        self.assertEqual(a, sorted(a))
        self.assertLessEqual(len(a), tw.MAX_PERMUTATIONS)

    def test_omission_and_transposition_present(self):
        perms = set(tw.permutations("brandku.com"))
        self.assertIn("brndku.com", perms)      # omission 'a'
        self.assertIn("rbandku.com", perms)     # transposisi br -> rb
        self.assertIn("brandk-u.com", perms)    # hyphenasi

    def test_digit_swap_and_original_excluded(self):
        perms = set(tw.permutations("brandku.com"))
        self.assertIn("br4ndku.com", perms)   # digit-swap a->4
        self.assertNotIn("brandku.com", perms)   # asli bukan kandidat

    def test_scoped_to_first_label(self):
        perms = set(tw.permutations("seed.brandku.co.id"))
        self.assertTrue(all(p.endswith(".brandku.co.id") or p == "brandku.co.id"
                            or ".co.id" in p for p in perms))
        self.assertIn("sed.brandku.co.id", perms)


class DriftTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._state = tw.STATE_DIR
        tw.STATE_DIR = Path(self.tmp.name) / "state"

    def tearDown(self):
        tw.STATE_DIR = self._state
        self.tmp.cleanup()

    def _mock(self, names: list[str]):
        orig = tw.fetch_names
        tw.fetch_names = lambda d: {"names": names}
        self.addCleanup(lambda: setattr(tw, "fetch_names", orig))

    def test_baseline_no_finding_then_new_name_flags(self):
        self._mock(["app.contoh.id", "www.contoh.id"])
        rows, meta = tw.audit("contoh.id")
        self.assertEqual(rows, [])          # baseline
        self.assertTrue(meta["baseline"])

        self._mock(["app.contoh.id", "www.contoh.id", "pay.contoh.id"])
        rows, meta = tw.audit("contoh.id")
        self.assertEqual(len(rows), 1)
        self.assertIn("pay.contoh.id", rows[0]["title"])
        self.assertEqual(rows[0]["verdict"], 1)  # L1 lead, bukan klaim phishing

    def test_same_names_again_no_finding(self):
        self._mock(["app.contoh.id"])
        tw.audit("contoh.id")
        rows, meta = tw.audit("contoh.id")
        self.assertEqual(rows, [])
        self.assertFalse(meta["baseline"])

    def test_corrupt_state_treated_as_baseline(self):
        tw.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (tw.STATE_DIR / "contoh.id.json").write_text("{zz", encoding="utf-8")
        self._mock(["app.contoh.id"])
        rows, meta = tw.audit("contoh.id")
        self.assertEqual(rows, [])
        self.assertTrue(meta["baseline"])

    def test_error_fail_closed(self):
        orig = tw.fetch_names
        tw.fetch_names = lambda d: {"__error__": "timeout"}
        try:
            rows, meta = tw.audit("contoh.id")
        finally:
            tw.fetch_names = orig
        self.assertFalse(meta["ok"])
        self.assertEqual(rows, [])


class RegistryGateTest(unittest.TestCase):
    def test_typosquat_watch_registered(self):
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        entry = next(s for s in reg["skills"] if s["name"] == "typosquat-watch")
        self.assertEqual(entry["needs"], "domain")
        self.assertEqual(entry["safety_class"], "read-only")


if __name__ == "__main__":
    unittest.main()
