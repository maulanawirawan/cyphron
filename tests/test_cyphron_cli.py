"""Test cyphron.py — papan satu pintu mode.

Nol jaringan, tanpa build Rust: runner disuntik untuk passthrough, core
binary dipaksa None untuk jalur fallback, dan registry asli dibaca
langsung dari disk (file repo). Yang dijamin: semua mode menunjuk file
yang benar-benar ada, submode contrib benar, dan jalur gagal fail-closed.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))

import cyphron  # noqa: E402
from findings import make_finding  # noqa: E402


class DispatchTableTest(unittest.TestCase):
    def test_every_mode_script_exists(self):
        for name, entry in cyphron.MODES.items():
            script = entry.get("script")
            if script:
                self.assertTrue((ROOT / script).exists(),
                                f"mode {name} menunjuk file hilang: {script}")

    def test_contrib_submode_scripts_exist(self):
        for name, (desc, script) in cyphron.CONTRIB_SUBMODES.items():
            self.assertTrue((ROOT / script).exists(),
                            f"submode {name} menunjuk file hilang: {script}")


class MenuTest(unittest.TestCase):
    def test_no_args_prints_menu_exit_0(self):
        out, code = capture(lambda: cyphron.dispatch([]))
        self.assertEqual(code, 0)
        for mode in cyphron.MODES:
            self.assertIn(mode, out)
        self.assertIn("no proof, no report", out)

    def test_help_flag_prints_menu(self):
        out, code = capture(lambda: cyphron.dispatch(["--help"]))
        self.assertEqual(code, 0)

    def test_unknown_mode_exit_2(self):
        err, out, code = capture_err(lambda: cyphron.dispatch(["ngabubulitu"]))
        self.assertEqual(code, 2)
        self.assertIn("mode tidak dikenal", err)


def capture(fn):
    buf_out, code = io.StringIO(), None
    with redirect_stdout(buf_out):
        code = fn()
    return buf_out.getvalue(), code


def capture_err(fn):
    buf_err, buf_out, code = io.StringIO(), io.StringIO(), None
    with redirect_stderr(buf_err), redirect_stdout(buf_out):
        code = fn()
    return buf_err.getvalue(), buf_out.getvalue(), code


class PassthroughTest(unittest.TestCase):
    def test_scout_forwards_to_target_scout(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return 0

        code = cyphron.dispatch(["scout", "https://lab.lokal", "--json"],
                                runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertTrue(Path(argv[1]).as_posix().endswith("tools/target_scout.py"))
        self.assertIn("https://lab.lokal", argv)
        self.assertIn("--json", argv)

    def test_contrib_sweep_forwards(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return 0

        code = cyphron.dispatch(
            ["contrib", "sweep", "--since", "2026-11-06T00:00:00"],
            runner=runner)
        self.assertEqual(code, 0)
        self.assertTrue(
            Path(calls[0][1]).as_posix().endswith("tools/cve_sweep.py"))

    def test_contrib_antidup_forwards(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            return 0

        code = cyphron.dispatch(["contrib", "antidup", "--repo", "a/b"],
                                runner=runner)
        self.assertEqual(code, 0)
        self.assertTrue(
            Path(calls[0][1]).as_posix().endswith("tools/antidup_check.py"))

    def test_contrib_menu_without_submode(self):
        out, code = capture(lambda: cyphron.mode_contrib([]))
        self.assertEqual(code, 0)
        self.assertIn("sweep", out)
        self.assertIn("antidup", out)

    def test_contrib_unknown_submode_exit_2(self):
        err, _, code = capture_err(
            lambda: cyphron.dispatch(["contrib", "ngabubulitu"]))
        self.assertEqual(code, 2)
        self.assertIn("submode contrib tidak dikenal", err)


class CoreFallbackTest(unittest.TestCase):
    def setUp(self):
        self._orig = cyphron.core_binary
        cyphron.core_binary = lambda: None

    def tearDown(self):
        cyphron.core_binary = self._orig

    def test_scan_without_build_fails_with_hint(self):
        err, _, code = capture_err(lambda: cyphron.dispatch(["scan"]))
        self.assertEqual(code, 2)
        self.assertIn("cargo build", err)

    def test_validate_without_build_uses_python_fallback(self):
        finding = make_finding(
            tool="test", title="uji kontrak", severity="low",
            description="temuan sah dari test", target_url="http://lab.local",
            evidence_kind="request-response", status="confirmed",
            verdict=2, confidence=1.0)
        with tempfile_named("f.json", json.dumps(finding)) as path:
            out, code = capture(
                lambda: cyphron.dispatch(["validate", str(path)]))
        self.assertEqual(code, 0)
        self.assertIn("[OK", out)

    def test_validate_rejects_bad_finding(self):
        with tempfile_named("f.json", json.dumps({"title": "ngawur"})) as path:
            err, _, code = capture_err(
                lambda: cyphron.dispatch(["validate", str(path)]))
        self.assertEqual(code, 1)
        self.assertIn("[INVALID", err)


class SkillsModeTest(unittest.TestCase):
    def test_lists_real_registry(self):
        out, code = capture(lambda: cyphron.dispatch(["skills"]))
        self.assertEqual(code, 0)
        self.assertIn("93 skill", out)
        self.assertIn("tier0", out)

    def test_class_filter(self):
        out, code = capture(
            lambda: cyphron.dispatch(["skills", "--class", "read-only"]))
        self.assertEqual(code, 0)
        for line in out.splitlines():
            if line.startswith("  "):
                self.assertIn("read-only", line)

    def test_text_filter(self):
        out, code = capture(
            lambda: cyphron.dispatch(["skills", "--text", "cors"]))
        self.assertEqual(code, 0)
        # tidak meledak; kalau tidak ada yang cocok tetap exit 0
        self.assertIn("skill (", out)

    def test_unknown_args_rejected(self):
        err, _, code = capture_err(
            lambda: cyphron.dispatch(["skills", "--ngawur"]))
        self.assertEqual(code, 2)


def tempfile_named(name, content):
    """Contextmanager file sementara berisi konten."""
    import tempfile
    import os
    from contextlib import contextmanager

    @contextmanager
    def ctx():
        fd, path = tempfile.mkstemp(prefix="cyphron_cli_", suffix=f"_{name}")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            yield path
        finally:
            os.unlink(path)
    return ctx()


if __name__ == "__main__":
    unittest.main()
