"""F74 — audit_offline: audit sumber lokal dengan jaringan DITOLAK
sebelum koneksi (net-guard budget 0, deny-all enforced)."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import audit_offline  # noqa: E402


class BuildEnvTest(unittest.TestCase):
    def test_env_membawa_guard_dan_pythonpath(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            env, budget, audit = audit_offline.build_env(
                Path(td), out, base_env={"PATH": os.environ["PATH"]})
            self.assertEqual(env[audit_offline.GUARD_ENV], "1")
            self.assertEqual(env[audit_offline.BUDGET_ENV],
                             str(budget))
            self.assertEqual(env[audit_offline.AUDIT_ENV],
                             str(audit))
            pp = env["PYTHONPATH"].split(os.pathsep)
            self.assertIn(str(ROOT), pp)                       # core.net_guard
            self.assertIn(str(ROOT / "tools" / "net_guard"), pp)  # sitecustomize
            # budget limit 0 = deny-all
            import json
            self.assertEqual(json.loads(budget.read_text(encoding="utf-8")),
                             {"limit": 0, "used": 0})

    def test_pythonpath_duplikat_tidak_terjadi(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            base = {"PATH": "x",
                    "PYTHONPATH": str(ROOT) + os.pathsep + "sudah-ada"}
            env, _, _ = audit_offline.build_env(Path(td), Path(td) / "o",
                                                base_env=base)
            pp = env["PYTHONPATH"].split(os.pathsep)
            self.assertEqual(pp.count(str(ROOT)), 1)


class EnforceTest(unittest.TestCase):
    def test_subprocess_dengan_env_ditolak_sebelum_connect(self):
        """End-to-end pola net-guard: python + env audit-offline ->
        koneksi apapun ditolak SEBELUM connect (server tak menerima)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            env, _, _ = audit_offline.build_env(Path(td), out,
                                                base_env={"PATH": os.environ["PATH"]})
            code = (
                "import socket\n"
                "try:\n"
                "    socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
                "    print('LEAK')\n"
                "except OSError as e:\n"
                "    print('BLOCKED', 'net-guard' in str(e))\n")
            proc = subprocess.run([sys.executable, "-c", code],
                                  capture_output=True, text=True,
                                  timeout=30, env=env)
            self.assertIn("BLOCKED True", proc.stdout,
                          f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_denied_count_dari_audit_log(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "audit.jsonl"
            audit.write_text(
                '{"allowed": true, "kind": "tcp-connect"}\n'
                '{"allowed": false, "kind": "tcp-connect"}\n'
                'baris-rusak\n'
                '{"allowed": false, "kind": "udp-sendto"}\n',
                encoding="utf-8")
            self.assertEqual(audit_offline.denied_count(audit), 2)
            self.assertEqual(audit_offline.denied_count(Path(td) / "nope"), 0)


class MainFailClosedTest(unittest.TestCase):
    def test_source_hilang_exit_2(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rc = audit_offline.main.__wrapped__() if hasattr(
                audit_offline.main, "__wrapped__") else None
            # panggil main dengan argv terarah ke source yang tidak ada
            old_argv = sys.argv
            sys.argv = ["audit_offline.py", "--source",
                        str(Path(td) / "tidak-ada"), "--out", str(Path(td) / "o")]
            try:
                rc = audit_offline.main()
            finally:
                sys.argv = old_argv
            self.assertEqual(rc, 2)

    def test_binary_hilang_exit_2(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            old_argv = sys.argv
            sys.argv = ["audit_offline.py", "--source", str(src),
                        "--out", str(Path(td) / "o"), "--binary",
                        str(Path(td) / "nope.exe")]
            try:
                rc = audit_offline.main()
            finally:
                sys.argv = old_argv
            self.assertEqual(rc, 2)


class EndToEndTest(unittest.TestCase):
    """Scan sumber fixture mini dgn enforcement — butuh binary release
    (dibangun cargo build --release; CI ubuntu: binary `cyphron`)."""

    def _binary(self) -> Path | None:
        exe = "cyphron.exe" if sys.platform == "win32" else "cyphron"
        b = ROOT / "core-rs" / "target" / "release" / exe
        return b if b.exists() else None

    def test_e2e_scan_fixture_nol_request(self):
        import tempfile
        b = self._binary()
        if b is None:
            self.skipTest("binary release belum dibangun")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "proj"
            src.mkdir()
            (src / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: nginx\n    ports: ['80:80']\n",
                encoding="utf-8")
            old_argv = sys.argv
            sys.argv = ["audit_offline.py", "--source", str(src),
                        "--out", str(Path(td) / "out"), "--binary", str(b)]
            try:
                rc = audit_offline.main()
            finally:
                sys.argv = old_argv
            self.assertEqual(rc, 0)
            summary = json.loads((Path(td) / "out" / "offline-summary.json")
                                 .read_text(encoding="utf-8"))
            self.assertTrue(summary["offline_enforced"])
            self.assertEqual(summary["requests"], 0)  # NOL request ke target
            self.assertIn("repo-secret-scan", summary["skills_run"])
            self.assertIn("infra-config-audit", summary["skills_run"])


if __name__ == "__main__":
    unittest.main()
