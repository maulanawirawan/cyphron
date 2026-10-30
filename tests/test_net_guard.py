"""Fase 2-B — net_guard: penegakan budget SEBELUM koneksi (skeleton).

Semua test pakai server lokal 127.0.0.1 dan SELALU uninstall patch di
finally — patch global tidak boleh bocor ke test lain.
"""
from __future__ import annotations

import io
import json
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import net_guard  # noqa: E402


class EchoServer:
    """Listener TCP lokal penghitung koneksi yang BENAR-BENAR diterima."""

    def __init__(self):
        self.accepted = 0
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            conn.close()

    def close(self):
        self._stop.set()
        self._t.join(timeout=2)
        self._srv.close()

    def wait_accepted(self, n: int, timeout: float = 3.0) -> int:
        """Poll sampai n koneksi di-accept atau timeout — hindari race
        assert vs thread accept."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.accepted >= n:
                break
            time.sleep(0.02)
        return self.accepted


class NetGuardTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = Path(tempfile.mkdtemp())
        self.budget = self.dir / "budget.json"
        self.audit = self.dir / "audit.jsonl"
        self.budget.write_text(json.dumps({"limit": 2, "used": 0}),
                               encoding="utf-8")

    def tearDown(self):
        # uninstall ada — patch tidak boleh bocor ke test lain
        pass  # uninstall dipanggil eksplisit di tiap test (finally)

    def _audit_rows(self) -> list[dict]:
        if not self.audit.exists():
            return []
        return [json.loads(l) for l in
                self.audit.read_text(encoding="utf-8").splitlines() if l]

    def test_budget_cukup_connect_lolos_dan_tercatat(self):
        srv = EchoServer()
        un = net_guard.install(self.budget, self.audit)
        try:
            s = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            s.close()
            self.assertEqual(srv.wait_accepted(1), 1)
            rows = self._audit_rows()
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["allowed"])
            self.assertEqual(rows[0]["kind"], "tcp-create-connection")
            self.assertEqual(
                json.loads(self.budget.read_text(encoding="utf-8"))["used"], 1)
        finally:
            un()
            srv.close()

    def test_budget_habis_ditolak_sebelum_connect(self):
        srv = EchoServer()
        un = net_guard.install(self.budget, self.audit)
        try:
            # token 1: lolos
            s = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            s.close()
            # token 2: habis
            s = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            s.close()
            self.assertEqual(srv.wait_accepted(2), 2)
            # token 3: DITOLAK — server TIDAK menerima koneksi ke-3
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            self.assertEqual(srv.wait_accepted(2), 2)  # tetap 2 = ditolak SEBELUM connect
            self.assertEqual(
                json.loads(self.budget.read_text(encoding="utf-8"))["used"], 2)
        finally:
            un()
            srv.close()

    def test_budget_file_hilang_fail_closed(self):
        srv = EchoServer()
        self.budget.unlink()
        un = net_guard.install(self.budget, self.audit)
        try:
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            self.assertEqual(srv.accepted, 0)
        finally:
            un()
            srv.close()

    def test_budget_file_korup_fail_closed(self):
        srv = EchoServer()
        self.budget.write_text("{bukan json", encoding="utf-8")
        un = net_guard.install(self.budget, self.audit)
        try:
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", srv.port), timeout=3)
            self.assertEqual(srv.accepted, 0)
        finally:
            un()
            srv.close()

    def test_udp_sendto_terhitung(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(3)
        rxport = rx.getsockname()[1]
        un = net_guard.install(self.budget, self.audit)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"ping", ("127.0.0.1", rxport))  # token 1
            data, _ = rx.recvfrom(1024)
            self.assertEqual(data, b"ping")
            socket.create_connection  # no-op agar linter senang
            # token 2 lalu ditolak
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.sendto(b"p2", ("127.0.0.1", rxport))
            rx.recvfrom(1024)
            s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            with self.assertRaises(OSError):
                s3.sendto(b"p3", ("127.0.0.1", rxport))
        finally:
            un()
            rx.close()

    def test_connect_ex_mengembalikan_error_bukan_raise(self):
        srv = EchoServer()
        self.budget.write_text(json.dumps({"limit": 1, "used": 1}),
                               encoding="utf-8")  # langsung habis
        un = net_guard.install(self.budget, self.audit)
        try:
            s = socket.socket()
            rc = s.connect_ex(("127.0.0.1", srv.port))
            self.assertNotEqual(rc, 0)
            import time
            time.sleep(0.3)  # beri kesempatan bila (salah) lolos
            self.assertEqual(srv.accepted, 0)
            s.close()
        finally:
            un()
            srv.close()

    def test_install_idempotent_dan_uninstall_bersih(self):
        srv = EchoServer()
        un1 = net_guard.install(self.budget, self.audit)
        un2 = net_guard.install(self.budget, self.audit)
        try:
            self.assertIs(un1, un2)  # tidak menumpuk patch
        finally:
            un1()
        # setelah uninstall: koneksi bebas, tanpa audit baru
        before = len(self._audit_rows())
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=3)
        s.close()
        self.assertEqual(len(self._audit_rows()), before)
        self.assertEqual(srv.wait_accepted(1), 1)
        srv.close()

    def test_sitecustomize_menyala_via_subprocess_env(self):
        """Integrasi mirip runner: subprocess Python dengan
        CYPHRON_NET_GUARD=1 + PYTHONPATH root + tools/net_guard harus
        ter-gate (budget habis -> connect ditolak)."""
        self.budget.write_text(json.dumps({"limit": 0, "used": 0}),
                               encoding="utf-8")
        code = (
            "import socket, sys\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print('BLOCKED', 'net-guard' in str(e))\n")
        env = {
            "PATH": __import__("os").environ["PATH"],
            "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
            "CYPHRON_NET_GUARD": "1",
            "CYPHRON_NET_BUDGET_FILE": str(self.budget),
            "CYPHRON_NET_AUDIT": str(self.audit),
            "PYTHONPATH": f"{ROOT}{__import__('os').pathsep}{ROOT / 'tools' / 'net_guard'}",
        }
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True, timeout=30,
                              env=env)
        self.assertIn("BLOCKED True", proc.stdout,
                      f"stdout={proc.stdout!r} stderr={proc.stderr!r}")


if __name__ == "__main__":
    unittest.main()
