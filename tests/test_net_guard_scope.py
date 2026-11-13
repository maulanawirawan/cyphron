"""Test net-guard scope-check + pin-IP anti-rebinding (Fase 2-C).

NOL jaringan eksternal — target = server HTTP lokal 127.0.0.1.
Kontrak yang dikunci:
  - tanpa scope: perilaku lama (hanya budget) — kompatibel;
  - scope aktif = default-DENY: host luar scope ditolak SEBELUM resolve
    (DNS untuk host itu tidak pernah dikirim);
  - anti-rebinding: hostname yang lolos di-resolve SEKALI dan koneksi
    dibuat KE SOCKADDR hasil resolve (bukan ke hostname);
  - resolve yang menghasilkan IP luar scope (mode IP/CIDR) ditolak;
  - scope file hilang/korup saat env diset = deny-all (fail-closed);
  - baris audit `scope-deny` tercatat dengan reason.
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import socket
import sys
import threading
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import net_guard as ng  # noqa: E402
from net_guard_scope import Scope, load_scope, resolve_pin, udp_pin  # noqa: E402


class ScopeMatchTest(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com"], ["127.0.0.1"],
                           [ipaddress.ip_network("10.0.0.0/8")])

    def test_domain_exact_and_suffix(self):
        self.assertTrue(self.scope.host_allowed("example.com"))
        self.assertTrue(self.scope.host_allowed("sub.example.com"))
        self.assertTrue(self.scope.host_allowed("EXAMPLE.com."))  # trailing dot
        self.assertFalse(self.scope.host_allowed("notexample.com"))
        self.assertFalse(self.scope.host_allowed("example.com.evil.test"))

    def test_ip_and_cidr(self):
        self.assertTrue(self.scope.host_allowed("127.0.0.1"))
        self.assertTrue(self.scope.host_allowed("10.1.2.3"))
        self.assertFalse(self.scope.host_allowed("192.168.1.1"))

    def test_deny_all_scope(self):
        s = Scope.deny_all()
        self.assertFalse(s.host_allowed("anything.test"))
        self.assertFalse(s.sockaddr_allowed(("127.0.0.1", 80)))


class LoadScopeTest(unittest.TestCase):
    def test_ok(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scope.json"
            p.write_text(json.dumps({"domains": ["example.com"],
                                     "ips": ["127.0.0.1"],
                                     "cidrs": ["10.0.0.0/8"]}),
                         encoding="utf-8")
            s = load_scope(p)
            self.assertTrue(s.host_allowed("sub.example.com"))
            self.assertTrue(s.host_allowed("10.2.3.4"))

    def test_missing_file_is_deny_all(self):
        s = load_scope("/nonexistent/scope.json")
        self.assertTrue(s.deny_all)

    def test_corrupt_file_is_deny_all(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scope.json"
            p.write_text("{rusak", encoding="utf-8")
            self.assertTrue(load_scope(p).deny_all)


class ResolvePinTest(unittest.TestCase):
    def test_ip_literal_checked_without_dns(self):
        scope = Scope([], ["127.0.0.1"], [])
        self.assertEqual(resolve_pin("127.0.0.1", 80, scope), ("127.0.0.1", 80))
        self.assertIsNone(resolve_pin("10.0.0.1", 80, scope))

    def test_out_of_scope_host_never_resolves(self):
        scope = Scope(["example.com"], [], [])
        with unittest.mock.patch("socket.getaddrinfo",
                                 side_effect=AssertionError("DNS leaked")):
            self.assertIsNone(resolve_pin("evil.test", 443, scope))

    def test_in_scope_host_resolves_once_and_pins(self):
        scope = Scope(["example.com"], [], [])
        infos = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with unittest.mock.patch("socket.getaddrinfo",
                                 return_value=infos) as gi:
            pin = resolve_pin("example.com", 443, scope)
        self.assertEqual(pin, ("93.184.216.34", 443))
        gi.assert_called_once()  # resolve SEKALI — inilah pin

    def test_resolved_ip_out_of_cidr_is_rejected(self):
        # domain di scope, tapi scope juga menyempitkan CIDR:
        scope = Scope([], ["93.184.216.34"], [])
        infos = [(2, 1, 6, "", ("203.0.113.9", 443))]
        with unittest.mock.patch("socket.getaddrinfo", return_value=infos):
            self.assertIsNone(resolve_pin("example.com", 443, scope))

    def test_udp_pin(self):
        scope = Scope(["example.com"], [], [])
        infos = [(2, 2, 17, "", ("93.184.216.34", 53))]
        with unittest.mock.patch("socket.getaddrinfo", return_value=infos):
            self.assertEqual(udp_pin("example.com", 53, scope),
                             ("93.184.216.34", 53))


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


class IntegrationTest(unittest.TestCase):
    """Server lokal 127.0.0.1 — bukti deny SEBELUM connect + pin."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _QuietHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _budget(self, tmp: Path, limit: int) -> Path:
        p = tmp / "budget.json"
        p.write_text(json.dumps({"limit": limit, "used": 0}),
                     encoding="utf-8")
        return p

    def test_in_scope_connect_allowed_and_pinned(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "a.jsonl"
            budget = self._budget(Path(td), 2)
            scope = Scope(["127.0.0.1"], ["127.0.0.1"], [])
            un = ng.install(budget, audit, scope)
            try:
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=3)
                s.close()
            finally:
                un()
            rows = [json.loads(l) for l in
                    audit.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["allowed"])
            self.assertEqual(rows[0]["kind"], "tcp-create-connection")

    def test_out_of_scope_denied_before_connect(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "a.jsonl"
            budget = self._budget(Path(td), 5)
            scope = Scope(["other.test"], [], [])  # 127.0.0.1 TIDAK di scope
            un = ng.install(budget, audit, scope)
            hits = []
            try:
                # patch DIPASANG setelah install dan uninstall DI LUAR
                # patch — kalau uninstall di dalam patch, patch-ex akan
                # mengembalikan guarded yang basi (kebocoran state).
                with unittest.mock.patch.object(
                        socket.socket, "connect",
                        side_effect=lambda addr: hits.append(addr)):
                    try:
                        socket.create_connection(("127.0.0.1", self.port),
                                                 timeout=3)
                    except OSError:
                        pass
            finally:
                un()
            # server TIDAK melihat koneksi; socket.connect asli tak dipanggil
            self.assertEqual(hits, [])

    def test_scope_deny_audited_with_reason(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "a.jsonl"
            budget = self._budget(Path(td), 5)
            scope = Scope(["other.test"], [], [])
            un = ng.install(budget, audit, scope)
            try:
                try:
                    socket.create_connection(("127.0.0.1", self.port),
                                             timeout=3)
                except OSError:
                    pass
            finally:
                un()
            rows = [json.loads(l) for l in
                    audit.read_text(encoding="utf-8").splitlines() if l.strip()]
            # 127.0.0.1 = IP literal out-of-scope -> reason "scope"
            # (resolve-out-of-scope hanya untuk hostname in-scope yang
            #  resolve-nya gagal/tak ada hasil in-scope — ter-cover unit)
            self.assertTrue(any(r["kind"] == "scope-deny"
                                and r["reason"] == "scope"
                                for r in rows))

    def test_deny_all_scope_file_missing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "a.jsonl"
            budget = self._budget(Path(td), 5)
            scope = load_scope(Path(td) / "missing.json")  # deny_all
            un = ng.install(budget, audit, scope)
            try:
                try:
                    socket.create_connection(("127.0.0.1", self.port),
                                             timeout=3)
                except OSError:
                    pass
            finally:
                un()
            rows = [json.loads(l) for l in
                    audit.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(rows and all(not r["allowed"] for r in rows))

    def test_budget_still_enforced_with_scope(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "a.jsonl"
            budget = self._budget(Path(td), 1)
            scope = Scope(["127.0.0.1"], ["127.0.0.1"], [])
            un = ng.install(budget, audit, scope)
            try:
                s = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=3)
                s.close()
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", self.port),
                                             timeout=3)
            finally:
                un()


if __name__ == "__main__":
    unittest.main()
