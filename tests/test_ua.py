"""Test F20 — modul UA terpusat (skills/ua.py).

Default = identitas alat (jujur); env CYPHRON_UA override; profil
'browser' diperluas ke UA Chrome realistis. Proxy tidak diuji di sini
(urllib menghormati env HTTP(S)_PROXY bawaan).
"""
from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))

import ua  # noqa: E402


class UaTest(unittest.TestCase):
    def _reset(self):
        importlib.reload(ua)

    def test_default_is_tool_identity(self):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("CYPHRON_UA", None)
            self.assertEqual(ua.user_agent(), ua.DEFAULT_UA)
            self.assertEqual(ua.user_agent(), "cyphron-audit/0.1")

    def test_browser_profile_expands_to_realistic_ua(self):
        with patch.dict("os.environ", {"CYPHRON_UA": "browser"}):
            val = ua.user_agent()
        self.assertTrue(val.startswith("Mozilla/5.0"), val)
        self.assertIn("Chrome", val)

    def test_custom_string_passthrough(self):
        with patch.dict("os.environ",
                        {"CYPHRON_UA": "sascanner-custom/1.0"}):
            self.assertEqual(ua.user_agent(), "sascanner-custom/1.0")

    def test_blank_env_falls_back_to_default(self):
        with patch.dict("os.environ", {"CYPHRON_UA": "   "}):
            self.assertEqual(ua.user_agent(), ua.DEFAULT_UA)

    def test_skills_read_central_module(self):
        # skill jaringan wajib memakai UA terpusat — tidak ada lagi UA
        # hardcoded selain di ua.py
        import re
        hard = []
        for p in (ROOT / "skills").glob("*.py"):
            if p.name in ("ua.py", "attack_common.py"):
                continue  # sumber definisi + helper lab
            src = p.read_text(encoding="utf-8-sig")
            for m in re.finditer(
                    r'(?:UA|UA_ENV)\s*=\s*["\'](?!["\'])([^"\']{4,})["\']',
                    src):
                if "Mozilla" in m.group(1):
                    hard.append(f"{p.name}: {m.group(1)[:40]}")
        self.assertEqual(hard, [], "UA hardcoded tersisa:\n" + "\n".join(hard))


class SocksEgressTest(unittest.TestCase):
    """F20c — egress socks5 butuh PySocks; ua.py memasangnya otomatis
    saat import bila env proxy ber-skema socks5://."""

    def _with_fake_socks(self, env):
        """Reload ua.py dengan modul socks palsu; balikin (calls,
        socket_aktif, kelas_fake)."""
        import socket as socket_mod
        import types
        import importlib
        calls = {}
        fake = types.ModuleType("socks")
        fake.SOCKS5 = 2
        def set_default_proxy(ptype, addr, port, **kw):
            calls["args"] = (ptype, addr, port, kw)
        fake.set_default_proxy = set_default_proxy
        class FakeSock:
            pass
        fake.socksocket = FakeSock
        old_socks = sys.modules.get("socks")
        old_socket = socket_mod.socket
        sys.modules["socks"] = fake
        try:
            with patch.dict("os.environ", env):
                importlib.reload(ua)
        finally:
            self.addCleanup(self._restore, old_socks, old_socket)
        return calls, socket_mod.socket, FakeSock

    def _restore(self, old_socks, old_socket):
        import socket as socket_mod
        import importlib
        if old_socks is None:
            sys.modules.pop("socks", None)
        else:
            sys.modules["socks"] = old_socks
        socket_mod.socket = old_socket
        with patch.dict("os.environ", {"CYPHRON_UA": ""}):
            importlib.reload(ua)

    def test_socks5_with_credentials_installed(self):
        calls, sock, fake_cls = self._with_fake_socks(
            {"HTTPS_PROXY": "socks5://user:secret@10.1.1.1:1080"})
        self.assertEqual(calls["args"][1], "10.1.1.1")
        self.assertEqual(calls["args"][2], 1080)
        self.assertEqual(calls["args"][3], {"username": "user",
                                            "password": "secret"})
        self.assertIs(sock, fake_cls, "socket global harus jadi socksocket")

    def test_socks5_plain_no_credentials(self):
        calls, sock, fake_cls = self._with_fake_socks(
            {"ALL_PROXY": "socks5://10.2.2.2:9050"})
        self.assertEqual(calls["args"][1], "10.2.2.2")
        self.assertEqual(calls["args"][2], 9050)
        self.assertEqual(calls["args"][3], {})
        self.assertIs(sock, fake_cls)

    def test_missing_pysocks_fails_loud_not_silent(self):
        # PySocks "hilang" (sys.modules None -> ImportError) -> harus
        # tetap tanpa patching socket TAPI tidak crash; disiplin
        # fail-loud dicek lewat tidak adanya penggantian socket.
        import socket as socket_mod
        import types
        import importlib
        old_socks = sys.modules.get("socks")
        old_socket = socket_mod.socket
        sys.modules["socks"] = None  # import socks -> ImportError
        try:
            with patch.dict("os.environ",
                            {"HTTPS_PROXY": "socks5://10.3.3.3:1080"}):
                importlib.reload(ua)
            self.assertIs(socket_mod.socket, old_socket,
                          "tanpa PySocks, socket TIDAK boleh digantikan "
                          "(request jalan langsung, terlihat di stderr)")
        finally:
            if old_socks is None:
                sys.modules.pop("socks", None)
            else:
                sys.modules["socks"] = old_socks
            socket_mod.socket = old_socket
            with patch.dict("os.environ", {"CYPHRON_UA": ""}):
                importlib.reload(ua)

    def test_no_proxy_env_is_noop(self):
        import socket as socket_mod
        old_socket = socket_mod.socket
        with patch.dict("os.environ", {"CYPHRON_UA": ""}):
            importlib.reload(ua)
        self.assertIs(socket_mod.socket, old_socket)


if __name__ == "__main__":
    unittest.main(verbosity=1)
