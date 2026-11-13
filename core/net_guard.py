"""[Fase 2-B][SAFETY: local-only] net_guard — controlled network engine
(skeleton teruji). Penegakan budget request SEBELUM koneksi terkirim
untuk proses skill Python.

Konsep: runner Rust menyuntik env SECAI_NET_GUARD=1 + budget file +
audit file, dan memuat modul ini via sitecustomize (PYTHONPATH). Setiap
upaya koneksi (TCP connect / UDP sendto) melewati cek budget atomik:
habis/hilang/korup = ditolak SEBELUM connect() — fail-closed.

Batas jujur: guard kesalahan proses sendiri, BUKAN sandbox adversarial
(lihat docs/CONTROLLED-NETWORK.md §3).
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

GUARD_ENV = "SECAI_NET_GUARD"
BUDGET_ENV = "SECAI_NET_BUDGET_FILE"
AUDIT_ENV = "SECAI_NET_AUDIT"
SCOPE_ENV = "SECAI_NET_SCOPE_FILE"  # Fase 2-C: scope-check + pin-IP

try:
    from net_guard_scope import (  # noqa: E402  (core/ di sys.path)
        Scope, load_scope, resolve_pin, udp_pin)
except ImportError:  # di-import sebagai core.net_guard (sitecustomize)
    from core.net_guard_scope import (  # noqa: E402
        Scope, load_scope, resolve_pin, udp_pin)

_installed = False
_uninstaller = None


def try_take(budget_file: str | Path, n: int = 1) -> int | None:
    """Ambil n token dari budget file atomik ({limit, used}).
    Kembalikan used baru; None = ditolak (habis / file hilang /
    korup / limit buruk). Atomic via tulis-tmp + os.replace."""
    bf = Path(budget_file)
    if not bf.exists():
        return None
    try:
        doc = json.loads(bf.read_text(encoding="utf-8"))
        limit = int(doc["limit"])
        used = int(doc["used"])
    except Exception:
        return None
    if limit < 0 or used < 0 or used + n > limit:
        return None
    tmp = bf.with_suffix(bf.suffix + f".tmp{os.getpid()}"
                         f".{threading.get_ident()}")
    try:
        tmp.write_text(json.dumps({"limit": limit, "used": used + n}),
                       encoding="utf-8")
        os.replace(tmp, bf)  # atomik (Windows + POSIX)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return None
    return used + n


def _audit(audit_file: str | Path, entry: dict) -> None:
    """Append satu baris JSONL — kegagalan audit TIDAK boleh mematikan
    skill di titik ini (budget yang menolak, bukan log); tapi kalau
    audit file tak bisa ditulis, runner akan melihat log kosong/hilang
    dan menandai skill (fase berikutnya)."""
    try:
        p = Path(audit_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def install(budget_file: str | Path, audit_file: str | Path,
            scope: "Scope | None" = None):
    """Pasang patch socket. Kembalikan uninstall() (untuk test).
    Idempotent — install dua kali tidak menumpuk patch.
    scope (Fase 2-C): None = hanya budget (perilaku lama); Scope =
    default-deny + pin-IP anti-rebinding (net_guard_scope)."""
    global _installed, _uninstaller
    if _installed and _uninstaller is not None:
        return _uninstaller

    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_sendto = socket.socket.sendto
    orig_create = socket.create_connection

    def _scope_check(kind: str, address) -> tuple[bool, object]:
        """(allowed, pinned_sockaddr|None). Deny = SEBELUM resolve
        (DNS utk host luar scope tidak pernah dikirim). Pin = hasil
        resolve tunggal — anti-rebinding (Fase 2-C)."""
        if scope is None or not isinstance(address, tuple):
            return True, None
        host = address[0] if address else ""
        if not isinstance(host, str) or not host:
            return True, None
        port = address[1] if len(address) > 1 else 0
        if _is_ip_literal(host):
            if not scope.host_allowed(host):
                _audit(audit_file, {"ts": round(time.time(), 3),
                                    "pid": os.getpid(),
                                    "kind": "scope-deny",
                                    "address": str(address),
                                    "allowed": False,
                                    "budget_used": None,
                                    "reason": "scope"})
                return False, None
            return True, None  # IP literal asli — tak perlu pin
        if not scope.host_allowed(host):
            _audit(audit_file, {"ts": round(time.time(), 3),
                                "pid": os.getpid(),
                                "kind": "scope-deny",
                                "address": str(address),
                                "allowed": False,
                                "budget_used": None,
                                "reason": "scope"})
            return False, None
        pin = (udp_pin(host, port, scope)
               if kind == "udp-sendto"
               else resolve_pin(host, port, scope))
        if pin is None:
            _audit(audit_file, {"ts": round(time.time(), 3),
                                "pid": os.getpid(),
                                "kind": "scope-deny",
                                "address": str(address),
                                "allowed": False,
                                "budget_used": None,
                                "reason": "resolve-out-of-scope"})
            return False, None
        return True, pin

    def _is_ip_literal(text: str) -> bool:
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    def _gate(kind: str, address, pinned: object = None):
        """True = boleh lanjut; False = ditolak (budget)."""
        used = try_take(budget_file)
        allowed = used is not None
        _audit(audit_file, {
            "ts": round(time.time(), 3), "pid": os.getpid(),
            "kind": kind, "address": str(pinned or address),
            "allowed": allowed,
            "budget_used": used,
        })
        return allowed

    def guarded_connect(self, address):
        allowed, pinned = _scope_check("tcp-connect", address)
        if not allowed:
            raise OSError(10061 if sys.platform == "win32" else 111,
                          "secai net-guard: scope deny/kontrak rusak "
                          f"(ditolak sebelum resolve) -> {address!r}")
        if not _gate("tcp-connect", address, pinned):
            raise OSError(10061 if sys.platform == "win32" else 111,
                          "secai net-guard: budget habis/kontrak hilang "
                          f"(ditolak sebelum connect) -> {address!r}")
        return orig_connect(self, pinned if pinned is not None else address)

    def guarded_connect_ex(self, address):
        allowed, pinned = _scope_check("tcp-connect-ex", address)
        if not allowed:
            return 10061 if sys.platform == "win32" else 111
        if not _gate("tcp-connect-ex", address, pinned):
            return 10061 if sys.platform == "win32" else 111
        return orig_connect_ex(self, pinned if pinned is not None else address)

    def guarded_sendto(self, data, address=None, *args, **kwargs):
        allowed, pinned = _scope_check("udp-sendto", address)
        if not allowed:
            raise OSError(10065 if sys.platform == "win32" else 101,
                          "secai net-guard: scope deny/kontrak rusak "
                          f"(ditolak sebelum resolve) -> {address!r}")
        target = pinned if pinned is not None else address
        if address is not None and not _gate("udp-sendto", address, pinned):
            raise OSError(10065 if sys.platform == "win32" else 101,
                          "secai net-guard: budget habis/kontrak hilang "
                          f"(ditolak sebelum sendto) -> {address!r}")
        return orig_sendto(self, data, target, *args, **kwargs)

    def guarded_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                                  source_address=None):
        # create_connection memanggil getaddrinfo lalu socket().connect —
        # tetap di-gate di sini supaya gagal cepat + tercatat sekali;
        # connect asli di dalamnya TIDAK ter-gate ulang (socket mentah
        # yang dibuat create_connection memakai connect yang sudah
        # di-patch — jadi token diambil 1x di sini, bukan 2x).
        allowed, pinned = _scope_check("tcp-create-connection", address)
        if not allowed:
            raise OSError(10061 if sys.platform == "win32" else 111,
                          "secai net-guard: scope deny/kontrak rusak "
                          f"(ditolak sebelum resolve) -> {address!r}")
        if not _gate("tcp-create-connection", address, pinned):
            raise OSError(10061 if sys.platform == "win32" else 111,
                          "secai net-guard: budget habis/kontrak hilang "
                          f"(ditolak sebelum connect) -> {address!r}")
        # buka koneksi tanpa melewati gate connect lagi (KE PIN bila ada)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        try:
            _bypass_orig_connect = orig_connect
            _bypass_orig_connect(
                sock, pinned if pinned is not None else address)
        except Exception:
            sock.close()
            raise
        return sock

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    socket.socket.sendto = guarded_sendto
    socket.create_connection = guarded_create_connection

    def uninstall():
        global _installed, _uninstaller
        # Identity-guard: pulihkan HANYA bila atribut masih patch kita.
        # Jika pihak lain (mis. patch test) menimpa di atas patch ini,
        # biarkan pemilik baru yang bertanggung jawab — tanpa ini,
        # uninstall di dalam patch eksternal memulihkan fungsi yang
        # SALAH (patch-exit lalu mengembalikan guarded yang basi).
        if socket.socket.connect is guarded_connect:
            socket.socket.connect = orig_connect
        if socket.socket.connect_ex is guarded_connect_ex:
            socket.socket.connect_ex = orig_connect_ex
        if socket.socket.sendto is guarded_sendto:
            socket.socket.sendto = orig_sendto
        if socket.create_connection is guarded_create_connection:
            socket.create_connection = orig_create
        _installed = False
        _uninstaller = None

    _installed = True
    _uninstaller = uninstall
    return uninstall


def auto_install_from_env() -> bool:
    """Dipakai sitecustomize: pasang guard bila env runner tersedia.
    Return True bila guard terpasang. Fail-closed: env GUARD aktif
    tapi budget/audit tidak lengkap -> tetap pasang dengan kontrak
    kosong (budget file tak ada = semua koneksi ditolak)."""
    if os.environ.get(GUARD_ENV) != "1":
        return False
    budget = os.environ.get(BUDGET_ENV, "")
    audit = os.environ.get(AUDIT_ENV, "")
    scope_path = os.environ.get(SCOPE_ENV, "")
    scope = load_scope(scope_path) if scope_path else None
    install(budget or "<no-budget-contract>",
            audit or os.devnull, scope)
    # Marker bukti guard terpasang: baris pertama audit berisi
    # kind="guard-install". Runner (fase 2-B lanjutan) menganggap skill
    # berjalan TANPA guard bila baris ini absen -> hard-fail
    # (fail-closed dua lapis, docs/CONTROLLED-NETWORK.md §3).
    if audit:
        _audit(audit, {"ts": round(time.time(), 3), "pid": os.getpid(),
                       "kind": "guard-install", "address": "-",
                       "allowed": True, "budget_used": None})
    return True
