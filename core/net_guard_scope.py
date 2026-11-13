"""Scope-check + pin-IP anti-rebinding untuk net_guard (Fase 2-C).

Desain (docs/CONTROLLED-NETWORK.md §6):
  - scope file JSON: {"domains": [...], "ips": [...], "cidrs": [...]}
    milik runner; env SECAI_NET_SCOPE_FILE menunjuk ke file itu.
  - TANPA env/file -> perilaku lama (hanya budget) — kompatibel penuh.
  - scope AKTIF -> default-DENY: koneksi hanya ke host yang cocok
    (domain exact/suffix, IP literal, CIDR), dan pengecekan TERJADI
    SEBELUM resolve — DNS untuk host di luar scope tidak pernah dikirim.
  - anti-rebinding: hostname yang lolos scope di-resolve SEKALI via
    getaddrinfo, hasilnya diverifikasi ulang terhadap scope (untuk
    mode IP/CIDR), lalu koneksi DIBUAT KE SOCKADDR TERSEBUT (pin) —
    library HTTP tidak pernah me-resolve ulang di titik connect().
  - fail-closed: env scope diset tapi file hilang/korup = deny-all
    (semua koneksi ditolak, baris audit scope-deny tercatat).

Batas jujur: guard kesalahan proses sendiri (bukan sandbox adversarial),
sama seperti budget. Resolver sistem dipanggil langsung oleh modul ini
(UDP DNS tidak melewati socket yang di-patch — tidak dihitung budget).
"""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path

SCOPE_ENV = "SECAI_NET_SCOPE_FILE"


class Scope:
    """Scope ter-load. deny_all = kontrak rusak (fail-closed)."""

    def __init__(self, domains: list[str], ips: list[str],
                 nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
                 deny_all: bool = False):
        self.domains = [d.lower().rstrip(".") for d in domains]
        self.ips = {str(ipaddress.ip_address(i)) for i in ips}
        self.nets = nets
        self.deny_all = deny_all

    @classmethod
    def deny_all(cls) -> "Scope":
        return cls([], [], [], deny_all=True)

    def host_allowed(self, host: str) -> bool:
        if self.deny_all:
            return False
        h = str(host).lower().rstrip(".")
        for d in self.domains:
            if h == d or h.endswith("." + d):
                return True
        if _is_ip(h):
            ip = ipaddress.ip_address(h)
            if str(ip) in self.ips:
                return True
            for net in self.nets:
                if ip in net:
                    return True
        return False

    def sockaddr_allowed(self, sockaddr: tuple) -> bool:
        if self.deny_all:
            return False
        if not self.ips and not self.nets:
            return True  # scope berbasis domain: IP hasil resolve bebas
        host = sockaddr[0] if isinstance(sockaddr, tuple) else str(sockaddr)
        return self.host_allowed(host)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def load_scope(scope_file: str | Path) -> Scope:
    """Load scope file; file hilang/korup = Scope.deny_all (fail-closed)."""
    try:
        doc = json.loads(Path(scope_file).read_text(encoding="utf-8"))
        domains = [str(d).lower() for d in doc.get("domains", [])]
        ips = [str(i) for i in doc.get("ips", [])]
        nets = [ipaddress.ip_network(c, strict=False)
                for c in doc.get("cidrs", [])]
        return Scope(domains, ips, nets)
    except Exception:
        return Scope.deny_all()


def resolve_pin(host: str, port: int, scope: Scope) -> tuple | None:
    """Resolve SEKALI + verifikasi scope + kembalikan sockaddr terpilih.

    None = ditolak (host di luar scope, atau tidak ada hasil in-scope).
    Ini inti anti-rebinding: pemanggil (net_guard) connect KE SOCKADDR
    hasil resolve ini — bukan ke hostname — sehingga resolve kedua oleh
    library HTTP tidak terjadi.
    """
    if _is_ip(host):
        return (host, port) if scope.host_allowed(host) else None
    if not scope.host_allowed(host):
        return None
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    for _fam, _typ, _proto, _canon, sa in infos:
        if scope.sockaddr_allowed(sa):
            return (sa[0], sa[1]) if len(sa) >= 2 else None
    return None


def udp_pin(host: str, port: int, scope: Scope) -> tuple | None:
    """Sama seperti resolve_pin untuk SOCK_DGRAM (sendto)."""
    if _is_ip(host):
        return (host, port) if scope.host_allowed(host) else None
    if not scope.host_allowed(host):
        return None
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_UDP)
    except OSError:
        return None
    for _fam, _typ, _proto, _canon, sa in infos:
        if scope.sockaddr_allowed(sa):
            return (sa[0], sa[1]) if len(sa) >= 2 else None
    return None
