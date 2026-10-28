"""Identitas jaringan terpusat untuk semua skill (F20): UA + egress.

User-Agent: default identitas alat (jujur di log target); override via
env CYPHRON_UA — orchestrator mengisinya dari flag --ua (profil
'browser' untuk black-box testing aset sendiri).

Egress/proxy: orchestrator --proxy / --proxies mengisi env
HTTP_PROXY/HTTPS_PROXY/ALL_PROXY untuk proses skill. Proxy http(s)
didukung urllib bawaan; proxy socks5 butuh PySocks — modul ini
memasangnya otomatis saat import (lihat _configure_socks_proxy).

Tidak ada rotasi IP/fingerprint bawaan — pool egress milik operator
(lihat docs/EGRESS-SETUP.md untuk cara membuatnya).
"""
import os
import sys

DEFAULT_UA = "cyphron-audit/0.1"

# Profil 'browser': string UA realistis agar respons target tidak
# berbeda dari yang dilihat pengunjung asli (akurasi black-box).
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")


def user_agent() -> str:
    """UA aktif: env CYPHRON_UA > default. Nilai 'browser' di env
    diperluas ke profil Chrome (dipakai orchestrator --ua browser)."""
    override = os.environ.get("CYPHRON_UA", "").strip()
    if not override:
        return DEFAULT_UA
    if override.lower() == "browser":
        return BROWSER_UA
    return override


def _configure_socks_proxy() -> None:
    """urllib bawaan hanya mendukung proxy http(s) di env — socks5
    diabaikan diam-diam. Bila egress run adalah socks5 (dari
    --proxies), pasang PySocks sebagai socket default. Tanpa PySocks:
    peringatan keras di stderr (fail-loud, bukan senyap)."""
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                "HTTP_PROXY", "http_proxy"):
        val = os.environ.get(var, "").strip()
        if not val.startswith("socks5://"):
            continue
        rest = val[len("socks5://"):]
        userinfo = None
        if "@" in rest:
            userinfo, rest = rest.rsplit("@", 1)
        host, _, port = rest.partition(":")
        try:
            import socks  # PySocks
        except ImportError:
            print(
                "[ua] egress socks5 terdeteksi tapi PySocks tidak ada "
                "(pip install pysocks) — request JALAN LANGSUNG tanpa "
                "proxy (bukan diam-diam lewat IP asli tanpa tahu)",
                file=sys.stderr)
            return
        if userinfo and ":" in userinfo:
            user, pwd = userinfo.split(":", 1)
            socks.set_default_proxy(socks.SOCKS5, host, int(port or 1080),
                                    username=user, password=pwd)
        else:
            socks.set_default_proxy(socks.SOCKS5, host, int(port or 1080))
        import socket
        socket.socket = socks.socksocket
        return


_configure_socks_proxy()
