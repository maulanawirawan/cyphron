"""Redaksi kredensial sebelum data menulis ke disk/output (pola dari
review bridge: dump fingerprint ter-redaksi — nama kredensial tampil,
nilainya hanya hash agar masih bisa dibandingkan deterministik).

Dipakai skill/tool yang menyimpan header/URL hasil observasi. Bukti
mentah yang memang sengaja disimpan utuh (mis. evidence sweep
--save-raw) TIDAK melewati modul ini — rantai bukti tidak boleh
disanitasi diam-diam.
"""
from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# header yang nilainya kredensial — selalu direduksi
SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-goog-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token",
})

# nama query param yang nilainya kredensial
SENSITIVE_QUERY = frozenset({
    "token", "access_token", "refresh_token", "key", "api_key", "apikey",
    "secret", "password", "passwd", "session", "sessionid", "sid", "auth",
})


def _marker(value: str) -> str:
    """Penanda deterministik: hash pendek memungkinkan diff antar-run
    tanpa membocorkan nilai."""
    h = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"[REDACTED sha256:{h}]"


def redact_headers(headers: dict | list[tuple]) -> dict:
    """Header ter-redaksi: nilai header sensitif -> penanda hash;
    sisanya dipertahankan apa adanya."""
    out: dict[str, str] = {}
    items = (headers.items() if isinstance(headers, dict)
             else headers)
    for k, v in items:
        k_l = str(k).lower()
        out[str(k)] = _marker(str(v)) if k_l in SENSITIVE_HEADERS else str(v)
    return out


def redact_url(url: str) -> str:
    """URL ter-redaksi: userinfo (user:pass@) dan query param kredensial
    diganti penanda; host/path tidak disentuh."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[REDACTED url-tidak-valid]"
    if parts.username or parts.password:
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        netloc = f"***@{host}"
    else:
        netloc = parts.netloc
    if parts.query:
        q = [(k, _marker(v) if k.lower() in SENSITIVE_QUERY else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        query = urlencode(q)
    else:
        query = ""
    return urlunsplit((parts.scheme, netloc, parts.path, query,
                       parts.fragment))
