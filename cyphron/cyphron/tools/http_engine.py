"""Built-in HTTP client over urllib — Cyphron's own probe engine.
No requests/httpx/aiohttp: stdlib only, redirects followed, body capped."""

from __future__ import annotations

import time
import urllib.error
import urllib.request

USER_AGENT = "CyphronCore/0.1 (authorized security testing; stdlib-only)"
MAX_BODY_BYTES = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler yang MEMBATALKAN redirect: 30x dikembalikan sebagai HTTPError
    sehingga penelepons melihat status + Location apa adanya. Diteruskan ke
    build_opener sebagai kelas handler agar default HTTPRedirectHandler
    benar-benar diganti (add_handler saja tidak menghapus default)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Grey-box session support: set once after a successful login; every
# subsequent request carries the session cookie.
_COOKIE_HEADER: str | None = None
LAST_RAW_HEADERS: list[tuple[str, str]] = []


def set_cookie_header(value: str | None) -> None:
    global _COOKIE_HEADER
    _COOKIE_HEADER = value


def get_cookie_header() -> str | None:
    return _COOKIE_HEADER


def http_get(url: str, timeout: float = 8.0, method: str = "GET",
             data: bytes | None = None, headers: dict[str, str] | None = None,
             max_body: int = MAX_BODY_BYTES, follow_redirects: bool = True):
    """Return (status, headers_dict, body_text, elapsed_ms). Raises on
    network errors; HTTP >=400 is returned, not raised."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if _COOKIE_HEADER:
        hdrs["Cookie"] = _COOKIE_HEADER
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    opener = urllib.request.build_opener()
    if not follow_redirects:
        opener = urllib.request.build_opener(_NoRedirect)
    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.getheaders()
            body = resp.read(max_body + 1)
    except urllib.error.HTTPError as e:
        status = e.code
        raw = list((e.headers or {}).items())
        body = e.read(max_body + 1)
    global LAST_RAW_HEADERS
    LAST_RAW_HEADERS = raw
    raw_headers = {k: v for k, v in raw}
    elapsed_ms = int((time.monotonic() - start) * 1000)
    truncated = len(body) > max_body
    text = body[:max_body].decode("utf-8", errors="replace")
    if truncated:
        text += f"\n[cyphron: body truncated at {max_body} bytes]"
    return status, raw_headers, text, elapsed_ms
