"""Reusable login helper — dipakai orchestrator (grey-box) dan engine
multi-akun (bola/priv_matrix). NextAuth dance dulu, lalu form POST klasik."""

from __future__ import annotations

import json
from urllib.parse import urlencode, urljoin

from . import http_engine
from .crawler import _PageParser


def login(target: str, user: str, pwd: str, timeout: float = 8.0) -> str | None:
    """Login ke target; return cookie sesi ("name=value") atau None.
    TIDAK menyentuh cookie global http_engine — pemanggil yang memutuskan."""
    # --- Path A: NextAuth dance (GET csrf -> POST callback/credentials) ---
    try:
        _cs, _ch, csrf_body, _cm = http_engine.http_get(
            urljoin(target, "/api/auth/csrf"), timeout=timeout)
        token = (json.loads(csrf_body or "{}").get("csrf_token")
                 or json.loads(csrf_body or "{}").get("csrfToken"))
        csrf_cookies = "; ".join(
            v.split(";")[0] for k, v in http_engine.LAST_RAW_HEADERS
            if k.lower() == "set-cookie")
        if token:
            _ps, _ph, _pb, _pm = http_engine.http_get(
                urljoin(target, "/api/auth/callback/credentials"),
                timeout=timeout, method="POST",
                data=urlencode({"csrfToken": token, "email": user,
                                "password": pwd, "json": "true"}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Cookie": csrf_cookies})
            for k, v in http_engine.LAST_RAW_HEADERS:
                if k.lower() == "set-cookie" and "session" in v.lower():
                    return v.split(";")[0]
    except Exception:
        pass

    # --- Path B: classic form POST ke halaman login ---
    for path in ("/login", "/signin", "/auth/login", "/masuk"):
        try:
            url = urljoin(target, path)
            _s, _h, body, _ms = http_engine.http_get(url, timeout=timeout)
            parser = _PageParser()
            parser.feed(body or "")
            for form in parser.forms:
                if not any("password" in f.lower() for f in form["fields"]):
                    continue
                action = urljoin(url, form["action"] or url)
                user_key = next((f for f in form["fields"]
                                 if "password" not in f.lower()), "email")
                user_key = "email" if user_key.startswith("input[type=") else user_key
                _ps, _ph, _pb, _pm = http_engine.http_get(
                    action, timeout=timeout, method="POST",
                    data=urlencode({user_key: user, "password": pwd}).encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
                for k, v in http_engine.LAST_RAW_HEADERS:
                    if k.lower() == "set-cookie" and "session" in v.lower():
                        return v.split(";")[0]
                cookie = _ph.get("set-cookie") or _ph.get("Set-Cookie") or ""
                if cookie:
                    return cookie.split(";")[0]
        except Exception:
            continue
    return None
