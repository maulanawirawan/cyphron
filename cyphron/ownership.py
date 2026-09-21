"""ownership — bukti kepemilikan domain sebelum mode ofensif diterima (U10).

Prinsip: dokumen otorisasi boleh menuntut bukti bahwa pengaju ENGAKAN
mengendalikan domain target. Dua kanal verifikasi:

- DNS TXT  : record ``cyphron-verify=<token>`` pada host target
             (dibaca via DoH dns.google — nslookup Windows tidak andal);
- well-known: berkas ``/.well-known/cyphron-verify.txt`` berisi token di
             baris pertama (HTTPS lalu HTTP mengikuti skema target).

Token DETERMINISTIK dari isi dokumen otorisasi itu sendiri:

    token = "cyphron-verify=" + sha256("<host>|<auth_id>|<issued_at>")[:32]

jadi pemilik domain cukup membaca dokumen yang ia tandatangani untuk
menerbitkan token — tidak ada kanal rahasia tambahan yang perlu dijaga.
Gagal verifikasi = fail-closed: mode ofensif ditolak (turun read-only).

Dipakai lewat field dokumen otorisasi:
    "require_ownership": true,
    "ownership_channel": "auto" | "dns" | "wellknown"   (opsional)
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .guardrails.authorization import AuthorizationDocument

PREFIX = "cyphron-verify="
WELLKNOWN_PATH = "/.well-known/cyphron-verify.txt"
_UA = "cyphron-ownership/1.0"


def ownership_token(host: str, auth_id: str, issued_at: str) -> str:
    """Token publikasi deterministik dari (host, id dokumen, tanggal terbit)."""
    basis = f"{str(host).lower().strip()}|{auth_id}|{issued_at}"
    return PREFIX + hashlib.sha256(basis.encode()).hexdigest()[:32]


def token_for(doc: AuthorizationDocument, host: str | None = None) -> str:
    host = host or _host_of(doc.raw.get("target_url", "")) or doc.target_name
    return ownership_token(host, doc.id, str(doc.raw.get("issued_at", "")))


def txt_via_doh(host: str, timeout: float = 6.0) -> list[str]:
    """TXT record host via DoH (lesson: nslookup Windows sering gagal)."""
    url = ("https://dns.google/resolve?name="
           + urlsplit(f"//{host}").netloc + "&type=TXT")
    req = Request(url, headers={"User-Agent": _UA})
    with urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    out: list[str] = []
    for ans in data.get("Answer") or []:
        if ans.get("type") == 16:
            out.append(str(ans.get("data", "")).strip().strip('"'))
    return out


def fetch_wellknown(target: str, timeout: float = 6.0) -> str | None:
    """Ambil baris pertama /.well-known/cyphron-verify.txt dari target."""
    parts = urlsplit(target if "://" in target else f"https://{target}")
    base = f"{parts.scheme or 'https'}://{parts.netloc}"
    try:
        req = Request(base + WELLKNOWN_PATH, headers={"User-Agent": _UA})
        with urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
    except Exception:
        # target eksplisit https: jangan retry http identik (dead path);
        # host tanpa skema (dianggap https awal) boleh dicoba http sekali
        if "://" in target:
            return None
        try:
            req = Request(f"http://{parts.netloc}{WELLKNOWN_PATH}",
                          headers={"User-Agent": _UA})
            with urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
        except Exception:
            return None
    for line in body.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def verify_ownership(target: str, doc: AuthorizationDocument,
                     channel: str = "auto", timeout: float = 6.0) -> tuple[bool, dict]:
    """Verifikasi bukti kepemilikan. Return (ok, detail)."""
    host = _host_of(target)
    detail: dict = {"host": host, "channel": channel, "token": "",
                    "method": "", "found": ""}
    if not host:
        detail["error"] = "target tanpa host"
        return False, detail
    token = ownership_token(host, doc.id, str(doc.raw.get("issued_at", "")))
    detail["token"] = token
    want = {token, f'"{token}"'}
    try:
        if channel in ("auto", "wellknown"):
            found = fetch_wellknown(target, timeout=timeout)
            detail["method"] = "wellknown"
            detail["found"] = found or ""
            if found is not None and found.strip() in want:
                return True, detail
        if channel in ("auto", "dns"):
            detail["method"] = "dns"
            for row in txt_via_doh(host, timeout=timeout):
                if row in want:
                    detail["found"] = row
                    return True, detail
    except Exception as exc:
        detail["error"] = f"{type(exc).__name__}: {exc}"
        return False, detail
    return False, detail


def _host_of(target: str) -> str:
    t = str(target or "")
    if "://" not in t:
        t = "https://" + t
    return (urlsplit(t).hostname or "").lower()
