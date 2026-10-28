"""[SAFETY: 1-request] brotli-stack-surface — stack HTTP di jalur
kompresi Brotli (F66b; latar Black October 2026: CVE-2026-111497
out-of-bounds write decoder Brotli di Node.js 22/24/26 — KB operator
dan watchlist seed 'node.js' sudah ada, tetapi belum ada skill yang
melihat jalur kompresi + stack aktif).

SATU GET / dengan Accept-Encoding: br, gzip. Klaim:
  - Content-Encoding memuat token utuh 'br' = Brotli aktif (L0 postur);
  - marker stack eksplisit: X-Powered-By Express / cookie connect.sid /
    __NEXT_DATA__ / _next/ = stack Node.js (L1 lead — watchlist token
    node.js); Server Kestrel / X-AspNet-Version / cookie ASP.NET /
    .AspNetCore. = stack ASP.NET (inventaris L1);
  - versi eksplisit x.y.z di Server/X-Powered-By diteruskan sebagai
    fakta cve-matcher bila token produk bersebelahan.

Zero-FP: 'br' hanya dihitung sebagai token utuh di Content-Encoding;
marker stack wajib token eksplisit (kata 'server' generik tidak
dihitung). Tanpa marker = AMAN. Gagal jaringan = tanpa klaim AMAN.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

TIMEOUT_S = 10.0
_RE_VER = re.compile(
    r"(?:express|node(?:\.js)?|kestrel|asp\.net(?: core)?)[ /v]*"
    r"(\d+(?:\.\d+)+)", re.I)
_CVE_NOTE = ("Black October 2026: CVE-2026-111497 (out-of-bounds write "
             "decoder Brotli Node.js 22/24/26, fix 22.23.4/24.22.1/"
             "26.12.1; Node 20.x EOL tanpa patch) — KB operator + "
             "watchlist node.js; verifikasi versi manual wajib.")


def _get(base: str, path: str, headers: dict):
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-brotli-stack", **headers})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return (r.status, r.read(64_000).decode("utf-8", "replace"),
                    dict(r.headers.items()))
    except urllib.error.HTTPError as e:
        return (e.code,
                (e.read(16_000) or b"").decode("utf-8", "replace"),
                dict(e.headers.items()) if e.headers else {})
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:120], {}


def _hget(headers: dict, name: str) -> str:
    lname = name.lower()
    for k, v in headers.items():
        if str(k).lower() == lname:
            return str(v)
    return ""


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): SATU GET ber-Accept-Encoding br -> (rows, meta)."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    st, body, hdrs = _get(base, "/", {"Accept-Encoding": "br, gzip"})
    responded = 1 if st is not None else 0
    lower = {str(k).lower(): str(v) for k, v in hdrs.items()}
    ce = lower.get("content-encoding", "").lower()
    brotli = any(t.strip() == "br" for t in ce.split(","))
    xb = lower.get("x-powered-by", "").lower()
    srv = lower.get("server", "").lower()
    cookie = lower.get("set-cookie", "").lower()
    low_body = body.lower()

    stack: list[str] = []
    if ("express" in xb or "connect.sid" in cookie
            or "__next_data__" in low_body or "/_next/" in low_body
            or "next.js" in xb):
        stack.append("node.js")
    if ("kestrel" in srv or "asp.net" in xb
            or "x-aspnet-version" in lower
            or "asp.net_sessionid" in cookie
            or ".aspnetcore." in cookie):
        stack.append("asp.net")
    versions = [m.group(1) for m in _RE_VER.finditer(f"{xb} {srv}")]

    if brotli:
        rows.append(make_finding(
            tool="brotli-stack-surface",
            title=f"Brotli aktif pada respons {base} "
                  f"(Content-Encoding: br)",
            severity="info",
            description="Respons menyajikan token utuh 'br' di "
                        f"Content-Encoding. {_CVE_NOTE}",
            recommendation="Pastikan runtime/gateway di jalur kompresi "
                           "bukan Node.js Brotli decoder versi rentan; "
                           "Verifikasi versi Node (+ /metrics bila ada).",
            cwe=None, target_url=base + "/",
            request="GET / (Accept-Encoding: br, gzip)",
            response=f"Content-Encoding: {ce}"[:150],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class":
                   "1-request", "brotli": True}))
    if "node.js" in stack:
        ver_s = f" versi eksplisit: {versions[0]}" if versions else ""
        rows.append(make_finding(
            tool="brotli-stack-surface",
            title=f"Stack Node.js terdeteksi di {base}"
                  + (f" ({versions[0]})" if versions else ""),
            severity="low",
            description="Marker stack eksplisit (Express/connect.sid/"
                        "__NEXT_DATA__/_next/)." + ver_s
                        + f" {_CVE_NOTE}",
            recommendation="Verifikasi versi Node.js vs fix CVE-2026-"
                           "111497 (22.23.4/24.22.1/26.12.1); Node 20.x "
                           "EOL tidak dipatch — upgrade.",
            cwe=None, target_url=base + "/",
            request="GET / (Accept-Encoding: br, gzip)",
            response=(f"X-Powered-By: {xb}" if xb else "marker body")[:150],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class": "1-request",
                   "version": versions[0] if versions else None,
                   "tech": ("node.js " + versions[0]) if versions
                   else "node.js"}))
    elif "asp.net" in stack:
        rows.append(make_finding(
            tool="brotli-stack-surface",
            title=f"Stack ASP.NET terdeteksi di {base}",
            severity="info",
            description="Marker stack eksplisit (Kestrel/ASP.NET/"
                        "X-AspNet-Version/cookie .AspNetCore.) — "
                        "inventaris, bukan klaim kerentanan.",
            target_url=base + "/",
            request="GET / (Accept-Encoding: br, gzip)",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class": "1-request",
                   "tech": "asp.net"}))
    elif responded == 0:
        rows.append(make_finding(
            tool="brotli-stack-surface",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description="GET dengan Accept-Encoding br gagal jaringan; "
                        "kegagalan koneksi BUKAN bukti tidak-ada-marker "
                        "(fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request",
                   "network_error": True}))
    else:
        rows.append(make_finding(
            tool="brotli-stack-surface",
            title=f"Tidak ada marker yang dicari pada {base} (1 GET)",
            severity="info",
            description="Tanpa Content-Encoding br dan tanpa marker "
                        "stack eksplisit (Express/connect.sid/Kestrel/"
                        "ASP.NET) — AMAN/inventaris.",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request"}))

    meta = {"url": base, "requests": 1, "brotli": brotli,
            "stack": stack, "versions": versions}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="brotli_stack_surface.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "1-request"})
    print(f"brotli-stack-surface: brotli={meta['brotli']} "
          f"stack={meta['stack']} ({meta['requests']} GET) -> "
          f"{args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
