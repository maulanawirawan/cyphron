"""[SAFETY: bounded-requests] php-posture — postur runtime PHP dari
target URL (F66a; latar Black October 2026: php2shell — RCE
unauthenticated CVE-2026-109618/109619, KB operator multi-branch sudah
ada, tetapi belum ada skill yang mengumpulkan marker PHP + versi
secara khusus).

Bounded MAKS 4 GET, read-only, tanpa payload dan tanpa brute-force:
  1. /                        -> X-Powered-By / Server / Set-Cookie,
                                 marker PHPSESSID + jejak error PHP;
  2. /?=PHPE9568F34-...       -> easter-egg expose_php (signature
                                 ketat: content-type image/gif DAN body
                                 berawalan GIF89a);
  3. /phpinfo.php             -> signature "phpinfo()" + "PHP Version"
                                 + ("php.ini" | "System") = L2 (CWE-538);
  4. /info.php                -> path kandidat kedua, signature sama.

Zero-FP: easter-egg hanya dihitung bila content-type image/gif DAN body
berawalan GIF89a (halaman HTML 200 tidak dihitung); phpinfo butuh tiga
signature sekaligus. Versi eksplisit X.Y.Z dicatat sebagai fakta
cve-matcher (KB php2shell rentang 4.0.0..8.5.12). Tanpa marker = AMAN.
Semua probe gagal jaringan = TANPA klaim AMAN (fail-closed).
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

MAX_GETS = 4
TIMEOUT_S = 10.0
EASTER_EGG = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"
INFO_PATHS = ("/phpinfo.php", "/info.php")
_RE_PHP_VER = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I)
_RE_PHP_ERR = re.compile(r"PHP (?:Warning|Notice|Fatal error|Parse error)")
_CVE_NOTE = ("Black October 2026: php2shell CVE-2026-109618/109619 "
             "(RCE unauthenticated, CVSS 9.2); KB operator memuat "
             "rentang 4.0.0..8.5.12 — versi eksplisit diteruskan ke "
             "cve-matcher, verifikasi manual tetap wajib.")


def _get(base: str, path: str):
    """Satu GET bounded (helper level modul — guard return-shape)."""
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-php-posture"})
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


def _phpinfo_sig(body: str) -> bool:
    """Tiga signature sekaligus — halaman login/error generik ditolak."""
    low = body.lower()
    return ("phpinfo()" in low and "php version" in low
            and ("php.ini" in low or "system" in low))


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): maks 4 GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    n_get = 0
    responded = 0

    # 1) homepage: header/cookie/body marker
    st, body, hdrs = _get(base, "/")
    n_get += 1
    responded += 1 if st is not None else 0
    blob = body + " " + " ".join(f"{k}: {v}" for k, v in hdrs.items())
    powered = _hget(hdrs, "x-powered-by")
    server = _hget(hdrs, "server")
    cookie = _hget(hdrs, "set-cookie")
    version = None
    for cand in (powered, server, body):
        m = _RE_PHP_VER.search(cand or "")
        if m:
            version = m.group(1)
            break
    is_php = ("php" in powered.lower()
              or "phpsessid" in cookie.lower()
              or bool(_RE_PHP_ERR.search(blob)))

    # 2) easter-egg expose_php (signature: image/gif + GIF89a)
    expose_php = False
    st_e, body_e, hdrs_e = _get(base, EASTER_EGG)
    n_get += 1
    responded += 1 if st_e is not None else 0
    ctype = _hget(hdrs_e, "content-type").lower()
    if (st_e == 200 and "image/gif" in ctype
            and body_e.startswith("GIF89a")):
        expose_php = True
        is_php = True

    # 3-4) phpinfo exposure (tiga signature sekaligus)
    phpinfo_paths: list[str] = []
    for pth in INFO_PATHS:
        if n_get >= MAX_GETS:
            break
        st_i, body_i, _ = _get(base, pth)
        n_get += 1
        responded += 1 if st_i is not None else 0
        if st_i == 200 and _phpinfo_sig(body_i):
            phpinfo_paths.append(pth)
            is_php = True

    if is_php:
        if version:
            rows.append(make_finding(
                tool="php-posture",
                title=f"Versi PHP ter-expose di {base} ({version})",
                severity="low",
                description=f"Marker PHP/{version} terlihat pada "
                            f"header/body target. {_CVE_NOTE}",
                recommendation="Set expose_php=Off (sembunyikan "
                               "X-Powered-By), patched ke rilis fix "
                               "php2shell, verifikasi cabang versi di "
                               "cve-kb operator.",
                cwe="CWE-200", target_url=base + "/",
                request="GET / -> marker PHP",
                response=(f"X-Powered-By: {powered}"
                          if powered else f"PHP/{version}")[:150],
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "SURFACE", "safety_class":
                       "bounded-requests", "version": version,
                       "tech": f"php {version}"}))
        else:
            rows.append(make_finding(
                tool="php-posture",
                title=f"Runtime PHP terdeteksi di {base} "
                      f"(versi tidak eksplisit)",
                severity="info",
                description="Marker PHP terlihat (X-Powered-By/"
                            "PHPSESSID/error body) tetapi versi tidak "
                            "diekspos — inventaris; verifikasi versi "
                            "manual bila perlu cek php2shell.",
                target_url=base + "/",
                request="GET / -> marker PHP tanpa versi",
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "SURFACE", "safety_class":
                       "bounded-requests", "version": None,
                       "tech": "php"}))
        if expose_php:
            rows.append(make_finding(
                tool="php-posture",
                title=f"expose_php aktif — easter-egg logo PHP "
                      f"tersaji di {base}",
                severity="low",
                description="GET easter-egg expose_php mengembalikan "
                            "image/gif berawalan GIF89a — expose_php=On; "
                            "perilaku ini dapat mempersempit versi PHP.",
                recommendation="Set expose_php=Off di php.ini.",
                cwe="CWE-200", target_url=base + EASTER_EGG,
                request=f"GET {EASTER_EGG} -> 200 image/gif GIF89a",
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "SURFACE", "safety_class":
                       "bounded-requests"}))
        for pth in phpinfo_paths:
            rows.append(make_finding(
                tool="php-posture",
                title=f"phpinfo() ter-expose: {pth}",
                severity="high",
                description="Halaman phpinfo terbuka (signature "
                            "phpinfo()+PHP Version+php.ini/System) — "
                            "kebocoran konfigurasi/path/env (CWE-538).",
                recommendation="Hapus file phpinfo dari webroot atau "
                               "batasi akses; rotasi secret yang "
                               "terlihat.",
                cwe="CWE-538", target_url=base + pth,
                request=f"GET {pth} -> 200 signature phpinfo",
                response="signature phpinfo()/PHP Version/php.ini",
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "SURFACE", "safety_class":
                       "bounded-requests"}))
    elif responded == 0:
        rows.append(make_finding(
            tool="php-posture",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{n_get} GET semua gagal jaringan; kegagalan "
                        "koneksi BUKAN bukti tidak-ada-marker "
                        "(fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="php-posture",
            title=f"Tidak ada marker yang dicari pada {base} "
                  f"({n_get} GET)",
            severity="info",
            description="Tidak ada marker PHP (X-Powered-By/PHPSESSID/"
                        "error body/easter-egg/phpinfo) dengan "
                        "signature ketat — AMAN/inventaris.",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))

    meta = {"url": base, "requests": n_get, "is_php": is_php,
            "version": version, "expose_php": expose_php,
            "phpinfo": phpinfo_paths}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="php_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"php-posture: php={meta['is_php']} "
          f"version={meta['version']} phpinfo={len(meta['phpinfo'])} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
