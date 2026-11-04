"""[SAFETY: bounded-requests] cached-sensitive-files — deteksi respons
sensitif yang ter-cache ke file statis publik (CWE-538/312).

Pola nyata: cache plugin WordPress (mis. WP Fastest Cache) menulis hasil
render halaman internal ke direktori statis publik. Kasus terdokumentasi
(CVE-2026-111464, 1.5.3): respons `wp-activate.php` multisite — yang
memuat username + password plaintext hasil aktivasi — ikut ter-cache ke
`/wp-content/cache/all/wp-activate.php/index.html` dan bisa dibaca siapa
pun tanpa login. Patch 1.5.4 menambah guard `pagenow` + exclude list,
sehingga file tidak pernah ditulis.

Dua GET ke path statis yang TERDOKUMENTASI publik (bukan bruteforce,
bukan directory scan):
  1. /wp-content/cache/all/wp-activate.php/index.html  (pola WPFC)
  2. /wp-content/cache/supercache/{host}/wp-activate.php/index.html
     (varian WP Super Cache dengan path per-host)

Fail-closed / zero-FP:
  - 404 / error fetch  -> AMAN, tanpa temuan (file tidak pernah ditulis).
  - 200 TANPA marker   -> bukan halaman hasil aktivasi; TANPA temuan.
  - 200 + marker
    `signup-welcome` (blok sukses aktivasi multisite core WordPress,
    hanya muncul SETELAH aktivasi berhasil) -> temuan L3 terkonfirmasi
    dengan cuplikan bukti.

Marker ini tidak ada di halaman form aktivasi, sehingga respons tidak
bisa dikelirukan dengan halaman input normal.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()

# Blok sukses aktivasi multisite core WordPress. Hanya dirender pada
# halaman aktivasi BERHASIL (bukan form input) — marker FP-rendah.
SUCCESS_MARKER = "signup-welcome"
# Kredensial plaintext dirender di dalam blok sukses tersebut.
CRED_HINT = re.compile(
    r"(username|password)[^<>]{0,40}(?:<[^>]+>\s*)*[A-Za-z0-9!@#$%^&*_.-]{4,}",
    re.IGNORECASE,
)

MAX_LIVE = 2  # batas keras: dua GET ke path statis terdokumentasi


def fetch_once(url: str, timeout: float = 30.0) -> dict:
    """SATU GET per path cache. Tidak ada retry (melanggar batas)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(256_000).decode("utf-8", errors="replace")
            return {"status": r.status, "body": body}
    except Exception as exc:
        return {"status": None, "body": f"__fetch_error__ {type(exc).__name__}: {exc}"}


def cache_paths(base_url: str) -> list[str]:
    """Dua path cache statis terdokumentasi (tethap tanpa bruteforce)."""
    base = base_url.rstrip("/")
    host = urllib.parse.urlparse(base_url).netloc
    return [
        base + "/wp-content/cache/all/wp-activate.php/index.html",
        base + "/wp-content/cache/supercache/" + host + "/wp-activate.php/index.html",
    ]


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    """Klasifikasi satu respons cache. Fail-closed: hanya 200 + marker.

    Kontrak skill: return (rows, meta) — meta membawa status cache yang
    diperiksa agar pemeriksa bisa membedakan 'aman' dari 'tidak diperiksa'.
    """
    body = result.get("body", "")
    status = result.get("status")
    meta = {"url": url, "status": status, "cached_page_seen": False}
    if status != 200:
        return [], meta
    if SUCCESS_MARKER not in body:
        return [], meta
    meta["cached_page_seen"] = True
    snippet = ""
    idx = body.find(SUCCESS_MARKER)
    if idx >= 0:
        snippet = body[max(0, idx - 120): idx + 400]
    cred_visible = bool(CRED_HINT.search(snippet))
    severity = "high" if cred_visible else "medium"
    conf = 0.9 if cred_visible else 0.75
    desc = (
        "File cache publik berisi halaman hasil aktivasi multisite WordPress "
        "(marker 'signup-welcome'): username dan password plaintext hasil "
        "aktivasi ikut tersimpan dan bisa dibaca tanpa login. Pola yang sama "
        "terdokumentasi pada WP Fastest Cache <= 1.5.3 (CVE-2026-111464)."
    )
    if not cred_visible:
        desc += " Pola kredensial tidak terverifikasi pada cuplikan ini."
    f = make_finding(
        tool="cached-sensitive-files",
        title="Cached wp-activate success page is publicly readable",
        severity=severity,
        description=desc,
        recommendation=(
            "Perbarui plugin cache ke versi yang meng-exclude wp-activate.php, "
            "hapus direktori cache lama, dan rotasi kredensial akun yang baru "
            "diaktivasi selama periode terekspos."
        ),
        cwe="CWE-538",
        target_url=url,
        request="GET " + url,
        response=snippet[:400],
        evidence_kind="in-band-marker",
        finding_class="exposure",
        confidence=conf,
        status="confirmed",
        verdict=3,
    )
    return [f], meta


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi file cache statis yang membocorkan halaman "
                    "aktivasi multisite WordPress (read-only, 2 GET)."
    )
    ap.add_argument("--url", required=True, help="URL dasar target (mis. https://site.id/)")
    ap.add_argument("--out", required=True, help="path keluaran findings.json")
    args = ap.parse_args()

    probes = cache_paths(args.url)[:MAX_LIVE]
    findings: list[dict] = []
    audits_meta: list[dict] = []
    for probe_url in probes:
        res = fetch_once(probe_url)
        rows, a_meta = audit(probe_url, res)
        findings.extend(rows)
        audits_meta.append(a_meta)

    meta = {
        "tool": "cached-sensitive-files",
        "target": args.url,
        "requests": len(probes),
        "safety": "bounded-requests",
        "probes": probes,
        "audit": audits_meta,
    }
    write_findings(args.out, findings, meta)
    print(
        f"cached-sensitive-files: {len(findings)} temuan "
        f"({len(probes)} request) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
