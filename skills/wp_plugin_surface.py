"""[SAFETY: bounded-requests] wp-plugin-surface — permukaan plugin
WordPress (F66c; latar Black October 2026: Bricksforge CVE-2026-85097
CVSS 10.0 upload+eksekusi PHP, dieksploitasi 2026-10-07; wp-posture F60
hanya menutup core, bukan plugin).

Bounded MAKS 6 GET: / (marker WP) + readme.txt 5 plugin kandidat
(bricksforge, elementor, woocommerce, contact-form-7, wordpress-seo).
readme.txt publik = sumber versi yang sah (konvensi WordPress.org);
versi diekstrak dari 'Stable tag:' atau 'Version:'.

Zero-FP: plugin dianggap terdeteksi HANYA bila readme.txt 200 DAN cocok
bentuk readme (header '===' / 'Stable tag:' / 'Requires at least:');
404/403/redirect tidak dihitung. Versi = fakta cve-matcher + watchlist
token (cth. bricksforge CVE-2026-85097). Tanpa marker = AMAN; gagal
jaringan pada probe utama = tanpa klaim AMAN.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 6
TIMEOUT_S = 10.0
PLUGINS = ("bricksforge", "elementor", "woocommerce",
           "contact-form-7", "wordpress-seo")
_RE_WP = re.compile(r"wp-content|wp-includes|wp-json", re.I)
_RE_STABLE = re.compile(r"(?im)^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)")
_RE_VERSION = re.compile(r"(?im)^\s*Version:\s*([0-9][0-9A-Za-z.\-]*)")


def _get(base: str, path: str):
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-wp-plugin-surface"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return (r.status, r.read(64_000).decode("utf-8", "replace"),
                    dict(r.headers.items()))
    except urllib.error.HTTPError as e:
        return (e.code,
                (e.read(16_000) or b"").decode("utf-8", "replace"),
                dict(e.headers.items()) if e.headers else {})
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:120], {}


def _readme_shape(body: str) -> bool:
    return (body.lstrip().startswith("===")
            or "Stable tag:" in body
            or "Requires at least:" in body)


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): maks 6 GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    st, body, _ = _get(base, "/")
    n_get = 1
    responded = 1 if st is not None else 0
    is_wp = st == 200 and bool(_RE_WP.search(body))

    if not is_wp:
        if responded == 0:
            rows.append(make_finding(
                tool="wp-plugin-surface",
                title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
                severity="info",
                description="GET homepage gagal jaringan; kegagalan "
                            "koneksi BUKAN bukti tidak-ada-marker "
                            "(fail-closed).",
                target_url=base,
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class":
                       "bounded-requests", "network_error": True}))
        else:
            rows.append(make_finding(
                tool="wp-plugin-surface",
                title=f"Tidak ada marker CMS target pada {base} (1 GET)",
                severity="info",
                description="Homepage tidak memuat marker wp-content/"
                            "wp-includes/wp-json — skill plugin CMS "
                            "berhenti (AMAN/skop).",
                target_url=base,
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class":
                       "bounded-requests"}))
        return rows, {"url": base, "requests": n_get, "is_wp": False,
                      "plugins": {}, "plugin_count": 0}

    found: dict[str, str | None] = {}
    for slug in PLUGINS:
        if n_get >= MAX_GETS:
            break
        st_p, body_p, _ = _get(
            base, f"/wp-content/plugins/{slug}/readme.txt")
        n_get += 1
        if st_p == 200 and _readme_shape(body_p):
            m = _RE_STABLE.search(body_p) or _RE_VERSION.search(body_p)
            found[slug] = m.group(1) if m else None

    for slug, ver in found.items():
        rows.append(make_finding(
            tool="wp-plugin-surface",
            title=f"Plugin {slug} terdeteksi di {base} "
                  f"(versi {ver or 'tidak eksplisit'})",
            severity="info",
            description=f"readme.txt publik plugin {slug} terbaca"
                        + (f" (Stable tag/Version: {ver})" if ver else "")
                        + " — fakta versi untuk cve-matcher/watchlist.",
            target_url=base + f"/wp-content/plugins/{slug}/readme.txt",
            request=f"GET /wp-content/plugins/{slug}/readme.txt -> 200",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "plugin": slug,
                   "plugin_version": ver,
                   "tech": (f"{slug} {ver}" if ver else f"{slug} plugin")}))

    if found:
        versions_s = ", ".join(
            f"{slug} {ver or '?'}" for slug, ver in found.items())
        rows.append(make_finding(
            tool="wp-plugin-surface",
            title=f"Versi plugin publik ter-expose di {base} "
                  f"({len(found)} plugin)",
            severity="low",
            description=f"readme.txt publik membocorkan versi plugin: "
                        f"{versions_s}. Versi publik memudahkan "
                        "pencocokan advisory (cth. Bricksforge "
                        "CVE-2026-85097, ≤3.1.8.9 fixed 3.1.8.10 — "
                        "lead watchlist, bukan klaim).",
            recommendation="Update plugin ke rilis patch, hapus plugin "
                           "tak terpakai, pertimbangkan menyembunyikan "
                           "readme/versi (defense-in-depth).",
            cwe="CWE-200", target_url=base + "/wp-content/plugins/",
            request="GET readme.txt plugin kandidat -> 200",
            response=versions_s[:200],
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class":
                   "bounded-requests", "plugins": found}))
    else:
        rows.append(make_finding(
            tool="wp-plugin-surface",
            title=f"Tidak ada plugin yang dicari pada {base} "
                  f"({n_get} GET)",
            severity="info",
            description="readme.txt 5 plugin kandidat tidak terbaca "
                        "dengan bentuk readme yang sah — AMAN/"
                        "inventaris (plugin lain di luar daftar kandidat "
                        "tetap mungkin ada).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))

    meta = {"url": base, "requests": n_get, "is_wp": True,
            "plugins": found, "plugin_count": len(found)}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="wp_plugin_surface.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"wp-plugin-surface: wp={meta['is_wp']} "
          f"plugins={len(meta['plugins'])} ({meta['requests']} GET) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
