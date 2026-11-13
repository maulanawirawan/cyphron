"""[SAFETY: max-2-request] Plex Media Server banner audit.

Skill v2 (produk SecAI). Melengkapi antrian F66: seed watchlist
Plex2Shell sudah ada di `assets/intel/watchlist-seeds.json`, deteksi
banner-nya belum — skill ini mengisi celah itu.

Batas keras: MAKSIMAL DUA GET:
  1. GET root '/' — Plex Media Server menandai setiap respons HTTP-nya
     dengan header khas `X-Plex-Protocol` (tidak dipakai produk lain)
     dan `X-Plex-Version`;
  2. hanya bila (1) tidak memuat penanda Plex, GET /web/ (antarmuka web
     bawaan — sering di-serve di bawah reverse proxy yang menyaring
     header). Tidak ada probing parameter.

Marker produk (ketat, anti-FP): header `x-plex-protocol` ATAU frasa
"plex media server" (word-boundary, case-insensitive). Kata "plex"
polos / "multiplex" TIDAK dianggap cukup.

Marker versi: header `X-Plex-Version` (format 1.41.2.9054-...) atau
format serupa di body. Versi yang TIDAK terekspos => pemetaan CVE
TIDAK diklaim (fail-closed, zero-FP).

Pemakaian:
  python skills/banner_plex.py --url http://media.example.lan:32400/ \
      --out findings/tier0-contoh/banner_plex.json
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

WEB_PATH = "/web/"
PRODUCT_HEADER = "x-plex-protocol"
VERSION_HEADER = "x-plex-version"
PRODUCT_PHRASE = re.compile(r"\bplex media server\b", re.I)
VERSION_BODY = re.compile(r"\b1\.\d{1,2}\.\d{1,4}\.\d{1,5}(?:-[0-9a-f]{8,12})?\b")
MAX_REQUESTS = 2


def fetch_once(url: str, timeout: float = 30.0) -> dict:
    """SATU GET, tanpa retry (retry = permintaan ekstra, melanggar batas)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(256_000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return {"url": url, "status": r.status, "headers": headers,
                    "body": body}
    except Exception as exc:
        return {"url": url, "status": None, "headers": {},
                "body": f"__fetch_error__ {type(exc).__name__}: {exc}"}


def _hdrs(result: dict) -> dict:
    """Header dinormalisasi lowercase (fetch_once sudah; input manual juga
    diterima — defensif)."""
    return {k.lower(): v for k, v in result.get("headers", {}).items()}


def _product_hit(result: dict) -> bool:
    """True bila respons ini memuat penanda Plex yang cukup (token ketat)."""
    if result.get("status") is None or not (200 <= result["status"] < 400):
        return False
    if PRODUCT_HEADER in _hdrs(result):
        return True
    blob = result.get("body", "") + " " + " ".join(
        f"{k}={v}" for k, v in _hdrs(result).items())
    return bool(PRODUCT_PHRASE.search(blob))


def _version_marker(result: dict) -> str | None:
    """Versi eksplisit dari header (utama) atau body (fallback)."""
    v = _hdrs(result).get(VERSION_HEADER)
    if v:
        return v[:80]
    m = VERSION_BODY.search(result.get("body", ""))
    return m.group(0) if m else None


def probe(base_url: str, timeout: float = 30.0) -> tuple[list[dict], int]:
    """Jalankan 1-2 GET sesuai batas. Kembalikan (results, requests_used)."""
    base = base_url.rstrip("/")
    r1 = fetch_once(base + "/", timeout=timeout)
    results = [r1]
    if not _product_hit(r1):
        results.append(fetch_once(base + WEB_PATH, timeout=timeout))
    return results, len(results)


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Audit murni dari hasil fetch (dipakai CLI dan test — NOL jaringan
    di sisi audit). results = [root, web?] sesuai probe()."""
    rows: list[dict] = []
    viewed = [r for r in results if r]
    best = next((r for r in viewed if _product_hit(r)), viewed[-1])

    def finding(title, sev, desc, rec="", category="MISC", verdict=0,
                response=""):
        rows.append(make_finding(
            tool="banner-plex", title=title, severity=sev,
            description=desc, recommendation=rec, target_url=url,
            response=response[:300], evidence_kind="request-response",
            finding_class="posture", confidence=1.0,
            status="confirmed", verdict=verdict,
            extra={"category": category, "safety_class": "2-request"}))

    if best.get("status") is None:
        rows.append(make_finding(
            tool="banner-plex",
            title=f"Fetch failed on {url}",
            severity="info", description=best.get("body", "")[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "2-request"}))
        return rows, {"url": url, "error": True, "requests": len(viewed)}

    hit = _product_hit(best)
    marker = _version_marker(best) if hit else None

    if hit:
        via = ("header X-Plex-Protocol"
               if PRODUCT_HEADER in _hdrs(best)
               else "frasa 'Plex Media Server' di body")
        finding(f"Plex Media Server banner observed on {url}",
                "info",
                f"Server media Plex terekspos publik (terdeteksi lewat "
                f"{via}; halaman: {best['url']}). Data yang dilihat siapa "
                "pun yang membuka alamat ini.",
                category="SURFACE", verdict=0,
                response=f"GET {best['url']} -> {best['status']}")
        if marker:
            finding(f"Plex version exposed on {url}: {marker}",
                    "low",
                    "X-Plex-Version / marker versi terekspos di halaman "
                    "publik — fakta masukan cve-matcher (watchlist "
                    "Plex2Shell). Versi eksplisit = pemetaan CVE boleh "
                    "dilakukan lapis berikutnya.",
                    rec="Sembunyikan X-Plex-Version dari respons "
                        "tanpa autentikasi (bila server tidak perlu "
                        "ditemukan klien LAN).",
                    category="SURFACE", verdict=1,
                    response=f"version={marker}")
        else:
            finding(f"Version not exposed on {url} (CVE mapping NOT claimed)",
                    "info",
                    "Produk Plex terdeteksi tetapi versi tidak terekspos; "
                    "pemetaan CVE tidak dilakukan (fail-closed — tanpa "
                    "versi, tanpa klaim).",
                    category="SURFACE", verdict=0,
                    response=f"GET {best['url']} -> {best['status']}")
    else:
        finding(f"No Plex banner on {url}",
                "info",
                "Tidak ada penanda Plex pada root maupun /web/ "
                "(maks 2 GET). Tidak diklaim apa pun.",
                category="MISC", verdict=0,
                response=f"GET {results[0]['url']} -> "
                         f"{results[0]['status']}")

    return rows, {
        "url": url,
        "status": best.get("status"),
        "products": ["Plex Media Server"] if hit else [],
        "version_marker": marker,
        "requests": len(viewed),
        "probed": [r.get("url") for r in viewed],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True,
                    help="basis URL Plex (MAKS 2 GET otomatis)")
    ap.add_argument("--out", default="banner_plex.json")
    args = ap.parse_args()

    results, used = probe(args.url)
    rows, meta = audit(args.url, results)
    meta["requests"] = used
    write_findings(args.out, rows, {**meta, "safety_class": "2-request"})
    print(f"banner-plex: {len(rows)} temuan "
          f"({used}/{MAX_REQUESTS} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
