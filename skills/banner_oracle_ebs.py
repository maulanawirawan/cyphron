"""[SAFETY: max-2-request] Oracle E-Business Suite banner audit.

Skill v2 (produk SecAI). Melengkapi antrian F66: seed watchlist Oracle
EBS sudah ada di `assets/intel/watchlist-seeds.json`, deteksi banner-nya
belum — skill ini mengisi celah itu.

Batas keras: MAKSIMAL DUA GET:
  1. GET /OA_HTML/AppsLogin — halaman login resmi EBS;
  2. hanya bila (1) bukan halaman EBS, GET root '/' (install di root /
     custom login). Tidak ada bruteforce path, tidak ada probing
     parameter. Dua GET = dua kunjungan halaman browser.

Marker produk (ketat, anti-FP): frasa "Oracle E-Business Suite"
(word-boundary, case-insensitive), ATAU frasa "e-business suite"
berpasangan dengan penanda aplikasi ("appslogin" / "oa_html") di
halaman yang sama. "Oracle" polos atau "e-business" terpotong TIDAK
dianggap cukup — blog/vendornya sendiri menyebut "Oracle" di mana-mana.

Marker versi: format rilis publik EBS (11.5.x / 12.0.x / 12.1.x /
12.2.x) di body. Versi yang TIDAK terekspos => pemetaan CVE TIDAK
diklaim (fail-closed, zero-FP).

Pemakaian:
  python skills/banner_oracle_ebs.py --url https://erp.example.go.id/ \
      --out findings/tier0-contoh/banner_oracle_ebs.json
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

LOGIN_PATH = "/OA_HTML/AppsLogin"
PRODUCT_PHRASE = re.compile(r"\boracle e-business suite\b", re.I)
PRODUCT_PHRASE_LOOSE = re.compile(r"\be-business suite\b", re.I)
APP_MARKER = re.compile(r"\b(?:appslogin|oa_html)\b", re.I)
VERSION_PATTERNS = [
    re.compile(r"\b11\.5\.\d{1,2}\b"),
    re.compile(r"\b12\.[0-2]\.\d{1,3}\b"),
]
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


def _product_hit(result: dict) -> bool:
    """True bila respons ini memuat penanda EBS yang cukup (token ketat)."""
    if result.get("status") is None or not (200 <= result["status"] < 400):
        return False
    blob = result.get("body", "") + " " + " ".join(
        f"{k}={v}" for k, v in result.get("headers", {}).items())
    if PRODUCT_PHRASE.search(blob):
        return True
    return bool(PRODUCT_PHRASE_LOOSE.search(blob) and APP_MARKER.search(blob))


def probe(base_url: str, timeout: float = 30.0) -> tuple[list[dict], int]:
    """Jalankan 1-2 GET sesuai batas. Kembalikan (results, requests_used)."""
    base = base_url.rstrip("/")
    r1 = fetch_once(base + LOGIN_PATH, timeout=timeout)
    results = [r1]
    if not _product_hit(r1):
        results.append(fetch_once(base + "/", timeout=timeout))
    return results, len(results)


def _version_markers(body: str) -> list[str]:
    found: set[str] = set()
    for pat in VERSION_PATTERNS:
        found.update(pat.findall(body))
    return sorted(found)


def audit(url: str, results: list[dict]) -> tuple[list[dict], dict]:
    """Audit murni dari hasil fetch (dipakai CLI dan test — NOL jaringan
    di sisi audit). results = [AppsLogin, root?] sesuai probe()."""
    rows: list[dict] = []
    viewed = [r for r in results if r]
    best = next((r for r in viewed if _product_hit(r)), viewed[-1])

    def finding(title, sev, desc, rec="", category="MISC", verdict=0,
                response=""):
        rows.append(make_finding(
            tool="banner-oracle-ebs", title=title, severity=sev,
            description=desc, recommendation=rec, target_url=url,
            response=response[:300], evidence_kind="request-response",
            finding_class="posture", confidence=1.0,
            status="confirmed", verdict=verdict,
            extra={"category": category, "safety_class": "2-request"}))

    if best.get("status") is None:
        rows.append(make_finding(
            tool="banner-oracle-ebs",
            title=f"Fetch failed on {url}",
            severity="info", description=best.get("body", "")[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "2-request"}))
        return rows, {"url": url, "error": True, "requests": len(viewed)}

    body = best.get("body", "")
    hit = _product_hit(best)
    vm = _version_markers(body) if hit else []

    if hit:
        finding(f"Oracle E-Business Suite banner observed on {url}",
                "info",
                f"ERP EBS terekspos publik (halaman: {best['url']}). "
                "Data yang dilihat siapa pun yang membuka alamat ini.",
                category="SURFACE", verdict=0,
                response=f"GET {best['url']} -> {best['status']}")
        if vm:
            finding(f"EBS version marker exposed on {url}: {', '.join(vm)}",
                    "low",
                    "Format rilis EBS terekspos di halaman publik — "
                    "fakta masukan cve-matcher (watchlist Oracle EBS). "
                    "Versi eksplisit = pemetaan CVE boleh dilakukan "
                    "lapis berikutnya.",
                    rec="Sembunyikan marker versi dari halaman publik "
                        "(cacheable pages/footer R12).",
                    category="SURFACE", verdict=1,
                    response=f"version_markers={vm}")
        else:
            finding(f"Version not exposed on {url} (CVE mapping NOT claimed)",
                    "info",
                    "Produk EBS terdeteksi tetapi versi tidak terekspos "
                    "di halaman publik; pemetaan CVE tidak dilakukan "
                    "(fail-closed — tanpa versi, tanpa klaim).",
                    category="SURFACE", verdict=0,
                    response=f"GET {best['url']} -> {best['status']}")
    else:
        finding(f"No Oracle EBS banner on {url}",
                "info",
                "Tidak ada penanda EBS pada halaman login maupun root "
                "(maks 2 GET). Tidak diklaim apa pun.",
                category="MISC", verdict=0,
                response=f"GET {results[0]['url']} -> "
                         f"{results[0]['status']}")

    return rows, {
        "url": url,
        "status": best.get("status"),
        "products": ["Oracle E-Business Suite"] if hit else [],
        "version_markers": vm,
        "requests": len(viewed),
        "probed": [r.get("url") for r in viewed],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True,
                    help="basis URL EBS (MAKS 2 GET otomatis)")
    ap.add_argument("--out", default="banner_oracle_ebs.json")
    args = ap.parse_args()

    results, used = probe(args.url)
    rows, meta = audit(args.url, results)
    meta["requests"] = used
    write_findings(args.out, rows, {**meta, "safety_class": "2-request"})
    print(f"banner-oracle-ebs: {len(rows)} temuan "
          f"({used}/{MAX_REQUESTS} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
