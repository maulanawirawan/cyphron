"""[SAFETY: bounded-requests] archive-url-checker — URL arsip Wayback
yang masih hidup / menarik (CWE-538/200), konsep publik ala
waymore/gau + port engine archive_diff legacy (endpoint terlupakan
yang masih HIDUP).

Dua tahap:
  1. PASIF — CDX API web.archive.org (1 GET, limit 300, collapse
     urlkey): daftar URL historis domain; klasifikasi pola menarik
     (api/admin/backup/config/.env/.sql/.bak/swagger/graphql/debug)
     murni dari string URL — nol klaim konten.
  2. LIVE (bounded, maks MAX_LIVE = 5) — SATU GET per URL menarik
     TERATAS: status "masih hidup" adalah FAKTUM, bukan kerentanan;
     lead L2 hanya untuk pola file sensitif yang masih hidup.

Fail-closed: CDX gagal/kosong = L0 inventaris, tanpa live check.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
CDX_LIMIT = 300
MAX_LIVE = 5  # estimasi bounded-requests orchestrator

# pola menarik murni dari nama path (zero-FP: klasifikasi string, bukan klaim)
PATTERNS = {
    "api-surface": ("/api/", "graphql", "/v1/", "/v2/"),
    "admin-panel": ("admin", "dashboard", "manager", "cpanel"),
    "config-secret": (".env", "config.json", "config.yml", "settings.py",
                      "wp-config"),
    "backup-dump": (".sql", ".bak", ".zip", ".tar.gz", ".old", "dump"),
    "debug-endpoint": ("debug", "phpinfo", "test", "swagger", "console"),
}
SENSITIVE_CLASSES = ("config-secret", "backup-dump")


def cdx_fetch(domain: str, timeout: float = 30.0) -> dict:
    url = ("http://web.archive.org/cdx/search/cdx?url="
           + urllib.parse.quote(f"{domain}/*")
           + f"&output=json&limit={CDX_LIMIT}&collapse=urlkey"
             "&filter=statuscode:200")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            rows = json.loads(r.read(2_000_000).decode("utf-8", "replace"))
        urls = [row[2] for row in rows[1:] if len(row) > 2]
        return {"ok": True, "urls": urls}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def classify(urls: list[str]) -> dict:
    """Klasifikasi pola murni dari string URL (zero-FP)."""
    out: dict[str, list[str]] = {}
    for u in urls:
        low = u.lower()
        for cls, needles in PATTERNS.items():
            if any(n in low for n in needles):
                out.setdefault(cls, []).append(u)
    return out


def live_check(urls: list[str], timeout: float = 15.0) -> dict:
    """SATU GET per URL (maks MAX_LIVE): status hidup = faktum."""
    out: dict = {}
    for u in urls[:MAX_LIVE]:
        req = urllib.request.Request(u, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out[u] = {"status": r.status}
        except urllib.error.HTTPError as e:
            out[u] = {"status": e.code}
        except Exception as exc:
            out[u] = {"status": None, "error": f"{type(exc).__name__}"}
    return out


def audit(domain: str, cdx: dict, classified: dict, live: dict | None) \
        -> tuple[list[dict], dict]:
    rows: list[dict] = []
    total = len(cdx.get("urls", [])) if cdx.get("ok") else 0
    if not cdx.get("ok"):
        rows.append(make_finding(
            tool="archive-url-checker",
            title=f"CDX fetch failed for {domain}", severity="info",
            description=str(cdx.get("error"))[:300],
            target_url=domain, evidence_kind="archive",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests"}))
        return rows, {"domain": domain, "error": True, "urls": 0}
    rows.append(make_finding(
        tool="archive-url-checker",
        title=f"Archive URL inventory on {domain}: {total} URLs",
        severity="info",
        description=f"CDX Wayback mengembalikan {total} URL historis "
                    "dengan pola menarik: "
                    f"{ {k: len(v) for k, v in classified.items()} } — "
                    "inventaris permukaan terlupakan (0 klaim).",
        target_url=domain, response=json.dumps(
            {k: v[:3] for k, v in classified.items()})[:400],
        evidence_kind="archive", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "SURFACE", "safety_class": "bounded-requests",
               "patterns": {k: len(v) for k, v in classified.items()}}))
    for cls, urls in classified.items():
        if cls in SENSITIVE_CLASSES:
            rows.append(make_finding(
                tool="archive-url-checker",
                title=f"Sensitive path pattern in archive on {domain}: "
                      f"{cls} ({len(urls)} URL)",
                severity="low",
                description=f"URL historis berpola '{cls}' ditemukan di "
                            "arsip — kandidat endpoint terlupakan untuk "
                            "dicek manual (lead; keberadaan URL arsip "
                            "BUKAN bukti file masih ada).",
                recommendation="Cek manual apakah path masih hidup; hapus "
                               "arsip/backup dari webroot.",
                cwe="CWE-538",
                target_url=urls[0], response="\n".join(urls[:5])[:400],
                evidence_kind="archive", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "EXPOSURE",
                       "safety_class": "bounded-requests",
                       "pattern": cls, "count": len(urls)}))
    if live:
        for u, res in live.items():
            if res.get("status") == 200 and any(
                    c in ("config-secret", "backup-dump")
                    for c, lst in classified.items() if u in lst):
                rows.append(make_finding(
                    tool="archive-url-checker",
                    title=f"Archived sensitive URL still live on {domain}",
                    severity="medium",
                    description=f"URL arsip berpola sensitif MASIH hidup "
                                "(HTTP 200 saat dicek ulang): {u} — "
                                "verifikasi konten manual; bukti hanya "
                                "status, konten TIDAK dibaca penuh.",
                    recommendation="Hapus/blokir file; rotasi kredensial "
                                   "bila berupa config.",
                    cwe="CWE-538",
                    target_url=u, response=f"status {res['status']}",
                    evidence_kind="request-response",
                    finding_class="weakness", confidence=1.0,
                    status="confirmed", verdict=2,
                    extra={"category": "EXPOSURE",
                           "safety_class": "bounded-requests",
                           "url": u}))
    return rows, {"domain": domain, "urls": total,
                  "patterns": {k: len(v) for k, v in classified.items()},
                  "live_checked": len(live or {}), "requests":
                      len(live or {})}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--no-live", action="store_true",
                    help="CDX pasif saja (0 GET ke domain)")
    ap.add_argument("--out", default="archive_url_findings.json")
    args = ap.parse_args()
    cdx = cdx_fetch(args.domain)
    classified = classify(cdx.get("urls", [])) if cdx.get("ok") else {}
    live = None
    if not args.no_live and classified:
        top = sorted((u for cls in classified.values() for u in cls),
                     key=lambda u: (0 if any(s in u.lower() for s in
                                             (".env", ".sql", ".bak",
                                              "config")) else 1,
                                    u))
        live = live_check(top)
    rows, meta = audit(args.domain, cdx, classified, live)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"archive-url-checker: {len(rows)} temuan "
          f"({meta.get('urls', 0)} URL arsip, "
          f"{meta.get('live_checked', 0)} live check) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
