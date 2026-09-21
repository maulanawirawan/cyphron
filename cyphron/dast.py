"""dast — DAST orchestration dengan profil bertahap (Fullpower B4 / CI-4).

Tiga profil (crawl-depth + policy aktif bertingkat) — semua tetap lewat
authorization gate + budget; "full" hanya untuk engagement berotorisasi
penuh:

  dev-cicd : depth 1, 10 halaman, PASIF saja (aman untuk pipeline CI)
  standard : depth 2, 30 halaman, aktif risiko rendah-menengah
  full     : depth 4, 100 halaman, aktif penuh (butuh otorisasi ofensif)

policy_for() mengembalikan ScanOptions-ready dict + alasan keputusan;
bilamana profil menuntut lebih daripada yang otorisasi izinkan, profil
OTOMatis diturunkan (fail-closed), bukan error.
"""

from __future__ import annotations

PROFILES: dict[str, dict] = {
    "dev-cicd": {"crawl_pages": 10, "crawl_depth": 1, "max_steps": 15,
                 "max_requests": 80, "active": False, "rate_limit": 0.05},
    "standard": {"crawl_pages": 30, "crawl_depth": 2, "max_steps": 40,
                 "max_requests": 250, "active": True, "rate_limit": 0.1},
    "full": {"crawl_pages": 100, "crawl_depth": 4, "max_steps": 120,
             "max_requests": 600, "active": True, "rate_limit": 0.15},
}
_ORDER = ["dev-cicd", "standard", "full"]


def policy_for(profile: str, authorized: bool = False,
               doc_restrictions: list[str] | None = None) -> dict:
    """Keputusan profil -> parameter scan; down-grade bila otorisasi kurang.

    Aturan:
    - profil aktif (standard/full) butuh dokumen otorisasi; tanpa dokumen,
      otomatis turun ke dev-cicd (pasif);
    - dokumen dengan restriction no_aggressive menolak profil full
      (turun ke standard);
    - return {profile_effective, requested, params, downgraded, reason}."""
    requested = profile if profile in PROFILES else "standard"
    effective = requested
    restrictions = {str(r).lower() for r in (doc_restrictions or [])}
    reason = "profil dipakai sesuai permintaan"
    downgraded = False
    if PROFILES[requested]["active"] and not authorized:
        effective = "dev-cicd"
        downgraded = True
        reason = "tanpa otorisasi aktif — profil turun ke pasif (fail-closed)"
    elif requested == "full" and "no_aggressive" in restrictions:
        effective = "standard"
        downgraded = True
        reason = "dokumen melarang teknik agresif — full diturunkan ke standard"
    params = dict(PROFILES[effective])
    return {"requested": requested, "profile_effective": effective,
            "params": params, "downgraded": downgraded, "reason": reason}


def plan_from_policy(policy: dict, target: str) -> dict:
    """Policy -> argumen siap ScanOptions/run_scan."""
    p = policy["params"]
    return {
        "target": target,
        "crawl_pages": p["crawl_pages"],
        "crawl_depth": p["crawl_depth"],
        "max_steps": p["max_steps"],
        "max_requests": p["max_requests"],
        "rate_limit_s": p["rate_limit"],
        "active_expected": p["active"],
    }
