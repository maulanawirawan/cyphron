"""pricing — tabel harga, konversi token, dan batasan trial Cyphron.

Model HYBRID yang disengaja (lihat docs/PRICING-TIERS.md):
- TIER  = kemampuan (engine apa yang boleh jalan; licensing.ENGINE_TIERS).
- TOKEN = kuota konsumsi. 1 token = 1 eksekusi tool (tool-run), dibobot
  risk_tag: pasif=1, aktif=2, agresif/eksploit=4. Mode scan mengalikan
  konsumsi: read-only ×1, active ×1.5, offensive ×2.
- TRIAL = lisensi kind=trial: 1 scan/24 jam, 30 token, report REDACTED,
  7 hari, 1x per device fingerprint (antibuse).

Keputusan harga (IDR, pasokan lokal; USD ±10x di billing server):
    trial    : Rp 0        — 30 token, report redacted
    basic    : Rp 299rb/bln — 150 token, 1 target
    pro      : Rp 799rb/bln — 600 token, 2 target, fix packs + verify
    business : Rp 1.999rb/bln — 2.000 token, 3 target, perf + white-box
    god      : Rp 4.999rb/bln — 5.000 token (fair-use), multi-akun, API
    top-up   : Rp 500rb / 1.000 token (semua tier)
"""

from __future__ import annotations

TOKEN_COST = {
    # 1 token per risk_tag utama tool (dari registry); agresif/eksploit 4x
    "passive": 1, "local": 1, "external": 2,
    "active": 2, "load": 3, "aggressive": 4, "exploit": 4,
}

MODE_MULTIPLIER = {"read-only": 1.0, "active": 1.5, "offensive": 2.0}

PLANS = {
    "trial": {"price_idr": 0, "token_limit": 30, "targets": 1,
              "report_mode": "redacted", "scans_per_day": 1, "days": 7},
    "basic": {"price_idr": 299_000, "token_limit": 150, "targets": 1,
              "report_mode": "full", "scans_per_day": 4},
    "pro": {"price_idr": 799_000, "token_limit": 600, "targets": 2,
            "report_mode": "full", "scans_per_day": 10},
    "business": {"price_idr": 1_999_000, "token_limit": 2000, "targets": 3,
                 "report_mode": "full", "scans_per_day": 30},
    "god": {"price_idr": 4_999_000, "token_limit": 5000, "targets": 999,
            "report_mode": "full", "scans_per_day": 999},
}

TOPUP = {"token": 1000, "price_idr": 500_000}


def token_cost_for(risk_tags: set[str]) -> int:
    """Harga token 1 eksekusi tool — dari risk_tag tool (deterministik)."""
    if "aggressive" in risk_tags or "exploit" in risk_tags:
        return TOKEN_COST["aggressive"]
    if "load" in risk_tags:
        return TOKEN_COST["load"]
    if "external" in risk_tags:
        return TOKEN_COST["external"]
    if "active" in risk_tags:
        return TOKEN_COST["active"]
    return TOKEN_COST["passive"]


def estimate_scan_cost(steps: list, mode: str = "active") -> dict:
    """Estimasi token untuk daftar Step planner (deterministik, tanpa LLM).
    steps: objek dengan .tool dan .risk_tags? — planner Step tidak menyimpan
    risk_tags, jadi pemanggil boleh pass list of (tool, risk_tags) tuple."""
    breakdown: dict[str, int] = {}
    total_raw = 0
    for item in steps:
        tool, tags = item
        c = token_cost_for(set(tags))
        breakdown[tool] = breakdown.get(tool, 0) + c
        total_raw += c
    mult = MODE_MULTIPLIER.get(mode, 1.0)
    total = int(total_raw * mult)
    return {"raw": total_raw, "mode": mode, "multiplier": mult,
            "total_tokens": total, "breakdown": breakdown}


def plan_for(tier: str) -> dict:
    return PLANS.get(tier, PLANS["basic"])


def price_table() -> str:
    lines = ["Cyphron — Harga (IDR), token, & batasan", "",
             f"{'Paket':9} {'Harga/bln':>12} {'Token':>7} {'Target':>7} {'Report':>9} {'Mode':>8}",
             "-" * 60]
    label = {"trial": "TRIAL", "basic": "basic", "pro": "pro",
             "business": "business", "god": "god"}
    for tier, p in PLANS.items():
        lines.append(
            f"{label[tier]:9} Rp{p['price_idr']:>10,} {p['token_limit']:>7} "
            f"{p['targets']:>7} {p['report_mode']:>9} "
            f"{p.get('scans_per_day', '-'):>8}")
    lines.append("")
    lines.append("Top-up: 1.000 token = Rp500.000 (semua tier)")
    lines.append("Mode multiplier: read-only ×1, active ×1.5, offensive ×2")
    lines.append("Token = 1 eksekusi tool: pasif 1, aktif 2, load 3, eksploit 4")
    return "\n".join(lines)
