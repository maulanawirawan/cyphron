r"""[SAFETY: read-only] campaign_correlate — skor korelasi kampanye berbobot
antar-event (pivot infrastruktur/kapabilitas/temporal/viktimologi),
offline.

Lead bukan keputusan: skor tinggi = sinyal untuk review manual, bukan
atribusi. Fail-closed: JSON rusak / bukan daftar / event tanpa id = lead
"event-unparsed" dan event TIDAK ikut skor (tidak pernah dihitung bersih).
Exit: 0 bersih; 1 ada lead >= --fail-on (default high = event-unparsed);
2 error input (file tidak ada).

Pemakaian:
  python tools/campaign_correlate.py --source events.json
  python tools/campaign_correlate.py --source events.json --json hasil.json
  python tools/campaign_correlate.py --source events.json --min-score 45
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "secai.campaign-correlate/1"

W_INFRA = 40
W_CAP = 35
W_TEMP = 15
W_VICT = 10
HIGH = 70
MEDIUM = 45
GUARD_SHARED = 0.25   # infra privat/CDN -> bobot dipangkas
GUARD_TEMPORAL_ONLY = 0.5

# rentang bawaan: konservatif, hanya CDN/hosting besar yang jelas bersama
DEFAULT_CDN_NETS = [
    "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22",        # Cloudflare
    "23.235.32.0/20", "151.101.0.0/16", "199.232.0.0/16",     # Fastly
    "185.199.108.0/22",                                        # GitHub Pages
]

# privat = RFC1918 + loopback + link-local + CGNAT + multicast + reserved,
# eksplisit (bukan is_private bawaan ipaddress — semantiknya berubah antar
# versi Python terkait rentang dokumentasi).
PRIVATE_NETS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",  # loopback/LL/CGNAT
    "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",         # this-net/mcast/res
    "fe80::/10", "::1/128", "fc00::/7",                # IPv6 LL/loopback/ULA
]
_PRIVATE_NETS = [ipaddress.ip_network(s) for s in PRIVATE_NETS]

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
SEV_HIGH = "high"


def _parse_time(raw: Any) -> datetime | None:
    """ISO-8601 (Z atau offset) -> datetime aware UTC; None jika tak valid."""
    if not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _as_str_list(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [x.strip().lower() for x in v if isinstance(x, str) and x.strip()]


def load_events(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Parse event JSON -> (event valid, lead unparsed). Fail-closed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON tidak bisa dibaca: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError("root JSON harus berupa daftar event")
    events: list[dict[str, Any]] = []
    leads: list[dict[str, str]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) \
                or not item["id"].strip():
            leads.append({"check": "event-unparsed", "severity": SEV_HIGH,
                          "message": f"event[{i}] tanpa id string — dilewati"})
            continue
        ev_id = item["id"].strip()
        t0 = _parse_time(item.get("time"))
        if t0 is None:
            leads.append({"check": "event-unparsed", "severity": SEV_HIGH,
                          "message": f"event {ev_id}: time tidak valid/absen — dilewati"})
            continue
        dur_raw = item.get("window_hours", 0)
        try:
            dur = max(0.0, float(dur_raw))
        except (TypeError, ValueError):
            dur = 0.0
        events.append({
            "id": ev_id,
            "t0": t0,
            "dur": dur,
            "ips": _as_str_list(item.get("ips")),
            "domains": _as_str_list(item.get("domains")),
            "hashes": _as_str_list(item.get("hashes")),
            "ttps": [x.upper() for x in _as_str_list(item.get("ttps"))],
            "sector": str(item.get("sector", "")).strip().lower(),
            "geography": str(item.get("geography", "")).strip().lower(),
        })
    return events, leads


def _ip_flags(ip: str, cdn_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> tuple[bool, bool]:
    """(privat, cdn-shared) untuk string IP; salah keduanya jika tak valid."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (False, False)
    priv = any(addr in n for n in _PRIVATE_NETS if n.version == addr.version)
    shared = any(addr in n for n in cdn_nets if n.version == addr.version)
    return (priv, shared)


def _overlap_ratio(a: set[str], b: set[str]) -> float:
    union = a | b
    return (len(a & b) / len(union)) if union else 0.0


def correlate(events: list[dict[str, Any]], cdn_nets: list) -> list[dict[str, Any]]:
    """Skor korelasi semua pasangan event valid."""
    pairs: list[dict[str, Any]] = []
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a, b = events[i], events[j]
            reasons: list[str] = []

            # --- infrastruktur (IP + domain) ---
            infra_a = set(a["ips"]) | set(a["domains"])
            infra_b = set(b["ips"]) | set(b["domains"])
            shared_infra = sorted(infra_a & infra_b)
            infra_ratio = _overlap_ratio(infra_a, infra_b)
            if shared_infra:
                for item in shared_infra:
                    priv, shared = _ip_flags(item, cdn_nets)
                    if priv:
                        infra_ratio *= GUARD_SHARED
                        reasons.append(f"{item}: IP privat — infra dibagi internal, pivot lemah")
                    elif shared:
                        infra_ratio *= GUARD_SHARED
                        reasons.append(f"{item}: rentang CDN/hosting bersama — pivot lemah")
            infra_score = infra_ratio * W_INFRA

            # --- kapabilitas (hash + TTP) ---
            cap_a = set(a["hashes"]) | set(a["ttps"])
            cap_b = set(b["hashes"]) | set(b["ttps"])
            shared_cap = sorted(cap_a & cap_b)
            cap_score = _overlap_ratio(cap_a, cap_b) * W_CAP
            if shared_cap:
                reasons.append(f"kapabilitas sama: {', '.join(shared_cap[:4])}"
                               + (" ..." if len(shared_cap) > 4 else ""))

            # --- temporal ---
            gap_h = abs((a["t0"] - b["t0"]).total_seconds()) / 3600.0
            window = max(a["dur"], b["dur"])
            eff_gap = max(0.0, gap_h - window)
            if eff_gap <= 24:
                temp_ratio = 1.0
            elif eff_gap <= 168:      # <= 1 minggu
                temp_ratio = 0.5
            elif eff_gap <= 720:      # <= 30 hari
                temp_ratio = 0.25
            else:
                temp_ratio = 0.0
            temporal_only = (not shared_infra and not shared_cap
                             and not (a["sector"] and a["sector"] == b["sector"]))
            if temporal_only and temp_ratio > 0:
                temp_ratio *= GUARD_TEMPORAL_ONLY
                reasons.append("hanya temporal — infra bisa didaur ulang aktor lain")
            temp_score = temp_ratio * W_TEMP
            if temp_ratio > 0:
                reasons.append(f"temporal: gap efektif {eff_gap:.0f} jam")

            # --- viktimologi ---
            vict_score = W_VICT if (a["sector"] and a["sector"] == b["sector"]) else 0.0
            if vict_score:
                reasons.append(f"sektor sama: {a['sector']}")
            if a["geography"] and a["geography"] == b["geography"]:
                reasons.append(f"geografi sama: {a['geography']}")

            total = round(infra_score + cap_score + temp_score + vict_score, 1)
            verdict = "HIGH" if total >= HIGH else ("MEDIUM" if total >= MEDIUM else "LOW")
            pairs.append({
                "a": a["id"],
                "b": b["id"],
                "score": total,
                "verdict": verdict,
                "pivots": {
                    "infra": round(infra_score, 1),
                    "capability": round(cap_score, 1),
                    "temporal": round(temp_score, 1),
                    "victimology": round(vict_score, 1),
                },
                "shared_infra": shared_infra,
                "shared_capability": shared_cap,
                "reasons": reasons,
            })
    pairs.sort(key=lambda p: p["score"], reverse=True)
    return pairs


def _load_cdn(extra: Path | None) -> list:
    nets: list = []
    for spec in DEFAULT_CDN_NETS:
        nets.append(ipaddress.ip_network(spec))
    if extra:
        for line in extra.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line))
            except ValueError as exc:
                raise ValueError(f"CDN file: CIDR tidak valid {line!r}: {exc}") from exc
    return nets


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="campaign_correlate — skor korelasi kampanye antar-event "
                    "(read-only, nol jaringan; #0360)")
    ap.add_argument("--source", required=True, help="file JSON daftar event")
    ap.add_argument("--json", dest="json_out", help="tulis hasil JSON ke file")
    ap.add_argument("--cdn-file", help="tambahan rentang CIDR host bersama, per baris")
    ap.add_argument("--min-score", type=float, default=0.0,
                    help="hanya tampilkan pasangan dengan skor >= nilai ini")
    args = ap.parse_args(argv)

    src = Path(args.source)
    if not src.is_file():
        print(f"ERROR sumber tidak ada: {src}", file=sys.stderr)
        return 2
    try:
        events, leads = load_events(src)
        cdn_nets = _load_cdn(Path(args.cdn_file) if args.cdn_file else None)
    except ValueError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2

    pairs = correlate(events, cdn_nets)
    shown = [p for p in pairs if p["score"] >= args.min_score]
    result = {
        "schema": SCHEMA,
        "source": str(src),
        "summary": {
            "events": len(events),
            "skipped": len(leads),
            "pairs": len(shown),
            "high": sum(1 for p in shown if p["verdict"] == "HIGH"),
            "medium": sum(1 for p in shown if p["verdict"] == "MEDIUM"),
            "low": sum(1 for p in shown if p["verdict"] == "LOW"),
        },
        "leads": leads,
        "pairs": shown,
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(text, encoding="utf-8")
    else:
        print(text)
    if leads:  # event-unparsed = high -> selalu gagal saat ada
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
