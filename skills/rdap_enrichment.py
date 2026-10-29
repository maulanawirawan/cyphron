"""[SAFETY: read-only] rdap-enrichment — postur domain + deteksi perubahan
antar-run (drift). NOL request tambahan selain satu query RDAP publik.

Eskalasi 2026-10 (keputusan operator: default rekomendasi desain
DESIGN-RDAP-RDRS-CTI.md §3 diterapkan — rdap-enrichment duluan, seed
dari watchlist, tanpa vendor CTI, polling mengikuti nightrun harian,
hasil masuk export OSS).

Lapisan di atas rdap_whois.py: selain postur sesaat (registrar, expiry,
transfer lock, NS), skill ini menyimpan SNAPSHOT per domain di
findings/night-run/state/rdap/<domain>.json dan membandingkan dengan run
sebelumnya. Perubahan yang dilaporkan (maks L1 — fakta, bukan klaim jahat):
  - registrar berganti
  - nameserver berubah (daftar lama -> baru)
  - status baru: clientHold/serverHold (pembekuan/sengketa)
  - expiry mendekat (< 30 hari)
Zero-FP: semua temuan = perbandingan fakta snapshot; tanpa snapshot lama
= baseline saja (bukan temuan drift).

Pemakaian (via orchestrator: needs=domain):
  python skills/rdap_enrichment.py --domain contoh.id --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "skills"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
RDAP = "https://rdap.org/domain/{domain}"
STATE_DIR = ROOT / "findings" / "night-run" / "state" / "rdap"
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed
EXPIRY_WARN_DAYS = 30


def fetch_rdap(domain: str, timeout: float = 30.0) -> dict:
    import urllib.request
    req = urllib.request.Request(RDAP.format(domain=domain),
                                 headers={"User-Agent": UA,
                                          "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"__error__": (f"respons melewati cap "
                                      f"{MAX_RESPONSE_BYTES}B — fail-closed")}
            return json.loads(raw.decode())
    except Exception as exc:  # noqa: BLE001
        return {"__error__": f"{type(exc).__name__}: {exc}"}


def _events(doc: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate")
            for e in doc.get("events", []) if e.get("eventAction")}


def _entities(doc: dict) -> list[dict]:
    return doc.get("entities", []) or []


def _registrar(doc: dict) -> str:
    for ent in _entities(doc):
        roles = ent.get("roles", []) or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray", []) or []
            for item in (vcard[1] if len(vcard) > 1 else []):
                if item and item[0] == "fn" and len(item) > 3:
                    return str(item[3])
            return ent.get("handle", "?")
    return ""


def _nameservers(doc: dict) -> list[str]:
    ns = doc.get("nameservers", []) or []
    return sorted(str(n.get("ldhName", "")).lower() for n in ns if n.get("ldhName"))


def _statuses(doc: dict) -> list[str]:
    return sorted(str(s) for s in (doc.get("status", []) or []))


def _expiry_days(doc: dict) -> int | None:
    exp = _events(doc).get("expiration")
    if not exp:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        return (dt - datetime.now(timezone.utc)).days
    except ValueError:
        return None


def snapshot_of(doc: dict) -> dict:
    return {
        "registrar": _registrar(doc),
        "nameservers": _nameservers(doc),
        "statuses": _statuses(doc),
        "expiration": _events(doc).get("expiration"),
        "taken_at": time.time(),
    }


def load_state(domain: str) -> dict | None:
    p = STATE_DIR / f"{domain}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None  # state rusak = anggap baseline baru (bukan klaim)


def save_state(domain: str, snap: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / f"{domain}.json").write_text(
        json.dumps(snap, indent=2, ensure_ascii=False), encoding="utf-8")


def drift_findings(domain: str, old: dict | None, snap: dict,
                   target_url: str) -> list[dict]:
    rows: list[dict] = []
    if not old:
        return rows

    def f(title, desc, evidence):
        rows.append(make_finding(
            tool="rdap-enrichment", title=title, severity="info",
            description=desc, recommendation="",
            target_url=target_url, evidence_kind="file-manifest",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0,  # fakta perubahan = OBSERVED, bukan klaim kerentanan
            response=json.dumps(evidence, ensure_ascii=False)[:400],
            lab_only=False,
            extra={"category": "DOMAIN-POSTURE", "safety_class": "read-only",
                   "requests": 1, "drift": True},
        ))

    if old.get("registrar") and snap["registrar"] \
            and old["registrar"] != snap["registrar"]:
        f(f"Registrar {domain} berganti: {old['registrar']} -> {snap['registrar']}",
          "Perubahan registrar terdeteksi antar-run. Umumnya administratif "
          "(transfer), namun berganti ke registrar berisiko tinggi layak "
          "diperiksa (pengambilalihan domain).",
          {"from": old["registrar"], "to": snap["registrar"]})

    old_ns, new_ns = old.get("nameservers") or [], snap["nameservers"]
    if old_ns and new_ns and old_ns != new_ns:
        f(f"Nameserver {domain} berubah: {len(old_ns)} -> {len(new_ns)} entri",
          "Pergantian nameserver mengubah arah seluruh layanan domain — pola "
          "yang juga dipakai saat pembajakan DNS. Cocokkan dengan rencana "
          "perubahan yang diketahui.",
          {"from": old_ns, "to": new_ns})

    old_st, new_st = set(old.get("statuses") or []), set(snap["statuses"])
    held = new_st - old_st
    for s in sorted(held):
        if "hold" in s.lower():
            f(f"Status {s} muncul pada {domain}",
              "Status hold (clientHold/serverHold) menandakan domain dibekukan "
              "registry/registrar — indikasi sengketa, penipuan, atau penonaktifan.",
              {"added": s})

    days = _expiry_days({"events": [{"eventAction": "expiration",
                                     "eventDate": snap.get("expiration")}]})
    if days is not None and days <= EXPIRY_WARN_DAYS:
        f(f"Domain {domain} kedaluwarsa dalam {days} hari",
          f"Masa berlaku berakhir {snap.get('expiration')} (< "
          f"{EXPIRY_WARN_DAYS} hari) — risiko drop catch.",
          {"expiration": snap.get("expiration"), "days_left": days})
    return rows


def audit(domain: str) -> tuple[list[dict], dict]:
    doc = fetch_rdap(domain)
    if "__error__" in doc:
        return [], {"ok": False, "error": doc["__error__"],
                    "domain": domain, "requests": 1,
                    "safety_class": "read-only"}
    snap = snapshot_of(doc)
    old = load_state(domain)
    target_url = f"rdap:{domain}"
    rows: list[dict] = []

    # postur saat ini (L0 — inventaris, selalu)
    if snap["registrar"]:
        rows.append(make_finding(
            tool="rdap-enrichment",
            title=f"Postur domain {domain}: registrar {snap['registrar']}",
            severity="info",
            description="Inventaris registrasi saat ini (snapshot RDAP publik).",
            target_url=target_url, evidence_kind="file-manifest",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=0, lab_only=False,
            extra={"category": "DOMAIN-POSTURE", "safety_class": "read-only",
                   "requests": 1, "snapshot": snap}))
    rows.extend(drift_findings(domain, old, snap, target_url))
    save_state(domain, snap)
    meta = {"ok": True, "domain": domain, "requests": 1,
            "safety_class": "read-only",
            "baseline": old is None,
            "drift_findings": sum(1 for r in rows if r["extra"].get("drift")),
            "snapshot": snap}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, meta = audit(args.domain)
    if not meta.get("ok"):
        print(f"GAGAL: {meta.get('error')} (fail-closed, "
              "bukan klaim bersih)", file=sys.stderr)
        return 1
    write_findings(args.out, rows, meta)
    print(f"rdap-enrichment: {args.domain} — {len(rows)} temuan "
          f"(baseline={meta['baseline']}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
