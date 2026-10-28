"""[SAFETY: read-only] RDAP domain posture — satu query RDAP publik.

Menggantikan WHOIS klasik (yang butuh server per-TLD) dengan RDAP —
standar terbuka tanpa autentikasi. Yang dianalisis: registrar, masa
berlaku domain (kedaluwarsa/<30 hari = lead), status serverTransferProhib
(aman), nameserver.

Pemakaian:
  python skills/rdap_whois.py --domain contoh.go.id --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

UA = user_agent()
RDAP = "https://rdap.org/domain/{domain}"


MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed


def fetch_rdap(domain: str, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(RDAP.format(domain=domain),
                                 headers={"User-Agent": UA,
                                          "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"__error__": (f"response over {MAX_RESPONSE_BYTES}"
                                      "-byte cap — fail-closed")}
            return json.loads(raw.decode())
    except Exception as exc:
        return {"__error__": f"{type(exc).__name__}: {exc}"}


def _events(doc: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate")
            for e in doc.get("events", []) if e.get("eventAction")}


def _parse_ts(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def audit(domain: str, doc: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []

    def finding(title, sev, desc, rec="", category="MISC", verdict=0,
                cwe=None):
        rows.append(make_finding(
            tool="rdap-whois", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe,
            target_url=domain, response=json.dumps(_events(doc))[:300],
            evidence_kind="dns", finding_class="posture", confidence=1.0,
            status="confirmed", verdict=verdict,
            extra={"category": category, "safety_class": "read-only"}))

    if "__error__" in doc:
        rows.append(make_finding(
            tool="rdap-whois", title=f"RDAP unreachable for {domain}",
            severity="info", description=doc["__error__"][:300],
            target_url=domain, evidence_kind="dns",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only"}))
        return rows, {"domain": domain, "error": True}

    events = _events(doc)
    exp_ts = _parse_ts(events.get("expiration"))
    ns = [n.get("ldhName") for n in doc.get("nameservers", [])
          if n.get("ldhName")]

    if exp_ts:
        days = (exp_ts - time.time()) / 86400
        if days < 0:
            finding(f"Domain EXPIRED on {domain} ({-days:.0f} days ago)",
                    "high",
                    "Domain sudah kedaluwarsa — risiko domain diambil "
                    "pihak lain (domain hijacking) dan layanan email/web "
                    "terputus.",
                    rec="Perpanjang domain segera.",
                    category="MISC", verdict=1)
        elif days < 30:
            finding(f"Domain expires in {days:.0f} days on {domain}", "low",
                    "Masa berlaku domain mendekati habis.",
                    rec="Perpanjang dan aktifkan auto-renew.",
                    category="MISC", verdict=1)
        else:
            finding(f"Domain validity OK on {domain} ({days:.0f} days left)",
                    "info", "Masa berlaku domain sehat.",
                    category="AMAN", verdict=0)

    statuses = doc.get("status", [])
    # FP-guard: registry menulis status dengan gaya berbeda —
    # "clientTransferProhibited" (camelCase), "client transfer
    # prohibited" (PIR, spasi), "client_transfer_prohibited" —
    # normalisasi sebelum cocok (temuan FP nyata 2026-10-18: PIR)
    norm = [str(s).lower().replace(" ", "").replace("_", "")
            .replace("-", "") for s in statuses]
    if any("transferprohibited" in t for t in norm):
        finding(f"Domain transfer-locked on {domain}", "info",
                f"Status {statuses} — transfer domain terkunci (perlindungan "
                "baik terhadap pembajakan domain).",
                category="AMAN", verdict=0)
    else:
        finding(f"Domain transfer NOT locked on {domain}", "low",
                "Tidak ada status transferProhibited — transfer domain "
                "lebih mudah bila akun registrar bocor.",
                rec="Aktifkan transfer lock di registrar.",
                category="MISC", verdict=1)

    finding(f"RDAP inventory on {domain}: registrar data + {len(ns)} "
            f"nameservers", "info",
            f"Nameservers: {', '.join(ns[:6]) or '—'}. Data publik RDAP, "
            "nol trafik ke target.",
            category="SURFACE", verdict=0)

    return rows, {"domain": domain, "events": events, "nameservers": ns,
                  "requests": 1}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="rdap_findings.json")
    args = ap.parse_args()
    doc = fetch_rdap(args.domain)
    rows, meta = audit(args.domain, doc)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    print(f"rdap-whois: {len(rows)} temuan -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
