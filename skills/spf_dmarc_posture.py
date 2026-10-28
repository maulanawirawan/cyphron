"""[SAFETY: read-only] spf-dmarc-posture — postur anti-spoofing email
domain via DNS TXT pasif (postur konfigurasi): dua query baca
  - TXT apex      -> record "v=spf1" (siapa yang boleh mengirim)
  - TXT _dmarc.*  -> record "v=DMARC1" (kebijakan atas spoofing)
Temuan = FAKTUAL dari isi record (SPF hilang / DMARC hilang / DMARC
p=none = monitoring-only), verdict maksimum L1 lead — bukan klaim
reportable. Kegagalan DNS = baris unconfirmed (tanpa klaim).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
import dns_light  # noqa: E402

_P_TAG = re.compile(r"\bp=([a-z]+)\b", re.IGNORECASE)


def probe(domain: str, resolver: str = dns_light.DEFAULT_RESOLVER,
          timeout: float = 5.0) -> dict:
    out: dict = {"txt": None, "dmarc_txt": None, "error": None}
    try:
        out["txt"] = dns_light.txt_lookup(resolver, domain, timeout)
        out["dmarc_txt"] = dns_light.txt_lookup(
            resolver, f"_dmarc.{domain}", timeout)
    except Exception as exc:  # pragma: no cover - dns_light sudah menelan
        out["error"] = f"{type(exc).__name__}"
    if out["txt"] is None or out["dmarc_txt"] is None:
        out["error"] = out["error"] or "dns-gagal"
    return out


def _lead_row(domain: str, title: str, desc: str,
              rec: str) -> dict:
    return make_finding(
        tool="spf-dmarc-posture", title=title, severity="low",
        description=desc, recommendation=rec, cwe=None,
        target_url=f"dns:{domain}",
        evidence_kind="request-response", finding_class="weakness",
        confidence=1.0, status="confirmed", verdict=1,
        extra={"category": "EMAIL-POSTURE",
               "safety_class": "read-only", "domain": domain})


def audit(domain: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    if result.get("error"):
        rows.append(make_finding(
            tool="spf-dmarc-posture",
            title=f"SPF/DMARC posture on {domain} — tidak dapat dinilai",
            severity="info",
            description=f"Query DNS gagal ({result['error']}) — postur "
                        "email tidak dinilai (tanpa klaim, fail-closed).",
            target_url=f"dns:{domain}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "error": result["error"]}))
        return rows, {"domain": domain, "error": True}

    txts = [s for s in (result.get("txt") or []) if isinstance(s, str)]
    dmarc_txts = [s for s in (result.get("dmarc_txt") or [])
                  if isinstance(s, str)]
    spf = next((s for s in txts if s.lower().startswith("v=spf1")), None)
    dmarc = next((s for s in dmarc_txts
                  if s.lower().startswith("v=dmarc1")), None)

    if spf is None:
        rows.append(_lead_row(domain,
            f"SPF absent on {domain}",
            "Tidak ada record 'v=spf1' pada apex domain — server email "
            "penerima tidak punya panduan resmi tentang pengirim sah, "
            "mempermudah spoofing alamat domain (faktual: TXT apex tanpa "
            "record SPF).",
            "Terbitkan record SPF yang mencantumkan pengirim sah + "
            "-all/all pada akhirnya."))
    if dmarc is None:
        rows.append(_lead_row(domain,
            f"DMARC absent on {domain}",
            "Tidak ada record 'v=DMARC1' pada _dmarc.<domain> — kebijakan "
            "penanganan spoofing tidak dideklarasikan (faktual: TXT "
            "_dmarc tanpa record DMARC).",
            "Terbitkan record DMARC (mulai p=quarantine/p=reject setelah "
            "monitoring rua)."))
    elif dmarc is not None:
        m = _P_TAG.search(dmarc)
        if m and m.group(1).lower() == "none":
            rows.append(_lead_row(domain,
                f"DMARC p=none on {domain}",
                "Record DMARC ada tapi kebijakan p=none (monitoring-only) "
                "— spoofing tidak ditolak maupun dikarantina (faktual dari "
                "isi record).",
                "Naikkan ke p=quarantine lalu p=reject setelah analisis "
                "laporan rua."))

    if not rows:
        rows.append(make_finding(
            tool="spf-dmarc-posture",
            title=f"SPF/DMARC posture on {domain}",
            severity="info",
            description="SPF ada dan DMARC ada dengan kebijakan penolakan "
                        "(bukan p=none) — postur anti-spoofing dasar "
                        "terpasang (AMAN/inventaris).",
            target_url=f"dns:{domain}",
            response=(f"spf={spf[:120]}\ndmarc={dmarc[:120]}"),
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only"}))
    return rows, {"domain": domain, "spf": bool(spf),
                  "dmarc": bool(dmarc), "requests": 2}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="spf_dmarc_findings.json")
    ap.add_argument("--resolver", default=dns_light.DEFAULT_RESOLVER)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()
    result = probe(args.domain, args.resolver, args.timeout)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    print(f"spf-dmarc-posture: {len(rows)} baris -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
