"""[SAFETY: read-only] Certificate Transparency subdomain inventory.

Skill v2 (produk Cyphron). Membaca CT log via API publik SSLMate Cert
Spotter (fallback terbukti lapangan; crt.sh sering 502). Murni data
sertifikat publik — NOL trafik ke target. Hasil: inventaris nama dari
sertifikat yang menerbitkan untuk domain (permukaan aset), plus temuan
nama yang menarik perhatian (kata kunci admin/test/staging/poc) sebagai
LEAD L1 — bukan klaim kerentanan.

Pemakaian:
  python skills/ct_inventory.py --domain example.go.id \
      --out findings/tier0-contoh/ct_inventory.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

CT_API = ("https://api.certspotter.com/v1/issuances?domain={domain}"
          "&include_subdomains=true&expand=dns_names")
UA = user_agent()

INTERESTING = ("admin", "test", "stage", "staging", "dev", "poc", "uat",
               "beta", "internal", "vpn", "mail", "remote", "portal",
               "backup", "old", "legacy", "panel", "cpanel", "console")


MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed


def fetch_ct(domain: str, timeout: float = 60.0):
    url = CT_API.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return None, (f"response over {MAX_RESPONSE_BYTES}-byte cap "
                              "— fail-closed")
            data = json.loads(raw.decode())
        return data, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def audit(domain: str) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    data, err = fetch_ct(domain)
    if err is not None:
        rows.append(make_finding(
            tool="ct-inventory", title=f"CT source unreachable for {domain}",
            severity="info", description=f"certspotter error: {err[:200]}",
            target_url=domain, evidence_kind="dns", finding_class="posture",
            status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only"}))
        return rows, {"domain": domain, "error": err}

    names = sorted({n.lstrip("*.").lower() for iss in data
                    for n in iss.get("dns_names", [])})
    own = [n for n in names if n.endswith(f".{domain}") or n == domain]
    interesting = [n for n in own if any(
        f".{k}." in f".{n}." or n.startswith(f"{k}.")
        for k in INTERESTING)]

    rows.append(make_finding(
        tool="ct-inventory",
        title=f"CT inventory on {domain}: {len(own)} unique hostnames "
              f"({len(data)} issuances)", severity="info",
        description="Inventaris permukaan dari sertifikat publik "
                    "(Certificate Transparency) — NOL trafik ke target. "
                    "Daftar nama tersimpan sebagai bukti di data laporan.",
        target_url=domain, response=json.dumps(own[:50])[:300],
        evidence_kind="dns", finding_class="posture", confidence=1.0,
        status="confirmed", verdict=0,
        extra={"category": "SURFACE", "safety_class": "read-only",
               "hostnames": own}))
    for n in interesting:
        rows.append(make_finding(
            tool="ct-inventory",
            title=f"Interesting CT hostname on {domain}: {n}",
            severity="info",
            description="Nama host dari CT log dengan kata kunci yang "
                        "biasanya menandai lingkungan non-produksi/"
                        "administratif — LEAD untuk verifikasi manual "
                        "berotorisasi, bukan kerentanan.",
            target_url=domain, evidence_kind="dns", finding_class="posture",
            status="unconfirmed", verdict=1,
            extra={"category": "SURFACE", "safety_class": "read-only"}))
    return rows, {"domain": domain, "issuances": len(data),
                  "hostnames": own, "requests": 1}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="ct_findings.json")
    ap.add_argument("--save-names", default=None,
                    help="path opsional untuk daftar hostname (json)")
    args = ap.parse_args()
    rows, meta = audit(args.domain)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    if args.save_names and meta.get("hostnames"):
        p = Path(args.save_names)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(meta["hostnames"], indent=2), encoding="utf-8")
    print(f"ct-inventory: {len(rows)} temuan -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
