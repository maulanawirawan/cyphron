"""[SAFETY: read-only] subdomain-enum-surface — Subdomain enum surface via CT log (read-only, overlap ct_inventory hygiene) — 0 request ke target"""
from __future__ import annotations
import argparse, json, sys, urllib.request, urllib.parse, ssl
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent
UA = user_agent()
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed

def fetch_ct(domain, timeout=20):
    url=f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        req=urllib.request.Request(url, headers={"User-Agent":UA})
        ctx=ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw=r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"__error__": "response over 256 KB cap"}
            j=json.loads(raw.decode())
            names=set()
            for e in j:
                for n in e.get("name_value","").split("\n"):
                    nn=n.strip().lower()
                    if nn.endswith(domain.lower()):
                        names.add(nn)
            return sorted(names)[:50]
    except Exception as e:
        return {"__error__": f"{type(e).__name__}: {e}"}
def audit(domain, data=None):
    names=data if data is not None else fetch_ct(domain)
    if isinstance(names, dict) and "__error__" in names:
        return [make_finding(tool="subdomain-enum-surface", title=f"CT fetch failed for {domain}", severity="info", description=names["__error__"][:300], target_url=domain, evidence_kind="dns", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"})], {"domain":domain, "requests":0}
    elif names:
        return [make_finding(tool="subdomain-enum-surface", title=f"CT surface on {domain}: {len(names)} subdomains", severity="info", description=f"CT mengungkap {len(names)} subdomain (SURFACE): {', '.join(names[:10])}", target_url=domain, response=json.dumps(names[:20])[:400], evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"read-only","count":len(names)})], {"domain":domain, "requests":0}
    else:
        return [make_finding(tool="subdomain-enum-surface", title=f"No CT subdomain surface on {domain}", severity="info", description="Tidak ada subdomain di CT — SURFACE.", target_url=domain, response="no names", evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"read-only"})], {"domain":domain, "requests":0}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] subdomain-enum-surface")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="subdomain_enum_surface_findings.json")
    args=ap.parse_args()
    rows,meta=audit(args.domain)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    print(f"subdomain-enum-surface: {len(rows)} temuan (0 request ke target) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
