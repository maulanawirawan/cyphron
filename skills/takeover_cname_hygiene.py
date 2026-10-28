"""[SAFETY: read-only] takeover-cname-hygiene — CNAME dangling hygiene via DoH dns.google (*.azurewebsites.net) — 0 claim, hygiene only"""
from __future__ import annotations
import argparse, json, sys, urllib.request, urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed

def doh(name, rtype="CNAME", timeout=15):
    try:
        url=f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={rtype}"
        req=urllib.request.Request(url, headers={"Accept":"application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"Status": -1, "Comment": "response over 256 KB cap"}
            return json.loads(raw.decode())
    except Exception as e:
        return {"Status": -1, "Comment": str(e)}
def audit(domain, doh_result=None):
    j=doh_result if doh_result is not None else doh(domain, "CNAME")
    status=j.get("Status", -1)
    answers=[a.get("data","") for a in j.get("Answer",[])]
    cname=" ".join(answers).lower() if answers else ""
    markers=["azurewebsites.net","azureedge.net","cloudfront.net","github.io"]
    has_dangling=any(m in cname for m in markers)
    if status==3:
        rows=[make_finding(tool="takeover-cname-hygiene", title=f"CNAME NXDOMAIN hygiene on {domain}: NXDOMAIN", severity="info", description="DoH Status 3 NXDOMAIN — tidak ada CNAME target (hygiene, bukan claim).", target_url=domain, response=json.dumps(j)[:400], evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"read-only"})]
    elif has_dangling:
        rows=[make_finding(tool="takeover-cname-hygiene", title=f"CNAME dangling hygiene on {domain}: {cname[:80]}", severity="low", description=f"CNAME mengandung marker dangling ({cname[:120]}) — hygiene saja, TIDAK di-claim sebagai takeover.", recommendation="Verifikasi kepemilikan CNAME target (asuid TXT / verifikasi cloud) — jangan claim otomatis.", target_url=domain, response=cname[:300], evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"})]
    else:
        rows=[make_finding(tool="takeover-cname-hygiene", title=f"No dangling CNAME hygiene issue on {domain}", severity="info", description="Tidak ada CNAME dangling terdeteksi — AMAN/SURFACE.", target_url=domain, response=cname[:200] or "no cname", evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"})]
    return rows, {"domain":domain, "requests":0, "cname":cname}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] takeover-cname-hygiene")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="takeover_cname_hygiene_findings.json")
    args=ap.parse_args()
    rows,meta=audit(args.domain)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    print(f"takeover-cname-hygiene: {len(rows)} temuan (0 request ke target) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
