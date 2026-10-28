"""[SAFETY: 1-request] wayback-history — Wayback CDX history via web.archive.org — hygiene (SURFACE) — 1 request ke archive.org, 0 ke target"""
from __future__ import annotations
import argparse, json, sys, urllib.request, urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402
UA=user_agent()
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed

def fetch_cdx(domain, timeout=20):
    url=f"https://web.archive.org/cdx/search/xd?url={urllib.parse.quote(domain)}/*&output=json&fl=timestamp,original,mimetype,statuscode&collapse=urlkey&limit=5"
    try:
        req=urllib.request.Request(url, headers={"User-Agent":UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return {"__error__": "response over 256 KB cap"}
            return json.loads(raw.decode())
    except Exception as e:
        return {"__error__": f"{type(e).__name__}: {e}"}
def audit(domain, data):
    rows=[]
    if isinstance(data, dict) and "__error__" in data:
        rows.append(make_finding(tool="wayback-history", title=f"Wayback fetch failed for {domain}", severity="info", description=data["__error__"][:300], target_url=domain, evidence_kind="dns", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
    elif isinstance(data, list) and len(data)>1:
        count=len(data)-1
        sample=str(data[1])[:300]
        rows.append(make_finding(tool="wayback-history", title=f"Wayback history exists for {domain}: {count} snapshot(s)", severity="info", description=f"Wayback memiliki {count} snapshot (SURFACE, hygiene). Sample: {sample}", target_url=domain, response=json.dumps(data[:3])[:400], evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"1-request","count":count}))
    else:
        rows.append(make_finding(tool="wayback-history", title=f"No Wayback history for {domain}", severity="info", description="Tidak ada snapshot Wayback — SURFACE observation.", target_url=domain, response="no snapshot", evidence_kind="dns", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"1-request"}))
    return rows, {"domain":domain, "requests":1}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: 1-request] wayback-history")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="wayback_history_findings.json")
    args=ap.parse_args()
    data=fetch_cdx(args.domain)
    rows,meta=audit(args.domain, data)
    meta["safety_class"]="1-request"
    write_findings(args.out, rows, meta)
    print(f"wayback-history: {len(rows)} temuan (1 request ke archive.org) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
