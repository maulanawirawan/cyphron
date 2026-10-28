"""[SAFETY: read-only] mixed-content-detector — Mixed-content http:// in https page — 0 request
Nol request — hanya baca HTML evidence tersimpan.
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings

PAT=re.compile(r"""src="http://""", re.I|re.S)

def audit(url, html):
    rows=[]
    m=PAT.findall(html) if html else []
    if m:
        sample=str(m[:3])[:300]
        rows.append(make_finding(tool="mixed-content-detector", title=f"Mixed-content http found on {url}", severity="low", description=f"Mixed-content http:// in https page — 0 request: {sample} — (lead, 0 request).", recommendation="Periksa konfigurasi.", cwe="CWE-829", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"}))
    else:
        rows.append(make_finding(tool="mixed-content-detector", title=f"No mixed-content on {url}", severity="info", description=f"Tidak ada mixed-content http:// in https page — 0 request di HTML evidence — AMAN observation (0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m)}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] mixed-content-detector")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="mixed_content_detector_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"mixed-content-detector: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
