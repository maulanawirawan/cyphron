"""[SAFETY: read-only] sri-checker — SRI integrity missing on external script/link (CWE-829) — 0 request
Nol request — hanya baca HTML evidence tersimpan.
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
RE_SCRIPT=re.compile(r'<script[^>]+src="https?://[^"]+"[^>]*>', re.I)
RE_LINK=re.compile(r'<link[^>]+href="https?://[^"]+"[^>]*>', re.I)
def audit(url, html):
    rows=[]
    scripts=RE_SCRIPT.findall(html) if html else []
    unsafe=[s for s in scripts if "integrity=" not in s.lower()]
    # also link rel stylesheet cross-origin
    links=RE_LINK.findall(html) if html else []
    unsafe+= [l for l in links if "integrity=" not in l.lower() and 'rel="stylesheet"' in l.lower()]
    if unsafe:
        sample=str(unsafe[0])[:300]
        rows.append(make_finding(tool="sri-checker", title=f"SRI missing on external resource on {url}", severity="low", description=f"External script/link tanpa integrity: {sample} (lead, CWE-829).", recommendation="Tambah integrity+SRI + crossorigin anonymous untuk resource cross-origin.", cwe="CWE-829", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","count":len(unsafe)}))
    else:
        rows.append(make_finding(tool="sri-checker", title=f"SRI posture OK on {url}", severity="info", description="Tidak ada external script/link tanpa SRI — AMAN.", target_url=url, response=f"scripts {len(scripts)}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "unsafe":len(unsafe) if unsafe else 0}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] sri-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True)
    ap.add_argument("--out", default="sri_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"sri-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
