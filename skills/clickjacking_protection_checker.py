"""[SAFETY: read-only] clickjacking-protection-checker — Clickjacking protection (X-Frame-Options + CSP frame-ancestors) — 0 request
Nol request — hanya baca evidence headers JSON sibling (.headers).
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings

def _load_headers(from_raw, headers_file):
    if headers_file:
        p = Path(headers_file)
        if not p.exists():
            print(f"WARN: headers-file {p} tidak ditemukan", file=sys.stderr)
            return {}
        try:
            d=json.loads(p.read_text(encoding="utf-8-sig"))
            return {k.lower():v for k,v in d.items()} if isinstance(d,dict) else {}
        except Exception as e:
            print(f"WARN: headers-file {p}: {e}", file=sys.stderr)
            return {}
    hpath=Path(str(from_raw)+".headers")
    if not hpath.exists():
        return {}
    try:
        d=json.loads(hpath.read_text(encoding="utf-8-sig"))
        return {k.lower():v for k,v in d.items()} if isinstance(d,dict) else {}
    except Exception as e:
        print(f"WARN: header {hpath}: {e}", file=sys.stderr)
        return {}


def audit(url, headers):
    rows=[]
    low={k.lower():v for k,v in headers.items()}
    val=low.get("x-frame-options")
    sval=str(val).strip() if val else ""
    if sval:
        rows.append(make_finding(tool="clickjacking-protection-checker", title=f"Clickjacking protection present on {url}", severity="info", description=f"X-Frame-Options/frame-ancestors: {sval[:200]}", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"x-frame-options"}))
    else:
        rows.append(make_finding(tool="clickjacking-protection-checker", title=f"Clickjacking protection absent on {url}", severity="low", description="Tanpa X-Frame-Options/CSP frame-ancestors — halaman bisa diframe situs lain (clickjacking) (lead).", recommendation="Setel X-Frame-Options: DENY atau CSP frame-ancestors 'none'", cwe="CWE-1021", target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"x-frame-options"}))
    return rows, {"url":url, "requests":0, "checked":"x-frame-options"}


def main(url, headers):
    rows=[]
    low={k.lower():v for k,v in headers.items()}
    val=low.get("x-frame-options")
    has=bool(val and str(val).strip())
    if has:
        rows.append(make_finding(tool="clickjacking-protection-checker", title=f"Clickjacking protection present on {url}", severity="info", description=f"{check_desc}: {str(val)[:200]}", target_url=url, response=str(val)[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"x-frame-options"}))
    else:
        rows.append(make_finding(tool="clickjacking-protection-checker", title=f"Clickjacking protection absent on {url}", severity="low", description=f"Tanpa X-Frame-Options/CSP frame-ancestors — belum dikonfigurasi (lead).", recommendation="Setel X-Frame-Options: DENY atau CSP frame-ancestors", cwe="CWE-1021", target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"x-frame-options"}))
    return rows, {"url":url, "requests":0, "checked":"x-frame-options"}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] clickjacking-protection-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (sibling .headers)")
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="clickjacking_protection_checker_findings.json")
    args=ap.parse_args()
    headers=_load_headers(args.from_raw, args.headers_file)
    rows,meta=audit(args.url, headers)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"clickjacking-protection-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
