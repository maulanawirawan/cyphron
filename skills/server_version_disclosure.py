"""[SAFETY: read-only] server-version-disclosure — Server version disclosure (Server header versi) — 0 request
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
    val=low.get("server","")
    sval=str(val) if val else ""
    has_version=bool(sval and __import__("re").search(r"\/\d+\.\d+|\d+\.\d+\.\d+", sval))
    if has_version:
        rows.append(make_finding(tool="server-version-disclosure", title=f"Version leak via header on {url}: {sval[:80]}", severity="low", description=f"Header membocorkan versi: {sval[:200]} (lead).", recommendation="Sembunyikan versi", cwe="CWE-200", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"server"}))  # FAO family quorum
    else:
        rows.append(make_finding(tool="server-version-disclosure", title=f"No version leak on {url}", severity="info", description="Header tidak membocorkan versi — AMAN.", target_url=url, response=sval[:200] or "no header", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"server"}))  # FAO family quorum
    return rows, {"url":url, "requests":0}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] server-version-disclosure")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True)
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="server_version_disclosure_findings.json")
    args=ap.parse_args()
    headers=_load_headers(args.from_raw, args.headers_file)
    rows,meta=audit(args.url, headers)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"server-version-disclosure: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
