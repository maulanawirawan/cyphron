"""[SAFETY: read-only] http2-support-checker — HTTP/2 support hint dari evidence — 0 request
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
    val=low.get("alt-svc")
    sval=str(val).strip() if val else ""
    if sval:
        rows.append(make_finding(tool="http2-support-checker", title=f"HTTP/2 hint present on {url}", severity="info", description=f"alt-svc hint: {sval[:200]}", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"alt-svc"}))
    else:
        rows.append(make_finding(tool="http2-support-checker", title=f"HTTP/2 hint absent on {url}", severity="info", description="Tidak ada HTTP/2 hint — inventaris permukaan (SURFACE), bukan kerentanan.", target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"SURFACE","safety_class":"read-only","header":"alt-svc"}))
    return rows, {"url":url, "requests":0, "checked":"alt-svc"}


def main(url, headers):
    rows=[]
    low={k.lower():v for k,v in headers.items()}
    val=low.get("alt-svc")
    has=bool(val and str(val).strip())
    if has:
        rows.append(make_finding(tool="http2-support-checker", title=f"HTTP/2 hint present on {url}", severity="info", description=f"{check_desc}: {str(val)[:200]}", target_url=url, response=str(val)[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"alt-svc"}))
    else:
        rows.append(make_finding(tool="http2-support-checker", title=f"HTTP/2 hint absent on {url}", severity="low", description=f"Tidak ada hint HTTP/2 — belum dikonfigurasi (lead).", recommendation="Aktifkan HTTP/2", cwe=None, target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"alt-svc"}))
    return rows, {"url":url, "requests":0, "checked":"alt-svc"}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] http2-support-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (sibling .headers)")
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="http2_support_checker_findings.json")
    args=ap.parse_args()
    headers=_load_headers(args.from_raw, args.headers_file)
    rows,meta=audit(args.url, headers)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"http2-support-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
