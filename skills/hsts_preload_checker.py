"""[SAFETY: read-only] hsts-preload-checker — HSTS preload readiness (preload+includeSubDomains+max-age) — 0 request
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
    val=low.get("strict-transport-security","")
    sval=str(val).strip()
    low_val=sval.lower()
    has_preload="preload" in low_val
    has_sub="includesubdomains" in low_val
    m=re.search(r"max-age\s*=\s*(\d+)", low_val)
    max_age=int(m.group(1)) if m else 0
    ready=has_preload and has_sub and max_age>=10886400
    if ready:
        rows.append(make_finding(tool="hsts-preload-checker", title=f"HSTS preload ready on {url}", severity="info", description=f"HSTS preload valid: {sval[:200]} — AMAN (preload+includeSubDomains+max-age {max_age}).", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"strict-transport-security"}))
    elif sval:
        rows.append(make_finding(tool="hsts-preload-checker", title=f"HSTS preload not ready on {url}", severity="low", description=f"HSTS ada tapi belum preload-ready: {sval[:200]} (need preload+includeSubDomains+max-age>=10886400) — lead.", recommendation="Tambah preload; includeSubDomains; max-age>=31536000 dan submit hstspreload.org", cwe="CWE-319", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"strict-transport-security"}))
        # perluasan konsolidasi (dir_probe legacy: hsts_short_maxage) —
        # HSTS ada TAPI max-age pendek = proteksi downgrade terputus cepat
        if 0 < max_age < 2592000:
            rows.append(make_finding(tool="hsts-preload-checker", title=f"HSTS max-age pendek (<30 hari) on {url}", severity="low", description=f"max-age={max_age}s (<2592000) — proteksi HSTS terputus dalam hitungan hari; downgrade SSL-stripping kembali mungkin setelah kedaluwarsa (lead).", recommendation="Naikkan max-age >= 31536000 (1 tahun) setelah yakin rollout aman.", cwe="CWE-319", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"strict-transport-security","max_age":max_age}))
    else:
        rows.append(make_finding(tool="hsts-preload-checker", title=f"HSTS preload not ready on {url}", severity="low", description="Tidak ada HSTS — preload belum dikonfigurasi (lead).", recommendation="Tambah Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", cwe="CWE-319", target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"strict-transport-security"}))
    return rows, {"url":url, "requests":0, "checked":"strict-transport-security"}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] hsts-preload-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (sibling .headers)")
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="hsts_preload_checker_findings.json")
    args=ap.parse_args()
    headers=_load_headers(args.from_raw, args.headers_file)
    rows,meta=audit(args.url, headers)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"hsts-preload-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
