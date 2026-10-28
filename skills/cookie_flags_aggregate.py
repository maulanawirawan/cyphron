"""[SAFETY: read-only] cookie-flags-aggregate — Cookie flags aggregate Secure/HttpOnly/SameSite — 0 request
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


def _parse_cookies(sval: str) -> list[dict]:
    """Satu header Set-Cookie bisa berisi beberapa cookie dipisah koma
    (batas koma di dalam Expires dijaga). Cukup untuk audit prefix."""
    cookies: list[dict] = []
    chunks, cur = [], ""
    for part in sval.split(","):
        cur = (cur + "," + part) if cur and "=" not in part.split(";")[0] \
            else part
        if "=" in cur.split(";")[0]:
            chunks.append(cur.strip())
            cur = ""
    if cur.strip():
        chunks.append(cur.strip())
    for c in chunks:
        kv = c.split(";", 1)
        name = kv[0].partition("=")[0].strip()
        attrs = {}
        for a in (kv[1].split(";") if len(kv) > 1 else []):
            k, _, v = a.strip().partition("=")
            attrs[k.lower()] = v.strip() if v else ""
        if name:
            cookies.append({"name": name, "attrs": attrs})
    return cookies


def audit(url, headers):
    rows=[]
    low={k.lower():v for k,v in headers.items()}
    val=low.get("set-cookie")
    sval=str(val).strip() if val else ""
    if not sval:
        rows.append(make_finding(tool="cookie-flags-aggregate", title=f"No Set-Cookie on {url}", severity="info", description="Tidak ada cookie di evidence — tidak ada yang perlu dilindungi (AMAN, bukan lead).", target_url=url, response=f"headers present: {sorted(low.keys())}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"set-cookie"}))
    else:
        lowv=sval.lower()
        missing=[f for f in ("secure","httponly","samesite") if f not in lowv]
        if missing:
            rows.append(make_finding(tool="cookie-flags-aggregate", title=f"Cookie flags missing on {url}: {','.join(missing)}", severity="low", description=f"Set-Cookie tanpa flag: {','.join(missing)} — cookie bisa bocor via plaintext/JS (lead).", recommendation="Setel Secure; HttpOnly; SameSite=Lax", cwe="CWE-614", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"set-cookie","missing":missing}))
        else:
            rows.append(make_finding(tool="cookie-flags-aggregate", title=f"Cookie flags OK on {url}", severity="info", description=f"Set-Cookie membawa Secure/HttpOnly/SameSite: {sval[:200]}", target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only","header":"set-cookie"}))
        # perluasan konsolidasi (dir_probe legacy: cookie_prefix_insecure) —
        # prefix __Host-/__Secure- punya syarat ketat RFC 6265bis; pelanggaran
        # = prefix jadi hiasan (perlindungan tidak efektif)
        for c in _parse_cookies(sval):
            name = c["name"]
            attrs = c["attrs"]
            viol: list[str] = []
            if name.startswith("__Host-"):
                if "secure" not in {k.lower() for k in attrs}:
                    viol.append("Secure hilang")
                if any(k.lower() == "domain" for k in attrs):
                    viol.append("Domain diset (prefix __Host- melarang)")
                if attrs.get("path", "/") != "/":
                    viol.append(f"Path={attrs.get('path') or '(kosong)'} bukan /")
                cwe = "CWE-1004"
            elif name.startswith("__Secure-"):
                if "secure" not in {k.lower() for k in attrs}:
                    viol.append("Secure hilang")
                cwe = "CWE-614"
            if viol:
                rows.append(make_finding(tool="cookie-flags-aggregate", title=f"Cookie prefix {name.split('-')[0]} dilanggar on {url}: {name}", severity="low", description=f"Prefix '{name.split('-')[0]}-' dipakai tanpa memenuhi syaratnya: {'; '.join(viol)} — browser memperlakukan prefix hanya bila syarat terpenuhi, jadi perlindungannya tidak efektif (lead).", recommendation=f"Untuk __Host-: Secure + tanpa atribut Domain + Path=/; untuk __Secure-: wajib Secure.", cwe=cwe, target_url=url, response=sval[:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","header":"set-cookie","cookie":name,"violations":viol}))
    return rows, {"url":url, "requests":0, "checked":"set-cookie"}


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] cookie-flags-aggregate")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (sibling .headers)")
    ap.add_argument("--headers-file", default=None)
    ap.add_argument("--out", default="cookie_flags_aggregate_findings.json")
    args=ap.parse_args()
    headers=_load_headers(args.from_raw, args.headers_file)
    rows,meta=audit(args.url, headers)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"cookie-flags-aggregate: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
