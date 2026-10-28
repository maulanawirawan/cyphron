"""[SAFETY: read-only] form-csrf-checker — Form CSRF token presence — 0 request
Nol request — hanya baca HTML evidence tersimpan.
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
RE_FORM=re.compile(r"<form[^>]*>", re.I)
RE_CSRF=re.compile(r'csrf|_token|authenticity_token', re.I)
def audit(url, html):
    rows=[]
    forms=RE_FORM.findall(html) if html else []
    if not forms:
        rows.append(make_finding(tool="form-csrf-checker", title=f"No form on {url}", severity="info", description="Tidak ada <form> — tidak relevan.", target_url=url, response="no form", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    else:
        has=bool(RE_CSRF.search(html or ""))
        if has:
            rows.append(make_finding(tool="form-csrf-checker", title=f"CSRF guard present on {url}", severity="info", description="Form mengandung token CSRF — AMAN.", target_url=url, response=f"forms {len(forms)}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
        else:
            rows.append(make_finding(tool="form-csrf-checker", title=f"Form without CSRF token on {url}", severity="low", description="Form tanpa token CSRF terdeteksi (lead).", recommendation="Tambah CSRF token per form.", cwe="CWE-352", target_url=url, response=f"forms {len(forms)}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] form-csrf-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True)
    ap.add_argument("--out", default="form_csrf_checker_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"form-csrf-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
