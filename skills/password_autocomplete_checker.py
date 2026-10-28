"""[SAFETY: read-only] password-autocomplete-checker — Password autocomplete off check — 0 request
Nol request — hanya baca HTML evidence tersimpan.
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
RE_PW=re.compile(r'<input[^>]+type="password"[^>]*>', re.I)
def audit(url, html):
    rows=[]
    pws=RE_PW.findall(html) if html else []
    # Nilai autocomplete yang benar untuk password field: current-password
    # (form login — membantu password manager, Fp16), new-password
    # (signup/reset), off. Tanpa atribut / autocomplete=on = lead.
    ok=('autocomplete="off"', 'autocomplete="new-password"',
        'autocomplete="current-password"')
    bad=[p for p in pws if not any(o in p.lower() for o in ok)]
    if bad and pws:
        rows.append(make_finding(tool="password-autocomplete-checker", title=f"Password autocomplete risk on {url}: {len(bad)} field(s)", severity="low", description="Password field tanpa autocomplete=current-password/new-password/off (lead).", recommendation="Setel autocomplete=current-password (login) atau new-password (signup/reset).", cwe="CWE-525", target_url=url, response=bad[0][:300], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"}))
    else:
        rows.append(make_finding(tool="password-autocomplete-checker", title=f"Password autocomplete posture OK on {url}", severity="info", description="Tidak ada password field berisiko atau sudah autocomplete off/new-password — AMAN." if pws else "Tidak ada password field — AMAN.", target_url=url, response=f"pw fields {len(pws)}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0}
def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] password-autocomplete-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True)
    ap.add_argument("--out", default="password_autocomplete_checker_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"password-autocomplete-checker: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
