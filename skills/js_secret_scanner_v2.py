"""[SAFETY: read-only] js-secret-scanner-v2 — Secret scanner (kanonik keluarga secret) — 0 request
Nol request — hanya baca HTML evidence tersimpan.
Kanonik keluarga secret: pola JS api-key/secret/token + sub-check
komentar HTML berisi password/secret/api-key/TODO (dulu
html-comment-secret-scanner).
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings

PAT=re.compile(r"""(api[_-]?key|secret|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']""", re.I|re.S)
# Sub-check dari konsolidasi: komentar HTML yang menyebut kredensial/TODO
HTML_COMMENT_PAT=re.compile(r"""<!--[^>]*?(password|secret|api[_-]?key|TODO)[^>]*?-->""", re.I|re.S)

def audit(url, html):
    rows=[]
    m=PAT.findall(html) if html else []
    c=HTML_COMMENT_PAT.findall(html) if html else []
    if m:
        sample=str(m[:3])[:300]
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"JS secret-like found on {url}", severity="low", description=f"JS secret-like (apiKey/token) di evidence — 0 request: {sample} — (lead, 0 request).", recommendation="Periksa konfigurasi.", cwe="CWE-798", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only"}))
    if c:
        sample=str(c[:3])[:300]
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"HTML comment secret-like found on {url}", severity="low", description=f"Komentar HTML berisi password/secret/api-key/TODO — 0 request: {sample} — (lead, 0 request).", recommendation="Hapus komentar berisi kredensial/TODO dari markup produksi.", cwe="CWE-798", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","source":"html-comment"}))
    if not m and not c:
        rows.append(make_finding(tool="js-secret-scanner-v2", title=f"No secret-like on {url}", severity="info", description=f"Tidak ada secret-like (JS api-key/token, komentar HTML) di HTML evidence — fail-closed: tanpa marker, tanpa temuan (AMAN observation, 0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m or c)}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] js-secret-scanner-v2")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="js_secret_scanner_v2_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"js-secret-scanner-v2: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
