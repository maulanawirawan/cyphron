"""[SAFETY: read-only] debug-page-detector — Debug page detector (Laravel/WP debug) — 0 request
Nol request — hanya baca HTML evidence tersimpan.
Kanonik keluarga debug: menggabungkan fingerprint APP_DEBUG/Ignition
(dulu laravel-debug-fingerprint) dan error-page/stack-trace
(dulu error-page-fingerprint) sebagai marker tambahan.
"""
from __future__ import annotations
import argparse, json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings

MARKERS = [
    ("laravel-whoops", "Laravel Whoops debug page",
     ["Whoops! There was an error", "handleException", "vendor/laravel"]),
    ("laravel-ignition", "Laravel Ignition error page",
     ["Ignition", "spatie/laravel-ignition"]),
    ("laravel-appdebug", "Laravel APP_DEBUG fingerprint",
     ["APP_DEBUG=true"]),
    ("django-debug", "Django DEBUG page",
     ["Traceback (most recent call last)", "Django Version:"]),
    ("stack-trace", "Raw stack trace in response",
     ["at org.", "at java.", "Stack trace", ".php on line"]),
    ("env-secrets", "Environment/secret exposure",
     ["APP_KEY=", "DB_PASSWORD=", "AWS_SECRET_ACCESS_KEY="]),
]
PAT=re.compile(r"""(DEBUG.*true|Laravel.*debug|Whoops)""", re.I|re.S)

def audit(url, html):
    rows=[]
    hits=[]
    if html:
        low=html.lower()
        for key,label,needles in MARKERS:
            for n in needles:
                idx=low.find(n.lower())
                if idx!=-1:
                    hits.append({"key":key,"label":label,"marker":n,
                                 "context":html[max(0,idx-60):idx+80]})
                    break
    if hits:
        for h in hits:
            sev="high" if h["key"]=="env-secrets" else ("medium" if h["key"] in ("laravel-whoops","laravel-ignition","laravel-appdebug","django-debug") else "low")
            rows.append(make_finding(tool="debug-page-detector", title=f"Debug/verbose page marker on {url}: {h['label']}", severity=sev, description=f"Marker '{h['marker']}' di respons produksi — kelas temuan yang diterima triage lapangan (debug page -> fixing).", recommendation="Matikan debug mode produksi; halaman error generik.", cwe="CWE-489" if h["key"]!="env-secrets" else "CWE-798", target_url=url, response=f"marker: {h['marker']} | ctx: {h['context'][:120]}", evidence_kind="request-response", finding_class="weakness", confidence=0.9, status="confirmed", verdict=3, extra={"category":"DEBUG-EXPOSURE","safety_class":"read-only","marker_key":h["key"]}))
    else:
        rows.append(make_finding(tool="debug-page-detector", title=f"No debug page on {url}", severity="info", description=f"Tidak ada penanda debug di HTML evidence — fail-closed (tanpa marker, tanpa temuan).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(hits), "hits":[h["key"] for h in hits]}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] debug-page-detector")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="debug_page_detector_findings.json")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    print(f"debug-page-detector: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
