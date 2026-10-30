"""[SAFETY: 1-request] robots-txt-surface — robots.txt disclosure surface — 1 GET
TEPAT 1 GET (setara kunjungan browser) — fail-closed.
"""
from __future__ import annotations
import argparse, json, sys, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402
UA=user_agent()

def fetch(url, timeout=20):
    try:
        req=urllib.request.Request(url, headers={"User-Agent":UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body=r.read(8192).decode(errors="replace")
            return {"status":r.status, "headers":{k.lower():v for k,v in r.headers.items()}, "body":body}
    except urllib.error.HTTPError as e:
        # 4xx = jawaban server eksplisit (resource tidak ada) — status asli
        # agar masuk jalur "No resource" (AMAN), BUKAN "fetch failed"
        # (bug tertangkap benchmark 2026-10-30: 404 robots dulu dilaporkan
        # "Fetch failed" verdict 1 = noise). 5xx = server error — tetap
        # fail-closed (status None, tidak dapat dinilai).
        try:
            body=e.read(8192).decode(errors="replace")
        except Exception:
            body=""
        hdrs={k.lower():v for k,v in (getattr(e, "headers", None) or {}).items()}
        return ({"status":e.code, "headers":hdrs, "body":body}
                if 400 <= e.code < 500
                else {"status":None, "headers":{},
                      "body":f"__error__ HTTPError: {e.code}"})
    except Exception as e:
        return {"status":None, "headers":{}, "body":f"__error__ {type(e).__name__}: {e}"}

def audit(target, result):
    rows=[]
    st=result.get("status")
    ct=str((result.get("headers") or {}).get("content-type", ""))
    body=str(result.get("body", "") or "")
    if st==200 and ("text/html" in ct.lower()
                    or body.lstrip()[:15].lower().startswith("<!doctype html")):
        # zero-FP (pelajaran soft-404 microsoft /sitemap.xml): 200 bisa
        # berupa halaman HTML dari redirect/error — bukan resource
        rows.append(make_finding(tool="robots-txt-surface", title=f"{target} resource not determinable (soft-404 suspicion)", severity="info",
            description=f"GET 200 tapi konten HTML (content-type: {ct or 'tidak ada'}) — untuk resource non-HTML ini indikasi halaman error/redirect (soft-404). Tidak diklaim (fail-closed); verifikasi manual bila perlu.",
            target_url=target, response=body[:300], evidence_kind="request-response", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
    elif st==200:
        rows.append(make_finding(tool="robots-txt-surface", title=f"{target} exposes resource — 1 GET observed", severity="low", description=f"GET 200 — resource ada (lead, SURFACE). Body preview: {result.get('body','')[:200]}", cwe=None, target_url=target, response=result.get("body","")[:300], evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
    elif st is None:
        rows.append(make_finding(tool="robots-txt-surface", title=f"Fetch failed for {target} (robots-txt-surface)", severity="info", description=result.get("body","")[:300], target_url=target, evidence_kind="request-response", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
    else:
        rows.append(make_finding(tool="robots-txt-surface", title=f"No resource on {target} (robots-txt-surface): {st}", severity="info", description=f"GET {st} — tidak terekspos (AMAN).", target_url=target, response=f"status {st}", evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"1-request"}))
    return rows, {"target":target, "status":st, "requests":1}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: 1-request] robots-txt-surface")
    ap.add_argument("--url", default=None, help="target URL")
    ap.add_argument("--domain", default=None, help="domain untuk well-known (akan jadi https://domain/.well-known/security.txt)")
    ap.add_argument("--target", default=None, help="alias --url")
    ap.add_argument("--out", default="robots_txt_surface_findings.json")
    args=ap.parse_args()
    target=args.url or args.target or (f"https://{args.domain}/robots.txt" if args.domain else None)
    if not target:
        ap.error("--url/--target atau --domain wajib")
    from urllib.parse import urlparse
    p=urlparse(target)
    if not p.scheme:
        target="https://"+target
    result=fetch(target)
    rows,meta=audit(target, result)
    meta["safety_class"]="1-request"
    write_findings(args.out, rows, meta)
    print(f"robots-txt-surface: {len(rows)} temuan (1 request) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
