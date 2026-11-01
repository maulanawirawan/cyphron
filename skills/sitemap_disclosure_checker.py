"""[SAFETY: bounded-requests] sitemap-disclosure-checker — sitemap.xml
disclosure — MAKS 2 GET: 1 GET resource + 1 GET canary differensial
HANYA bila resource menjawab 200 (kontrol anti-FP, pola F75).

Canary = path sengaja-tidak-ada (`.cx-canary-sitemap-7f3a.txt`) di origin
yang sama:
  - canary 200 dgn body IDENTIK = host wildcard-200 TERBUKTI:
    * resource HTML (suspicion) -> tetap tidak dapat dinilai, kini dgn
      bukti deterministik (fail-closed jujur);
    * resource non-HTML ("exposes resource") -> lead DITOLAK L-x
      (status false-positive — 200 tak berarti resource ada).
  - canary 4xx = respons resource SPESIFIK (bukan wildcard) -> lead
    dipertahankan/diperkuat;
  - canary gagal/beda konten = tanpa kesimpulan (perilaku lama).
Fail-closed: 4xx resource = "No resource" (AMAN — fix bug benchmark
2026-10-30, kelas sama dgn robots), 5xx/gagal = tidak dapat dinilai.
"""
from __future__ import annotations
import argparse, json, sys, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402
UA=user_agent()
CANARY_PATH = "/.cx-canary-sitemap-7f3a.txt"

def fetch(url, timeout=20):
    try:
        req=urllib.request.Request(url, headers={"User-Agent":UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body=r.read(8192).decode(errors="replace")
            return {"status":r.status, "headers":{k.lower():v for k,v in r.headers.items()}, "body":body}
    except urllib.error.HTTPError as e:
        # 4xx = jawaban server eksplisit (resource tidak ada) — status
        # asli agar masuk jalur "No resource" (AMAN), bukan "Fetch
        # failed" (bug kelas benchmark 2026-10-30; fix sama dgn robots).
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

def fetch_canary(target, timeout=20):
    """1 GET path sengaja-tak-ada di origin yang sama (kontrol)."""
    from urllib.parse import urlparse
    p = urlparse(target)
    base = f"{p.scheme or 'https'}://{p.netloc}"
    return fetch(base + CANARY_PATH, timeout=timeout)

def _canary_outcome(result):
    """Klasifikasi differensial canary vs resource — deterministik.
    Return (outcome, note): none|wildcard-proven|specific-404|
    inconclusive|error."""
    c = result.get("canary")
    if not c:
        return "none", ""
    res_body = str(result.get("body", "") or "")
    cst = c.get("status")
    if cst is None:
        return "error", " canary gagal jaringan — tanpa kesimpulan."
    if 200 <= cst < 300:
        if str(c.get("body", "") or "") == res_body:
            return ("wildcard-proven",
                    f" Canary differensial: GET {CANARY_PATH} -> 200 dgn "
                    "body IDENTIK — host wildcard-200 TERBUKTI "
                    "(respons 200 tidak membuktikan keberadaan resource).")
        return ("inconclusive",
                f" Canary differensial: GET {CANARY_PATH} -> 200 beda "
                "konten — inkonklusif.")
    if 400 <= cst < 500:
        return ("specific-404",
                f" Canary differensial: GET {CANARY_PATH} -> {cst} (path "
                "sengaja tak ada) — respons resource SPESIFIK, bukan "
                "wildcard.")
    return ("inconclusive",
            f" Canary differensial: GET {CANARY_PATH} -> {cst} — "
            "inkonklusif.")

def audit(target, result):
    rows=[]
    st=result.get("status")
    ct=str((result.get("headers") or {}).get("content-type", ""))
    body=str(result.get("body", "") or "")
    outcome, note = _canary_outcome(result)
    canary_meta = {"outcome": outcome,
                   "path": CANARY_PATH if result.get("canary") else None}
    if st==200 and ("text/html" in ct.lower()
                    or body.lstrip()[:15].lower().startswith("<!doctype html")):
        # zero-FP (pelajaran soft-404 microsoft /sitemap.xml): 200 bisa
        # berupa halaman HTML dari redirect/error — bukan resource.
        # [F75] canary menambah bukti deterministik utk baris ini.
        rows.append(make_finding(tool="sitemap-disclosure-checker", title=f"{target} resource not determinable (soft-404 suspicion)", severity="info",
            description=f"GET 200 tapi konten HTML (content-type: {ct or 'tidak ada'}) — untuk resource non-HTML ini indikasi halaman error/redirect (soft-404). Tidak diklaim (fail-closed); verifikasi manual bila perlu.{note}",
            target_url=target, response=body[:300], evidence_kind="request-response", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"bounded-requests","canary": canary_meta}))
    elif st==200:
        if outcome == "wildcard-proven":
            # [F75] FP-ELIMINATED: path sengaja-tak-ada membalas body
            # identik -> klaim "resource ada" TERBUKTI salah (disiplin
            # L-x, pola reconciliation dependency F68b).
            rows.append(make_finding(tool="sitemap-disclosure-checker", title=f"{target} exposes resource — DITOLAK (wildcard-200 terbukti via canary)", severity="info",
                description=f"GET 200 non-HTML dulu dicatat sebagai lead; canary differensial GET {CANARY_PATH} -> 200 dgn body IDENTIK — host wildcard-200 TERBUKTI, klaim 'resource ada' gugur (false positive tereliminasi dgn bukti tersimpan).",
                target_url=target,
                response=json.dumps({"resource_status": 200,
                                     "canary_path": CANARY_PATH,
                                     "canary_status": (result.get("canary") or {}).get("status"),
                                     "body_identical": True},
                                    separators=(",", ":"))[:300],
                evidence_kind="request-response", finding_class="posture", confidence=1.0, status="false-positive", verdict=-1, extra={"category":"FP-ELIMINATED","safety_class":"bounded-requests","canary": canary_meta}))
        else:
            rows.append(make_finding(tool="sitemap-disclosure-checker", title=f"{target} exposes resource — 1 GET observed", severity="low", description=f"GET 200 — resource ada (lead, SURFACE). Body preview: {result.get('body','')[:200]}{note or ' Canary tidak dijalankan.'}", cwe=None, target_url=target, response=result.get("body","")[:300], evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"bounded-requests","canary": canary_meta}))
    elif st is None:
        rows.append(make_finding(tool="sitemap-disclosure-checker", title=f"Fetch failed for {target} (sitemap-disclosure-checker)", severity="info", description=result.get("body","")[:300], target_url=target, evidence_kind="request-response", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"bounded-requests"}))
    else:
        rows.append(make_finding(tool="sitemap-disclosure-checker", title=f"No resource on {target} (sitemap-disclosure-checker): {st}", severity="info", description=f"GET {st} — tidak terekspos (AMAN).", target_url=target, response=f"status {st}", evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"bounded-requests"}))
    n_req = 1 + (1 if result.get("canary") else 0)
    return rows, {"target":target, "status":st, "canary": outcome,
                  "requests":n_req}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: bounded-requests] sitemap-disclosure-checker")
    ap.add_argument("--url", default=None, help="target URL")
    ap.add_argument("--domain", default=None, help="domain (akan jadi https://domain/sitemap.xml)")
    ap.add_argument("--target", default=None, help="alias --url")
    ap.add_argument("--no-canary", action="store_true",
                    help="matikan canary differensial (kembali 1 GET)")
    ap.add_argument("--out", default="sitemap_disclosure_checker_findings.json")
    args=ap.parse_args()
    target=args.url or args.target or (f"https://{args.domain}/sitemap.xml" if args.domain else None)
    if not target:
        ap.error("--url/--target atau --domain wajib")
    from urllib.parse import urlparse
    p=urlparse(target)
    if not p.scheme:
        target="https://"+target
    result=fetch(target)
    if result.get("status") == 200 and not args.no_canary:
        result["canary"]=fetch_canary(target)
    rows,meta=audit(target, result)
    meta["safety_class"]="bounded-requests"
    write_findings(args.out, rows, meta)
    print(f"sitemap-disclosure-checker: {len(rows)} temuan "
          f"(canary: {meta.get('canary')}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
