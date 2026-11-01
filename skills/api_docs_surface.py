"""[SAFETY: read-only] api-docs-surface — API docs surface (openapi/docs) — 0 request
Nol request — hanya baca HTML evidence tersimpan.

Flag opt-in --verify (+1 GET ke --verify-url): bila evidence memuat
signature ketat dokumen API (OpenAPI JSON "openapi": "3.x" / "swagger":
"2.x", atau halaman Swagger UI dgn DOM #swagger-ui + swagger-ui-bundle),
GET ulang yang menampilkan signature sama = TEREPRODUKSI 2x — lead L1
naik L3 deterministik (strategi D). Gagal/tidak cocok = tetap L1 + catatan
(fail-closed).

Anti-FP: teks "/openapi.json" atau "swagger" di HTML biasa (link, artikel)
TIDAK strict — signature ketat hanya pada dokumen/DOM nyata di atas.
"""
from __future__ import annotations
import argparse, json, sys, re, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402

UA = user_agent()

PAT=re.compile(r"""/api/docs|/openapi\.json|/swagger""", re.I|re.S)

# signature ketat dokumen API (struktur nyata, bukan teks biasa)
_STRICT_RES = (
    ("openapi-json", re.compile(r'["\']openapi["\']\s*:\s*["\'][0-9]', re.I)),
    ("swagger-json", re.compile(r'["\']swagger["\']\s*:\s*["\']2', re.I)),
    ("swagger-ui-dom", re.compile(r'id="swagger-ui"', re.I)),
)
_SWAGGER_BUNDLE = re.compile(r"swagger-ui-bundle|SwaggerUIBundle", re.I)


def strict_docs(html: str) -> str | None:
    """Label signature ketat bila html = dokumen/halaman API docs nyata."""
    if not html:
        return None
    for label, pat in _STRICT_RES:
        if pat.search(html):
            if label == "swagger-ui-dom" and not _SWAGGER_BUNDLE.search(html):
                continue  # DOM tanpa bundle = belum cukup kuat
            return label
    return None


def _fetch(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(64_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(32_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as exc:
        return {"status": None, "body": "", "error": type(exc).__name__}


def audit(url, html):
    rows=[]
    m=PAT.findall(html) if html else []
    strict = strict_docs(html or "")
    if m or strict:
        sample=str(m[:3])[:300]
        desc=(f"API docs surface (openapi/docs) — 0 request: "
              f"{sample or strict} — (lead, 0 request).")
        if strict:
            desc += (f" Signature ketat teramati ({strict}) — jalur "
                     "verifikasi ulang --verify tersedia utk naik L3.")
        if strict and not m:
            desc = ("Dokumen OpenAPI/Swagger nyata di evidence "
                    f"(signature ketat: {strict}) — (lead, 0 request). "
                    "Jalur verifikasi ulang --verify tersedia utk naik "
                    "L3.")
        rows.append(make_finding(tool="api-docs-surface", title=f"API docs surface found on {url}", severity="low", description=desc, recommendation="Periksa konfigurasi.", cwe=None, target_url=url, response=sample or str(strict)[:120], evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","strict": strict}))
    else:
        rows.append(make_finding(tool="api-docs-surface", title=f"No API docs surface on {url}", severity="info", description=f"Tidak ada api docs surface (openapi/docs) — 0 request di HTML evidence — AMAN observation (0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m),
                  "strict": strict}


def apply_verify(rows, meta, verify_url: str, res: dict):
    """Naikkan lead L1 -> L3 bila GET ulang menampilkan signature ketat
    yang sama (TEREPRODUKSI 2x). Gagal/tidak cocok = tetap L1 + catatan."""
    lead = next((r for r in rows if r.get("verdict") == 1), None)
    meta["verify"] = {"url": verify_url, "status": res.get("status"),
                      "outcome": None}
    if lead is None:
        meta["verify"]["outcome"] = "no-lead"
        return rows, meta
    live_strict = strict_docs(res.get("body", "") or "")
    if res.get("status") is None:
        meta["verify"]["outcome"] = "error"
        lead["description"] = (str(lead["description"])
                               + f" Verifikasi ulang gagal jaringan "
                                 f"({res.get('error')}) — tetap lead "
                                 "(fail-closed).")
        return rows, meta
    if live_strict:
        meta["verify"]["outcome"] = "reproduced"
        lead["verdict"] = 3
        from findings import verdict_tag as _vt
        lead["verdict_tag"] = _vt(3)
        lead["reportable"] = True  # kontrak: L3 => reportable
        lead["request"] = f"GET {verify_url} (verifikasi ulang)"
        lead["response"] = (f"capture-1 (evidence): {meta.get('strict')} | "
                            f"capture-2 (GET ulang): HTTP "
                            f"{res.get('status')} — {live_strict}")[:300]
        lead["evidence_kind"] = "request-response"
        lead["finding_class"] = "weakness"
        lead["description"] = (
            "Dokumen/halaman API docs TEREPRODUKSI 2x: signature ketat "
            f"sama pada bukti tersimpan ({meta.get('strict')}) DAN GET "
            f"ulang live (HTTP {res.get('status')}, {live_strict}) — "
            "deterministik, bukan cuma lead surface.")
        lead["extra"] = {**(lead.get("extra") or {}),
                         "verify": {"url": verify_url,
                                    "status": res.get("status"),
                                    "strict_1": meta.get("strict"),
                                    "strict_2": live_strict,
                                    "reproduced": True}}
        return rows, meta
    meta["verify"]["outcome"] = "not-reproduced"
    lead["description"] = (str(lead["description"])
                           + f" GET ulang ke {verify_url} TIDAK menampilkan "
                             f"signature ketat (HTTP {res.get('status')}) "
                             "— tidak terkonfirmasi ulang; verifikasi "
                             "manual (fail-closed, tetap lead).")
    return rows, meta


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] api-docs-surface")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="api_docs_surface_findings.json")
    ap.add_argument("--verify", action="store_true",
                    help="opt-in: 1 GET ulang ke --verify-url utk bukti reproduced (L3)")
    ap.add_argument("--verify-url", default=None,
                    help="URL verifikasi ulang (default: --url)")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    if args.verify:
        vurl = args.verify_url or args.url
        if any(r.get("verdict") == 1 for r in rows):
            res = _fetch(vurl)
            rows, meta = apply_verify(rows, meta, vurl, res)
        else:
            # tidak ada lead — NOL request verifikasi (bounded jujur)
            meta["verify"] = {"url": vurl, "outcome": "no-lead",
                              "status": None, "requests": 0}
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    vinfo = meta.get("verify") or {}
    print(f"api-docs-surface: {len(rows)} temuan ({aman} AMAN) "
          f"(0 request{' +1 verify: ' + str(vinfo.get('outcome')) if vinfo else ''}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
