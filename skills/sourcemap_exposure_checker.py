"""[SAFETY: read-only] sourcemap-exposure-checker — Sourcemap exposure
(.map) — 0 request (dari evidence). Flag opt-in --verify (+1 GET ke URL
.map yang ditemukan di evidence; default: URL dari sourceMappingURL,
atau --map-url eksplisit):

  - map ter-fetch + JSON valid ("version" + "sources") = **L2** — file
    map terbukti dapat diunduh (TEREPRODUKSI dgn konten nyata, bukan
    cuma referensi di evidence);
  - map + "sourcesContent" tidak kosong = **L3** — SOURCE ASLI
    pra-minify terbaca (nama variabel/struktur/komentar) — dampak penuh
    CWE-540 terbukti deterministik (isi TIDAK disimpan di bukti, hanya
    jumlah entri + nama path pertama yang disanitasi);
  - fetch gagal/bukan map = tetap L1 + catatan jujur (fail-closed).
"""
from __future__ import annotations
import argparse, json, re, sys, urllib.error, urllib.request
from pathlib import Path
from urllib.parse import urljoin
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402

UA = user_agent()

PAT = re.compile(r"""\.map["\']""", re.I | re.S)
# URL map dari directive baku (sourcemap spec) — lebih spesifik daripada
# regex longgar; fallback: string berakhiran .map dalam tanda kutip
_SMURL = re.compile(r"sourceMappingURL\s*=\s*([^\s'\"<>]+\.map)", re.I)
_SMURL_Q = re.compile(r"[\"']([^\"']*\.map)[\"']", re.I)


def map_url_from_evidence(html: str) -> str | None:
    """URL map pertama dari evidence (sourceMappingURL diutamakan)."""
    if not html:
        return None
    m = _SMURL.search(html) or _SMURL_Q.search(html)
    return m.group(1) if m else None


def strict_map(body: str) -> dict | None:
    """Signature ketat map: JSON valid dgn "version" + "sources".
    Return ringkasan ter-sanitasi (tanpa isi source) atau None."""
    try:
        doc = json.loads(body)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    if not ("version" in doc and isinstance(doc.get("sources"), list)):
        return None
    sc = doc.get("sourcesContent")
    return {"version": doc.get("version"),
            "n_sources": len(doc["sources"]),
            "n_sources_content": (len(sc) if isinstance(sc, list) else 0),
            "first_source": str(doc["sources"][0])[:80]
                            if doc["sources"] else None}


def _fetch(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(512_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(32_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body}
    except Exception as exc:
        return {"status": None, "body": "",
                "error": type(exc).__name__}


def audit(url, html):
    rows = []
    m = PAT.findall(html) if html else []
    map_url = map_url_from_evidence(html or "")
    if m:
        sample = str(m[:3])[:300]
        desc = (f"Sourcemap exposure (.map) — 0 request: {sample} — "
                "(lead, 0 request).")
        if map_url:
            desc += (f" URL map terbaca dari evidence ({map_url}) — "
                     "jalur --verify tersedia utk naik L2/L3.")
        rows.append(make_finding(tool="sourcemap-exposure-checker", title=f"Sourcemap exposure found on {url}", severity="low", description=desc, recommendation="Periksa konfigurasi.", cwe="CWE-538", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","map_url": map_url}))
    else:
        rows.append(make_finding(tool="sourcemap-exposure-checker", title=f"No sourcemap exposure on {url}", severity="info", description=f"Tidak ada sourcemap exposure (.map) — 0 request di HTML evidence — AMAN observation (0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m),
                  "map_url": map_url}


def apply_verify(rows, meta, map_url: str, res: dict):
    """Naikkan lead L1 -> L2 (map valid ter-fetch) / L3 (sourcesContent
    terbaca). Gagal/bukan map = tetap L1 + catatan (fail-closed)."""
    lead = next((r for r in rows if r.get("verdict") == 1), None)
    meta["verify"] = {"url": map_url, "status": res.get("status"),
                      "outcome": None}
    if lead is None:
        meta["verify"]["outcome"] = "no-lead"
        return rows, meta
    if res.get("status") is None:
        meta["verify"]["outcome"] = "error"
        lead["description"] = (str(lead["description"])
                               + f" Verifikasi gagal jaringan "
                                 f"({res.get('error')}) — tetap lead "
                                 "(fail-closed).")
        return rows, meta
    info = strict_map(res.get("body", "") or "")
    if res.get("status") != 200 or info is None:
        meta["verify"]["outcome"] = "not-a-map"
        lead["description"] = (str(lead["description"])
                               + f" GET {map_url} -> HTTP "
                                 f"{res.get('status')}, bukan file map "
                                 "valid — tetap lead, verifikasi manual.")
        return rows, meta
    n_sc = info["n_sources_content"]
    verdict = 3 if n_sc > 0 else 2
    meta["verify"].update({"outcome": ("sources-content" if verdict == 3
                                       else "map-confirmed"),
                           "n_sources": info["n_sources"],
                           "n_sources_content": n_sc})
    lead["verdict"] = verdict
    # sinkron kontrak: verdict_tag + reportable (pelajaran batch 1 —
    # kontrak menolak mutasi setengah)
    from findings import verdict_tag as _vt
    lead["verdict_tag"] = _vt(verdict)
    lead["reportable"] = verdict >= 3
    if verdict == 3:
        lead["cwe"] = "CWE-540"  # source asli terbaca — kelas penuh
    lead["request"] = f"GET {map_url} (verifikasi map)"
    lead["response"] = json.dumps(
        {"status": res.get("status"), "map_version": info["version"],
         "n_sources": info["n_sources"],
         "n_sources_content": n_sc,
         "first_source": info["first_source"]},
        separators=(",", ":"))[:300]
    lead["evidence_kind"] = "request-response"
    lead["finding_class"] = "weakness"
    lead["description"] = (
        ("Source asli pra-minify TERBACA dari map publik ("
         f"{n_sc}/{info['n_sources']} entri sourcesContent) — dampak "
         "penuh sourcemap exposure terbukti deterministik. "
         if verdict == 3 else
         f"File map publik TERKONFIRMASI ter-fetch (HTTP "
         f"{res.get('status')}, {info['n_sources']} entri sources, "
         "tanpa sourcesContent) — ")
        + "Isi source TIDAK disimpan di bukti ini (disiplin zero-"
        "retention; hanya jumlah + nama path pertama).")
    lead["extra"] = {**(lead.get("extra") or {}),
                     "verify": {**meta["verify"],
                                "reproduced": True}}
    return rows, meta


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] sourcemap-exposure-checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="sourcemap_exposure_checker_findings.json")
    ap.add_argument("--verify", action="store_true",
                    help="opt-in: 1 GET ke URL map utk bukti L2/L3")
    ap.add_argument("--map-url", default=None,
                    help="URL map eksplisit (default: dari evidence)")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    if args.verify:
        raw_map_url = args.map_url or meta.get("map_url")
        if raw_map_url and any(r.get("verdict") == 1 for r in rows):
            base = args.url if "://" in args.url else "https://" + args.url
            full = urljoin(base, raw_map_url)
            res = _fetch(full)
            rows, meta = apply_verify(rows, meta, full, res)
        else:
            # tidak ada lead / tidak ada URL map — NOL request (bounded)
            meta["verify"] = {"url": raw_map_url, "outcome": "no-lead",
                              "status": None, "requests": 0}
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    vinfo = meta.get("verify") or {}
    print(f"sourcemap-exposure-checker: {len(rows)} temuan ({aman} AMAN) "
          f"(0 request{' +1 verify: ' + str(vinfo.get('outcome')) if vinfo else ''}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
