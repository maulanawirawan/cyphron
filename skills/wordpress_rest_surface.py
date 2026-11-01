"""[SAFETY: read-only] wordpress-rest-surface — WordPress REST surface
(/wp-json, ?rest_route=) pasif — 0 request dari evidence.

Flag opt-in --verify (+1 GET ke REST root; URL dari evidence bila ada,
fallback --rest-url eksplisit):
  - 200 + JSON dgn "routes" (dict) + "namespaces" berisi "wp/v2" =
    **L3** — index REST API WordPress asli terbaca utuh (signature
    eksklusif WP; host = target sendiri, atribusi inheren). Bukti
    ter-sanitasi: jumlah route + daftar namespace saja (daftar path
    route TIDAK disimpan — zero-retention);
  - 200 JSON bukan shape WP / 200 HTML = tidak direproduksi -> tetap
    L1 + catatan;
  - 401/403 = endpoint terlindungi di edge -> tetap L1 + catatan
    (lead dari evidence tetap sah);
  - gagal jaringan = tetap L1 (fail-closed).
"""
from __future__ import annotations
import argparse, json, sys, re, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402

UA = user_agent()

PAT = re.compile(r"""wp-json|\?rest_route=""", re.I | re.S)
# URL wp-json absolut dari evidence (link/og:shortlink dsb.)
_WPJSON_URL = re.compile(r"https?://[^\s'\"<>]+/wp-json/?", re.I)


def wpjson_url_from_evidence(html: str) -> str | None:
    if not html:
        return None
    m = _WPJSON_URL.search(html)
    return m.group(0) if m else None


def strict_wpjson(body: str) -> dict | None:
    """Signature eksklusif index REST WP: "routes" dict (kunci berawalan
    "/") + "namespaces" list. wp/v2 TIDAK diwajibkan — plugin keamanan
    bisa memfilter namespace itu sementara index tetap nyata (kasus
    nyata: wp/v2 difilter, oembed/jetpack tampil). Return ringkasan
    ter-sanitasi atau None."""
    try:
        doc = json.loads(body)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    routes = doc.get("routes")
    ns = doc.get("namespaces")
    if not isinstance(routes, dict) or not isinstance(ns, list):
        return None
    if not routes or not ns:
        return None
    if not all(str(k).startswith("/") for k in list(routes)[:5]):
        return None  # kunci route selalu path-prefix (bentuk WP)
    return {"n_routes": len(routes),
            "namespaces": [str(x) for x in ns][:12],
            "wp_v2_open": "wp/v2" in ns}


def _fetch(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            # index WP dgn banyak plugin bisa >256 KB (kasus nyata:
            # jetpack/rttpg memperluas routes) — batas baca 1 MB
            # (bounded); lebih besar = JSON terpotong = fail-closed
            return {"status": r.status,
                    "body": r.read(1_000_000).decode("utf-8", "replace")}
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
    rest_url = wpjson_url_from_evidence(html or "")
    if m:
        sample = str(m[:3])[:300]
        desc = (f"WordPress REST surface (/wp-json, ?rest_route=) "
                f"pasif — 0 request: {sample} — (lead, 0 request).")
        if rest_url:
            desc += (f" URL REST root terbaca dari evidence ({rest_url}) "
                     "— jalur --verify tersedia utk naik L3.")
        rows.append(make_finding(tool="wordpress-rest-surface", title=f"WordPress REST surface found on {url}", severity="low", description=desc, recommendation="Periksa konfigurasi.", cwe=None, target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","rest_url": rest_url}))
    else:
        rows.append(make_finding(tool="wordpress-rest-surface", title=f"No WordPress REST surface on {url}", severity="info", description=f"Tidak ada wordpress rest surface (/wp-json, ?rest_route=) pasif — 0 request di HTML evidence — AMAN observation (0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m),
                  "rest_url": rest_url}


def apply_verify(rows, meta, verify_url: str, res: dict):
    """Naikkan lead L1 -> L3 bila GET ulang membaca index REST WP asli
    (signature eksklusif). Gagal/terlindungi = tetap L1 + catatan."""
    lead = next((r for r in rows if r.get("verdict") == 1), None)
    meta["verify"] = {"url": verify_url, "status": res.get("status"),
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
    info = strict_wpjson(res.get("body", "") or "")
    if res.get("status") == 200 and info:
        wp_v2 = info.get("wp_v2_open")
        meta["verify"].update({"outcome": "wp-rest-index",
                               "n_routes": info["n_routes"],
                               "namespaces": info["namespaces"],
                               "wp_v2_open": wp_v2})
        lead["verdict"] = 3
        from findings import verdict_tag as _vt
        lead["verdict_tag"] = _vt(3)
        lead["reportable"] = True  # kontrak: L3 => reportable
        lead["request"] = f"GET {verify_url} (verifikasi REST root)"
        lead["response"] = json.dumps(
            {"status": 200, "n_routes": info["n_routes"],
             "namespaces": info["namespaces"],
             "wp_v2_open": info.get("wp_v2_open")},
            separators=(",", ":"))[:300]
        lead["evidence_kind"] = "request-response"
        lead["finding_class"] = "weakness"
        wp_v2_note = (
            "namespace wp/v2 TERDAFTAR — cek enumerasi user (wp/v2/"
            "users) utk guest, lihat wp-posture."
            if wp_v2 else
            "namespace wp/v2 TIDAK terdaftar (difilter plugin keamanan/"
            "konfigurasi) — enumerasi user via REST kemungkinan diblokir "
            "di sisi ini (postur, bukan jaminan).")
        lead["description"] = (
            "Index REST API WordPress TERBACA utuh via GET ulang "
            f"({info['n_routes']} route, namespaces: "
            f"{', '.join(info['namespaces'])}) — signature eksklusif WP, "
            f"deterministik. {wp_v2_note} Daftar path route TIDAK "
            "disimpan di bukti (zero-retention).")
        lead["extra"] = {**(lead.get("extra") or {}), "verify": True}
        return rows, meta
    if res.get("status") in (401, 403):
        meta["verify"]["outcome"] = "protected"
        lead["description"] = (str(lead["description"])
                               + f" GET ulang -> {res.get('status')} "
                                 "(REST root terlindungi di lapis "
                                 "edge — referensi di evidence tetap "
                                 "lead, verifikasi manual).")
        return rows, meta
    meta["verify"]["outcome"] = "not-reproduced"
    lead["description"] = (str(lead["description"])
                           + f" GET ulang -> HTTP {res.get('status')}, "
                             "bukan index REST WP — tidak direproduksi; "
                             "verifikasi manual (fail-closed).")
    return rows, meta


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] wordpress-rest-surface")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="wordpress_rest_surface_findings.json")
    ap.add_argument("--verify", action="store_true",
                    help="opt-in: 1 GET ke REST root utk bukti L3")
    ap.add_argument("--rest-url", default=None,
                    help="URL REST root eksplisit (default: dari evidence)")
    args=ap.parse_args()
    html=Path(args.from_raw).read_text(encoding="utf-8-sig", errors="replace") if Path(args.from_raw).exists() else ""
    rows,meta=audit(args.url, html)
    if args.verify:
        raw = args.rest_url or meta.get("rest_url")
        if raw and any(r.get("verdict") == 1 for r in rows):
            rows, meta = apply_verify(rows, meta, raw, _fetch(raw))
        else:
            # tidak ada lead / tidak ada URL — NOL request (bounded)
            meta["verify"] = {"url": raw, "outcome": "no-lead",
                              "status": None, "requests": 0}
    meta["safety_class"]="read-only"
    write_findings(args.out, rows, meta)
    aman=sum(1 for r in rows if r.get("category")=="AMAN")
    vinfo = meta.get("verify") or {}
    print(f"wordpress-rest-surface: {len(rows)} temuan ({aman} AMAN) "
          f"(0 request{' +1 verify: ' + str(vinfo.get('outcome')) if vinfo else ''}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
