"""[SAFETY: read-only] directory-listing-detector — Directory listing detector — 0 request
Nol request — hanya baca HTML evidence tersimpan.

Flag opt-in --verify (+1 GET ke --verify-url): bila evidence memuat
signature ketat listing (struktur autoindex: anchor "../" + teks khas),
GET ulang yang menampilkan signature struktural yang sama = bukti
TEREPRODUKSI 2x — lead L1 naik L3 deterministik (strategi D). GET ulang
gagal/tidak cocok = tetap L1 dgn catatan jujur (fail-closed, tanpa
penghapusan bukti).

Signature ketat (anti-FP): WAJIB ada anchor struktural <a href="../">
(ciri autoindex apache/nginx/tomcat) DAN salah satu teks khas
(title/h1 "Index of /", "Parent Directory</a>", "Directory Listing For
/") — artikel/blog tentang nginx tidak memenuhi keduanya sekaligus.
Konten "sama" diukur pada signature struktural, BUKAN byte-identik
(listing apache memuat mtime yang berubah).
"""
from __future__ import annotations
import argparse, json, sys, re, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402

UA = user_agent()

PAT = re.compile(r"""Index of /|Parent Directory""", re.I | re.S)

# signature ketat: anchor parent struktural + teks khas autoindex
_PARENT_ANCHOR = re.compile(r'<a\s+href="\.\./"', re.I)
_STRICT_TEXTS = (
    ("title-index-of", re.compile(r"<title>[^<]*Index of /", re.I)),
    ("h1-index-of", re.compile(r"<h1>[^<]*Index of /", re.I)),
    ("parent-directory", re.compile(r">Parent Directory</a>", re.I)),
    ("tomcat-dir-listing", re.compile(r"Directory Listing For /", re.I)),
)


def strict_listing(html: str) -> str | None:
    """Label signature ketat bila html = listing direktori nyata."""
    if not html or not _PARENT_ANCHOR.search(html):
        return None
    for label, pat in _STRICT_TEXTS:
        if pat.search(html):
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
    rows = []
    m = PAT.findall(html) if html else []
    strict = strict_listing(html or "")
    if m:
        sample = str(m[:3])[:300]
        desc = (f"Directory listing detector — 0 request: {sample} — "
                "(lead, 0 request).")
        if strict:
            desc += (f" Signature ketat teramati ({strict}) — jalur "
                     "verifikasi ulang --verify tersedia utk naik L3.")
        rows.append(make_finding(tool="directory-listing-detector", title=f"Directory listing signature found on {url}", severity="low", description=desc, recommendation="Periksa konfigurasi.", cwe="CWE-548", target_url=url, response=sample, evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"read-only","strict": strict}))
    else:
        rows.append(make_finding(tool="directory-listing-detector", title=f"No directory listing on {url}", severity="info", description=f"Tidak ada directory listing detector — 0 request di HTML evidence — AMAN observation (0 request).", target_url=url, response=f"len={len(html) if html else 0}", evidence_kind="header", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"read-only"}))
    return rows, {"url":url, "requests":0, "matched":bool(m),
                  "strict": strict}


def apply_verify(rows, meta, verify_url: str, res: dict):
    """Naikkan lead L1 -> L3 bila GET ulang menampilkan signature ketat
    yang sama (TEREPRODUKSI 2x). Gagal/tidak cocok = tetap L1 + catatan
    (fail-closed; bukti asli tidak dihapus)."""
    lead = next((r for r in rows if r.get("verdict") == 1), None)
    meta["verify"] = {"url": verify_url, "status": res.get("status"),
                      "outcome": None}
    if lead is None:
        meta["verify"]["outcome"] = "no-lead"
        return rows, meta
    live_strict = strict_listing(res.get("body", "") or "")
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
                            f"{res.get('status')} — {live_strict}"
                            )[:300]
        lead["evidence_kind"] = "request-response"
        lead["finding_class"] = "weakness"
        lead["description"] = (
            "Directory listing TEREPRODUKSI 2x: signature struktural "
            f"ketat sama pada bukti tersimpan ({meta.get('strict')}) DAN "
            f"GET ulang live (HTTP {res.get('status')}, {live_strict}) "
            "— deterministik, bukan cuma lead surface.")
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
                             "— listing tidak terkonfirmasi ulang; "
                             "verifikasi manual (fail-closed, tetap lead).")
    return rows, meta


def main():
    ap=argparse.ArgumentParser(description="[SAFETY: read-only] directory-listing-detector")
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True, help="path HTML evidence (0 request)")
    ap.add_argument("--out", default="directory_listing_detector_findings.json")
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
    print(f"directory-listing-detector: {len(rows)} temuan ({aman} AMAN) "
          f"(0 request{' +1 verify: ' + str(vinfo.get('outcome')) if vinfo else ''}) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
