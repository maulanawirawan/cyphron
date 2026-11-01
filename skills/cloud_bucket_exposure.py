"""[SAFETY: bounded-requests] cloud-bucket-exposure — bucket cloud
publik yang NAMA-nya diturunkan dari domain target (maks 5 GET: 4 probe
+ 1 verifikasi ulang HANYA bila ada bucket listable). Disiplin zero-FP
yang ketat:
  - kepemilikan bucket TIDAK TERVERIFIKASI dari nama saja — peringatan
    verifikasi manual eksplisit SELALU menempel (atribusi = caveat);
  - hanya listing XML ListBucketResult yang dihitung (isi tabel
    TIDAK dibaca — bukan ekstraksi data);
  - [F75] listable terkonfirmasi ulang (re-GET, signature XML sama) =
    lead naik **L2 REPRODUCED** — listing publik itu sendiri terbukti
    dapat diulang; L3 TIDAK diberikan karena atribusi kepemilikan
    tetap tak terverifikasi (bucket = host terpisah dari target);
  - verifikasi gagal/beda signature = tetap L1 + catatan jujur;
  - kegagalan jaringan = unconfirmed (tanpa klaim).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
MAX_REQUESTS = 4
LISTING_SIGNATURE = "<ListBucketResult"


def bucket_candidates(domain: str) -> list[str]:
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    base = d.rsplit(".", 2)[0] if d.count(".") >= 1 else d
    return list(dict.fromkeys([d.replace(".", "-"), d]))


def fetch_url(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(16_000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": ""}
    except Exception as exc:
        return {"status": None, "error": type(exc).__name__, "body": ""}


def verify_listable(result: dict, timeout: float = 15.0) -> dict:
    """Re-GET bucket listable PERTAMA — signature XML identik = listing
    publik TEREPRODUKSI (bukti deterministik, tersimpan)."""
    first = next((u for u, res in (result.get("results") or {}).items()
                  if res.get("status") == 200
                  and LISTING_SIGNATURE in res.get("body", "")), None)
    if first is None:
        return {}
    res2 = fetch_url(first, timeout=timeout)
    match = (res2.get("status") == 200
             and LISTING_SIGNATURE in res2.get("body", ""))
    return {"url": first, "status": res2.get("status"),
            "signature_match": match}


def bucket_candidates(domain: str) -> list[str]:
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    base = d.rsplit(".", 2)[0] if d.count(".") >= 1 else d
    return list(dict.fromkeys([d.replace(".", "-"), d]))


def probe(domain: str, timeout: float = 15.0) -> dict:
    out: dict = {"results": {}}
    for bucket in bucket_candidates(domain)[:2]:
        for url in (f"https://{bucket}.s3.amazonaws.com/",
                    f"https://s3.amazonaws.com/{bucket}/"):
            if len(out["results"]) >= MAX_REQUESTS:
                break
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    out["results"][url] = {"status": r.status,
                                           "body": r.read(16_000)
                                           .decode("utf-8", "replace")}
            except urllib.error.HTTPError as e:
                out["results"][url] = {"status": e.code, "body": ""}
            except Exception as exc:
                out["results"][url] = {"status": None,
                                       "error": type(exc).__name__,
                                       "body": ""}
    return out


def audit(domain: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    listable: list[str] = []
    errors = 0
    for url, res in (result.get("results") or {}).items():
        if res.get("status") is None:
            errors += 1
            continue
        # hanya listing XML yang dihitung — isi bucket TIDAK dibaca
        if res.get("status") == 200 and "<ListBucketResult" in \
                res.get("body", ""):
            listable.append(url)
    if listable:
        verify = result.get("verify") or {}
        reproduced = bool(verify.get("signature_match"))
        if reproduced:
            verdict = 2
            verdict_desc = (
                " TEREPRODUKSI: re-GET "
                f"{verify.get('url')} -> HTTP {verify.get('status')} dgn "
                "signature XML sama — listing publik terbukti dapat "
                "diulang (L2; L3 tidak diberikan karena atribusi "
                "kepemilikan tetap tak terverifikasi).")
            req = (f"GET {verify.get('url')} (probe) + re-GET "
                   f"{verify.get('url')} (verifikasi ulang)")
            resp = (f"capture-1: 200 ListBucketResult | capture-2: HTTP "
                    f"{verify.get('status')} ListBucketResult"
                    )[:300]
        else:
            verdict = 1
            verdict_desc = (
                "" if not verify else
                f" Verifikasi ulang TIDAK cocok (HTTP "
                f"{verify.get('status')}) — tetap lead, verifikasi "
                "manual (fail-closed).")
            req = f"GET {listable[0]} (probe)"
            resp = "; ".join(listable)[:300]
        rows.append(make_finding(
            tool="cloud-bucket-exposure",
            title=f"Publicly listable cloud bucket for {domain}",
            severity="low",
            description=f"Bucket dengan nama turunan domain target "
                        f"terbuka untuk listing publik: {listable}. "
                        "PERINGATAN zero-FP: kepemilikan bucket TIDAK "
                        "terverifikasi dari nama saja — wajib verifikasi "
                        "manual (bukti kepemilikan/konten milik target) "
                        "sebelum klaim apa pun. Isi bucket TIDAK dibaca "
                        f"tool ini.{verdict_desc}",
            recommendation="Matikan akses listing publik (bucket policy "
                           "least-privilege) bila bucket memang milik "
                           "target.",
            cwe="CWE-732",
            target_url=f"https://{domain}",
            request=req, response=resp,
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=verdict,
            extra={"category": "EXPOSURE",
                   "safety_class": "bounded-requests",
                   "listable": listable,
                   "ownership_verified": False,
                   "verify": {k: verify.get(k) for k in
                              ("url", "status", "signature_match")}
                              if verify else None}))
    else:
        rows.append(make_finding(
            tool="cloud-bucket-exposure",
            title=f"Cloud bucket posture on {domain}",
            severity="info",
            description=("Tidak ada bucket nama-turunan-domain yang "
                         "terbuka listing (AMAN/inventaris)." if not errors
                         else f"{errors} pengecekan gagal jaringan — "
                              "sebagian tidak dapat dinilai (tanpa klaim)."),
            target_url=f"https://{domain}",
            response=json.dumps({u: r.get("status") for u, r in
                                 (result.get("results") or {}).items()})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0,
            status="confirmed" if not errors else "unconfirmed",
            verdict=0 if not errors else 1,
            extra={"category": "AMAN" if not errors else "MISC",
                   "safety_class": "bounded-requests", "errors": errors}))
    return rows, {"domain": domain, "listable": listable,
                  "verify": (result.get("verify") or {}).get("signature_match"),
                  "requests": len(result.get("results") or {})
                              + (1 if result.get("verify") else 0)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="bucket_findings.json")
    args = ap.parse_args()
    result = probe(args.domain)
    # [F75] verifikasi ulang HANYA bila ada bucket listable (+1 GET,
    # total tetap dalam estimasi kelas bounded-requests)
    result["verify"] = verify_listable(result)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"cloud-bucket-exposure: {len(meta.get('listable', []))} bucket "
          f"terbuka (reproduced: {meta.get('verify')}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
