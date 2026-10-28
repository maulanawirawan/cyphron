"""[SAFETY: bounded-requests] cloud-bucket-exposure — bucket cloud
publik yang NAMA-nya diturunkan dari domain target (maks 4 GET ke
endpoint listing bucket publik). Disiplin zero-FP yang ketat:
  - kepemilikan bucket TIDAK TERVERIFIKASI dari nama saja — temuan
    DIBATASI L1 lead dengan peringatan verifikasi manual eksplisit;
  - hanya listing XML ListBucketResult yang dihitung (isi tabel
    TIDAK dibaca — bukan ekstraksi data);
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
                        "tool ini.",
            recommendation="Matikan akses listing publik (bucket policy "
                           "least-privilege) bila bucket memang milik "
                           "target.",
            cwe="CWE-732",
            target_url=f"https://{domain}",
            response="; ".join(listable)[:300],
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "EXPOSURE",
                   "safety_class": "bounded-requests",
                   "listable": listable,
                   "ownership_verified": False}))
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
                  "requests": len(result.get("results") or {})}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="bucket_findings.json")
    args = ap.parse_args()
    result = probe(args.domain)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"cloud-bucket-exposure: {len(meta.get('listable', []))} bucket "
          f"terbuka -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
