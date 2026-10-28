"""[SAFETY: 1-request] favicon-fingerprint — fingerprint favicon
(inventaris postur / padanan favicon_hash legacy, digabung jalur
tech-fingerprint): SATU GET /favicon.ico, hash MurmurHash3 x86_32 atas
body base64 (konvensi kompatibel layanan favicon-hash eksternal —
operator bisa mencari hash itu manual di layanan pilihan).
Implementasi hash = clean-room stdlib murni (algoritma publik RFC/
reference MurmurHash3 — TANPA dependensi; vektor uji terverifikasi).
Verdict: L1 inventaris faktual (hash + ukuran + content-type) — bukan
klaim kerentanan; 404/kosong = AMAN; gagal jaringan = unconfirmed.
Tabel fingerprint default TIDAK disertakan (tidak ada data primer —
tanpa fabrikasi data).
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (algoritma publik, clean-room stdlib).
    Return signed 32-bit (konvensi mmh3.hash)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593

    def rotl(x: int, r: int) -> int:
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    def fmix(h: int) -> int:
        h ^= h >> 16
        h = (h * 0x85EBCA6B) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xC2B2AE35) & 0xFFFFFFFF
        h ^= h >> 16
        return h

    h = seed & 0xFFFFFFFF
    nblocks = len(data) // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i * 4:(i + 1) * 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = rotl(h, 13)
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = rotl(k, 15)
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h = fmix(h)
    # konversi ke signed 32-bit (konvensi mmh3.hash)
    return ctypes.c_int32(h).value


def favicon_hash(body: bytes) -> int:
    """Hash atas body base64 (konvensi layanan favicon-hash eksternal:
    mmh3 atas representasi utf-8 dari string base64)."""
    return mmh3_x86_32(base64.b64encode(body).decode("ascii")
                       .encode("utf-8"))


def probe(base_url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(base_url.rstrip("/") + "/favicon.ico",
                                 headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "content_type": r.headers.get("Content-Type", ""),
                    "body": r.read(256_000)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": b"", "content_type": ""}
    except Exception as exc:
        return {"status": None, "body": b"",
                "error": type(exc).__name__}


def audit(base_url: str, result: dict) -> tuple[list[dict], dict]:
    status = result.get("status")
    body = result.get("body", b"")
    if result.get("error") or status is None:
        rows = [make_finding(
            tool="favicon-fingerprint",
            title=f"Favicon fingerprint on {base_url} — gagal",
            severity="info",
            description=(f"Fetch gagal ({result.get('error')}) — favicon "
                         "tidak dinilai (tanpa klaim, fail-closed)."),
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"})]
        return rows, {"url": base_url, "error": True}
    if status != 200 or not body:
        rows = [make_finding(
            tool="favicon-fingerprint",
            title=f"Favicon fingerprint on {base_url}: tidak ada favicon",
            severity="info",
            description="Tidak ada favicon.ico yang terhidang (status "
                        f"{status}) — tidak ada yang bisa di-fingerprint "
                        "(AMAN/inventaris).",
            target_url=base_url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "1-request",
                   "status": status})]
        return rows, {"url": base_url, "hash": None}
    h = favicon_hash(body)
    rows = [make_finding(
        tool="favicon-fingerprint",
        title=f"Favicon fingerprint on {base_url}: {h}",
        severity="info",
        description=f"Favicon ({len(body)} byte, "
                    f"{result.get('content_type') or 'tanpa content-type'}) "
                    f"hash = {h} (MurmurHash3 x86_32 atas body base64 — "
                    "konvensi layanan favicon-hash eksternal). Inventaris "
                    "faktual: hash identik lintas host = aplikasi/panel "
                    "sama; cari hash manual di layanan pilihan untuk "
                    "korelasi. BUKAN klaim kerentanan.",
        target_url=base_url,
        response=f"len={len(body)} ct={result.get('content_type')}",
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1,
        extra={"category": "SURFACE", "safety_class": "1-request",
               "hash": h, "bytes": len(body)})]
    return rows, {"url": base_url, "hash": h}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="favicon_findings.json")
    args = ap.parse_args()
    result = probe(args.url)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"favicon-fingerprint: hash={meta.get('hash', '-')} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
