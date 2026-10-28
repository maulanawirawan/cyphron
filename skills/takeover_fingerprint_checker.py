"""[SAFETY: bounded-requests] takeover-fingerprint-checker — verifikasi
fingerprint respons pada CNAME dangling (konsep publik ala Subzy /
can-i-take-over-xyz, signature kecil clean-room).

Input: domain yang SEBELUMNYA ditandai dangling oleh
takeover-cname-hygiene (hygiene saja). Skill ini menambah SATU langkah
verifikasi: GET domain (maks 2 request: https, lalu http bila https
gagal) dan mencari fingerprint respons layanan yang dikenal TIDAK
dikelola (edge provider menolak tanpa klaim kepemilikan).

Zero-FP: lead L2 hanya bila fingerprint cocok PERSIS (string khas
provider) — halaman 404 generik/Blok WAF tidak dihitung. L2 = kandidat
takeover yang WAJIB diverifikasi manual (registrasi/klaim uji tidak
pernah dilakukan skill ini).

Pemakaian:
  python skills/takeover_fingerprint_checker.py --domain sub.example.com \
      --out f.json
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
MAX_REQUESTS = 2

# signature clean-room: string kegagalan khas edge provider saat
# endpoint tidak diklaim siapa pun (publik, dikenal luas)
SIGNATURES = [
    ("github-pages", "There isn't a GitHub Pages site here."),
    ("s3-bucket", "NoSuchBucket"),
    ("azure-websites", "404 Web Site not found."),
    ("cloudfront", "Bad request. We can't connect to the server for this application"),
    ("fastly", "Fastly error: unknown domain:"),
    ("heroku", "No such app"),
    ("shopify", "Sorry, this shop is currently unavailable"),
    ("zendesk", "Help Center Closed"),
]


def probe(domain: str, timeout: float = 15.0) -> dict:
    """Maks 2 request (https dulu)."""
    out = {"requests": 0, "responses": []}
    for scheme in ("https", "http"):
        if out["requests"] >= MAX_REQUESTS:
            break
        url = f"{scheme}://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        out["requests"] += 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(64_000).decode("utf-8", "replace")
                out["responses"].append({"scheme": scheme,
                                         "status": r.status,
                                         "body_head": body[:2000]})
                break  # hidup via https — cukup
        except urllib.error.HTTPError as e:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
            out["responses"].append({"scheme": scheme, "status": e.code,
                                     "body_head": body[:2000]})
            break  # server menjawab (4xx) — cukup
        except Exception as exc:
            out["responses"].append({"scheme": scheme, "status": None,
                                     "error": f"{type(exc).__name__}"})
    return out


def audit(domain: str, probe_result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    matched = None
    for resp in probe_result.get("responses", []):
        body = resp.get("body_head", "")
        for name, sig in SIGNATURES:
            if sig.lower() in body.lower():
                matched = (name, sig, resp)
                break
        if matched:
            break
    if matched:
        name, sig, resp = matched
        rows.append(make_finding(
            tool="takeover-fingerprint-checker",
            title=f"Unclaimed service fingerprint on {domain} ({name})",
            severity="high",
            description=f"Respons {resp.get('scheme')} {resp.get('status')} "
                        f"memuat fingerprint '{name}' (string kegagalan "
                        "khas edge provider untuk endpoint TIDAK "
                        "DIKLAIM) — CNAME domain menunjuk ke layanan "
                        "yang bisa diklaim pihak lain. L2 kandidat "
                        "takeover: WAJIB verifikasi manual (cek rules "
                        "klaim provider) sebelum dilaporkan; skill ini "
                        "TIDAK melakukan klaim/uji registrasi.",
            recommendation="Klaim/hapus entri DNS atau daftar ulang "
                           "layanan; aktifkan verifikasi kepemilikan "
                           "provider (TXT/ASUID).",
            cwe="CWE-350",
            target_url=f"{resp.get('scheme')}://{domain}/",
            response=f"fingerprint '{name}': {sig} (status "
                     f"{resp.get('status')})",
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=2,
            extra={"category": "TAKEOVER", "safety_class":
                   "bounded-requests", "service": name,
                   "status": resp.get("status")}))
    else:
        rows.append(make_finding(
            tool="takeover-fingerprint-checker",
            title=f"No unclaimed fingerprint on {domain}", severity="info",
            description="Tidak ada fingerprint layanan tak-diklaim pada "
                        f"{probe_result.get('requests', 0)} respons — "
                        "bukan kandidat takeover berbasis fingerprint "
                        "(AMAN/inventaris).",
            target_url=domain,
            response=json.dumps(probe_result.get("responses", []))[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))
    return rows, {"domain": domain,
                  "requests": probe_result.get("requests", 0),
                  "matched": matched[0] if matched else None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="takeover_fingerprint_findings.json")
    args = ap.parse_args()
    result = probe(args.domain)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"takeover-fingerprint-checker: {len(rows)} temuan "
          f"(matched={meta.get('matched', '-')}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
