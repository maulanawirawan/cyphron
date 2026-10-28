"""[SAFETY: 1-request] security.txt discovery — mesin pencari kanal disclosure.

Standar RFC 9116: banyak organisasi mempublikasikan /.well-known/security.txt
berisi Contact (kanal lapor), Policy (aturan program), dsb. Skill ini SATU
GET per lokasi standar (maks 2 GET: /.well-known/ dan /security.txt) untuk
menemukan kanal laporan resmi sebuah domain — pintu masuk "cari program
tanpa register" yang paling standar dan sah.

Hasil: inventaris L0 (kanal ditemukan) / L1 lead (tidak ada security.txt —
organisasi belum publikkan kanal). NOL probing lain.

Pemakaian:
  python skills/security_txt.py --domain contoh.go.id --out f.json
"""
from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

UA = user_agent()
PATHS = ["/.well-known/security.txt", "/security.txt"]
FIELDS = ("contact", "policy", "acknowledgments", "hiring", "csaf",
          "preferred-languages", "expires")


def fetch(url: str, timeout: float = 15.0) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status == 200 and "text/plain" in (r.headers.get(
                    "content-type") or ""):
                return r.read(16_000).decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def parse(body: str) -> dict:
    out: dict[str, list[str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            if k in FIELDS:
                out.setdefault(k, []).append(v.strip())
    return out


def audit(domain: str) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    found: dict | None = None
    found_at: str | None = None
    gets = 0
    base = f"https://{domain}"
    for p in PATHS:
        gets += 1
        body = fetch(base + p)
        if body is not None:
            found = parse(body)
            found_at = p
            break

    if found:
        rows.append(make_finding(
            tool="security-txt",
            title=f"security.txt found on {domain} at {found_at}",
            severity="info",
            description="Kanal disclosure resmi ditemukan (RFC 9116) — "
                        "jalur pelaporan sah untuk domain ini. Isi dianalisis "
                        "sebagai bukti.",
            target_url=base + (found_at or ""),
            response=(body or "")[:400],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "safety_class": "1-request",
                   **{k: v for k, v in found.items()}}))
        if "contact" not in found:
            rows.append(make_finding(
                tool="security-txt",
                title=f"security.txt on {domain} has no Contact field",
                severity="low",
                description="File ada tetapi tanpa Contact — pelapor tidak "
                            "punya kanal resmi (melanggar RFC 9116).",
                rec="Tambahkan field Contact.",
                target_url=base + (found_at or ""),
                evidence_kind="request-response", finding_class="posture",
                status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "1-request"}))
        elif "expires" not in found:
            # Sub-check dari konsolidasi security-txt-enhanced: RFC 9116
            # menganjurkan Expires agar isi file tidak dipakai tanpa batas.
            rows.append(make_finding(
                tool="security-txt",
                title=f"security.txt on {domain} has no Expires field",
                severity="low",
                description="File ada dengan Contact tetapi tanpa Expires — "
                            "isi bisa dipakai tanpa batas waktu (RFC 9116 "
                            "menganjurkan tanggal kedaluwarsa).",
                rec="Tambahkan field Expires (RFC 9116).",
                target_url=base + (found_at or ""),
                evidence_kind="request-response", finding_class="posture",
                status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "1-request"}))
    else:
        rows.append(make_finding(
            tool="security-txt",
            title=f"No security.txt on {domain}",
            severity="low",
            description="Domain tidak publikkan security.txt — kanal "
                        "disclosure resmi tidak ditemukan via standar. "
                        "Cari manual di situs (halaman keamanan/kontak).",
            rec="Publikasikan /.well-known/security.txt (RFC 9116).",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            status="confirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"}))

    return rows, {"domain": domain, "found": bool(found),
                  "path": found_at, "fields": found or {},
                  "requests": gets}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="sectxt_findings.json")
    args = ap.parse_args()
    rows, meta = audit(args.domain)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"security-txt: {len(rows)} temuan ({meta.get('requests', 0)} GET) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
