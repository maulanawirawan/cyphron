"""[SAFETY: read-only] HTTP security headers — skill kanonik keluarga header.

Satu skill untuk seluruh keluarga header keamanan (konsolidasi F18):
  - presence/absence 6 header utama (HSTS, CSP, XFO, XCTO,
    Referrer-Policy, Permissions-Policy) dengan severity per header
  - sub-check disclosure: bocor versi via Server & X-Powered-By
    (CWE-200) — bekas header-leak-detector + x-powered-by-leak

Mode read-only: 100% dari evidence tersimpan (banner_posture --save-raw).
NOL request ke target. Input: sibling .headers JSON atau --headers-file.

Pemakaian:
  python skills/http_security_headers.py --url https://example.go.id/ \\
      --from-raw evidence/banner.html --out findings/hsh.json
  # header JSON eksplisit:
  python skills/http_security_headers.py --url https://example.go.id/ \\
      --headers-file evidence/banner.html.headers --out findings/hsh.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

TOOL = "http-security-headers"

# (header_lower, Label, CWE, severity_when_missing, recommendation)
SECURITY_HEADERS: list[tuple[str, str, str, str, str]] = [
    ("strict-transport-security", "Strict-Transport-Security", "CWE-319", "medium",
     "Setel Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", "CWE-693", "low",
     "Setel CSP minimal: default-src 'self'; frame-ancestors 'none'; object-src 'none'"),
    ("x-frame-options", "X-Frame-Options", "CWE-1021", "low",
     "Setel X-Frame-Options: DENY atau frame-ancestors via CSP"),
    ("x-content-type-options", "X-Content-Type-Options", "CWE-693", "low",
     "Setel X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer-Policy", "CWE-693", "info",
     "Setel Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Permissions-Policy", "CWE-693", "info",
     "Setel Permissions-Policy untuk membatasi fitur browser sensitif"),
]

# Sub-check disclosure (bekas header-leak-detector & x-powered-by-leak):
# header yang nilainya memuat versi = bocor info versi (CWE-200).
VERSION_RE = re.compile(r"/\d+\.\d+|\d+\.\d+\.\d+")
DISCLOSURE_HEADERS: list[tuple[str, str, str]] = [
    ("server", "Server", "Sembunyikan versi di Server header (mis. Server: apache tanpa nomor versi)"),
    ("x-powered-by", "X-Powered-By", "Hapus header X-Powered-By dari respons produksi"),
]


def load_headers(from_raw: str | None, headers_path: str | None) -> dict:
    """Load header JSON dari --headers-file atau sibling <from-raw>.headers.
    Fail-soft: file tak ada/tak terbaca -> dict kosong + WARN di stderr
    (temuan absence tetap dihitung dari headers yang TERLIHAT saja)."""
    path = Path(headers_path) if headers_path else (
        Path(str(from_raw) + ".headers") if from_raw else None)
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        print(f"WARN: header {path} tidak terbaca: {exc}", file=sys.stderr)
        return {}
    if isinstance(data, dict):
        return {str(k).lower(): v for k, v in data.items()}
    return {}


def audit(url: str, headers: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    low = {k.lower(): v for k, v in headers.items()}
    present: list[str] = []
    missing: list[str] = []

    for key, label, cwe, sev_missing, rec in SECURITY_HEADERS:
        val = low.get(key)
        # HSTS hanya relevan untuk https — untuk http, absen bukan temuan
        if key == "strict-transport-security" and not url.lower().startswith("https://"):
            continue
        if val:
            present.append(label)
            rows.append(make_finding(
                tool=TOOL,
                title=f"Security header present on {url}: {label}",
                severity="info",
                description=f"{label}: {str(val)[:160]}",
                target_url=url,
                response=f"{label}: {str(val)[:200]}",
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class": "read-only", "header": key}))
        else:
            missing.append(label)
            rows.append(make_finding(
                tool=TOOL,
                title=f"Security header absent on {url}: {label}",
                severity=sev_missing,  # type: ignore[arg-type]
                description=f"Respons tidak menyertakan {label} — pengerasan header belum lengkap (lead, bukan kerentanan).",
                recommendation=rec,
                cwe=cwe, target_url=url,
                response=f"headers present: {sorted(low.keys())}",
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "read-only", "header": key}))

    # --- sub-check disclosure: versi di Server / X-Powered-By ---
    for key, label, rec in DISCLOSURE_HEADERS:
        sval = str(low.get(key, "") or "").strip()
        if sval and VERSION_RE.search(sval):
            rows.append(make_finding(
                tool=TOOL,
                title=f"Version leak via {label} on {url}: {sval[:80]}",
                severity="low",
                description=f"Header {label} membocorkan versi: {sval[:200]} (lead).",
                recommendation=rec,
                cwe="CWE-200", target_url=url,
                response=sval[:300],
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "read-only", "header": key}))
        else:
            rows.append(make_finding(
                tool=TOOL,
                title=f"No version leak via {label} on {url}",
                severity="info",
                description=f"Header {label} tidak membocorkan versi — AMAN.",
                target_url=url,
                response=sval[:200] or "no header",
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "AMAN", "safety_class": "read-only", "header": key}))

    # Ringkasan agregat — 1 finding tambahan untuk dashboard
    total = len(present) + len(missing)
    if missing:
        rows.append(make_finding(
            tool=TOOL,
            title=f"Security headers posture on {url}: {len(present)}/{total} present",
            severity="low" if len(missing) >= 2 else "info",
            description=f"Hadir: {', '.join(present) or '-'}; "
                        f"Absen: {', '.join(missing) or '-'} — "
                        f"{len(missing)} header belum disetel (lead).",
            target_url=url,
            response=json.dumps({"present": present, "missing": missing}, ensure_ascii=False)[:500],
            evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "family": "header", "present": present, "missing": missing}))
    else:
        rows.append(make_finding(
            tool=TOOL,
            title=f"Security headers complete on {url}: {len(present)}/{total} present",
            severity="info",
            description=f"Semua header keamanan utama hadir: {', '.join(present)}.",
            target_url=url,
            response=json.dumps({"present": present}, ensure_ascii=False)[:400],
            evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only",
                   "family": "header", "present": present}))

    meta = {"url": url, "present": present, "missing": missing,
            "headers_seen": sorted(low.keys()), "requests": 0}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="target URL (label temuan)")
    ap.add_argument("--from-raw", default=None,
                    help="HTML evidence tersimpan (sibling .headers berisi JSON)")
    ap.add_argument("--headers-file", default=None,
                    help="path JSON headers eksplisit (override sibling)")
    ap.add_argument("--out", default="hsh_findings.json", help="path findings.json output")
    args = ap.parse_args()
    headers = load_headers(args.from_raw, args.headers_file)
    rows, meta = audit(args.url, headers)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    aman = sum(1 for r in rows if r.get("category") == "AMAN")
    print(f"{TOOL}: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
