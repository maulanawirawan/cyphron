"""[SAFETY: read-only] CSP analyzer from evidence headers

Analisis Content-Security-Policy dari bukti header tersimpan.
Nol request ke target; hanya membaca file evidence headers JSON
sibling (.headers) atau --headers-file eksplisit.

Checks:
  - missing CSP            -> L1 low CWE-693, category MISC
  - unsafe-inline present  -> L1 low CWE-693, category MISC
  - wildcard (*) present   -> L1 low CWE-693, category MISC
  - else                   -> AMAN info verdict 0, category AMAN
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402


def _load_headers(from_raw: str, headers_file: str | None) -> dict:
    """Load headers JSON dari --headers-file atau sibling .headers."""
    if headers_file:
        p = Path(headers_file)
        if not p.exists():
            print(f"WARN: headers-file {p} tidak ditemukan -> header kosong", file=sys.stderr)
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                return {k.lower(): v for k, v in data.items()}
            return {}
        except Exception as exc:
            print(f"WARN: headers-file {p} tidak terbaca: {exc}", file=sys.stderr)
            return {}
    hpath = Path(from_raw + ".headers")
    if not hpath.exists():
        return {}
    try:
        data = json.loads(hpath.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            return {k.lower(): v for k, v in data.items()}
        return {}
    except Exception as exc:
        print(f"WARN: header {hpath} tidak terbaca: {exc}", file=sys.stderr)
        return {}


def audit(url: str, headers: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    csp_value: str | None = None
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            csp_value = str(v)
            break

    if csp_value is None or not csp_value.strip():
        rows.append(make_finding(
            tool="csp-analyzer",
            title=f"CSP missing on {url}",
            severity="low",
            description="Respons tidak menyertakan Content-Security-Policy â€” proteksi XSS/clickjacking via CSP belum dikonfigurasi (lead, bukan kerentanan).",
            recommendation="Konfigurasi CSP minimal: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'.",
            cwe="CWE-693",
            target_url=url,
            response=json.dumps({k: headers.get(k) for k in ("content-type", "server")})[:300] if headers else "no headers",
            evidence_kind="header",
            finding_class="posture",
            confidence=1.0,
            status="confirmed",
            verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "header": "content-security-policy"},  # FAO family quorum
        ))
        return rows, {"url": url, "requests": 0, "csp_present": False}

    low = csp_value.lower()

    if "'unsafe-inline'" in low:
        rows.append(make_finding(
            tool="csp-analyzer",
            title=f"CSP contains unsafe-inline on {url}",
            severity="low",
            description=f"CSP mengandung 'unsafe-inline' yang melemahkan proteksi XSS: {csp_value[:200]}",
            recommendation="Hilangkan 'unsafe-inline'; gunakan nonce atau hash untuk inline script yang diperlukan.",
            cwe="CWE-693",
            target_url=url,
            response=csp_value[:400],
            evidence_kind="header",
            finding_class="posture",
            confidence=1.0,
            status="confirmed",
            verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "header": "content-security-policy"},  # FAO family quorum
        ))
        return rows, {"url": url, "requests": 0, "csp_present": True, "csp_value": csp_value[:300]}

    if re.search(r"(?:^|[\s;\"'])\*(?:[\s;\"']|$)", csp_value):
        rows.append(make_finding(
            tool="csp-analyzer",
            title=f"CSP contains wildcard on {url}",
            severity="low",
            description=f"CSP mengandung wildcard '*' yang terlalu permisif: {csp_value[:200]}",
            recommendation="Ganti wildcard '*' dengan daftar sumber eksplisit (mis. 'self' + domain terpercaya).",
            cwe="CWE-693",
            target_url=url,
            response=csp_value[:400],
            evidence_kind="header",
            finding_class="posture",
            confidence=1.0,
            status="confirmed",
            verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "header": "content-security-policy"},  # FAO family quorum
        ))
        return rows, {"url": url, "requests": 0, "csp_present": True, "csp_value": csp_value[:300]}

    rows.append(make_finding(
        tool="csp-analyzer",
        title=f"CSP present and restrictive on {url}",
        severity="info",
        description=f"Content-Security-Policy terkonfigurasi tanpa unsafe-inline/wildcard: {csp_value[:200]}",
        target_url=url,
        response=csp_value[:400],
        evidence_kind="header",
        finding_class="posture",
        confidence=1.0,
        status="confirmed",
        verdict=0,
        extra={"category": "AMAN", "safety_class": "read-only",
                   "header": "content-security-policy"},  # FAO family quorum
    ))
    return rows, {"url": url, "requests": 0, "csp_present": True, "csp_value": csp_value[:300]}


def main() -> int:
    ap = argparse.ArgumentParser(description="[SAFETY: read-only] CSP analyzer from evidence headers")
    ap.add_argument("--url", required=True, help="target URL (untuk label temuan)")
    ap.add_argument("--from-raw", required=True, help="path evidence HTML (sibling .headers berisi header JSON)")
    ap.add_argument("--headers-file", default=None, help="path JSON header eksplisit (override sibling)")
    ap.add_argument("--out", default="csp_findings.json", help="path output findings JSON")
    args = ap.parse_args()

    headers = _load_headers(args.from_raw, args.headers_file)
    rows, meta = audit(args.url, headers)
    meta["safety_class"] = "read-only"
    write_findings(args.out, rows, meta)
    aman = sum(1 for r in rows if r.get("category") == "AMAN")
    print(f"csp-analyzer: {len(rows)} temuan ({aman} AMAN) (0 request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
