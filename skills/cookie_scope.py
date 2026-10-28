"""[SAFETY: read-only] Cookie scope audit — CWE-1004 (evidence-based).

Berbeda dari cookie-flags-aggregate (Secure/HttpOnly/SameSite): skill ini
menilai LINGKUPAN cookie — apakah Domain/Path lebih lebar dari yang
dibutuhkan sehingga cookie sensitif ikut terbawa ke permukaan lain:
  - atribut Domain diset (cookie ikut ke SEMUA subdomain) -> L1 lead
  - Path=/ untuk cookie bernama sensitif (session/auth/token/sid) -> L1
  - host-only (tanpa Domain) + path spesifik -> AMAN L0
Fail-closed: tanpa Set-Cookie = AMAN L0 (bukan lead).

Pemakaian (evidence-based, 0 request):
  python skills/cookie_scope.py --url https://host/ \
      --from-raw <evidence.json> --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SENSITIVE_NAMES = ("session", "sess", "auth", "token", "sid", "jwt",
                   "remember", "api")


def _parse_set_cookie(sval: str) -> list[dict]:
    """Satu header Set-Cookie bisa berisi beberapa cookie dipisah koma —
    pemisahan naive (per '=name,' boundary) cukup untuk audit scope."""
    cookies: list[dict] = []
    chunks, cur = [], ""
    for part in sval.split(","):
        cur = (cur + "," + part) if cur and "=" not in part.split(";")[0] \
            else part
        if "=" in cur.split(";")[0]:
            chunks.append(cur.strip())
            cur = ""
    if cur.strip():
        chunks.append(cur.strip())
    for c in chunks:
        kv = c.split(";", 1)
        name, _, value = kv[0].partition("=")
        attrs = {}
        for a in kv[1].split(";") if len(kv) > 1 else []:
            k, _, v = a.strip().partition("=")
            attrs[k.lower()] = v.strip() if v else ""
        cookies.append({"name": name.strip(), "value": value.strip(),
                        "attrs": attrs})
    return [c for c in cookies if c["name"]]


def audit(url: str, headers: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    low = {k.lower(): v for k, v in headers.items()}
    sval = str(low.get("set-cookie", "")).strip()
    cookies = _parse_set_cookie(sval)
    if not cookies:
        rows.append(make_finding(
            tool="cookie-scope", title=f"No Set-Cookie on {url}",
            severity="info",
            description="Tidak ada cookie di evidence — tidak ada lingkup "
                        "yang perlu dinilai (AMAN, bukan lead).",
            target_url=url, evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only"}))
        return rows, {"url": url, "requests": 0, "cookies": 0, "matched": False}

    from urllib.parse import urlparse
    host = urlparse(url).netloc or ""
    leads = 0
    for c in cookies:
        attrs = c["attrs"]
        name_low = c["name"].lower()
        domain = attrs.get("domain", "")
        path = attrs.get("path", "") or "/"
        sensitive = any(s in name_low for s in SENSITIVE_NAMES)
        if domain:
            rows.append(make_finding(
                tool="cookie-scope",
                title=f"Cookie '{c['name']}' memakai Domain eksplisit "
                      f"({domain}) — lingkup lintas subdomain",
                severity="low",
                description="Atribut Domain membuat cookie ikut terkirim ke "
                            "semua subdomain dalam lingkup itu — permukaan "
                            "bocor meluas bila ada subdomain berisiko "
                            "(CWE-1004).",
                recommendation="Hindari atribut Domain (host-only) kecuali "
                               "sharing lintas subdomain memang dibutuhkan.",
                cwe="CWE-1004", target_url=url,
                response=f"name={c['name']} domain={domain}",
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "read-only",
                       "cookie": c["name"], "domain": domain}))
            leads += 1
        if sensitive and path == "/":
            rows.append(make_finding(
                tool="cookie-scope",
                title=f"Cookie sensitif '{c['name']}' memakai Path=/",
                severity="low",
                description=f"Cookie bernama sensitif ({name_low}) terkirim "
                            "ke SELURUH path aplikasi — permukaan terekspos "
                            "meluas (CWE-1004).",
                recommendation="Kunci Path ke prefix yang benar-benar "
                               "membutuhkan cookie tsb.",
                cwe="CWE-1004", target_url=url,
                response=f"name={c['name']} path=/",
                evidence_kind="header", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "read-only",
                       "cookie": c["name"], "path": path}))
            leads += 1
    if leads == 0:
        rows.append(make_finding(
            tool="cookie-scope",
            title=f"Cookie scope wajar on {url} ({len(cookies)} cookie)",
            severity="info",
            description="Semua cookie host-only dan tidak ada Path=/ pada "
                        "nama sensitif — lingkup wajar (AMAN, bukan lead).",
            target_url=url,
            response="; ".join(c["name"] for c in cookies)[:300],
            evidence_kind="header", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only"}))
    return rows, {"url": url, "requests": 0, "cookies": len(cookies),
                  "matched": leads > 0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--from-raw", required=True,
                    help="file evidence headers (JSON dict)")
    ap.add_argument("--out", default="cookie_scope_findings.json")
    args = ap.parse_args()
    headers = json.loads(Path(args.from_raw).read_text(encoding="utf-8"))
    rows, meta = audit(args.url, headers)
    write_findings(args.out, rows, {**meta, "safety_class": "read-only"})
    print(f"cookie-scope: {len(rows)} temuan ({meta.get('cookies', 0)} cookie) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
