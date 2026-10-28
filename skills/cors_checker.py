"""[SAFETY: 1-request] CORS policy checker — satu GET dengan header Origin.

Menganalisis kebijakan CORS dari respons: apakah Origin asing direfleksikan
(berbahaya bila kredensial ikut), wildcard, atau tidak diizinkan.
Fail-closed: tanpa header CORS = AMAN L0 (bukan temuan).

Pemakaian:
  python skills/cors_checker.py --url https://host/ --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

UA = user_agent()
PROBE_ORIGIN = "https://evil-probe.example"


def probe(url: str, timeout: float = 20.0,
          origin_suffix: str | None = None) -> dict:
    """SATU GET membawa Origin asing (khas browser lintas origin).
    Bila origin_suffix diisi: SATU GET tambahan dengan Origin subdomain
    di bawah suffix target (uji trust wildcard-subdomain)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Origin": PROBE_ORIGIN})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = {"status": r.status,
                   "headers": {k.lower(): v for k, v in r.headers.items()}}
    except Exception as exc:
        return {"status": None, "error": f"{type(exc).__name__}: {exc}",
                "headers": {}}
    if origin_suffix:
        sub_origin = f"https://evil-probe.{origin_suffix}"
        req2 = urllib.request.Request(url, headers={
            "User-Agent": UA, "Origin": sub_origin})
        try:
            with urllib.request.urlopen(req2, timeout=timeout) as r:
                out["sub"] = {"origin": sub_origin, "status": r.status,
                              "headers": {k.lower(): v
                                          for k, v in r.headers.items()}}
        except Exception as exc:
            out["sub"] = {"origin": sub_origin, "status": None,
                          "error": f"{type(exc).__name__}",
                          "headers": {}}
    return out


def audit(url: str, result: dict,
          origin_suffix: str | None = None) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    h = result.get("headers", {})
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower()

    def finding(title, sev, desc, rec="", cwe=None, category="MISC",
                verdict=0):
        rows.append(make_finding(
            tool="cors-checker", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe, target_url=url,
            response=json.dumps({"acao": acao, "acac": acac})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=verdict,
            extra={"category": category, "safety_class": "1-request"}))

    if result.get("status") is None:
        rows.append(make_finding(
            tool="cors-checker", title=f"Fetch failed on {url}",
            severity="info", description=str(result.get("error"))[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "1-request"}))
        return rows, {"url": url, "error": True}

    if acao is None:
        finding(f"No CORS policy on {url} (safe default)", "info",
                "Respons tidak mengizinkan origin asing mana pun — "
                "default aman browser berlaku.",
                category="AMAN", verdict=0)
    elif acao.strip() == "*":
        finding(f"CORS wildcard on {url} (no credentials possible)",
                "info",
                "Access-Control-Allow-Origin: * — semua origin boleh baca, "
                "TAPI kredensial tidak bisa disertakan (browser melarang). "
                "Risiko terbatas pada data publik.",
                category="MISC", verdict=0)
    elif acao.strip() == PROBE_ORIGIN:
        if acac == "true":
            finding(f"CORS reflects arbitrary origin WITH credentials on {url}",
                    "high",
                    f"Server merefleksikan Origin asing ({PROBE_ORIGIN}) dan "
                    "mengizinkan kredensial — situs mana pun dapat membaca "
                    "data ter-autentikasi korban dari domain ini.",
                    rec="Izinkan origin eksplisit (allowlist), jangan refleksi; "
                        "kredensial hanya untuk origin terpercaya.",
                    cwe="CWE-942", category="WEAKNESS", verdict=1)
        else:
            finding(f"CORS reflects arbitrary origin on {url} "
                    "(no credentials)", "low",
                    f"Server merefleksikan Origin asing ({PROBE_ORIGIN}) "
                    "tanpa kredensial — data publik bisa dibaca lintas "
                    "origin; risiko terbatas.",
                    rec="Gunakan allowlist origin eksplisit.",
                    cwe="CWE-942", category="MISC", verdict=1)
    else:
        finding(f"CORS allowlist on {url}: {acao}", "info",
                "Origin asing tidak direfleksikan; kebijakan eksplisit.",
                category="AMAN", verdict=0)

    sub_reflected = None
    if origin_suffix and result.get("status") is not None:
        sub = result.get("sub") or {}
        sh = sub.get("headers", {})
        s_acao = sh.get("access-control-allow-origin", "")
        s_acac = sh.get("access-control-allow-credentials", "").lower()
        s_origin = sub.get("origin", "")
        if s_acao.strip() == s_origin and s_origin:
            # refleksi origin subdomain di bawah suffix = trust berbasis
            # suffix, bukan allowlist eksplisit (CWE-942)
            sub_reflected = True
            if s_acac == "true":
                finding(
                    f"CORS trusts subdomain wildcard on {url} "
                    f"({s_origin} + credentials)",
                    "medium",
                    f"Origin subdomain di bawah suffix '{origin_suffix}' "
                    "DIREFELEKSI dan diberi kredensial — allowlist yang "
                    "dipakai berbasis suffix, bukan origin eksplisit. "
                    "Subdomain yang direbut/di-host di bawah suffix itu "
                    "bisa membaca data ter-autentikasi korban.",
                    rec="Allowlist origin eksplisit per-host, jangan "
                        "pencocokan suffix.",
                    cwe="CWE-942", category="WEAKNESS", verdict=2)
            else:
                finding(
                    f"CORS trusts subdomain wildcard on {url} "
                    "(no credentials)", "low",
                    f"Origin subdomain '{s_origin}' direfleksikan tanpa "
                    "kredensial — data publik bisa dibaca dari subdomain "
                    "mana pun di bawah suffix.",
                    rec="Allowlist origin eksplisit per-host.",
                    cwe="CWE-942", category="MISC", verdict=1)
        elif result.get("sub", {}).get("status") is not None:
            sub_reflected = False
            finding(f"CORS subdomain suffix not trusted on {url}",
                    "info",
                    f"Origin subdomain '{s_origin}' TIDAK direfleksikan — "
                    "allowlist eksplisit berlaku untuk subdomain juga "
                    "(AMAN).",
                    category="AMAN", verdict=0)

    meta = {"url": url, "acao": acao, "acac": acac,
            "requests": 2 if origin_suffix else 1}
    if origin_suffix:
        meta["subdomain_reflected"] = sub_reflected
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="cors_findings.json")
    args = ap.parse_args()
    result = probe(args.url)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    print(f"cors-checker: {len(rows)} temuan -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
