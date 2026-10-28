"""[SAFETY: bounded-requests] header-reflection-matrix — uji apakah
server memercayai header proxy-standar (CWE-348/444-adjacent), port
dari header_reflection legacy: SATU GET baseline + SATU GET per header
kandidat (maks 4) dengan nilai canary unik:
  X-Forwarded-For, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL

Zero-FP: lead hanya bila respons berubah BERMAKNA vs baseline DAN
canary muncul di respons (body/headers) ATAU status berubah —
differensial ganda. Akses-acuan yang menghormati header ini = pintu
bypass ACL/IP-allowlist -> L2 lead (verifikasi manual dalam scope).
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
HEADERS = ["X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL",
           "X-Rewrite-URL"]


def _get(url: str, extra: dict | None, timeout: float = 15.0) -> dict:
    h = {"User-Agent": UA}
    h.update(extra or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(32_000).decode("utf-8", "replace")
            return {"status": r.status, "len": len(body), "body": body,
                    "headers": {k.lower(): v for k, v in
                                r.headers.items()}}
    except urllib.error.HTTPError as e:
        try:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "len": len(body), "body": body,
                "headers": {}}
    except Exception as exc:
        return {"status": None, "len": 0, "error": str(exc)[:120],
                "body": "", "headers": {}}


def probe(url: str, canary: str, timeout: float = 15.0) -> dict:
    out = {"baseline": _get(url, None, timeout)}
    for h in HEADERS:
        out[h] = _get(url, {h: canary}, timeout)
    return out


def audit(url: str, results: dict, canary: str) \
        -> tuple[list[dict], dict]:
    rows: list[dict] = []
    base = results.get("baseline", {})
    if base.get("status") is None:
        rows.append(make_finding(
            tool="header-reflection-matrix",
            title=f"Fetch failed on {url}", severity="info",
            description=str(base.get("error"))[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC",
                   "safety_class": "bounded-requests"}))
        return rows, {"url": url, "error": True}
    honored = []
    for h in HEADERS:
        res = results.get(h, {})
        if res.get("status") is None:
            continue
        changed_status = res.get("status") != base.get("status")
        canary_in = canary in res.get("body", "") or \
            any(canary in str(v) for v in res.get("headers", {}).values())
        if (changed_status or canary_in) and res.get("len") != \
                base.get("len"):
            honored.append(h)
            rows.append(make_finding(
                tool="header-reflection-matrix",
                title=f"Proxy header honored on {url}: {h}",
                severity="medium",
                description=f"Respons BERUBAH saat header {h}: "
                            f"{canary} dikirim (canary terlihat/"
                            f"status berubah: {base.get('status')} -> "
                            f"{res.get('status')}) — server memercayai "
                            "header proxy tanpa validasi; kombinasi ini "
                            "adalah pintu klasik bypass IP-allowlist/ACL "
                            "atau cache-key manipulation (L2 lead, "
                            "verifikasi manual dalam scope).",
                recommendation="Strip/override header proxy di edge; "
                               "jangan percaya X-Forwarded-* dari "
                               "klien langsung.",
                cwe="CWE-348",
                target_url=url,
                response=f"{h}: {canary[:24]}... -> status "
                         f"{res.get('status')}",
                evidence_kind="request-response",
                finding_class="weakness", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "ACCESS-CONTROL",
                       "safety_class": "bounded-requests",
                       "header": h}))
    rows.append(make_finding(
        tool="header-reflection-matrix",
        title=f"Proxy header posture on {url}", severity="info",
        description=(f"{len(honored)} header dihormati: {honored}"
                     if honored else
                     "Tidak ada header proxy yang mengubah respons "
                     "(AMAN/inventaris)."),
        target_url=url,
        response=json.dumps({h: results[h].get("status")
                             for h in HEADERS if h in results})[:300],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed",
        verdict=1 if honored else 0,
        extra={"category": "ACCESS-CONTROL" if honored else "AMAN",
               "safety_class": "bounded-requests", "honored": honored,
               "requests": 1 + len(HEADERS)}))
    return rows, {"url": url, "requests": 1 + len(HEADERS),
                  "honored": honored, "canary": canary}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="header_reflection_findings.json")
    args = ap.parse_args()
    canary = "hdr-" + secrets.token_hex(8)
    results = probe(args.url, canary)
    rows, meta = audit(args.url, results, canary)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"header-reflection-matrix: {len(rows)} temuan "
          f"({len(meta.get('honored', []))} honored) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
