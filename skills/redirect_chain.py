"""[SAFETY: bounded-requests] Redirect chain analyzer — maksimal 5 hop.

Mengikuti rantai redirect secara manual (tanpa auto-follow) dan
menganalisis: penurunan https->http, hop lintas domain, jumlah hop
berlebihan, dan loop. Setiap hop = 1 GET, dibatasi keras MAX_HOPS.

Pemakaian:
  python skills/redirect_chain.py --url https://host/ --out f.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

UA = user_agent()
MAX_HOPS = 5


def follow(url: str, max_hops: int = MAX_HOPS) -> dict:
    """Ikuti redirect SATU per satu (bukan auto-follow) — tiap hop tercatat."""
    hops: list[dict] = []
    current = url
    for i in range(max_hops + 1):
        req = urllib.request.Request(current, headers={"User-Agent": UA})
        try:
            # no auto-follow: tangkap 3xx manual
            opener = urllib.request.build_opener(NoFollow)
            with opener.open(req, timeout=15) as r:
                hops.append({"hop": i, "url": current, "status": r.status,
                             "location": None})
                return {"hops": hops, "final": current, "loop": False,
                        "truncated": False}
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") if e.headers else None
            hops.append({"hop": i, "url": current, "status": e.code,
                         "location": loc})
            if e.code in (301, 302, 303, 307, 308) and loc and i < max_hops:
                nxt = loc if loc.startswith("http") else (
                    urlparse(current)._replace(path=loc).geturl())
                if any(h["url"] == nxt for h in hops):
                    return {"hops": hops, "final": nxt, "loop": True,
                            "truncated": False}
                current = nxt
                continue
            return {"hops": hops, "final": current, "loop": False,
                    "truncated": False}
        except Exception as exc:
            hops.append({"hop": i, "url": current, "status": None,
                         "error": f"{type(exc).__name__}: {exc}"})
            return {"hops": hops, "final": current, "loop": False,
                    "truncated": True}
    return {"hops": hops, "final": current, "loop": False, "truncated": True}


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # jangan ikuti otomatis; kita catat manual


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    hops = result.get("hops", [])

    def finding(title, sev, desc, rec="", cwe=None, category="MISC",
                verdict=0):
        rows.append(make_finding(
            tool="redirect-chain", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe, target_url=url,
            response=json.dumps(hops)[:400], evidence_kind="request-response",
            finding_class="posture", confidence=1.0, status="confirmed",
            verdict=verdict,
            extra={"category": category, "safety_class": "bounded-requests"}))

    domains = {urlparse(h["url"]).netloc for h in hops if h.get("url")}
    https_downgrade = any(
        h["url"].startswith("https://") and (h.get("location") or "").startswith("http://")
        for h in hops)
    cross_domain = len(domains) > 1
    n_hops = len([h for h in hops if h.get("status")])

    if result.get("loop"):
        finding(f"Redirect LOOP detected on {url}", "medium",
                f"Rantai redirect kembali ke URL yang sudah dikunjungi "
                f"({result['final']}) — indikasi misconfig.",
                rec="Perbaiki aturan redirect agar berhingga.",
                cwe="CWE-601", category="MISC", verdict=1)
    if https_downgrade:
        finding(f"HTTPS to HTTP downgrade in redirect chain on {url}",
                "medium",
                "Ada hop yang menurunkan https:// ke http:// — trafik "
                "pengguna bisa disadap pada hop tersebut.",
                rec="Jaga skema https di semua hop redirect.",
                cwe="CWE-319", category="MISC", verdict=1)
    if cross_domain:
        finding(f"Cross-domain redirect chain on {url} "
                f"({len(domains)} domains)", "info",
                "Rantai melewati domain lain — wajar untuk SSO/analytics, "
                "dicatat sebagai permukaan (bukan klaim).",
                category="SURFACE", verdict=0)
    if n_hops > 3:
        finding(f"Long redirect chain on {url} ({n_hops} hops)", "low",
                "Rantai redirect panjang menambah latensi dan memperlebar "
                "permukaan open-redirect.",
                rec="Sederhanakan rantai redirect.",
                cwe="CWE-601", category="MISC", verdict=1)
    if n_hops <= 1 and not result.get("loop"):
        finding(f"No redirects on {url}", "info",
                "URL langsung menjawab final tanpa redirect.",
                category="AMAN", verdict=0)
    if result.get("truncated"):
        finding(f"Redirect chain truncated at {MAX_HOPS} hops on {url}",
                "low",
                "Rantai melebihi batas aman analyzer — dihentikan "
                "(fail-closed, bukan diikuti tanpa batas).",
                category="MISC", verdict=1)

    return rows, {"url": url, "hops": hops, "domains": sorted(domains),
                  "requests": len(hops)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="redirect_findings.json")
    args = ap.parse_args()
    result = follow(args.url)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows, {**meta, "safety_class": "bounded-requests"})
    print(f"redirect-chain: {len(rows)} temuan ({len(result['hops'])} hop) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
