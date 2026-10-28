"""[SAFETY: bounded-requests; OPT-IN KETAT] github-leak-check — cari
kode publik yang merujuk domain target bersama indikator secret
(CWE-798/200). OPT-IN: tanpa token di env CYPHRON_GH_TOKEN skill
MELEWATI (nol request, satu baris audit) — keputusan desain pola
program-discovery. Bounded: 1 query search code, maks 5 hasil.
Temuan = L1 lead faktual (tautan + path) — WAJIB verifikasi manual
sebelum klaim; konten file TIDAK diambil (bukan ekstraksi).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
SEARCH_URL = "https://api.github.com/search/code"
MAX_RESULTS = 5
SECRET_HINTS = ("password", "secret", "api_key", "apikey", "token",
                "passwd", "credential")


def probe(domain: str, token: str | None = None,
          timeout: float = 20.0) -> dict:
    token = token or os.environ.get("CYPHRON_GH_TOKEN", "").strip()
    if not token:
        return {"skipped": "opt-in: tanpa token (CYPHRON_GH_TOKEN kosong)",
                "items": []}
    q = f'"{domain}" ' + " OR ".join(f'"{h}"' for h in SECRET_HINTS[:3])
    req = urllib.request.Request(
        f"{SEARCH_URL}?q={urllib.parse.quote(q)}&per_page={MAX_RESULTS}",
        headers={"User-Agent": UA, "Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(64_000).decode("utf-8", "replace"))
        items = [{"html_url": it.get("html_url", ""),
                  "repository": (it.get("repository") or {})
                  .get("full_name", ""),
                  "path": it.get("path", "")}
                 for it in (data.get("items") or [])[:MAX_RESULTS]]
        return {"skipped": None, "items": items,
                "total_count": data.get("total_count", 0)}
    except urllib.error.HTTPError as e:
        return {"skipped": None, "items": [],
                "error": f"HTTP {e.code}"}
    except Exception as exc:
        return {"skipped": None, "items": [],
                "error": type(exc).__name__}


def audit(domain: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    if result.get("skipped"):
        rows.append(make_finding(
            tool="github-leak-check",
            title=f"GitHub leak check on {domain} — dilewati (opt-in)",
            severity="info",
            description=f"{result['skipped']} — skill opt-in: isi env "
                        "CYPHRON_GH_TOKEN untuk mengaktifkan (nol request "
                        "tanpa itu, fail-closed).",
            target_url=f"https://{domain}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests",
                   "opt_in": False}))
        return rows, {"domain": domain, "skipped": True, "hits": []}
    if result.get("error"):
        rows.append(make_finding(
            tool="github-leak-check",
            title=f"GitHub leak check on {domain} — gagal",
            severity="info",
            description=f"Query gagal ({result['error']}) — tidak dapat "
                        "dinilai (tanpa klaim).",
            target_url=f"https://{domain}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests",
                   "error": result["error"]}))
        return rows, {"domain": domain, "error": True, "hits": []}
    items = result.get("items") or []
    for it in items:
        rows.append(make_finding(
            tool="github-leak-check",
            title=f"Public code references {domain} ({it.get('path')})",
            severity="low",
            description=f"Kode publik merujuk '{domain}' dengan indikator "
                        f"secret di path yang sama: {it.get('html_url')} "
                        "(repo " + f"{it.get('repository')}). LEAD L1 — "
                        "wajib verifikasi manual isi file sebelum klaim "
                        "apa pun; tool ini TIDAK mengambil konten file.",
            recommendation="Bila terbocori milik target: rotasi secret, "
                           "lapor ke mekanisme VDP pemilik repo.",
            cwe="CWE-798",
            target_url=it.get("html_url") or f"https://{domain}",
            response=json.dumps(it)[:300],
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "EXPOSURE",
                   "safety_class": "bounded-requests",
                   "repository": it.get("repository"),
                   "path": it.get("path")}))
    if not rows:
        rows.append(make_finding(
            tool="github-leak-check",
            title=f"GitHub leak check on {domain}: no public hits",
            severity="info",
            description="Tidak ada hasil pencarian kode publik yang "
                        "merujuk domain + indikator secret "
                        "(AMAN/inventaris).",
            target_url=f"https://{domain}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests"}))
    return rows, {"domain": domain, "hits": [it.get("html_url")
                                             for it in items],
                  "requests": 1}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="github_leak_findings.json")
    args = ap.parse_args()
    result = probe(args.domain)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"github-leak-check: {len(meta.get('hits', []))} hit -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
