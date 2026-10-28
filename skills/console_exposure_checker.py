"""[SAFETY: bounded-requests] console-exposure-checker — konsol
framework/panel terbuka tanpa auth (postur/200), 5 path kandidat
dengan SIGNATURE isi (zero-FP: halaman login generik tidak dihitung):
  /actuator          -> JSON "_links" (Spring Boot Actuator)
  /actuator/env      -> "propertySources" (env terbuka — lebih berat)
  /laravel/telescope -> halaman "Telescope" (Laravel debug console)
  /_profiler         -> "Symfony Profiler" / "symfony-profiler"
  /solr/admin        -> "Solr Admin"
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
CANDIDATES = [
    ("/actuator", "spring-actuator", lambda b: "_links" in b),
    ("/actuator/env", "spring-actuator-env",
     lambda b: "propertySources" in b),
    ("/laravel/telescope", "laravel-telescope",
     lambda b: "telescope" in b.lower()),
    ("/_profiler", "symfony-profiler",
     lambda b: "symfony" in b.lower()),
    ("/solr/admin", "solr-admin", lambda b: "solr admin" in b.lower()),
]


def probe(base_url: str, timeout: float = 15.0) -> dict:
    out = {}
    for path, _n, _sig in CANDIDATES:
        req = urllib.request.Request(base_url.rstrip("/") + path,
                                     headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out[path] = {"status": r.status,
                             "body": r.read(32_000).decode("utf-8",
                                                           "replace")}
        except urllib.error.HTTPError as e:
            try:
                body = (e.read(16_000) or b"").decode("utf-8", "replace")
            except Exception:
                body = ""
            out[path] = {"status": e.code, "body": body}
        except Exception as exc:
            out[path] = {"status": None, "error": f"{type(exc).__name__}",
                         "body": ""}
    return out


def audit(base_url: str, results: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    open_consoles = []
    for path, name, sig in CANDIDATES:
        res = results.get(path, {})
        if res.get("status") == 200 and sig(res.get("body", "")):
            open_consoles.append(path)
            rows.append(make_finding(
                tool="console-exposure-checker",
                title=f"Framework console exposed on {base_url}{path} "
                      f"({name})",
                severity="high",
                description=f"Konsol '{name}' terbuka tanpa otentikasi di "
                            f"{path} (isi cocok signature — bukan halaman "
                            "login generik). Konsol debug/actuator "
                            "membocorkan konfigurasi, env var, dan bisa "
                            "menjadi pintu eskalasi.",
                recommendation="Matikan/nonaktifkan di produksi; kalau "
                               "wajib, kunci di belakang auth + network "
                               "allowlist.",
                cwe=None,
                target_url=base_url.rstrip("/") + path,
                response=str(res.get("body", ""))[:300],
                evidence_kind="request-response",
                finding_class="weakness", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "EXPOSURE",
                       "safety_class": "bounded-requests",
                       "console": name, "path": path}))
    rows.append(make_finding(
        tool="console-exposure-checker",
        title=f"Console exposure posture on {base_url}", severity="info",
        description=(f"{len(open_consoles)} konsol terbuka: "
                     f"{open_consoles}" if open_consoles else
                     "Tidak ada konsol framework terbuka pada 5 path "
                     "kandidat (AMAN/inventaris)."),
        target_url=base_url,
        response=json.dumps({p: r.get("status")
                             for p, r in results.items()})[:300],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed",
        verdict=1 if open_consoles else 0,
        extra={"category": "EXPOSURE" if open_consoles else "AMAN",
               "safety_class": "bounded-requests",
               "open": open_consoles, "checked": len(results)}))
    return rows, {"url": base_url, "requests": len(results),
                  "open": open_consoles}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="console_exposure_findings.json")
    args = ap.parse_args()
    results = probe(args.url)
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    print(f"console-exposure-checker: {len(rows)} temuan "
          f"({len(meta.get('open', []))} terbuka) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
