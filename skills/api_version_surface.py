"""[SAFETY: bounded-requests] api-version-surface — inventaris versi API
yang hidup (maks 4 GET: /api itu sendiri + v1..v3 di bawah base-path).
Faktual: setiap respons <500 dihitung hidup. Versi lama yang masih
hidup = lead L1 inventaris (kandidat luput patch/deprecation) — BUKAN
klaim kerentanan; NOL asumsi auth/perilaku antar versi.
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
VERSIONS = ("v1", "v2", "v3")


def probe(base_url: str, base_path: str = "/api/",
          timeout: float = 15.0) -> dict:
    out: dict = {}
    paths = [base_path] + [f"{base_path}{v}/" for v in VERSIONS]
    for path in paths[:4]:
        req = urllib.request.Request(base_url.rstrip("/") + path,
                                     headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out[path] = {"status": r.status,
                             "body": r.read(16_000).decode("utf-8",
                                                           "replace")}
        except urllib.error.HTTPError as e:
            try:
                body = (e.read(16_000) or b"").decode("utf-8", "replace")
            except Exception:
                body = ""
            out[path] = {"status": e.code, "body": body}
        except Exception as exc:
            out[path] = {"status": None, "error": type(exc).__name__,
                         "body": ""}
    return out


def audit(base_url: str, results: dict) -> tuple[list[dict], dict]:
    alive: list[str] = []
    for path, res in results.items():
        st = res.get("status")
        # hidup = path ada (200/401/403); 404/410 = tidak ada; >=500 =
        # rusak, tidak dihitung
        if st in (200, 401, 403):
            alive.append(path.rstrip("/").rsplit("/", 1)[-1] or "root")
    rows: list[dict] = []
    if alive:
        rows.append(make_finding(
            tool="api-version-surface",
            title=f"API versions alive on {base_url}: "
                  f"{', '.join(alive)}",
            severity="info",
            description=f"Versi API yang merespons (<500): {alive} "
                        "(faktual, inventaris). Versi lama yang masih "
                        "hidup sering luput patch/deprecation — kandidat "
                        "pemetaan, bukan klaim kerentanan.",
            recommendation="Matikan/deprecate versi lama secara eksplisit "
                           "(410) bila tidak lagi didukung.",
            target_url=base_url,
            response=json.dumps({p: r.get("status")
                                 for p, r in results.items()})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE",
                   "safety_class": "bounded-requests",
                   "alive": alive, "checked": len(results)}))
    else:
        rows.append(make_finding(
            tool="api-version-surface",
            title=f"API version surface on {base_url}",
            severity="info",
            description="Tidak ada versi API yang merespons pada path "
                        "yang diuji (AMAN/inventaris kosong).",
            target_url=base_url,
            response=json.dumps({p: r.get("status")
                                 for p, r in results.items()})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "bounded-requests",
                   "alive": [], "checked": len(results)}))
    return rows, {"url": base_url, "alive": alive,
                  "requests": len(results)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="api_version_findings.json")
    ap.add_argument("--base-path", default="/api/")
    args = ap.parse_args()
    results = probe(args.url, args.base_path)
    rows, meta = audit(args.url, results)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"api-version-surface: {len(meta.get('alive', []))} versi hidup "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
