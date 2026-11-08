"""[LEGION] Target scout — recon murah sebelum scan mahal.

Terinspirasi pola "scout" sapper-v2: 4 menit pertama dipakai mengukur
kesulitan target, lalu keputusan tenaga ikut hasil ukur — prajurit
(mass, murah) atau jenderal (assault, mahal). Dibangun from scratch untuk
secai: scout TIDAK mengeksploitasi, TIDAK menebak — dia mengirim
maksimal 2 permintaan GET jinak (/, /robots.txt), mencatat bukti mentah
per target, dan memetakan ke tier tenaga:

  SOFT        : merespons 2xx HTML cepat        -> tier0 scan penuh
  GUARDED     : 401/403/404/5xx atau redirect  -> tier0 dengan budget hemat
  UNREACHABLE : DNS gagal / refused / timeout  -> skip + baris audit
                (senada nightrun: budget 0 = SKIP tercatat, bukan senyap)

Fail-closed: satu target gagal diprobe TIDAK menghentikan sweep —
tier UNREACHABLE dengan bukti error-nya, laporan tetap keluar. Verdict
adalah HEURISTIK permukaan (bukan klaim kerentanan); keputusan tenaga
akhir tetap di operator/nightrun config.

Pemakaian:
  python tools/target_scout.py --targets targets.txt
  python tools/target_scout.py https://lab.lokal https://staging.internal
  python tools/target_scout.py --targets t.txt --json --out scout.json

Sesuai rambu repo: hanya target yang berhak kamu uji (milik sendiri /
izin tertulis / lab lokal — pasangan natural: tools/lab_target.py).
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "secai-target-scout/1.0"
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 8.0
PROBE_PATHS = ("/", "/robots.txt")
MAX_BODY_SNIP = 300

# Skor permukaan dari status respons (murni dari bukti, bukan tebakan).
STATUS_TIER = {
    "2xx": "SOFT",
    "3xx": "GUARDED",  # redirect — permukaannya di belakang pintu
    "4xx": "GUARDED",  # 401/403 = permukaan terlindungi; 404 = tidak jelas
    "5xx": "GUARDED",  # server rapuh — mass probe murah dulu, bukan tekan
}


def normalize_target(raw: str) -> str | None:
    """Normalisasi target -> origin URL (scheme://host[:port]).

    Return None kalau argumen tak bisa diurai (dilaporkan, bukan crash).
    """
    value = raw.strip()
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    parsed = urllib.parse.urlparse(value)
    if not parsed.netloc:
        return None
    origin = f"{parsed.scheme or 'http'}://{parsed.netloc}"
    return origin.rstrip("/")


def probe_target(origin: str, fetch=None) -> dict:
    """Probe jinak satu origin: maksimal len(PROBE_PATHS) permintaan GET.

    Return bukti mentah: per-path status/latency/bytes/snippet + error.
    Tanpa klaim — klasifikasi di classify_evidence().
    """
    evidence: dict = {"origin": origin, "paths": {}, "error": None}
    for path in PROBE_PATHS:
        url = origin + path
        started = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
            })
            opener = fetch or _default_fetch
            body, status, headers = opener(url)
            latency_ms = round((time.monotonic() - started) * 1000, 1)
            snippet = body[:MAX_BODY_SNIP]
            if isinstance(snippet, bytes):
                snippet = snippet.decode("utf-8", errors="replace")
            evidence["paths"][path] = {
                "status": status,
                "latency_ms": latency_ms,
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type"),
                "bytes": len(body),
                "snippet": snippet,
            }
        except Exception as exc:  # noqa: BLE001 — bukti error = data
            evidence["paths"][path] = {
                "status": None,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": f"{type(exc).__name__}: {exc}"[:200],
            }
    return evidence


def _default_fetch(url: str) -> tuple[bytes, "object", "object"]:
    """GET satu URL (timeout ketat + tidak pernah mengirim data).

    4xx/5xx = bukti status yang sah (urllib melempar HTTPError untuk
    itu — ditangkap di sini, bukan diperlakukan sebagai kegagalan probe).
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=READ_TIMEOUT) as resp:
            return resp.read(), resp.status, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return body, exc.code, dict(exc.headers or {})


def classify_evidence(evidence: dict) -> dict:
    """Bukti mentah -> tier tenaga + alasan. Murni, tanpa jaringan.

    Aturan (dokumentasi publik, mudah diaudit):
      - / gagal semua                    -> UNREACHABLE
      - / robots.txt ada tapi / gagal    -> UNREACHABLE (server hidup
                                            tapi root tak merespons —
                                            tetap butuh riset manual)
      - / 2xx                            -> SOFT
      - / 3xx/4xx/5xx                    -> GUARDED
    """
    root = evidence.get("paths", {}).get("/", {})
    status = root.get("status")
    reasons: list[str] = []
    if status is None:
        reasons.append(f"/ tidak merespons: {root.get('error', '?')}")
        tier = "UNREACHABLE"
    elif status is not None and 200 <= status < 300:
        tier = "SOFT"
        reasons.append(f"/ merespons {status} dalam {root.get('latency_ms')}ms")
    else:
        bucket = f"{status // 100}xx"
        tier = STATUS_TIER.get(bucket, "GUARDED")
        reasons.append(f"/ merespons {status}")
    suggestion = {
        "SOFT": "tier0 scan penuh (budget default)",
        "GUARDED": "tier0 budget hemat + cek permukaan manual",
        "UNREACHABLE": "skip — catat baris audit, riset DNS/rute manual",
    }[tier]
    return {"tier": tier, "reasons": reasons, "suggestion": suggestion}


def scout(targets: list[str], fetch=None) -> dict:
    """Sweep semua target -> laporan lengkap (JSON-able)."""
    results: list[dict] = []
    skipped: list[dict] = []
    for raw in targets:
        origin = normalize_target(raw)
        if not origin:
            skipped.append({"input": raw, "reason": "tidak bisa diurai"})
            continue
        evidence = probe_target(origin, fetch=fetch)
        verdict = classify_evidence(evidence)
        results.append({**verdict, "evidence": evidence})
    tiers = {"SOFT": 0, "GUARDED": 0, "UNREACHABLE": 0}
    for result in results:
        tiers[result["tier"]] += 1
    return {"scouted_at": _now_iso(), "results": results,
            "skipped": skipped, "tier_counts": tiers,
            "note": "tier = heuristik permukaan 2 permintaan GET; "
                    "bukan klaim kerentanan"}


def _now_iso() -> str:
    import datetime
    return (datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S+00:00"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scout murah: klasifikasi tier tenaga per target "
                    "(SOFT/GUARDED/UNREACHABLE) sebelum scan mahal.")
    parser.add_argument("targets", nargs="*",
                        help="URL/host target (milik sendiri/berizin/lab)")
    parser.add_argument("--targets-file", default=None,
                        help="file berisi target satu per baris")
    parser.add_argument("--json", action="store_true",
                        help="keluaran JSON penuh")
    parser.add_argument("--out", default=None,
                        help="tulis laporan JSON ke file ini")
    args = parser.parse_args(argv)

    targets = list(args.targets)
    if args.targets_file:
        lines = Path(args.targets_file).read_text(
            encoding="utf-8").splitlines()
        targets += [line for line in (l.strip() for l in lines) if line]
    if not targets:
        parser.error("berikan target posisional atau --targets-file")

    report = scout(targets)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    for result in report["results"]:
        print(f"[{result['tier']:<11}] {result['evidence']['origin']}  "
              f"({result['reasons'][0]})")
        print(f"               -> {result['suggestion']}")
    for skip in report["skipped"]:
        print(f"[SKIP       ] {skip['input']}  ({skip['reason']})")
    print(f"tier: {report['tier_counts']['SOFT']} SOFT / "
          f"{report['tier_counts']['GUARDED']} GUARDED / "
          f"{report['tier_counts']['UNREACHABLE']} UNREACHABLE"
          + (f" (+{len(report['skipped'])} skip)" if report["skipped"] else ""))
    if args.out:
        print(f"laporan : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
