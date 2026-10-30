"""[SAFETY: bounded-requests + LAB/program-authorized] Login rate-limit
validator — kelas temuan yang diterima triage lapangan (-> fixing).

Mengukur, bukan menyerang: N percobaan login kredensial-dummy ke SATU
endpoint yang diotorisasi operator, lalu menilai respons:
  - ada 429/lockout/captcha setelah ambang -> AMAN L0
  - tanpa throttling sampai MAX_ATTEMPTS   -> L1 lead TERUKUR
Batas keras (anti-abuse): maks 15 request total, delay antar percobaan,
wajib --lab / LAB=1 + endpoint eksplisit. Tidak ada kredensial nyata.

Pemakaian:
  python skills/rate_limit_validator.py --url https://host/login \
      --field username --field password --out f.json --lab
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402
UA = user_agent()

MAX_ATTEMPTS = 15
ATTEMPT_DELAY_S = 0.6
LOCKOUT_SIGNALS = ("429", "captcha", "locked", "too many", "throttl",
                   "blocked", "delay")


def attempt(url: str, fields: list[str], timeout: float = 15.0) -> dict:
    """SATU percobaan login kredensial-dummy; return status + sinyal."""
    payload = "&".join(f"{f.rstrip('=')}=smita-dummy-probe" for f in fields)
    data = payload.encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": UA,
                 "Content-Type": "application/x-www-form-urlencoded"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(16_000).decode("utf-8", errors="replace")
            status = r.status
    except urllib.error.HTTPError as e:
        body = (e.read(16_000) or b"").decode("utf-8", errors="replace")
        status = e.code
    except Exception as exc:
        return {"status": None, "error": f"{type(exc).__name__}: {exc}",
                "elapsed_s": round(time.perf_counter() - t0, 3)}
    elapsed = round(time.perf_counter() - t0, 3)
    blob = body.lower()
    signal = next((s for s in LOCKOUT_SIGNALS if s in blob), None)
    return {"status": status, "lockout_signal": signal,
            "elapsed_s": elapsed}


def audit(url: str, fields: list[str], attempts_results: list[dict]) \
        -> tuple[list[dict], dict]:
    rows: list[dict] = []
    n = len(attempts_results)
    throttled = [i for i, r in enumerate(attempts_results)
                 if r.get("lockout_signal") or r.get("status") == 429]
    grew = [r.get("elapsed_s", 0) for r in attempts_results]
    delay_grows = n >= 4 and grew[-1] > grew[0] * 2

    def finding(title, sev, desc, rec="", cwe=None, category="MISC",
                verdict=0):
        rows.append(make_finding(
            tool="rate-limit-validator", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe, target_url=url,
            response=json.dumps({
                "attempts": n,
                "statuses": [r.get("status") for r in attempts_results],
                "throttled_at": throttled,
                "elapsed_first_last": [grew[0] if grew else None,
                                       grew[-1] if grew else None],
            })[:400],
            evidence_kind="arithmetic", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=verdict,
            extra={"category": category, "safety_class": "bounded-requests",
                   "max_attempts": MAX_ATTEMPTS}))

    if n == 0:
        finding(f"Rate-limit probe failed on {url}", "info",
                "Tidak ada data percobaan (fail-closed).", verdict=1)
        return rows, {"url": url, "attempts": 0}

    if throttled:
        finding(f"Rate limiting ACTIVE on {url} "
                f"(throttled at attempt {throttled[0] + 1}/{n})", "info",
                "Server memberi sinyal throttle/lockout — kontrol aktif.",
                category="AMAN", verdict=0)
    elif delay_grows:
        finding(f"Rate limiting via delay on {url}", "info",
                f"Latensi respons membesar ({grew[0]}s -> {grew[-1]}s) — "
                "indikasi throttling timing-based.",
                category="AMAN", verdict=0)
    else:
        finding(f"No rate limiting on {url} after {n} attempts", "low",
                f"{n} percobaan login berurutan tanpa 429/lockout/captcha "
                "dan tanpa delay bertumbuh — kelas temuan yang DITERIMA "
                "triage nyata (program yang sama: -> fixing).",
                rec="Terapkan rate limit/lockout + backoff eksponensial.",
                cwe="CWE-307", category="WEAKNESS", verdict=1)

    return rows, {"url": url, "attempts": n, "throttled": bool(throttled),
                  "delay_grows": delay_grows, "requests": n}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="endpoint login (POST)")
    ap.add_argument("--field", action="append", default=["username", "password"],
                    help="nama field form (boleh diulang)")
    ap.add_argument("--attempts", type=int, default=10,
                    help=f"jumlah percobaan (maks {MAX_ATTEMPTS})")
    ap.add_argument("--out", default="ratelimit_findings.json")
    ap.add_argument("--lab", action="store_true")
    args = ap.parse_args()

    import os
    if not args.lab and os.environ.get("LAB") != "1":
        print("DITOLAK: butuh --lab / LAB=1 (active-probe, fail-closed)",
              file=sys.stderr)
        return 3
    n = min(args.attempts, MAX_ATTEMPTS)
    results = []
    for i in range(n):
        r = attempt(args.url, args.field)
        results.append(r)
        if r.get("status") is None:
            break  # endpoint mati -> berhenti, fail-closed
        time.sleep(ATTEMPT_DELAY_S)
    rows, meta = audit(args.url, args.field, results)
    write_findings(args.out, rows, {**meta, "safety_class": "bounded-requests",
                                    "lab": True})
    print(f"rate-limit-validator: {len(rows)} temuan "
          f"({meta.get('attempts', 0)} percobaan) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
