"""perf_engine — Cyphron's own load/performance testing engine (k6-class,
stdlib-only). Configurable scenarios: virtual users, duration, ramp stages,
multi-URL round-robin, custom method/headers/body. Produces RPS timeline,
latency percentiles, and status histograms.

Safety model: the ENGINE is capability, the GATE is policy. Standalone `perf`
runs require an authorization document, and CLI default profiles are bounded;
`--scenario` gives full manual control for owners running on staging."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone


def _percentile(sorted_vals: list[int], p: float) -> int:
    if not sorted_vals:
        return 0
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * p))
    return sorted_vals[idx]


def run_scenario(sc: dict) -> dict:
    """sc: {url|urls, vus, duration_s, method, headers, body, sleep_s, timeout}
    Returns metrics dict. No auth logic here — callers enforce the gate."""
    urls = sc.get("urls") or [sc["url"]]
    method = sc.get("method", "GET")
    headers = sc.get("headers") or {}
    body = sc.get("body")
    data = body.encode() if isinstance(body, str) else body
    sleep_s = float(sc.get("sleep_s", 0))
    timeout = float(sc.get("timeout", 10))
    vus = max(1, int(sc.get("vus", 1)))
    duration_s = max(1, int(sc.get("duration_s", 30)))
    stop = threading.Event()
    lock = threading.Lock()
    samples: list[tuple[float, int, int]] = []  # (t_rel, status, elapsed_ms)
    t_start = time.monotonic()

    def worker(idx: int):
        i = idx
        while not stop.is_set():
            url = urls[i % len(urls)]
            i += 1
            try:
                _s, _h, _b, elapsed = http_call(url, method, headers, data, timeout)
                status = _s
            except Exception:
                status, elapsed = 0, 0
            with lock:
                samples.append((time.monotonic() - t_start, status, elapsed))
            if sleep_s:
                time.sleep(sleep_s)

    from .tools import http_engine

    def http_call(url, method, headers, data, timeout):
        return http_engine.http_get(url, timeout=timeout, method=method,
                                    data=data, headers=headers)

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(vus)]
    for t in workers:
        t.start()
    # ramp support: kill extra VUs progressively if ramp specified
    ramp = sc.get("ramp") or []  # e.g. [{"after_s": 10, "vus": 5}, ...]
    ramp_thread = None
    if ramp:
        def apply_ramp():
            for step in ramp:
                time.sleep(float(step.get("after_s", 0)))
                target = int(step.get("vus", vus))
                if target < len(workers):
                    stop.set()
                # v1: ramp-down only via stop; ramp-up beyond initial VUs requires
                # pre-spawning max VUs — document in scenario help
        ramp_thread = threading.Thread(target=apply_ramp)
        ramp_thread.start()
    time.sleep(duration_s)
    stop.set()
    for t in workers:
        t.join()
    wall = time.monotonic() - t_start

    statuses = [s for _t, s, _e in samples]
    # request gagal jaringan (status 0, elapsed 0) tidak boleh masuk distribusi
    # latensi — target down bikin p50/p90 palsu "sehat"
    latencies = sorted(e for _t, s, e in samples if s != 0)
    ok = sum(1 for s in statuses if 200 <= s < 400)
    e4 = sum(1 for s in statuses if 400 <= s < 500)
    e5 = sum(1 for s in statuses if s >= 500)
    net = sum(1 for s in statuses if s == 0)
    buckets: dict[int, int] = {}
    for t_rel, _s, _e in samples:
        buckets[int(t_rel // 5) * 5] = buckets.get(int(t_rel // 5) * 5, 0) + 1
    hist: dict[str, int] = {}
    for s in statuses:
        key = "net-err" if s == 0 else f"{s // 100}xx"
        hist[key] = hist.get(key, 0) + 1

    return {
        "scenario": {"urls": urls, "vus": vus, "duration_s": duration_s,
                     "method": method, "sleep_s": sleep_s},
        "started_at": datetime.now(timezone.utc).isoformat(),
        "wall_s": round(wall, 2),
        "total": len(samples), "ok": ok, "4xx": e4, "5xx": e5, "net_err": net,
        "rps": round(len(samples) / wall, 2) if wall else 0,
        "rps_timeline_5s": [{"t_s": k, "count": v} for k, v in sorted(buckets.items())],
        "latency_ms": {"p50": _percentile(latencies, 0.50),
                       "p90": _percentile(latencies, 0.90),
                       "p95": _percentile(latencies, 0.95),
                       "p99": _percentile(latencies, 0.99),
                       "max": latencies[-1] if latencies else 0},
        "status_histogram": hist,
    }
