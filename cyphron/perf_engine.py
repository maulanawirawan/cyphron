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

    def worker(idx: int, active: threading.Event):
        i = idx
        while not stop.is_set():
            if not active.is_set():
                # VU di-pause oleh ramp-down: parkir (bukan mati), bangun
                # cepat saat ramp-up mengaktifkan lagi atau stop diset
                stop.wait(0.2)
                continue
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

    ramp = list(sc.get("ramp") or [])  # e.g. [{"after_s": 10, "vus": 5}, ...]
    max_vus = max([vus] + [int(s.get("vus", vus)) for s in ramp])
    # pre-spawn VU MAKSIMUM: ramp-up = aktifkan event, ramp-down = parkirkan
    # (dulu stop.set() mematikan SEMUA worker — ramp-down jadi beban nol dan
    # ramp-up tidak mungkin)
    events = [threading.Event() for _ in range(max_vus)]
    for e in events[:vus]:
        e.set()
    workers = [threading.Thread(target=worker, args=(i, events[i]),
                                daemon=True)
               for i in range(max_vus)]
    for t in workers:
        t.start()

    def apply_ramp():
        for step in ramp:
            if stop.wait(float(step.get("after_s", 0))):
                return  # scan selesai — jangan lanjut menunggu ramp sisanya
            target = max(0, min(int(step.get("vus", vus)), max_vus))
            for e in events[:target]:
                e.set()
            for e in events[target:]:
                e.clear()

    ramp_thread = threading.Thread(target=apply_ramp, daemon=True)
    if ramp:
        ramp_thread.start()
    stop.wait(duration_s)   # bangun segera kalau ada yang set stop
    stop.set()
    for t in workers:
        t.join(timeout=2.0)
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
