"""[BENCHMARK] F0 — angka dasar platform referensi + baseline runtime.

Mengukur yang bisa diukur LOKAL (tanpa Docker daemon):
  1. ukuran node_modules referensi (robocopy list-only)
  2. cold-start dev server web (waktu sampai port menjawab)
  3. cold-start worker (waktu sampai baris output pertama / gagal butuh infra)
  4. cold-start binary sidecar PyInstaller (--version, 5x median)
  5. footprint Playwright Chromium di cache user
  6. baseline startup python & bun (subprocess kosong)
Hasil: benchmarks/f0-results.json (angka mentah + metode).

Path platform pembanding lewat env CYPHRON_BENCH_REF (opsional): seksi
1-4 di-skip otomatis bila direktorinya tidak ada; seksi 5-6 jalan di
mana pun. Benchmark tidak bergantung pada mesin tertentu.
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import time
import urllib.request
from pathlib import Path

REF = Path(os.environ.get("CYPHRON_BENCH_REF", "scratch/reference-src"))
OUT = Path(__file__).resolve().parents[1] / "benchmarks" / "f0-results.json"


def measure_cmd(cmd, cwd=None, n=5):
    """Median wall-clock (detik) menjalankan cmd sampai selesai."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        subprocess.run(cmd, cwd=cwd, capture_output=True)
        times.append(time.perf_counter() - t0)
    return {"runs": [round(t, 4) for t in times],
            "median_s": round(statistics.median(times), 4)}


def dir_stats(path: Path) -> dict:
    """Ukuran direktori via robocopy list-mode ke folder sementara kosong
    (robocopy src==dest menghasilkan NOL baris — jangan dipakai)."""
    import re
    import tempfile
    t0 = time.perf_counter()
    dest = tempfile.mkdtemp(prefix="rcempty_")
    r = subprocess.run(
        ["robocopy", str(path), dest, "/L", "/S", "/NJH", "/BYTES",
         "/FP", "/NC", "/NDL", "/XJ"],
        capture_output=True, text=True, timeout=600)
    elapsed = time.perf_counter() - t0
    lines = [l for l in r.stdout.splitlines()
             if re.match(r"^\s*\d+\s+[A-Za-z]:\\", l)]
    total = 0
    for l in lines:
        m = re.match(r"^\s*(\d+)\s+", l)
        if m:
            total += int(m.group(1))
    return {"bytes": total, "files": len(lines), "measure_s": round(elapsed, 1)}


def wait_port(url: str, timeout_s: float) -> float | None:
    """Poll sampai URL menjawab; balikin elapsed atau None jika timeout.
    Poll ke 'localhost' (bukan 127.0.0.1) — vite 8 bisa bind IPv6-only.
    Per-attempt timeout panjang: SSR dev (TanStack Start/nitro) meng-compile
    on-demand pada GET pertama, jadi first-byte memang lambat di dev."""
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout_s:
        remaining = timeout_s - (time.perf_counter() - t0)
        try:
            with urllib.request.urlopen(url, timeout=min(30, remaining)) as r:
                if r.status:
                    return round(time.perf_counter() - t0, 3)
        except Exception:
            time.sleep(0.3)
    return None


def main() -> int:
    results: dict = {"date": "2026-10-06", "note": "Docker daemon MATI di mesin ini; benchmark kontainer (ZAP/postgres/redis) tidak bisa dijalankan — hanya footprint + cold-start lokal."}

    # 1. node_modules referensi
    nm = REF / "node_modules"
    if nm.exists():
        results["node_modules_ref"] = dir_stats(nm)

    # 5. Playwright chromium cache
    pw = Path.home() / "AppData/Local/ms-playwright"
    if pw.exists():
        results["playwright_cache"] = dir_stats(pw)

    # 2. web dev server cold start (vite dev langsung, tanpa turbo).
    #    Catatan Windows: bun x men-spawn child node — kill harus
    #    taskkill /T (tree) atau child bertahan dan mengunci port.
    #    Skip bila platform pembanding tidak tersedia.
    vite_port = 5219
    if not (REF / "apps/web").exists():
        results["web_dev_cold_start"] = {
            "ready_s": None,
            "skipped": f"REF '{REF}/apps/web' tidak ada — "
                       "set CYPHRON_BENCH_REF untuk mengukur",
        }
        return _worker_and_rest(results)
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        ["bun", "x", "vite", "dev", "--port", str(vite_port), "--strictPort"],
        cwd=str(REF / "apps/web"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ready = wait_port(f"http://localhost:{vite_port}/", timeout_s=300)
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                   capture_output=True)
    results["web_dev_cold_start"] = {
        "ready_s": ready,
        "method": f"bun x vite dev --port {vite_port} --strictPort; "
                  "poll GET http://localhost sampai HTTP 200 "
                  "(termasuk compile on-demand GET pertama); kill tree",
        "killed": True,
    }
    if ready is None:
        results["web_dev_cold_start"]["note"] = (
            "port tidak menjawab dalam 150s — periksa manual; "
            " kemungkinan TanStack Start dev (nitro) butuh waktu lebih "
            "atau gagal start")

    return _worker_and_rest(results)


def _worker_and_rest(results: dict) -> int:
    # 3. worker cold start (tanpa infra redis/pg): ukur waktu sampai baris
    #    output PERTAMA lalu bunuh proses — jujur dicatat kondisinya.
    #    Skip bila platform pembanding tidak tersedia.
    if not (REF / "apps/worker").exists():
        results["worker_cold_start"] = {
            "skipped": f"REF '{REF}/apps/worker' tidak ada — "
                       "set CYPHRON_BENCH_REF untuk mengukur",
        }
        return _tail(results)
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        ["bun", "src/index.ts"], cwd=str(REF / "apps/worker"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    first_line, elapsed = None, None
    try:
        for line in proc.stdout:
            if line.strip():
                elapsed = round(time.perf_counter() - t0, 3)
                first_line = line.strip()[:200]
                break
        time.sleep(1.0)  # lihat apakah berhenti sendiri (fail-fast?)
    finally:
        alive = proc.poll() is None
        proc.kill()
    results["worker_cold_start"] = {
        "first_output_at_s": elapsed,
        "first_output": first_line,
        "still_running_without_infra": alive,
        "method": "bun src/index.ts tanpa redis/pg; ukur baris pertama lalu kill",
    }

    return _tail(results)


def _tail(results: dict) -> int:
    # 4. sidecar PyInstaller cold start (skip bila tidak ada)
    exe = REF / "sidecar/cyphron/dist/cyphron.exe"
    if exe.exists():
        results["sidecar_pyinstaller"] = {
            "bytes": exe.stat().st_size,
            "startup_version": measure_cmd([str(exe), "--version"], n=5),
        }

    # 6. baseline runtime startup
    results["baseline"] = {
        "python_c": measure_cmd(["python", "-c", "pass"], n=10),
        "bun_eval": measure_cmd(["bun", "-e", "process.exit(0)"], n=10),
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(json.dumps(results, indent=2, ensure_ascii=False)[:2600])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
