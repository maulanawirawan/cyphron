"""[FLEET] fleet_dispatch — dispatch pekerjaan ke worker pool paralel.

Konsep "dispatching parallel agents" (tugas dipecah ke worker independen
dengan kontrak hasil dan kegagalan yang tercatat — populer di framework
agentic seperti obra/superpowers) diadaptasi ke bentuk yang jujur untuk
secai: WORKER POOL PROSES (multiprocessing), bukan "agent LLM" —
setiap worker menjalankan job nyata (playbook exploit / skill CLI) di
subprocess, dengan gerbang config yang sama seperti engine.

Fail-closed per job:
  - job gagal (exit != 0 / timeout / crash) TIDAK membunuh fleet;
    error tercatat di ledger dengan alasan;
  - hasil worker tanpa file output yang dideklarasikan = job FAIL
    (bukti hilang = tidak lulus, bukan "mungkin berhasil");
  - worker tanpa jobs atau pool 0 = error input (exit 2).

Kontrak job file (JSON):
  {"jobs": [
     {"id": "lab-idor", "cmd": ["python", "tools/exploit_engine.py",
                                 "--config", "cfg.json", "--out", "f.json"],
      "timeout_sec": 600, "outputs": ["f.json"]}
  ]}
  workers: jumlah paralel (default min(4, cpu)); semua job dijalankan via
  subprocess shell=False; outputs WAJIB ada setelah sukses (fresh check).

Pemakaian:
  python tools/fleet_dispatch.py --jobs jobs.json --out-dir fleet-out/
  (ledger: fleet-out/ledger.json; log per job: fleet-out/logs/<id>.log)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCHEMA = "secai.fleet-dispatch/1"
DEFAULT_TIMEOUT_SEC = 900
MAX_WORKERS = 16


def load_jobs(path: str) -> dict:
    """Baca + validasi job file; fail-closed (rusak/kosong = error)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"job file tidak ada: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"job file bukan JSON valid: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), list):
        raise ValueError("job file harus objek dengan 'jobs': [ ... ]")
    if not data["jobs"]:
        raise ValueError("jobs kosong — fleet tanpa pekerjaan = error (exit 2)")
    seen = set()
    for i, job in enumerate(data["jobs"]):
        if not isinstance(job, dict):
            raise ValueError(f"job #{i} bukan objek")
        jid = job.get("id") or f"job-{i}"
        if jid in seen:
            raise ValueError(f"id job duplikat: {jid}")
        seen.add(jid)
        cmd = job.get("cmd")
        if not isinstance(cmd, list) or not cmd or not all(
                isinstance(x, str) for x in cmd):
            raise ValueError(f"job '{jid}': cmd wajib list argv string")
    workers = int(data.get("workers") or min(4, os.cpu_count() or 4))
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers harus 1..{MAX_WORKERS}")
    return {"jobs": data["jobs"], "workers": workers}


def _run_job(job: dict, log_dir: Path) -> dict:
    """Jalankan satu job di subprocess; return baris ledger fail-closed."""
    jid = job.get("id") or "job"
    timeout = float(job.get("timeout_sec", DEFAULT_TIMEOUT_SEC))
    outputs = list(job.get("outputs") or [])
    log_path = log_dir / f"{jid}.log"
    entry = {"id": jid, "cmd": job["cmd"]}
    t0 = time.time()
    try:
        proc = subprocess.run(
            job["cmd"], capture_output=True, text=True,
            timeout=timeout, shell=False, check=False)
        exit_code, tail = proc.returncode, (proc.stdout + proc.stderr)[-2000:]
        entry["timed_out"] = False
    except subprocess.TimeoutExpired:
        exit_code, tail = None, f"timeout {timeout}s"
        entry["timed_out"] = True
    except OSError as exc:
        exit_code, tail = None, repr(exc)[:2000]
        entry["timed_out"] = False
    entry["duration_sec"] = round(time.time() - t0, 3)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path.write_text(tail, encoding="utf-8")
    entry["log"] = str(log_path)
    entry["exit_code"] = exit_code
    missing = [o for o in outputs if not Path(o).is_file()]
    if entry["timed_out"]:
        entry["status"], entry["reason"] = "FAIL", f"timeout {timeout}s"
    elif exit_code != 0:
        entry["status"] = "FAIL"
        entry["reason"] = f"exit {exit_code}"
    elif missing:
        entry["status"] = "FAIL"
        entry["reason"] = f"output hilang: {missing}"
    else:
        entry["status"], entry["reason"] = "OK", "selesai + output ada"
    return entry


def dispatch(jobs: dict, out_dir: Path) -> dict:
    """Jalankan semua job dgn worker pool; tulis ledger; return ringkasan."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir / "logs"
    ledger: list[dict] = []
    with ThreadPoolExecutor(max_workers=jobs["workers"]) as pool:
        futures = {pool.submit(_run_job, j, log_dir): j for j in jobs["jobs"]}
        for fut in as_completed(futures):
            entry = fut.result()
            ledger.append(entry)
            print(f"[fleet] [{entry['status']}] {entry['id']} "
                  f"({entry['duration_sec']}s) — {entry['reason']}")
    ledger.sort(key=lambda e: e["id"])
    ok = sum(1 for e in ledger if e["status"] == "OK")
    (out_dir / "ledger.json").write_text(
        json.dumps({"schema": SCHEMA, "total": len(ledger), "ok": ok,
                    "failed": len(ledger) - ok, "ledger": ledger},
                   indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"schema": SCHEMA, "total": len(ledger), "ok": ok,
            "failed": len(ledger) - ok, "ledger": ledger}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="fleet_dispatch — dispatch jobs ke worker pool "
                    "(fail-closed per job).")
    ap.add_argument("--jobs", required=True, help="job file JSON")
    ap.add_argument("--out-dir", default="fleet-out",
                    help="direktori output (ledger + logs)")
    args = ap.parse_args(argv)

    try:
        jobs = load_jobs(args.jobs)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[fleet] input tidak valid: {exc}", file=sys.stderr)
        return 2
    result = dispatch(jobs, Path(args.out_dir))
    print(f"[fleet] {result['ok']}/{result['total']} job OK "
          f"({result['failed']} gagal, semua tercatat di ledger)")
    # fleet selesai walau ada job gagal (fail-closed per job, bukan per fleet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
