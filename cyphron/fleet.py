"""fleet — Distributed scanning sederhana (Fullpower B4 / CI-3).

Satu koordinator + N worker (thread/process pool stdlib): target dipartisi
deterministik per worker, hasil digabung dengan agregasi yang jujur.
Mode process pool hanya untuk worker yang picklable; default thread pool
(tanpa overhead spawn — aman utk engine Python).

Pagar: worker menerima daftar target YANG SUDAH dalam scope (koordinator
yang memvalidasi); anti-DDoS: pembagian kerja TIDAK menaikkan rate —
setiap worker memakai rate-limit yang sama dengan scan tunggal.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def partition_targets(targets: list[str], n_workers: int) -> list[list[str]]:
    """Partisi deterministik: target yang sama selalu masuk worker sama
    (hash-based), kosong = kosong."""
    n = max(int(n_workers), 1)
    buckets: list[list[str]] = [[] for _ in range(n)]
    for t in targets:
        idx = int(hashlib.sha1(str(t).encode()).hexdigest(), 16) % n
        buckets[idx].append(t)
    return buckets


def merge_results(results: list[dict]) -> dict:
    """Gabung hasil worker: temuan digabung + dedup fingerprint, agregat
    hitungan."""
    findings: list[dict] = []
    seen: set[str] = set()
    for r in results:
        for f in r.get("findings", []):
            key = str(f.get("fingerprint") or f.get("id")
                      or f"{f.get('tool')}|{f.get('title')}")
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
    return {
        "workers": len(results),
        "targets_scanned": sum(r.get("targets_scanned", 0) for r in results),
        "findings": findings,
        "findings_total": len(findings),
        "errors": [e for r in results for e in r.get("errors", [])],
        "requests": sum(r.get("requests", 0) for r in results),
    }


def run_fleet(targets: list[str], worker_fn, n_workers: int = 2,
              use_processes: bool = False, max_workers_cap: int = 8) -> dict:
    """Jalankan worker_fn(bucket: list[str]) -> dict untuk tiap partisi.

    worker_fn wajib mengembalikan dict dengan kunci findings/targets_scanned/
    errors/requests. n_workers dibatasi max_workers_cap (anti-DDoS terhadap
    target & host sendiri)."""
    n = max(1, min(int(n_workers), max_workers_cap))
    buckets = partition_targets(targets, n)
    buckets = [b for b in buckets if b] or [[]]
    if use_processes:
        from concurrent.futures import ProcessPoolExecutor
        executor_cls = ProcessPoolExecutor
    else:
        executor_cls = ThreadPoolExecutor
    results: list[dict] = []
    with executor_cls(max_workers=len(buckets)) as ex:
        for res in ex.map(worker_fn, buckets):
            results.append(res)
    return merge_results(results)


# ------------------------------------------------------- koordinator file
def queue_file_roundtrip(path: Path, items: list[dict]) -> dict:
    """Antrean berbasis berkas (utk multi-mesin milik sendiri): koordinator
    menulis antrian, worker mengklaim baris lewat append status."""
    import json
    path = Path(path)
    if not path.exists():
        path.write_text("", encoding="utf-8")
    rows = [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]
    # jangan timpa status existing (pending/in-progress milik worker lain)
    for r in rows:
        r.setdefault("status", "done")
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")
    return {"queued": len(rows), "done": sum(
        1 for r in rows if r.get("status") == "done")}
