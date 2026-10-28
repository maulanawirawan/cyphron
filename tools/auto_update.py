"""[F67][SAFETY: read-only] Intel auto-update — satu perintah untuk
menyegarkan SEMUA komponen intel (TTL-gated) lalu melaporkan
kesehatan cakupan deteksi dalam kontrak findings.

Alur: sync semua komponen -> freshness_report -> findings.json.
Komponen: nuclei-templates, kev, cwe, watchlist, nvd-ranges.
Gagal satu komponen TIDAK menghapus state lama (fail-closed) dan
dicatat sebagai lead L1 (bukan crash).

Bisa dijadwalkan harian tanpa manual:
  python tools/auto_update.py --install-schedule                 # 01:30 harian
  python tools/auto_update.py --install-schedule 01:30 --interval-hours 6
  python tools/auto_update.py --remove-schedule
  python tools/auto_update.py --check                       # lapor saja
  python tools/auto_update.py --force                       # abaikan TTL

Pemakaian harian:
  python tools/auto_update.py
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import detection_freshness  # noqa: E402
import intel_sync  # noqa: E402
from findings import make_finding, write_findings  # noqa: E402

TASK_NAME = "cyphron-intel-daily"
DEFAULT_COMPONENTS = ("nuclei-templates", "kev", "cwe", "watchlist",
                      "nvd-ranges")

COMPONENTS = {
    "nuclei-templates": lambda force: intel_sync.sync_nuclei_templates(force),
    "kev": lambda force: intel_sync.sync_kev(force),
    "cwe": lambda force: intel_sync.sync_cwe(force),
    "watchlist": lambda force: intel_sync.sync_watchlist(force),
    "nvd-ranges": lambda force: intel_sync.sync_nvd_ranges(force),
}


def run_once(components: list[str] | None = None, force: bool = False,
             out: str | Path | None = None) -> tuple[dict, list, dict, Path]:
    """Sync (TTL-gated) + freshness + findings. Tidak pernah crash
    karena satu komponen — error dicatat per komponen."""
    names = components or list(DEFAULT_COMPONENTS)
    results: dict = {}
    for name in names:
        fn = COMPONENTS.get(name)
        if fn is None:
            results[name] = {"error": "komponen tidak dikenal"}
            continue
        try:
            results[name] = fn(force)
        except Exception as exc:  # noqa: BLE001
            results[name] = {
                "error": f"{type(exc).__name__}: {exc}"[:200]}

    manifest = intel_sync.load_manifest()
    rows, meta = detection_freshness.freshness_report(manifest)
    for name, res in results.items():
        if res.get("error"):
            rows.append(make_finding(
                tool="intel-autoupdate",
                title=f"Auto-update '{name}' gagal — state lama "
                      f"dipertahankan",
                severity="medium",
                description=f"Sync {name} error: {res['error']}. "
                            "Fail-closed: file lama tidak ditimpa; "
                            "cakupan deteksi memakai versi terakhir "
                            "yang baik sampai sync berikutnya sukses.",
                recommendation="python tools/intel_sync.py --components "
                               f"{name} --force",
                target_url="intel:manifest",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "INTEL-AUTOUPDATE",
                       "component": name, "error": res["error"]}))

    out_path = (Path(out) if out else
                ROOT / "findings" / "intel" / "status.json")
    sync_meta = {}
    for k, v in results.items():
        sync_meta[k] = {kk: vv for kk, vv in v.items()
                        if kk in ("synced", "skipped", "reason",
                                  "entry_count", "template_count",
                                  "delta_from_prev", "error", "version")}
    write_findings(out_path, rows, {
        **meta, "run": "intel-autoupdate", "components": names,
        "results": sync_meta, "safety_class": "read-only",
        "requests": 0,
    })
    return results, rows, meta, out_path


def install_schedule(hhmm: str = "01:30",
                     interval_hours: int = 0) -> dict:
    """Daftarkan task Windows (interactive-only, tanpa password).
    interval_hours 1..23 = ulang tiap N jam; 0 = harian."""
    if os.name != "nt":
        return {"ok": False,
                "error": "schtasks hanya tersedia di Windows"}
    tr = (f'"{sys.executable}" '
          f'"{ROOT / "tools" / "auto_update.py"}" --quiet')
    sched = (["/SC", "HOURLY", "/MO", str(interval_hours)]
             if 1 <= interval_hours <= 23 else ["/SC", "DAILY"])
    cmd = ["schtasks", "/Create", "/TN", TASK_NAME, *sched,
           "/ST", hhmm, "/IT", "/F", "/TR", tr]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return {"ok": r.returncode == 0, "task": TASK_NAME,
            "time": hhmm, "interval_hours": interval_hours,
            "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}


def remove_schedule() -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "schtasks hanya tersedia di Windows"}
    r = subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                       capture_output=True, text=True)
    return {"ok": r.returncode == 0, "task": TASK_NAME,
            "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--components", default=",".join(DEFAULT_COMPONENTS))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="lapor freshness saja, tanpa sync")
    ap.add_argument("--out", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--install-schedule", nargs="?", const="01:30",
                    default=None, metavar="HH:MM")
    ap.add_argument("--interval-hours", type=int, default=0,
                    help="ulang tiap N jam (1-23); 0 = harian")
    ap.add_argument("--remove-schedule", action="store_true")
    args = ap.parse_args()

    if args.remove_schedule:
        res = remove_schedule()
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("ok") else 2
    if args.install_schedule:
        res = install_schedule(args.install_schedule,
                               args.interval_hours)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("ok") else 2

    if args.check:
        manifest = intel_sync.load_manifest()
        rows, meta = detection_freshness.freshness_report(manifest)
        print(json.dumps({"stale": meta["stale"],
                          "drift": meta["drift"],
                          "synced_at": meta["components"]},
                         indent=2, ensure_ascii=False))
        return 0

    names = [c.strip() for c in args.components.split(",") if c.strip()]
    results, rows, meta, out_path = run_once(names, args.force, args.out)
    if not args.quiet:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"intel-autoupdate: stale={len(meta['stale'])} "
          f"drift={meta['drift']} -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
