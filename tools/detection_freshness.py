"""[F40] Detection freshness — jawaban atas "jangan sampai jadul".

Satu perintah yang melaporkan SESEGAR APA cakupan deteksi produk:
  - intel components (nuclei-templates, KEV): umur vs TTL, jumlah
    file/entri vs manifest (drift terdeteksi = lead);
  - saran aksi konkret (perintah refresh) per komponen basi.

Bukan pengganti intel_sync — konsumen laporannya. Dengan --sync, intel
disegarkan DULU baru diukur (alur: segarkan -> ukur -> lapor).

Pemakaian:
  python tools/detection_freshness.py                 # lapor saja
  python tools/detection_freshness.py --sync          # segarkan + lapor
  python tools/detection_freshness.py --max-age-hours 48
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import intel_sync  # noqa: E402
from findings import make_finding, write_findings  # noqa: E402


def freshness_report(manifest: dict, now_epoch: float | None = None,
                     max_age_hours: float = 24.0) -> tuple[list[dict], dict]:
    """Murni: nilai umur tiap komponen intel vs ambang. Return
    (rows, meta) — laporan dalam kontrak findings."""
    now = now_epoch if now_epoch is not None else time.time()
    rows: list[dict] = []
    comps = manifest.get("components", {}) or {}
    stale: list[str] = []
    for name, ttl in intel_sync.TTL_HOURS.items():
        comp = comps.get(name) or {}
        synced_at = comp.get("synced_at")
        if not synced_at:
            rows.append(make_finding(
                tool="detection-freshness",
                title=f"Intel '{name}' belum pernah di-sync",
                severity="medium",
                description=f"Komponen intel '{name}' tidak ada di "
                            "manifest — cakupan deteksi dari sumber ini "
                            "NOL. Jalankan intel_sync untuk mengisi.",
                recommendation=f"python tools/intel_sync.py --components {name}",
                cwe="CWE-1104",
                target_url="intel:manifest",
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "INTEL-FRESHNESS", "component": name,
                       "missing": True}))
            stale.append(name)
            continue
        age_h = (now - float(synced_at)) / 3600.0
        if age_h > max_age_hours:
            stale.append(name)
            rows.append(make_finding(
                tool="detection-freshness",
                title=f"Intel '{name}' stale: {age_h:.0f} jam "
                      f"(TTL {ttl:.0f} jam)",
                severity="low",
                description=f"Terakhir disinkron {age_h/24:.1f} hari lalu "
                            f"(ambang {max_age_hours:.0f} jam) — cakupan "
                            "deteksi dari sumber ini berhenti di titik "
                            "itu; CVE/template baru setelah tanggalnya "
                            "tidak tercakup.",
                recommendation=("python tools/intel_sync.py --components "
                                + name),
                cwe="CWE-1104",
                target_url="intel:manifest",
                response=json.dumps({
                    "age_hours": round(age_h, 1),
                    "count": comp.get("template_count")
                    or comp.get("entry_count")})[:300],
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "INTEL-FRESHNESS", "component": name,
                       "age_hours": round(age_h, 1)}))
    # drift: jumlah file/entri nyata vs manifest (verify_counts balik int;
    # laporan konsolnya milik intel_sync — diamkan di sini)
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        drift_count = intel_sync.verify_counts()
    if drift_count:
        rows.append(make_finding(
            tool="detection-freshness",
            title=f"Intel drift: {drift_count} komponen tidak cocok "
                  f"manifest",
            severity="medium",
            description=f"{drift_count} komponen punya jumlah nyata di "
                        "disk yang berbeda dari manifest; sync terakhir "
                        "tidak bersih atau ada file yang "
                        "hilang/tambahan.",
            recommendation="python tools/intel_sync.py (re-sync penuh)",
            cwe="CWE-1104",
            target_url="intel:manifest",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "INTEL-FRESHNESS", "drift": True,
                   "count": drift_count}))
    if not rows:
        rows.append(make_finding(
            tool="detection-freshness",
            title="Detection coverage FRESH",
            severity="info",
            description=f"Semua komponen intel segar (<= {max_age_hours:.0f}"
                        " jam), jumlah file/entri cocok dengan manifest "
                        "(AMAN/inventaris).",
            target_url="intel:manifest",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    return rows, {"stale": stale, "drift": drift_count,
                  "components": {k: (v or {}).get("synced_at")
                                 for k, v in comps.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="findings/freshness.json")
    ap.add_argument("--sync", action="store_true",
                    help="segarkan intel dulu (intel_sync) sebelum ukur")
    ap.add_argument("--max-age-hours", type=float, default=24.0)
    args = ap.parse_args()

    if args.sync:
        print("[freshness] menyegarkan intel via intel_sync ...",
              file=sys.stderr)
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "intel_sync.py"),
             "--components", "nuclei-templates,kev,cwe,watchlist,"
                             "nvd-ranges"],
            capture_output=True, text=True, timeout=900)
        rc = r.returncode
        if rc != 0:
            print("[freshness] peringatan: sync tidak sukses penuh — "
                  "laporan tetap dibuat dari state terakhir",
                  file=sys.stderr)

    manifest = intel_sync.load_manifest()
    rows, meta = freshness_report(manifest, max_age_hours=args.max_age_hours)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "read-only"})
    print(f"detection-freshness: stale={len(meta['stale'])} "
          f"drift={meta['drift']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
