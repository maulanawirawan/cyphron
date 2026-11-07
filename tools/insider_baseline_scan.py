"""[SAFETY: read-only] insider_baseline_scan — deteksi eksfiltrasi data
oleh insider dari log aktivitas file CSV: baseline volume per user,
anomali 3x baseline, z-score, aktivitas di luar jam kerja, bulk download,
deviasi peer group. NOL jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0421 + #0423 (mukul975/
Anthropic-Cybersecurity-Skills 'detecting-insider-data-exfiltration-via-
dlp' dan 'detecting-insider-threat-with-ueba' — baseline perilaku,
z-score, peer group; lisensi sumber Apache-2.0, atribusi konsep — kode
dibangun from scratch TANPA menyalin kode sumber). Skill sumber memakai
pandas + Elasticsearch (live cluster); cyphron memilih artefak offline:
SATU CSV aktivitas file/upload yang diekspor dari DLP/file server/EDR,
dianalisis stdlib csv+statistics supaya dapat dites nol jaringan.
Deteksi live (streaming watchdog, korelasi ES) tidak di-port.

Input -> mekanisme -> output:
  - Input : CSV dgn kolom wajib `timestamp`, `user`, `bytes_transferred`
            (opsional: `group` utk peer analysis, `file`, `action` —
            kolom lain diabaikan). Satu baris = satu event akses file.
  - Mekanisme: agregasi per (user, tanggal) -> baseline harian per user
            (SEMUA tanggal kecuali hari target) -> cek deterministik.
            Hari target = --day (default: tanggal maksimum di data).
  - Output: temuan {type, severity, user, day, detail, ...} + meta
            (baris valid/rusak, users, rentang tanggal, catatan) — JSON
            deterministik terurut. SEMUA temuan = LEAD perilaku, bukan
            klaim pencurian data (penjadwalan backup, migrasi proyek,
            perubahan peran bisa memenuhi pola yang sama).

Cek (threshold di-echo di output meta agar dapat diaudit):
  volume-anomaly   (high)  : total byte hari target > --mult x mean
                             baseline harian user; hanya dievaluasi bila
                             mean baseline >= --min-baseline-bytes
                             (anti-FP utk user bervolume kecil) dan user
                             punya baseline.
  zscore-anomaly   (medium): z = (total_hari - mean_hari_lain) /
                             stdev_hari_lain >= --zscore; butuh >= 4 hari
                             aktivitas utk user & stdev > 0 — kalau tidak,
                             cek dilewati + catatan (tidak pura-pura).
  off-hours        (medium): >= --off-count event di luar jendela jam
                             kerja (default < 06:00 atau >= 22:00) pada
                             hari target.
  bulk-download    (medium): >= --bulk-events event pada hari target.
  peer-deviation   (medium): hanya bila kolom `group` ada — total hari
                             target user >= --peer-mult x median teman
                             segrup (>= --peer-min user beraktivitas
                             di grup itu hari itu).

Fail-closed: file tidak ada / kolom wajib kurang / NOL baris valid ->
exit 2; baris rusak dicatat meta.bad_rows (maks 10 contoh) + catatan —
tidak pernah dihitung bersih diam-diam.

Exit: 0 selesai (temuan tetap exit 0); 2 input error.

Pemakaian:
  python tools/insider_baseline_scan.py --log file_activity.csv
  python tools/insider_baseline_scan.py --log a.csv --day 2026-03-18 \\
      --mult 3.0 --out triase.json
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

SCHEMA = "cyphron.insider-baseline-scan/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
REQUIRED_COLS = ("timestamp", "user", "bytes_transferred")
MAX_BAD_SAMPLES = 10


def _parse_ts(val: str) -> datetime | None:
    val = (val or "").strip()
    if not val:
        return None
    iso = val.replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return dt if dt.tzinfo is None else dt  # jam lokal/naif tetap dipakai


def load_activity(path: Path) -> "tuple[list[dict], list[str], list[str]]":
    """Baca CSV -> (rows valid, bad_rows, kolom). Fail-closed di pemanggil."""
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = [c for c in (reader.fieldnames or []) if c]
        missing = [c for c in REQUIRED_COLS if c not in cols]
        if missing:
            raise ValueError(f"kolom wajib kurang: {', '.join(missing)}")
        rows: list[dict] = []
        bad: list[str] = []
        for i, rec in enumerate(reader, start=2):
            ts = _parse_ts(rec.get("timestamp") or "")
            try:
                nbytes = int(float(rec.get("bytes_transferred") or "0"))
            except ValueError:
                nbytes = 0
                if (rec.get("bytes_transferred") or "").strip():
                    bad.append(f"baris {i}: bytes tidak valid")
                    continue
            if ts is None:
                bad.append(f"baris {i}: timestamp tidak valid")
                continue
            user = (rec.get("user") or "").strip()
            if not user:
                bad.append(f"baris {i}: user kosong")
                continue
            rows.append({
                "ts": ts, "user": user, "bytes": nbytes,
                "group": (rec.get("group") or "").strip(),
                "file": (rec.get("file") or "").strip(),
                "action": (rec.get("action") or "").strip(),
            })
        return rows, bad, cols


def _d(day: date) -> str:
    return day.isoformat()


def triage(rows: "list[dict]", *, target_day: date | None, mult: float,
           zscore: float, off_start: int, off_end: int, off_count: int,
           bulk_events: int, min_baseline: int, peer_mult: float,
           peer_min: int) -> dict:
    """Agregasi + cek deterministik. SEMUA temuan = LEAD."""
    notes: list[str] = []
    by_user_day: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"bytes": 0, "events": 0,
                                     "off": 0}))
    has_group = any(r["group"] for r in rows)
    for r in rows:
        d = _d(r["ts"].date())
        cell = by_user_day[r["user"]][d]
        cell["bytes"] += r["bytes"]
        cell["events"] += 1
        if r["ts"].hour < off_start or r["ts"].hour >= off_end:
            cell["off"] += 1

    if target_day is None:
        target_day = max(r["ts"].date() for r in rows)
    tgt = _d(target_day)
    all_days = sorted({d for cells in by_user_day.values()
                       for d in cells})
    if tgt not in all_days:
        notes.append(f"tidak ada aktivitas pada hari target {tgt} — "
                     "cek volume/zscore/off-hours/bulk dilewati")
    users = sorted(by_user_day)
    findings: list[dict] = []

    for u in users:
        cells = by_user_day[u]
        today = cells.get(tgt)
        other = {d: c for d, c in cells.items() if d != tgt}
        base_vals = [c["bytes"] for c in other.values()]
        base_mean = (statistics.fmean(base_vals)
                     if base_vals else 0.0)

        # volume-anomaly (butuh baseline memadai — anti-FP)
        if today is not None and base_vals:
            if base_mean < min_baseline:
                notes.append(f"{u}: mean baseline {base_mean:.0f} byte "
                             f"< {min_baseline} — volume-anomaly "
                             "dilewati (baseline kecil, rasio tak bermakna)")
            elif today["bytes"] > mult * base_mean:
                findings.append({
                    "type": "volume-anomaly", "severity": "high",
                    "user": u, "day": tgt,
                    "detail": f"upload {today['bytes']} byte "
                              f"> {mult}x mean baseline "
                              f"({base_mean:.0f} byte/hari)",
                    "today_bytes": today["bytes"],
                    "baseline_mean_bytes": round(base_mean, 1),
                })
        elif today is not None and not base_vals:
            notes.append(f"{u}: hanya beraktivitas pada hari target — "
                         "tanpa baseline, cek volume dilewati")

        # z-score (butuh >= 4 hari & stdev > 0)
        if today is not None and len(base_vals) >= 3:
            sd = statistics.pstdev(base_vals)
            if sd > 0:
                z = (today["bytes"] - statistics.fmean(base_vals)) / sd
                if z >= zscore:
                    findings.append({
                        "type": "zscore-anomaly", "severity": "medium",
                        "user": u, "day": tgt,
                        "detail": f"z-score {z:.2f} >= {zscore} vs hari "
                                  "lainnya",
                        "z": round(z, 2),
                    })
            else:
                notes.append(f"{u}: stdev baseline nol — z-score "
                             "dilewati (aktivitas harian identik)")
        elif today is not None:
            notes.append(f"{u}: {len(base_vals)} hari baseline (< 3) — "
                         "z-score dilewati")

        if today is None:
            continue

        # off-hours
        if today["off"] >= off_count:
            findings.append({
                "type": "off-hours", "severity": "medium",
                "user": u, "day": tgt,
                "detail": f"{today['off']} event di luar jam kerja "
                          f"(>= {off_count}) — jendela aktif "
                          f"{off_start:02d}:00-{off_end:02d}:00",
                "off_hours_events": today["off"],
            })
        # bulk-download
        if today["events"] >= bulk_events:
            findings.append({
                "type": "bulk-download", "severity": "medium",
                "user": u, "day": tgt,
                "detail": f"{today['events']} event akses file pada hari "
                          f"target (>= {bulk_events}) — kandidat mass "
                          "download",
                "events": today["events"],
            })

    # peer-deviation: median dari peer AKTIF (>= min_baseline) hari itu,
    # KECUALI user yang dievaluasi — user pasif tak memaknai median
    if has_group and all_days:
        user_group: dict[str, str] = {}
        for u in users:
            user_group[u] = next((r["group"] for r in rows
                                  if r["user"] == u and r["group"]), "")
        grp_users: dict[str, list[str]] = defaultdict(list)
        for u, g in user_group.items():
            if g:
                grp_users[g].append(u)
        if not grp_users:
            notes.append("kolom group ada tapi tak terisi — "
                         "peer-deviation dilewati")
        flagged_groups = 0
        for grp, members in sorted(grp_users.items()):
            active = {u: by_user_day[u].get(tgt, {"bytes": 0})["bytes"]
                      for u in members}
            active = {u: t for u, t in active.items()
                      if t >= min_baseline}
            if len(active) < peer_min:
                flagged_groups += 1
                continue
            for u in sorted(members):
                others = [t for u2, t in active.items() if u2 != u]
                # median "others" bermakna utk >= 2 nilai (peer_min-1, min 2)
                if len(others) < max(2, peer_min - 1):
                    continue
                med = statistics.median(others)
                tot = by_user_day[u].get(tgt, {"bytes": 0})["bytes"]
                if tot >= peer_mult * med:
                    findings.append({
                        "type": "peer-deviation", "severity": "medium",
                        "user": u, "day": tgt, "group": grp,
                        "detail": f"total {tot} byte >= "
                                  f"{peer_mult}x median teman segrup "
                                  f"aktif ({med:.0f} byte)",
                        "user_bytes": tot,
                        "peer_median_bytes": round(med, 1),
                    })
        if flagged_groups:
            notes.append(f"{flagged_groups} grup punya < {peer_min} peer "
                         "aktif (>= min-baseline) pada hari target — "
                         "peer-deviation dilewati untuk grup itu")
    elif not has_group:
        notes.append("kolom group tidak tersedia — peer-deviation "
                     "dilewati (UEBA peer group butuh atribusi departemen)")

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["type"],
                                 f["user"]))
    meta = {
        "rows_valid": len(rows),
        "users": len(users),
        "days_covered": len(all_days),
        "target_day": tgt,
        "date_range": [all_days[0], all_days[-1]] if all_days else [],
        "thresholds": {
            "volume_mult": mult, "zscore": zscore,
            "off_window": [off_start, off_end], "off_count": off_count,
            "bulk_events": bulk_events, "min_baseline_bytes": min_baseline,
            "peer_mult": peer_mult, "peer_min": peer_min,
        },
        "has_group_column": has_group,
    }
    return {
        "schema": SCHEMA, "meta": meta, "notes": notes,
        "findings": findings,
        "verdict": ("INDICATORS_FOUND" if findings
                    else "CLEAN_NO_BEHAVIORAL_LEAD"),
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Baseline perilaku insider dari log aktivitas file "
                    "CSV (LEAD — bukan klaim pencurian data).")
    ap.add_argument("--log", required=True,
                    help="CSV aktivitas file/upload (timestamp, user, "
                         "bytes_transferred[, group, file, action])")
    ap.add_argument("--day", help="hari target YYYY-MM-DD "
                                  "(default: tanggal maksimum data)")
    ap.add_argument("--mult", type=float, default=3.0,
                    help="multiplier volume anomaly (default 3.0)")
    ap.add_argument("--zscore", type=float, default=3.0,
                    help="ambang z-score (default 3.0)")
    ap.add_argument("--off-start", type=int, default=6,
                    help="jam mulai kerja (default 6)")
    ap.add_argument("--off-end", type=int, default=22,
                    help="jam selesai kerja (default 22)")
    ap.add_argument("--off-count", type=int, default=5,
                    help="min event off-hours utk lead (default 5)")
    ap.add_argument("--bulk-events", type=int, default=200,
                    help="min event/hari utk bulk-download (default 200)")
    ap.add_argument("--min-baseline-bytes", type=int, default=1_000_000,
                    help="baseline mean minimum utk cek volume (default "
                         "1 MB/hari — anti-FP user kecil)")
    ap.add_argument("--peer-mult", type=float, default=10.0,
                    help="multiplier deviasi peer (default 10.0)")
    ap.add_argument("--peer-min", type=int, default=3,
                    help="min peer per grup (default 3)")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    p = Path(args.log)
    try:
        if not p.is_file():
            raise ValueError(f"file tidak ada: {p}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"file melebihi {MAX_FILE_BYTES} byte")
        rows, bad, _ = load_activity(p)
        if not rows:
            raise ValueError(f"{p.name}: nol baris aktivitas valid")
        tday = None
        if args.day:
            try:
                tday = date.fromisoformat(args.day)
            except ValueError:
                raise ValueError(f"--day bukan tanggal valid: {args.day}")
    except ValueError as exc:
        print(f"[insider-baseline-scan] input error: {exc}",
              file=sys.stderr)
        return 2

    result = triage(
        rows, target_day=tday, mult=args.mult, zscore=args.zscore,
        off_start=args.off_start, off_end=args.off_end,
        off_count=args.off_count, bulk_events=args.bulk_events,
        min_baseline=args.min_baseline_bytes, peer_mult=args.peer_mult,
        peer_min=args.peer_min)
    if bad:
        result["meta"]["bad_rows_count"] = len(bad)
        result["meta"]["bad_rows_sample"] = bad[:MAX_BAD_SAMPLES]
        result["notes"].append(
            f"{len(bad)} baris rusak TIDAK dianalisis — jumlahnya dihitung "
            "eksplisit, tidak dianggap bersih diam-diam")
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
