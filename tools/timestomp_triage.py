r"""[SAFETY: read-only] timestomp_triage — deteksi OFFLINE timestomping
(T1070.006) dari perbandingan timestamp $STANDARD_INFORMATION (SI, 0x10)
vs $FILE_NAME (FN, 0x30) pada entri MFT. TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0542 (mukul975/
Anthropic-Cybersecurity-Skills 'hunting-for-defense-evasion-via-
timestomping'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun
FROM SCRATCH: parser CSV/JSON + logika perbandingan ditulis sendiri
dari konsep deteksi publik (properti atribut NTFS yang terdokumentasi:
SI bisa diubah user-mode, FN hanya di-update driver NTFS kernel-mode).
Skill sumber memakai pandas; cyphron stdlib-only (csv + datetime).

Input -> mekanisme -> output:
  - Input : (a) CSV hasil MFTECmd (Eric Zimmerman) dgn kolom
            Created0x10/LastModified0x10/Created0x30/LastRecordChange0x10
            + FileName/ParentPath, ATAU (b) JSON output tools/mft_scan.py
            (entri times{si_*} + FN created/modified) — komposisi
            $MFT -> mft_scan -> tool ini.
  - Mekanisme: per baris, bandingkan urutan timestamp SI vs FN.
  - Output: temuan {check, severity, path, nilai timestamp, delta}
            + stats + notes.

Cek (verdict = LEAD — korelasikan dgn USN Journal/$LogFile/ShimCache
sebelum disimpulkan; skill sumber eksplisit: JANGAN jadikan satu
metode tunggal):
  si-created-before-fn        (high)   : SI Created < FN Created — SI
                                          didorong mundur oleh alat
                                          user-mode (Timestomp/
                                          SetMACE/Set-ItemProperty);
                                          normal NTFS: SI >= FN.
  si-modified-before-fn-creat (high)   : SI Modified < FN Created —
                                          file tak mungkin dimodifikasi
                                          sebelum namanya diciptakan.
  zero-precision-si           (medium) : SI timestamp ber-nanodetik
                                          NOL padahal FN punya presisi
                                          nanodetik normal — artefak
                                          alat timestomping (hanya
                                          tersedia pada input CSV
                                          MFTECmd; JSON mft_scan
                                          presisi detik -> cek ini
                                          dilewati dgn catatan).
  Anti-FP: --min-delta-seconds (default 1.0) — deviasi di bawah
  ambang dihitung noise resolusi dan TIDAK ditandai; jumlah baris
  yang disaring dgn alasan ini dicatat di stats.

Fail-closed:
  - CSV tanpa kolom wajib / JSON bukan output mft_scan -> exit 2.
  - Baris dgn timestamp kosong/tidak ter-parse dihitung di
    stats.skipped_missing_ts (tidak dipendam, tidak dianggap bersih).
  - Tidak ada baris valid di semua input -> exit 2.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/timestomp_triage.py --csv mft_parsed.csv
  python tools/timestomp_triage.py --mft-json mft.json
  python tools/timestomp_triage.py --csv mft.csv --min-delta-seconds 5
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "cyphron.timestomp-triage/1"
MAX_FILE_BYTES = 512 * 1024 * 1024

CSV_TS_COLS = {
    "si_created": "Created0x10",
    "si_modified": "LastModified0x10",
    "fn_created": "Created0x30",
    "fn_modified": "LastModified0x30",
    "si_mft_modified": "LastRecordChange0x10",
    "fn_mft_modified": "LastRecordChange0x30",
}

TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_ts(raw: str | None) -> "tuple[datetime | None, bool]":
    """Parse timestamp CSV/ISO -> (dt UTC, nanodetik_semua_nol).

    Pecahan 7 digit (100ns) dipotong ke mikrodetik utk aritmetika, tapi
    informasi 'semua nol' tetap dipertahankan utk cek presisi. None bila
    kosong/tidak ter-parse (baris dihitung skipped, bukan bersih).
    """
    if not raw or not raw.strip():
        return None, False
    m = TS_RE.match(raw.strip())
    if m is None:
        return None, False
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    tz = m.group(8)
    if y <= 1601 and mo == 1 and d == 1:
        # epoch FILETIME mentah = atribut kosong
        return None, False
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    except ValueError:
        return None, False
    micros = int((frac + "000000")[:6]) if frac else 0
    dt = dt.replace(microsecond=micros)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        dt = datetime.fromtimestamp(
            dt.timestamp() - sign * (hh * 3600 + mm * 60),
            tz=timezone.utc)
    return dt, bool(frac) and set(frac) == {"0"}


def _mk_path(row: dict) -> str:
    parent = (row.get("ParentPath") or "").strip()
    name = (row.get("FileName") or "").strip()
    if parent and name:
        return f"{parent}\\{name}"
    return name or "(nama tak tersedia)"


def _delta_s(a: datetime, b: datetime) -> float:
    return (b - a).total_seconds()


def analyze_csv(path: Path, min_delta: float) -> tuple[list[dict], dict,
                                                       list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    stats = {"rows": 0, "checked": 0, "skipped_missing_ts": 0,
             "below_delta_threshold": 0}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = set(reader.fieldnames or [])
        missing = [c for c in CSV_TS_COLS.values() if c not in cols]
        if missing:
            raise ValueError(
                f"CSV bukan hasil MFTECmd — kolom hilang: {missing}")
        for row in reader:
            stats["rows"] += 1
            parsed: dict[str, datetime | None] = {}
            zero_nano: dict[str, bool] = {}
            for key, col in CSV_TS_COLS.items():
                dt, zns = parse_ts(row.get(col))
                parsed[key] = dt
                zero_nano[key] = zns
            if any(v is None for v in parsed.values()):
                stats["skipped_missing_ts"] += 1
                continue
            stats["checked"] += 1
            p = _mk_path(row)
            f = _compare(parsed, zero_nano, p, min_delta, stats,
                         precision="nanosecond")
            findings.extend(f)
    return findings, stats, notes


def _compare(parsed: dict, zero_nano: dict, path: str, min_delta: float,
             stats: dict, precision: str) -> list[dict]:
    out: list[dict] = []
    si_c, fn_c = parsed["si_created"], parsed["fn_created"]
    si_m = parsed["si_modified"]
    if si_c and fn_c and si_c < fn_c:
        delta = _delta_s(si_c, fn_c)
        if delta >= min_delta:
            out.append({
                "check": "si-created-before-fn", "severity": "high",
                "path": path, "si_created": si_c.isoformat(),
                "fn_created": fn_c.isoformat(), "delta_s": round(delta, 3),
                "message": f"SI Created ({si_c.isoformat()}) lebih LAMA "
                           f"{delta:.3f}s daripada FN Created "
                           f"({fn_c.isoformat()}) — SI didorong mundur "
                           "(T1070.006; korelasi USN/$LogFile/ShimCache "
                           "utk konfirmasi)",
            })
        else:
            stats["below_delta_threshold"] += 1
    if si_m and fn_c and si_m < fn_c:
        delta = _delta_s(si_m, fn_c)
        if delta >= min_delta:
            out.append({
                "check": "si-modified-before-fn-created",
                "severity": "high", "path": path,
                "si_modified": si_m.isoformat(),
                "fn_created": fn_c.isoformat(),
                "delta_s": round(delta, 3),
                "message": f"SI Modified ({si_m.isoformat()}) lebih LAMA "
                           f"daripada FN Created ({fn_c.isoformat()}) — "
                           "mustahil pada perilaku NTFS normal "
                           "(T1070.006)",
            })
        else:
            stats["below_delta_threshold"] += 1
    if precision == "nanosecond" and si_c and zero_nano.get("si_created") \
            and not zero_nano.get("fn_created"):
        out.append({
            "check": "zero-precision-si", "severity": "medium",
            "path": path, "si_created": si_c.isoformat(),
            "message": "SI Created ber-nanodetik NOL sementara FN "
                       "memiliki presisi nanodetik normal — artefak "
                       "khas alat timestomping (lead)",
        })
    return out


def analyze_mft_json(path: Path, min_delta: float) -> tuple[list[dict],
                                                            dict,
                                                            list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    stats = {"rows": 0, "checked": 0, "skipped_missing_ts": 0,
             "below_delta_threshold": 0}
    doc = json.loads(path.read_text(encoding="utf-8"))
    entries = doc.get("entries") if isinstance(doc, dict) else doc
    if not isinstance(entries, list):
        raise ValueError("JSON bukan output mft_scan (butuh daftar "
                         "'entries')")
    notes.append(
        "Input mft_scan JSON ber-presisi detik: cek zero-precision-si "
        "dilewati eksplisit (gunakan CSV MFTECmd utk cek penuh).")
    for e in entries:
        if not isinstance(e, dict):
            continue
        stats["rows"] += 1
        times = e.get("times") or {}
        parsed = {
            "si_created": parse_ts(times.get("si_created"))[0],
            "si_modified": parse_ts(times.get("si_modified"))[0],
            "fn_created": parse_ts(times.get("created"))[0],
            "fn_modified": parse_ts(times.get("modified"))[0],
        }
        if any(v is None for v in parsed.values()):
            stats["skipped_missing_ts"] += 1
            continue
        stats["checked"] += 1
        findings.extend(_compare(
            parsed, {}, e.get("name") or f"(mft_ref {e.get('mft_ref')})",
            min_delta, stats, precision="second"))
    return findings, stats, notes


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi OFFLINE timestomping SI-vs-FN (T1070.006) "
                    "dari CSV MFTECmd atau JSON mft_scan — read-only, "
                    "nol jaringan.")
    ap.add_argument("--csv", type=Path, help="CSV hasil MFTECmd")
    ap.add_argument("--mft-json", type=Path,
                    help="JSON output tools/mft_scan.py")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--min-delta-seconds", type=float, default=1.0,
                    help="deviasi minimum utk menandai (anti-FP resolusi)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    inputs = [p for p in (args.csv, args.mft_json) if p]
    if len(inputs) != 1:
        print("error: pilih SATU input: --csv ATAU --mft-json",
              file=sys.stderr)
        return 2
    p = inputs[0]
    if not p.is_file():
        print(f"error: file tidak ada: {p}", file=sys.stderr)
        return 2
    if p.stat().st_size > MAX_FILE_BYTES:
        print(f"error: file terlalu besar (> {MAX_FILE_BYTES} B)",
              file=sys.stderr)
        return 2
    try:
        if args.csv:
            findings, stats, notes = analyze_csv(p,
                                                 args.min_delta_seconds)
        else:
            findings, stats, notes = analyze_mft_json(
                p, args.min_delta_seconds)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    report = {"schema": SCHEMA, "input": str(p), "stats": stats,
              "findings": findings, "notes": notes}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        for f in findings:
            print(f"[{f['severity'].upper():6}] {f['check']}: {p}: "
                  f"{f['message']}")
        print(f"-- {stats['checked']}/{stats['rows']} entri dicek, "
              f"{stats['skipped_missing_ts']} dilewati (timestamp kosong), "
              f"{stats['below_delta_threshold']} di bawah ambang, "
              f"{len(findings)} temuan")
        for n in notes:
            print(f"note: {n}")
    return 1 if any(rank[f["severity"]] >= rank[args.fail_on]
                    for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
