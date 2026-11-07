"""[AUDIT: read-only] vuln_exception_check — gerbang validasi + kedaluwarsa
pengecualian (risk acceptance) kerentanan.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/building-vulnerability-exception-tracking-system' (antrean
SKILL-PORT-QUEUE #0309; atribusi ide, lisensi sumber Apache-2.0).
Dibangun from scratch TANPA kode sumber itu dan TANPA Flask/SQLAlchemy/
database: inti deterministiknya adalah ATURAN TATA KELOLA — bukan
aplikasi web-nya. Tool ini memeriksa file register pengecualian
(JSON) terhadap kebijakan kategori, bukan menjalankan server.

Kebijakan yang diekstrak (deterministik):
  kategori        maks hari   butuh kontrol-kompensasi
  remediation_delay   30      ya
  no_fix              90      ya
  business_critical   60      ya
  compensating_control 180    ya
  false_positive     365      tidak
  - durasi keberlakuan = expires_at - approved_at (fallback
    requested_at); melebihi maks kategori = pelanggaran;
  - field wajib: id, category valid, justification non-kosong,
    expires_at, requested_by;
  - status approved/active wajib punya approved_by + durasi;
    status pending dicatat pending_approval (bukan dianggap sah);
  - kedaluwarsa: expires_at < as-of -> expired; dalam --warn-days
    (default 14) -> expiring_soon;
  - false_positive tanpa batas praktis dibatasi 365 hari (siklus
    audit tahunan) — pilihan ketat, bukan 'permanen'.

Fail-closed:
  - source tidak ada / JSON tidak valid / bukan list      -> exit 2;
  - tanggal tak bisa diurai / kategori tak dikenal / field wajib
    hilang -> item berstatus invalid + alasan di "issues"; TIDAK
    pernah dianggap valid diam-diam;
  - as-of tanpa --as-of = hari ini UTC (tes memakai --as-of tetap).

Pemakaian:
  python tools/vuln_exception_check.py --source exceptions.json \
      --as-of 2026-11-08 --out check.json
  python tools/vuln_exception_check.py --source exc.json --fail-on expired
Exit: 0 selesai; 1 temuan gagal ambang --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

SCHEMA = "cyphron.vuln-exception-check/1"
MAX_FILE_BYTES = 4 * 1024 * 1024

# kategori -> (maks hari, butuh kontrol kompensasi)
CATEGORIES: dict[str, tuple[int, bool]] = {
    "remediation_delay": (30, True),
    "no_fix": (90, True),
    "business_critical": (60, True),
    "compensating_control": (180, True),
    "false_positive": (365, False),
}

FINAL_STATES = ("expired", "expiring_soon", "valid", "invalid",
                "pending_approval")


def _norm_category(value: str) -> str:
    return (value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _parse_date(value: str, field: str, ref: str) -> date:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{ref}: {field} kosong")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        raise ValueError(f"{ref}: {field} bukan tanggal ISO: {value!r}")


def check_record(rec: dict, as_of: date, warn_days: int) -> tuple[dict,
                                                                  list[str]]:
    """Validasi satu pengecualian -> (row, issues)."""
    issues: list[str] = []
    ref = str(rec.get("id") or rec.get("finding_id")
              or rec.get("cve_id") or "#tanpa-id")
    category = _norm_category(str(rec.get("category", "")))
    if category not in CATEGORIES:
        issues.append(f"kategori tak dikenal: {rec.get('category')!r}")

    for field in ("justification", "requested_by"):
        if not str(rec.get(field) or "").strip():
            issues.append(f"field wajib kosong: {field}")

    expires: date | None = None
    approved: date | None = None
    requested: date | None = None
    try:
        expires = _parse_date(str(rec.get("expires_at", "")),
                              "expires_at", ref)
    except ValueError as exc:
        issues.append(str(exc))
    for field, holder in (("approved_at", "approved"),
                          ("requested_at", "requested")):
        raw = str(rec.get(field) or "").strip()
        if not raw:
            continue
        try:
            parsed = _parse_date(raw, field, ref)
        except ValueError as exc:
            issues.append(str(exc))
            continue
        if holder == "approved":
            approved = parsed
        else:
            requested = parsed

    status = (str(rec.get("status") or "pending")).strip().lower()
    approved_by = str(rec.get("approved_by") or "").strip()
    controls = rec.get("compensating_controls") or []
    if not isinstance(controls, list):
        controls = [controls]

    duration_days: int | None = None
    if expires is not None:
        start = approved if approved is not None else requested
        if start is not None:
            if expires < start:
                issues.append(f"expires_at ({expires}) sebelum "
                              f"{('approved_at' if approved is not None else 'requested_at')} ({start})")
            else:
                duration_days = (expires - start).days

    max_days, need_control = CATEGORIES.get(category, (None, None))
    if category in CATEGORIES and need_control and not controls:
        issues.append("kategori ini wajib mencantumkan "
                      "compensating_controls")
    if category in CATEGORIES and max_days is not None \
            and duration_days is not None and duration_days > max_days:
        issues.append(f"durasi {duration_days} hari melebihi maks "
                      f"kategori {category} ({max_days} hari)")

    if status in ("approved", "active"):
        if not approved_by:
            issues.append("status approved/active tanpa approved_by")
    elif status == "pending":
        pass  # ditangani sebagai state pending_approval di bawah
    else:
        issues.append(f"status tak dikenal: {status!r}")

    days_left: int | None = None
    if expires is not None:
        days_left = (expires - as_of).days

    if issues:
        state = "invalid"
    elif status == "pending":
        state = "pending_approval"
    elif days_left is None:
        state = "invalid"  # tak mungkin: expires kosong sudah menghasilkan issue
    elif days_left < 0:
        state = "expired"
    elif days_left <= warn_days:
        state = "expiring_soon"
    else:
        state = "valid"

    row = {
        "id": ref,
        "cve_id": str(rec.get("cve_id") or "") or None,
        "finding_id": str(rec.get("finding_id") or "") or None,
        "category": category or None,
        "status": status,
        "expires_at": expires.isoformat() if expires else None,
        "duration_days": duration_days,
        "max_days": max_days,
        "days_left": days_left,
        "state": state,
        "issues": issues,
    }
    return row, issues


def assess(records: list[dict], as_of: date, warn_days: int) -> dict:
    rows: list[dict] = []
    errors: list[str] = []
    counts = {s: 0 for s in FINAL_STATES}
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            errors.append(f"#index-{idx}: record bukan objek")
            counts["invalid"] += 1
            continue
        row, _ = check_record(rec, as_of, warn_days)
        rows.append(row)
        counts[row["state"]] += 1
    summary = {
        "total": len(rows),
        "counts": counts,
        "over_max_duration": sum(
            1 for r in rows
            if r["duration_days"] is not None and r["max_days"] is not None
            and r["duration_days"] > r["max_days"]),
        "errors": len(errors),
    }
    return {"rows": rows, "summary": summary, "errors": errors}


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="vuln_exception_check — validasi register pengecualian "
                    "kerentanan (read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file JSON register pengecualian (list)")
    ap.add_argument("--as-of", help="tanggal acuan (ISO, default hari ini)")
    ap.add_argument("--warn-days", type=int, default=14,
                    help="ambang expiring_soon (default 14 hari)")
    ap.add_argument("--fail-on",
                    choices=("expired", "expiring_soon", "invalid",
                             "pending", "over-max", "any"),
                    help="exit 1 bila kondisi itu ada")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    source = Path(args.source)
    if not source.exists():
        print(f"[exc-check] source tidak ada: {source}", file=sys.stderr)
        return 2
    if args.as_of:
        try:
            as_of = _parse_date(args.as_of, "--as-of", "--as-of")
        except ValueError as exc:
            print(f"[exc-check] {exc}", file=sys.stderr)
            return 2
    else:
        as_of = datetime.now(timezone.utc).date()
    try:
        raw = source.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"file terlalu besar (> {MAX_FILE_BYTES} byte)")
        data = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except (OSError, ValueError) as exc:
        print(f"[exc-check] gagal: {exc}", file=sys.stderr)
        return 2
    if isinstance(data, dict):
        data = data.get("exceptions")
    if not isinstance(data, list):
        print("[exc-check] JSON harus list atau objek berisi 'exceptions'",
              file=sys.stderr)
        return 2
    result = assess(data, as_of, max(0, args.warn_days))
    out = {
        "schema": SCHEMA,
        "source": str(source),
        "as_of": as_of.isoformat(),
        "policy_categories": {k: {"max_days": v[0],
                                  "needs_compensating_control": v[1]}
                              for k, v in CATEGORIES.items()},
        "summary": result["summary"],
        "exceptions": result["rows"],
        "errors": result["errors"],
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    c = s["counts"]
    print(f"[exc-check] {s['total']} pengecualian "
          f"(as-of {as_of.isoformat()}): valid={c['valid']} "
          f"expiring={c['expiring_soon']} expired={c['expired']} "
          f"pending={c['pending_approval']} invalid={c['invalid']}")
    for row in result["rows"]:
        if row["state"] != "valid":
            line = f"  [{row['state']:16}] {row['id']}"
            if row["days_left"] is not None:
                line += f" (sisa {row['days_left']} hari)"
            print(line)
            for issue in row["issues"]:
                print(f"      - {issue}")
    if args.fail_on:
        hit = ((args.fail_on == "expired" and c["expired"] > 0)
               or (args.fail_on == "expiring_soon"
                   and c["expiring_soon"] > 0)
               or (args.fail_on == "invalid" and c["invalid"] > 0)
               or (args.fail_on == "pending"
                   and c["pending_approval"] > 0)
               or (args.fail_on == "over-max"
                   and s["over_max_duration"] > 0)
               or (args.fail_on == "any"
                   and (c["expired"] + c["expiring_soon"] + c["invalid"]
                        + c["pending_approval"] > 0)))
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
