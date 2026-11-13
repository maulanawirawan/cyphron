"""[AUDIT: read-only] vuln_sla_aging — mesin aging + SLA remediasi
kerentanan (severity -> tenggat, umur, status overdue, eskalasi, KPI).

Konsep yang diekstrak (deterministik, tanpa jaringan):
  - kebijakan SLA per severity (default: critical 14, high 30,
    medium 60, low 90 hari; info = tanpa SLA);
  - modifier: aset internet-facing -> SLA x faktor (default 0.5);
    CVE di CISA KEV -> override hari KEV (default 2);
  - umur = (resolved atau as-of) - discovered; overdue bila terbuka
    dan umur > SLA; closed diukur kepatuhannya (age <= SLA);
  - tangga eskalasi persentase SLA (>=50% reminder, >=75% manager,
    >=100% CISO);
  - KPI: MTTR, tingkat kepatuhan SLA item closed, overdue per
    severity, distribusi bucket umur (0-14/15-30/31-60/60+).

Fail-closed:
  - source tidak ada / JSON-CSV tidak valid      -> exit 2;
  - tanggal tak bisa diurai / resolved < discovered / severity tak
    dikenal -> tercatat di "errors" + item TIDAK pernah dianggap
    sehat (state "error"); tidak pernah dihitung bersih diam-diam;
  - as-of tanpa --as-of = hari ini UTC (tes memakai --as-of tetap
    supaya deterministik).

Input: satu file JSON (list, atau {"findings": [...]}) atau CSV
(kolom minimal: id, severity, discovered; opsional resolved,
asset, internet_facing, kev). Tanggal ISO-8601 (YYYY-MM-DD sudah
cukup); severity case-insensitive.

Pemakaian:
  python tools/vuln_sla_aging.py --source findings.json --out aging.json
  python tools/vuln_sla_aging.py --source vulns.csv --as-of 2026-11-08 \
      --fail-on overdue
Exit: 0 selesai; 1 temuan gagal ambang --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from datetime import date, datetime, timezone
from pathlib import Path

SCHEMA = "secai.vuln-sla-aging/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

DEFAULT_SLA_DAYS = {"critical": 14, "high": 30, "medium": 60, "low": 90}
SEVERITIES = tuple(DEFAULT_SLA_DAYS) + ("info",)
NO_SLA = "info"

ESCALATION_TIERS = ((100.0, "ciso"), (75.0, "manager"), (50.0, "reminder"))

BUCKETS = ((0, 14, "0-14d"), (15, 30, "15-30d"), (31, 60, "31-60d"),
           (61, None, "60d+"))


def _parse_date(value: str, field: str, ref: str) -> date:
    """Urai tanggal ISO-8601; ValueError berisi konteks field."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{ref}: {field} kosong")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        raise ValueError(f"{ref}: {field} bukan tanggal ISO: {value!r}")


def _norm_severity(value: str) -> str:
    return (value or "").strip().lower()


def effective_sla(severity: str, policy: dict[str, int],
                  facing: bool, kev: bool, facing_factor: float,
                  kev_days: int) -> int | None:
    """SLA efektif hari; None = tanpa SLA (info)."""
    if severity == NO_SLA:
        return None
    days = policy[severity]
    if kev:
        return kev_days
    if facing:
        # faktor 0.5 -> ceil(hari * 0.5); minimum 1 hari
        days = max(1, math.ceil(days * facing_factor))
    return days


def _escalation(pct: float) -> str:
    for threshold, tier in ESCALATION_TIERS:
        if pct >= threshold:
            return tier
    return "none"


def _bucket(days: int) -> str:
    for lo, hi, label in BUCKETS:
        if days >= lo and (hi is None or days <= hi):
            return label
    return "60d+"


def load_findings(path: Path) -> tuple[list[dict], list[str]]:
    """Baca JSON/CSV -> list record; kembalikan (records, errors)."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"file terlalu besar (> {MAX_FILE_BYTES} byte)")
    text = raw.decode("utf-8-sig", errors="replace")
    errors: list[str] = []
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames:
            raise ValueError("CSV tanpa header")
        records = [dict(row) for row in reader]
        return records, errors
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON tidak valid: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        raise ValueError("JSON harus list atau objek berisi 'findings'")
    return data, errors


def assess(records: list[dict], as_of: date, policy: dict[str, int],
           facing_factor: float, kev_days: int) -> dict:
    """Hitung aging per temuan + ringkasan KPI (murni deterministik)."""
    rows: list[dict] = []
    errors: list[str] = []
    overdue_by_sev: dict[str, int] = {}
    bucket_counts: dict[str, int] = {}
    closed_ages: list[int] = []
    closed_in_sla = 0
    overdue_total = 0

    for idx, rec in enumerate(records):
        ref = rec.get("id") or f"#index-{idx}"
        severity = _norm_severity(str(rec.get("severity", "")))
        if severity not in SEVERITIES:
            errors.append(f"{ref}: severity tak dikenal: "
                          f"{rec.get('severity')!r}")
            rows.append({"id": str(ref), "severity": str(rec.get("severity")),
                         "state": "error"})
            continue
        try:
            discovered = _parse_date(str(rec.get("discovered", "")),
                                     "discovered", str(ref))
        except ValueError as exc:
            errors.append(str(exc))
            rows.append({"id": str(ref), "severity": severity,
                         "state": "error"})
            continue
        resolved_raw = str(rec.get("resolved") or "").strip()
        resolved: date | None = None
        if resolved_raw:
            try:
                resolved = _parse_date(resolved_raw, "resolved", str(ref))
            except ValueError as exc:
                errors.append(str(exc))
                rows.append({"id": str(ref), "severity": severity,
                             "state": "error"})
                continue
            if resolved < discovered:
                errors.append(f"{ref}: resolved ({resolved}) sebelum "
                              f"discovered ({discovered})")
                rows.append({"id": str(ref), "severity": severity,
                             "state": "error"})
                continue
        facing = str(rec.get("internet_facing", "")).strip().lower() \
            in ("1", "true", "yes", "y")
        kev = str(rec.get("kev", "")).strip().lower() \
            in ("1", "true", "yes", "y")
        sla_days = effective_sla(severity, policy, facing, kev,
                                 facing_factor, kev_days)
        end = resolved if resolved is not None else as_of
        age_days = (end - discovered).days
        row: dict = {
            "id": str(ref),
            "severity": severity,
            "asset": str(rec.get("asset") or "") or None,
            "discovered": discovered.isoformat(),
            "resolved": resolved.isoformat() if resolved else None,
            "internet_facing": facing,
            "kev": kev,
            "sla_days": sla_days,
            "age_days": age_days,
        }
        if sla_days is None:
            row.update({"state": "no-sla", "deadline": None,
                        "sla_pct_elapsed": None, "escalation": "none",
                        "days_overdue": 0})
        else:
            deadline = discovered.toordinal() + sla_days
            deadline_d = date.fromordinal(deadline)
            pct = round(age_days / sla_days * 100, 1) if sla_days else 0.0
            days_over = max(0, age_days - sla_days)
            if resolved is not None:
                state = "compliant" if age_days <= sla_days else "breached"
            else:
                state = "overdue" if age_days > sla_days else "open"
            row.update({
                "state": state,
                "deadline": deadline_d.isoformat(),
                "sla_pct_elapsed": pct,
                "escalation": _escalation(pct)
                if state in ("overdue", "open") else "none",
                "days_overdue": days_over if state == "overdue" else 0,
            })
            if state == "overdue":
                overdue_total += 1
                overdue_by_sev[severity] = overdue_by_sev.get(severity, 0) + 1
            if resolved is not None:
                closed_ages.append(age_days)
                if state == "compliant":
                    closed_in_sla += 1
            else:
                bucket_counts[_bucket(age_days)] = \
                    bucket_counts.get(_bucket(age_days), 0) + 1
        rows.append(row)

    by_sev_open = {}
    for row in rows:
        if row["state"] in ("open", "overdue"):
            by_sev_open[row["severity"]] = \
                by_sev_open.get(row["severity"], 0) + 1
    summary = {
        "total": len(rows),
        "open": sum(1 for r in rows if r["state"] in ("open", "overdue")),
        "closed": sum(1 for r in rows if r["state"] in ("compliant",
                                                        "breached")),
        "overdue": overdue_total,
        "errors": len(errors),
        "no_sla": sum(1 for r in rows if r["state"] == "no-sla"),
        "mttr_days": round(sum(closed_ages) / len(closed_ages), 1)
        if closed_ages else None,
        "sla_compliance_rate": round(closed_in_sla / len(closed_ages) * 100, 1)
        if closed_ages else None,
        "overdue_by_severity": dict(sorted(overdue_by_sev.items())),
        "open_by_severity": dict(sorted(by_sev_open.items())),
        "aging_buckets_open": dict(sorted(bucket_counts.items())),
    }
    return {"rows": rows, "summary": summary, "errors": errors}


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="vuln_sla_aging — aging + SLA remediasi kerentanan "
                    "(read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file JSON/CSV temuan kerentanan")
    ap.add_argument("--as-of",
                    help="tanggal acuan (ISO, default hari ini UTC)")
    ap.add_argument("--sla",
                    help="override SLA hari, mis. critical=7,high=14")
    ap.add_argument("--facing-factor", type=float, default=0.5,
                    help="faktor SLA utk aset internet-facing (default 0.5)")
    ap.add_argument("--kev-days", type=int, default=2,
                    help="override SLA hari utk CVE di KEV (default 2)")
    ap.add_argument("--fail-on", choices=("overdue", "breach", "error"),
                    help="exit 1 bila kondisi itu ada")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    source = Path(args.source)
    if not source.exists():
        print(f"[sla-aging] source tidak ada: {source}", file=sys.stderr)
        return 2
    if args.as_of:
        try:
            as_of = _parse_date(args.as_of, "--as-of", "--as-of")
        except ValueError as exc:
            print(f"[sla-aging] {exc}", file=sys.stderr)
            return 2
    else:
        as_of = datetime.now(timezone.utc).date()
    policy = dict(DEFAULT_SLA_DAYS)
    if args.sla:
        try:
            for part in args.sla.split(","):
                key, _, val = part.partition("=")
                key = key.strip().lower()
                if key not in DEFAULT_SLA_DAYS or not val.isdigit():
                    raise ValueError(f"entri --sla tak valid: {part!r}")
                policy[key] = max(1, int(val))
        except ValueError as exc:
            print(f"[sla-aging] {exc}", file=sys.stderr)
            return 2
    try:
        records, _ = load_findings(source)
    except (OSError, ValueError) as exc:
        print(f"[sla-aging] gagal: {exc}", file=sys.stderr)
        return 2
    result = assess(records, as_of, policy, args.facing_factor,
                    max(1, args.kev_days))
    out = {
        "schema": SCHEMA,
        "source": str(source),
        "as_of": as_of.isoformat(),
        "policy": policy,
        "summary": result["summary"],
        "findings": result["rows"],
        "errors": result["errors"],
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    print(f"[sla-aging] {s['total']} temuan (as-of {as_of.isoformat()}); "
          f"open={s['open']} overdue={s['overdue']} closed={s['closed']} "
          f"error={s['errors']}")
    if s["mttr_days"] is not None:
        print(f"[sla-aging] MTTR={s['mttr_days']} hari, "
              f"kepatuhan SLA closed={s['sla_compliance_rate']}%")
    for row in result["rows"]:
        if row["state"] in ("overdue", "breached", "error"):
            print(f"  [{row['state']:8}] {row['id']} "
                  f"(sev={row.get('severity')}, "
                  f"sla={row.get('sla_days')}, "
                  f"age={row.get('age_days')})")
    if args.fail_on:
        hit = ((args.fail_on == "overdue" and s["overdue"] > 0)
               or (args.fail_on == "breach"
                   and (s["overdue"] > 0
                        or any(r["state"] == "breached"
                               for r in result["rows"])))
               or (args.fail_on == "error" and s["errors"] > 0))
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
