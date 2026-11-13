r"""[SAFETY: read-only] ioc_lifecycle_score — skor siklus-hidup & disposisi
indikator IOC dari daftar tersimpan (decay eksponensial + kualitas
hit/FP). NOL jaringan, read-only, stdlib murni.

Mekanisme (deterministik, semua jam di-UTC):
  1. Umur indikator = --now - last_seen (fallback created); RFC3339 dgn
     offset dihormati, naive = dianggap UTC (dicatat); last_seen masa-
     depan = entry flagged data-error, TIDAK diskor senyap.
  2. Peluruhan: conf_decayed = conf * 0.5 ** (umur_hari / half_life).
     Half-life per keluarga (konsep skill): ip 30 hari, domain/url 90,
     mutex 60, email 180, hash (md5/sha1/sha256) 365. Tipe tak dikenal =
     flagged type-unknown (dihitung eksplisit, tanpa skor senyap).
  3. FP rate = fp_count / (hit_count + fp_count) bila salah satu ada;
     > 0.5 = kandidat pensiun (kualitas indikator buruk).
  4. State: RETIRE-CANDIDATE bila conf_decayed < --expire-threshold
     (default 10) ATAU fp_rate > 0.5; UNDER-REVIEW bila < --review-
     threshold (default 30); selain itu MONITORING.
  5. Disposisi rekomendasi (KONTEKS utk analis, bukan keputusan
     otomatis — spirit enrichment): >=60 watchlist-aktif, 30-59
     monitor, <30 kontekstual-saja.
  6. Faktor gabungan = conf_decayed * (1 - fp_rate) bila ada hit/FP.

Verdict: aritmetika atas data tersimpan -> status confirmed, evidence_
kind "arithmetic", verdict L3, poc = rumus decay dgn angka nyata.
Severity low/info (higiene intel, bukan kerentanan).

Fail-closed: file tidak ada / bukan list / 0 indikator valid -> exit 2;
entry rusak dihitung malformed di meta, tidak diam-diam.

Pemakaian:
  python tools/ioc_lifecycle_score.py --indicators ioc.json --out f.json
  python tools/ioc_lifecycle_score.py --indicators ioc.json --now \
      2026-11-08T00:00:00Z --expire-threshold 15 --out f.json
Exit: 0 tanpa kandidat pensiun, 1 ada kandidat pensiun/FP-berat,
2 error input.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.ioc-lifecycle-score/1"

# tipe -> (keluarga, half-life hari)
FAMILIES: dict[str, tuple[str, int]] = {
    "ip": ("ip", 30),
    "ipv4": ("ip", 30),
    "ipv6": ("ip", 30),
    "domain": ("domain", 90),
    "hostname": ("domain", 90),
    "url": ("url", 90),
    "mutex": ("mutex", 60),
    "email": ("email", 180),
    "file-md5": ("hash", 365),
    "md5": ("hash", 365),
    "file-sha1": ("hash", 365),
    "sha1": ("hash", 365),
    "file-sha256": ("hash", 365),
    "sha256": ("hash", 365),
}

FP_RETIRE_RATE = 0.5


def parse_ts(raw: str) -> datetime:
    """RFC3339; naive = UTC (dipakai eksplisit). Raises ValueError."""
    s = raw.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def score_indicator(entry: dict, now: datetime, review_th: float,
                    expire_th: float) -> tuple[dict | None, dict | None]:
    """Skor satu indikator. Return (hasil, flag) — flag utk entry rusak."""
    value = entry.get("value")
    itype = str(entry.get("type", "")).lower()
    if not value or not itype:
        return None, {"value": value, "reason": "tanpa value/type"}
    fam = FAMILIES.get(itype)
    if fam is None:
        return None, {"value": value, "reason": f"type-unknown: {itype}"}
    family, half_life = fam
    conf = entry.get("confidence")
    if not isinstance(conf, (int, float)) or not 0 <= conf <= 100:
        return None, {"value": value, "reason": "confidence bukan 0-100"}
    try:
        ts_raw = entry.get("last_seen") or entry.get("created")
        ts = parse_ts(str(ts_raw))
    except (TypeError, ValueError) as exc:
        return None, {"value": value, "reason": f"timestamp rusak: {exc}"}
    age_days = (now - ts).total_seconds() / 86400.0
    if age_days < 0:
        return None, {"value": value, "reason": "last_seen/created di masa "
                                               "depan (data-error)"}

    conf_decayed = conf * math.pow(0.5, age_days / half_life)
    hit = entry.get("hit_count")
    fp = entry.get("false_positive_count")
    fp_rate = None
    factor = conf_decayed
    if isinstance(hit, (int, float)) or isinstance(fp, (int, float)):
        h = float(hit or 0)
        f = float(fp or 0)
        if h + f > 0:
            fp_rate = f / (h + f)
            factor = conf_decayed * (1.0 - fp_rate)

    if (fp_rate is not None and fp_rate > FP_RETIRE_RATE) or \
            conf_decayed < expire_th:
        state = "RETIRE-CANDIDATE"
    elif conf_decayed < review_th:
        state = "UNDER-REVIEW"
    else:
        state = "MONITORING"
    if factor >= 60:
        disp = "watchlist-aktif"
    elif factor >= 30:
        disp = "monitor"
    else:
        disp = "kontekstual-saja"

    result = {
        "type": itype,
        "family": family,
        "half_life_days": half_life,
        "value": value,
        "age_days": round(age_days, 2),
        "confidence_initial": conf,
        "confidence_decayed": round(conf_decayed, 2),
        "fp_rate": round(fp_rate, 3) if fp_rate is not None else None,
        "combined_factor": round(factor, 2),
        "state": state,
        "disposition": disp,
    }
    flag = None
    if state == "RETIRE-CANDIDATE":
        flag = "retire"
    return result, flag


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] ioc_lifecycle_score — decay "
                    "confidence + disposisi IOC dari daftar tersimpan "
                    "(NOL jaringan)")
    ap.add_argument("--indicators", required=True,
                    help="JSON list indikator (type/value/confidence/"
                         "last_seen|created/hit_count/false_positive_count)")
    ap.add_argument("--out", default="ioc_lifecycle_findings.json")
    ap.add_argument("--now", default=None,
                    help="RFC3339 — override 'sekarang' utk reproduksi "
                         "deterministik (default: UTC saat ini)")
    ap.add_argument("--review-threshold", type=float, default=30.0)
    ap.add_argument("--expire-threshold", type=float, default=10.0)
    args = ap.parse_args(argv)

    p = Path(args.indicators)
    if not p.is_file():
        print(f"[ioc_lifecycle_score] file tidak ada: {p} (fail-closed)",
              file=sys.stderr)
        return 2
    try:
        entries = json.loads(p.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        print(f"[ioc_lifecycle_score] JSON rusak: {exc} (fail-closed)",
              file=sys.stderr)
        return 2
    if not isinstance(entries, list) or not entries:
        print("[ioc_lifecycle_score] input bukan list terisi (fail-closed)",
              file=sys.stderr)
        return 2
    if args.expire_threshold >= args.review_threshold:
        print("[ioc_lifecycle_score] expire-threshold >= review-threshold "
              "(tidak wajar, fail-closed)", file=sys.stderr)
        return 2

    if args.now:
        try:
            now = parse_ts(args.now)
        except ValueError as exc:
            print(f"[ioc_lifecycle_score] --now rusak: {exc} (fail-closed)",
                  file=sys.stderr)
            return 2
    else:
        now = datetime.now(timezone.utc)

    results: list[dict] = []
    flags: list[dict] = []
    for e in entries:
        if not isinstance(e, dict):
            flags.append({"value": None, "reason": "entry bukan objek"})
            continue
        res, flag = score_indicator(e, now, args.review_threshold,
                                    args.expire_threshold)
        if res is None:
            flags.append(flag)
        else:
            results.append(res)
            if flag == "retire":
                flags.append({"value": res["value"], "reason": "retire"})

    if not results:
        print(f"[ioc_lifecycle_score] 0 indikator valid dari "
              f"{len(entries)} entry ({len(flags)} flag) — tidak ada "
              "kesimpulan (fail-closed)", file=sys.stderr)
        return 2

    findings: list[dict] = []
    for r in results:
        if r["state"] != "RETIRE-CANDIDATE":
            continue
        fp_txt = (f", fp_rate={r['fp_rate']}" if r["fp_rate"] is not None
                  else "")
        findings.append(make_finding(
            tool="ioc-lifecycle-score",
            title=f"RETIRE-CANDIDATE {r['type']} {r['value'][:48]} "
                  f"(conf {r['confidence_initial']} -> "
                  f"{r['confidence_decayed']})",
            severity="low",
            description=(
                f"Indikator {r['type']} ({r['family']}, half-life "
                f"{r['half_life_days']} hari) berumur {r['age_days']} hari: "
                f"confidence {r['confidence_initial']} meluruh ke "
                f"{r['confidence_decayed']}{fp_txt} — di bawah ambang "
                "expire/review atau FP-berat; infrastruktur adversary "
                "berotasi, indikator basi = noise analis"),
            recommendation=(
                "Tinjau lalu pensiunkan/arsipkan indikator; jangan hapus "
                "senyap (jejak lifecycle tersimpan di hasil ini)"),
            param=r["value"],
            poc=f"conf_decayed = {r['confidence_initial']} * 0.5^("
                f"{r['age_days']}/{r['half_life_days']}) = "
                f"{r['confidence_decayed']}",
            evidence_kind="arithmetic",
            finding_class="observation",
            confidence=1.0,
            status="confirmed",
            verdict=2,
            extra={**r, "schema": SCHEMA},
        ))

    states: dict[str, int] = {}
    for r in results:
        states[r["state"]] = states.get(r["state"], 0) + 1
    meta = {
        "schema": SCHEMA,
        "indicators": len(entries),
        "scored": len(results),
        "flags": flags,
        "states": states,
        "now": now.isoformat(),
        "review_threshold": args.review_threshold,
        "expire_threshold": args.expire_threshold,
        "half_lives": {t: hl for t, (_, hl) in sorted(
            {k: v for k, v in FAMILIES.items()}.items())},
        "note": "disposisi = KONTEKS utk analis, bukan keputusan blokir "
                "otomatis (spirit enrichment); lookup live VT/Shodan/"
                "AbuseIPDB = ops jaringan di luar tool ini (cf. intel_sync)",
    }
    write_findings(args.out, findings, meta)
    retire = states.get("RETIRE-CANDIDATE", 0)
    if retire or any(fl.get("reason") == "retire" for fl in flags):
        print(f"[ioc_lifecycle_score] {retire} kandidat pensiun dari "
              f"{len(results)} indikator -> {args.out}")
        return 1
    print(f"[ioc_lifecycle_score] {len(results)} indikator, tanpa kandidat "
          f"pensiun -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
