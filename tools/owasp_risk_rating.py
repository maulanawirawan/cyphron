"""[SCORE: read-only] owasp_risk_rating — penskoran risiko temuan web
memakai OWASP Risk Rating Methodology (likelihood x impact -> level),
ditambah pemetaan kelas OWASP Top 10 2021 dari CWE.

Mengisi antrean port dari SKILL-PORT-QUEUE #0920 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-web-application-vulnerability-
triage'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH dari metodologi terpublikasi (owasp.org/www-community/
OWASP_Risk_Rating_Methodology) — bukan salinan kode sumber.

Inti deterministik yang diport (bukan proses triase-nya):
  - 16 faktor 0-9: likelihood = rerata 8 faktor (4 threat-agent:
    skill_level, motive, opportunity, size + 4 vulnerability:
    ease_of_discovery, ease_of_exploit, awareness, intrusion_detection);
    impact = rerata 8 faktor (4 technical: confidentiality, integrity,
    availability, accountability + 4 business: financial, reputation,
    non_compliance, privacy);
  - band: <=3 low, 3-6 medium, >6 high (L dan I sama);
  - matriks band OWASP (L baris, I kolom):
                  I=low    I=medium  I=high
      L=high      medium   high      critical
      L=medium    low      medium    high
      L=low       note     low       medium
  - skor L x I (0..81) dibawa keluar untuk keterlacakan — LEVEL resmi
    dari MATRIKS, bukan dari ambang skor;
  - pemetaan CWE -> OWASP Top 10 2021 (faktual, 11 CWE yang dipublikasi
    skill sumber; CWE lain = None, TIDAK ditebak — anti-FP).

Derivasi default faktor dari flag/konteks (eksplisit di output sebagai
"derived", selalu bisa ditimpa dgn faktor eksplisit per temuan):
  skill_level=6 utk CWE injeksi-kelas (78/79/89) else 4; motive=7;
  opportunity=7 (authenticated=False) else 4; size=9 internet_facing
  else 4; ease_of_discovery=8 scanner_detected else 5;
  ease_of_exploit=7 exploit_available else 4; awareness=6;
  intrusion_detection=3 waf_enabled else 8; confidentiality=9
  data_exposure else 5; integrity=9 utk CWE 78/89 else 4;
  availability=7 flag dos else 2; accountability=3 logging_enabled
  else 7; financial=7 processes_payments else 3; reputation=6
  customer_facing else 2; non_compliance=8 pci_scope else 3;
  privacy=9 handles_pii else 2.

Ranah EKSPLISIT: cvss_score = skor CVSS v3.1 dari vektor (basis
teknis, tanpa konteks bisnis); risk_matrix_80030 = register risiko
kualitatif 5x5 NIST; triage_advisor = learning loop outcome historis —
di sini metodologi OWASP utk temuan WEB dgn konteks aplikasi.

Fail-closed:
  - source/context tidak ada / JSON rusak / bukan list -> exit 2;
  - faktor di luar 0-9, bukan angka, atau NAMA faktor tak dikenal ->
    item masuk "errors", tidak pernah ikut peringkat;
  - cwe di luar tabel = class None (bukan tebakan);
  - temuan tanpa id -> error;
  - flag konteks di luar daftar -> item error (typo-protection);
  - --fail-on <level|any> -> exit 1.

Pemakaian:
  python tools/owasp_risk_rating.py --source findings.json
  python tools/owasp_risk_rating.py --source f.json --context app.json \
      --out risiko.json --fail-on high
Exit: 0 selesai; 1 temuan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "cyphron.owasp-risk-rating/1"
MAX_FILE_BYTES = 4 * 1024 * 1024

LIKELIHOOD_FACTORS = (
    "skill_level", "motive", "opportunity", "size",
    "ease_of_discovery", "ease_of_exploit", "awareness",
    "intrusion_detection",
)
IMPACT_FACTORS = (
    "confidentiality", "integrity", "availability", "accountability",
    "financial", "reputation", "non_compliance", "privacy",
)
ALL_FACTORS = LIKELIHOOD_FACTORS + IMPACT_FACTORS
FACTOR_SET = set(ALL_FACTORS)

CONTEXT_FLAGS = (
    "internet_facing", "waf_enabled", "logging_enabled",
    "processes_payments", "customer_facing", "pci_scope", "handles_pii",
)
FINDING_FLAGS = (
    "authenticated", "scanner_detected", "exploit_available",
    "data_exposure", "dos",
) + CONTEXT_FLAGS
FLAG_SET = set(FINDING_FLAGS)

# band OWASP RR: <=3 low, 3-6 medium, >6 high (rerata 0..9)
BAND_HIGH_FROM = 6.0
BAND_LOW_TO = 3.0
LEVELS = ("critical", "high", "medium", "low", "note")

# baris = band L (high, medium, low), kolom = band I (low, medium, high)
RISK_MATRIX: tuple[tuple[str, ...], ...] = (
    ("medium", "high", "critical"),
    ("low", "medium", "high"),
    ("note", "low", "medium"),
)

# pemetaan faktual CWE -> OWASP Top 10 2021 (dipublikasi skill sumber)
CWE_TO_OWASP = {
    79: "A03", 89: "A03", 78: "A03", 352: "A01", 22: "A01",
    200: "A02", 327: "A02", 287: "A07", 918: "A10", 502: "A08",
    611: "A05",
}
INJECTION_CWES = (78, 79, 89)

PASSTHROUGH_KEYS = ("title", "cwe", "url", "source")


def band(value: float) -> str:
    """Rerata 0-9 -> band low/medium/high (ambang OWASP RR)."""
    if value > BAND_HIGH_FROM:
        return "high"
    if value >= BAND_LOW_TO:
        return "medium"
    return "low"


def risk_level(l_band: str, i_band: str) -> str:
    """Lookup matriks band OWASP; input sudah kanonik."""
    row = {"high": 0, "medium": 1, "low": 2}[l_band]
    col = {"low": 0, "medium": 1, "high": 2}[i_band]
    return RISK_MATRIX[row][col]


def parse_cwe(value: object) -> "int | None":
    """'CWE-79' / 79 / '79' -> int; lainnya None (tanpa tebakan)."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value > 0 else None
    text = str(value or "").strip().upper()
    if text.isdigit():
        num = int(text)
        return num if num > 0 else None
    if text.startswith("CWE-") and text[4:].isdigit():
        return int(text[4:])
    return None


def derive_defaults(finding: dict, context: dict, cwe: "int | None") -> \
        dict[str, float]:
    """Default 16 faktor dari flag temuan + konteks aplikasi.

    Flag per temuan menimpa konteks HANYA bila eksplisit diset (bukan
    None) — tidak ada penimpaan senyap dgn None."""
    flags: dict[str, object] = {k: context.get(k) for k in CONTEXT_FLAGS}
    for k in FINDING_FLAGS:
        v = finding.get(k)
        if v is not None:
            flags[k] = v
    inj = cwe in INJECTION_CWES
    return {
        "skill_level": 6 if inj else 4,
        "motive": 7,
        "opportunity": 4 if flags.get("authenticated") else 7,
        "size": 9 if flags.get("internet_facing") else 4,
        "ease_of_discovery": 8 if flags.get("scanner_detected") else 5,
        "ease_of_exploit": 7 if flags.get("exploit_available") else 4,
        "awareness": 6,
        "intrusion_detection": 3 if flags.get("waf_enabled") else 8,
        "confidentiality": 9 if flags.get("data_exposure") else 5,
        "integrity": 9 if cwe in (78, 89) else 4,
        "availability": 7 if flags.get("dos") else 2,
        "accountability": 3 if flags.get("logging_enabled") else 7,
        "financial": 7 if flags.get("processes_payments") else 3,
        "reputation": 6 if flags.get("customer_facing") else 2,
        "non_compliance": 8 if flags.get("pci_scope") else 3,
        "privacy": 9 if flags.get("handles_pii") else 2,
    }


def rate(finding: dict, context: dict) -> dict:
    """Nilai SATU temuan -> dict lengkap; raise ValueError utk input
    salah (faktor/flag/angka) — pemanggil memutuskan error vs lanjut."""
    ref = str(finding.get("id") or "").strip()
    if not ref:
        raise ValueError("temuan tanpa id")
    flags = {k: finding.get(k) for k in FINDING_FLAGS}
    for k, v in flags.items():
        if v is not None and not isinstance(v, bool):
            raise ValueError(f"flag {k} bukan boolean: {v!r}")
    cwe = parse_cwe(finding.get("cwe"))
    defaults = derive_defaults(finding, context, cwe)
    explicit_raw = finding.get("factors") or {}
    if not isinstance(explicit_raw, dict):
        raise ValueError("factors harus objek {nama: 0-9}")
    factors: dict[str, float] = {}
    derived: list[str] = []
    for name in ALL_FACTORS:
        if name in explicit_raw:
            v = explicit_raw[name]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(f"faktor {name} bukan angka: {v!r}")
            if not 0 <= v <= 9:
                raise ValueError(f"faktor {name} di luar skala 0-9: {v!r}")
            factors[name] = float(v)
        else:
            factors[name] = defaults[name]
            derived.append(name)
    unknown = set(explicit_raw) - FACTOR_SET
    if unknown:
        raise ValueError(f"nama faktor tak dikenal: {sorted(unknown)}")
    l_score = sum(factors[f] for f in LIKELIHOOD_FACTORS) / 8
    i_score = sum(factors[f] for f in IMPACT_FACTORS) / 8
    lb, ib = band(l_score), band(i_score)
    lvl = risk_level(lb, ib)
    row = {
        "id": ref,
        "risk_level": lvl,
        "likelihood": {"score": round(l_score, 2), "band": lb,
                       "band_bounds": {"medium_from": BAND_LOW_TO,
                                       "high_from": BAND_HIGH_FROM}},
        "impact": {"score": round(i_score, 2), "band": ib},
        "risk_score_lxI": round(l_score * i_score, 2),
        "owasp_top10": CWE_TO_OWASP.get(cwe) if cwe else None,
        "cwe": f"CWE-{cwe}" if cwe else None,
        "factors": {k: round(v, 2) for k, v in factors.items()},
        "factors_derived": sorted(derived),
        "formula": "likelihood=rerata(8 faktor); impact=rerata(8 "
                   "faktor); level=matriks band OWASP RR (bukan skor "
                   "LxI)",
    }
    for k in PASSTHROUGH_KEYS:
        if k != "cwe" and finding.get(k) is not None:
            row[k] = finding[k]
    return row


def assess(records: list[dict], context: dict) -> dict:
    ranked: list[dict] = []
    errors: list[str] = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            errors.append(f"#index-{idx}: record bukan objek")
            continue
        try:
            ranked.append(rate(rec, context))
        except ValueError as exc:
            ref = str(rec.get("id") or f"#index-{idx}")
            errors.append(f"{ref}: {exc}")
    order = {lv: i for i, lv in enumerate(LEVELS)}
    ranked.sort(key=lambda r: (order[r["risk_level"]],
                               -r["risk_score_lxI"], r["id"]))
    by_level = {lv: 0 for lv in LEVELS}
    for r in ranked:
        by_level[r["risk_level"]] += 1
    summary = {
        "total": len(ranked),
        "by_level": by_level,
        "errors": len(errors),
        "owasp_top10_coverage": {
            cls: sum(1 for r in ranked if r["owasp_top10"] == cls)
            for cls in sorted({v for v in CWE_TO_OWASP.values()})
            if any(r["owasp_top10"] == cls for r in ranked)
        },
    }
    return {"ranked": ranked, "summary": summary, "errors": errors}


def _read_json(path: Path, what: str) -> object:
    if not path.exists():
        raise ValueError(f"{what} tidak ada: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"{what} terlalu besar (> {MAX_FILE_BYTES} b)")
    try:
        return json.loads(raw.decode("utf-8-sig", errors="replace"))
    except ValueError as exc:
        raise ValueError(f"{what} JSON rusak: {exc}") from exc


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="owasp_risk_rating — OWASP Risk Rating Methodology "
                    "(likelihood x impact -> level) + kelas OWASP Top 10 "
                    "dari CWE (read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file JSON temuan (list)")
    ap.add_argument("--context",
                    help="file JSON konteks aplikasi (flag global)")
    ap.add_argument("--fail-on",
                    choices=("any", "critical", "high", "medium", "low"),
                    help="exit 1 bila ada temuan setinggi itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    try:
        data = _read_json(Path(args.source), "source")
        context = {}
        if args.context:
            ctx = _read_json(Path(args.context), "context")
            if not isinstance(ctx, dict):
                raise ValueError("context harus objek")
            unknown = set(ctx) - set(CONTEXT_FLAGS)
            if unknown:
                raise ValueError(f"flag konteks tak dikenal: "
                                 f"{sorted(unknown)}")
            context = ctx
    except ValueError as exc:
        print(f"[owasp-rr] gagal: {exc}", file=sys.stderr)
        return 2
    if isinstance(data, dict):
        data = data.get("findings")
    if not isinstance(data, list):
        print("[owasp-rr] JSON harus list atau objek berisi 'findings'",
              file=sys.stderr)
        return 2
    result = assess(data, context)
    out = {
        "schema": SCHEMA,
        "source": args.source,
        "model": "OWASP Risk Rating Methodology (16 faktor 0-9 -> "
                 "likelihood x impact -> matriks band)",
        "matrix": [list(row) for row in RISK_MATRIX],
        "context": context,
        "summary": result["summary"],
        "findings": result["ranked"],
        "errors": result["errors"],
        "note": "default faktor = derivasi flag (eksplisit di "
                "factors_derived); skor LxI keterlacakan, LEVEL resmi "
                "dari matriks band.",
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    dist = ", ".join(f"{k}={v}" for k, v in s["by_level"].items()
                     if v or k in ("critical", "high"))
    print(f"[owasp-rr] {s['total']} temuan dinilai ({dist}); "
          f"error={s['errors']}")
    for row in result["ranked"][:10]:
        top10 = row["owasp_top10"] or "-"
        print(f"  [{row['risk_level']:8}] {row['id']} "
              f"(L={row['likelihood']['score']} {row['likelihood']['band']}"
              f", I={row['impact']['score']} {row['impact']['band']}, "
              f"LxI={row['risk_score_lxI']}, {top10})")
    if result["errors"]:
        for e in result["errors"][:10]:
            print(f"  [error    ] {e}")
    if args.fail_on:
        hit_levels = (["critical", "high"] if args.fail_on == "any"
                      else LEVELS[:LEVELS.index(args.fail_on) + 1])
        if any(r["risk_level"] in hit_levels for r in result["ranked"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
