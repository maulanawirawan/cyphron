"""[AUDIT: read-only] risk_matrix_80030 — penskoran register risiko
kualitatif ala NIST SP 800-30 Rev 1 (likelihood x impact -> level).

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/conducting-cyber-risk-assessment-with-nist-800-30' (antrean
SKILL-PORT-QUEUE #0320; atribusi ide, lisensi sumber Apache-2.0).
Dibangun from scratch TANPA kode sumber itu; inti deterministiknya
adalah MATRIKS 5x5 publik dari metodologi 800-30 (Appendix I: risiko
adalah fungsi likelihood dan impact) — bukan proses asesmen-nya.

Skala 5 level (qualitative, NIST 800-30): very_low, low, moderate,
high, very_high. Alias diterima case-insensitive: vl/l/m/h/vh,
medium->moderate, atau angka 1..5 (1=very_low .. 5=very_high).
Level di luar itu DITOLAK (fail-closed) — tidak ada pemetaan senyap
skala 0-10/0-100; konversi skala adalah keputusan operator.

Matriks (likelihood baris, impact kolom; VL..VH) — monotonic,
makin tinggi salah satunya, makin tinggi risiko:

            VL   L    M    H    VH
    VL      VL   VL   VL   L    M
    L       VL   VL   L    M    H
    M       VL   L    M    H    VH
    H       L    M    H    VH   VH
    VH      M    H    VH   VH   VH

Fitur:
  - risiko inheren per item (likelihood x impact) + peringkat
    (very_high dulu);
  - opsional residual: field residual_likelihood/residual_impact ->
    level residu + arah perubahan (unchanged/lowered/raised/worse);
  - opsional treatment (mitigate/transfer/avoid/accept) sekadar
    dibawa tembus ke output (tidak dinilai);
  - ringkasan distribusi per level + daftar top-risks.

Fail-closed:
  - source tidak ada / JSON tidak valid / bukan list  -> exit 2;
  - likelihood/impact tak dikenal / item tanpa id / field bukan
    string-angka -> item dicatat di "errors" TANPA level risiko dan
    tidak pernah ikut peringkat;
  - skala hasil matriks dicantumkan di output (keterlacakan model).

Pemakaian:
  python tools/risk_matrix_80030.py --source register.json --out risks.json
  python tools/risk_matrix_80030.py --source reg.json --fail-on very_high
Exit: 0 selesai; 1 item mencapai ambang --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "secai.risk-matrix-80030/1"
MAX_FILE_BYTES = 4 * 1024 * 1024

LEVELS = ("very_low", "low", "moderate", "high", "very_high")
LEVEL_INDEX = {name: i for i, name in enumerate(LEVELS)}
ALIASES = {
    "vl": "very_low", "very low": "very_low", "very_low": "very_low",
    "l": "low", "low": "low",
    "m": "moderate", "med": "moderate", "medium": "moderate",
    "moderate": "moderate",
    "h": "high", "high": "high",
    "vh": "very_high", "very high": "very_high", "very_high": "very_high",
}
NUM_ALIAS = {1: "very_low", 2: "low", 3: "moderate", 4: "high",
             5: "very_high"}

# baris = likelihood (VL..VH), kolom = impact (VL..VH)
RISK_MATRIX: tuple[tuple[str, ...], ...] = (
    ("very_low", "very_low", "very_low", "low", "moderate"),
    ("very_low", "very_low", "low", "moderate", "high"),
    ("very_low", "low", "moderate", "high", "very_high"),
    ("low", "moderate", "high", "very_high", "very_high"),
    ("moderate", "high", "very_high", "very_high", "very_high"),
)

TREATMENTS = ("mitigate", "transfer", "avoid", "accept")


def normalize_level(value: object) -> str:
    """Terima nama level/alias/angka 1..5 -> nama kanonik; selain itu
    ValueError (fail-closed, tanpa pemetaan senyap)."""
    if isinstance(value, bool):
        raise ValueError(f"level bukan skala valid: {value!r}")
    if isinstance(value, int) and value in NUM_ALIAS:
        return NUM_ALIAS[value]
    if isinstance(value, float) and value.is_integer() \
            and int(value) in NUM_ALIAS:
        return NUM_ALIAS[int(value)]
    text = str(value or "").strip().lower().replace("-", "_")
    if text.isdigit() and int(text) in NUM_ALIAS:
        return NUM_ALIAS[int(text)]
    if text in ALIASES:
        return ALIASES[text]
    raise ValueError(f"level bukan skala valid: {value!r}")


def risk_level(likelihood: str, impact: str) -> str:
    """Lookup matriks 5x5; input sudah nama kanonik."""
    return RISK_MATRIX[LEVEL_INDEX[likelihood]][LEVEL_INDEX[impact]]


def _direction(inherent: str, residual: str) -> str:
    di, dr = LEVEL_INDEX[inherent], LEVEL_INDEX[residual]
    if dr == di:
        return "unchanged"
    return "lowered" if dr < di else "raised"


def assess(records: list[dict]) -> dict:
    ranked: list[dict] = []
    errors: list[str] = []
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            errors.append(f"#index-{idx}: record bukan objek")
            continue
        ref = rec.get("id")
        if not str(ref or "").strip():
            errors.append(f"#index-{idx}: item tanpa id")
            continue
        ref = str(ref)
        try:
            lik = normalize_level(rec.get("likelihood"))
            imp = normalize_level(rec.get("impact"))
        except ValueError as exc:
            errors.append(f"{ref}: {exc}")
            continue
        inherent = risk_level(lik, imp)
        row: dict = {
            "id": ref,
            "threat_event": str(rec.get("threat_event") or "") or None,
            "asset": str(rec.get("asset") or "") or None,
            "likelihood": lik,
            "impact": imp,
            "risk_level": inherent,
        }
        treatment = str(rec.get("treatment") or "").strip().lower()
        if treatment:
            if treatment not in TREATMENTS:
                errors.append(f"{ref}: treatment tak dikenal: {treatment!r}")
                row["treatment"] = treatment
                row["treatment_valid"] = False
            else:
                row["treatment"] = treatment
        rlik_raw = rec.get("residual_likelihood")
        rimp_raw = rec.get("residual_impact")
        if rlik_raw is not None and rimp_raw is not None:
            try:
                rlik = normalize_level(rlik_raw)
                rimp = normalize_level(rimp_raw)
            except ValueError as exc:
                errors.append(f"{ref}: residual {exc}")
            else:
                residual = risk_level(rlik, rimp)
                row["residual_likelihood"] = rlik
                row["residual_impact"] = rimp
                row["residual_risk_level"] = residual
                row["residual_direction"] = _direction(inherent, residual)
        ranked.append(row)

    sev_rank = {name: i for i, name in enumerate(reversed(LEVELS))}
    ranked.sort(key=lambda r: (sev_rank[r["risk_level"]], r["id"]))

    by_level = {name: 0 for name in LEVELS}
    for row in ranked:
        by_level[row["risk_level"]] += 1
    by_level_residual = {name: 0 for name in LEVELS}
    for row in ranked:
        if row.get("residual_risk_level"):
            by_level_residual[row["residual_risk_level"]] += 1
    summary = {
        "total": len(ranked),
        "by_level": by_level,
        "by_level_residual": by_level_residual,
        "lowered": sum(1 for r in ranked
                       if r.get("residual_direction") == "lowered"),
        "raised": sum(1 for r in ranked
                      if r.get("residual_direction") == "raised"),
        "errors": len(errors),
    }
    return {"ranked": ranked, "summary": summary, "errors": errors}


def _matrix_markdown() -> str:
    head = "likelihood\\impact | " + " | ".join(
        l.upper() for l in LEVELS)
    lines = [head]
    for lik in LEVELS:
        cells = " | ".join(
            risk_level(lik, imp).upper() for imp in LEVELS)
        lines.append(f"{lik:<17} | {cells}")
    return "\n".join(lines)


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="risk_matrix_80030 — penskoran register risiko "
                    "kualitatif NIST SP 800-30 (read-only, nol jaringan, "
                    "fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file JSON register risiko (list item)")
    ap.add_argument("--fail-on", choices=LEVELS + ("any",),
                    help="exit 1 bila ada item pada level itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    source = Path(args.source)
    if not source.exists():
        print(f"[risk-80030] source tidak ada: {source}", file=sys.stderr)
        return 2
    try:
        raw = source.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"file terlalu besar (> {MAX_FILE_BYTES} byte)")
        data = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except (OSError, ValueError) as exc:
        print(f"[risk-80030] gagal: {exc}", file=sys.stderr)
        return 2
    if isinstance(data, dict):
        data = data.get("risks")
    if not isinstance(data, list):
        print("[risk-80030] JSON harus list atau objek berisi 'risks'",
              file=sys.stderr)
        return 2
    result = assess(data)
    out = {
        "schema": SCHEMA,
        "source": str(source),
        "model": "NIST SP 800-30 Rev.1 qualitative 5x5 (likelihood x "
                 "impact -> risk)",
        "matrix": [list(row) for row in RISK_MATRIX],
        "summary": result["summary"],
        "register": result["ranked"],
        "errors": result["errors"],
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    dist = ", ".join(f"{k}={v}" for k, v in s["by_level"].items()
                     if v or k == "very_high")
    print(f"[risk-80030] {s['total']} item dinilai "
          f"({dist}); error={s['errors']}")
    for row in result["ranked"][:10]:
        extra = ""
        if row.get("residual_risk_level"):
            extra = (f", residu={row['residual_risk_level']} "
                     f"({row['residual_direction']})")
        print(f"  [{row['risk_level']:10}] {row['id']}{extra}")
    if result["errors"]:
        for e in result["errors"][:10]:
            print(f"  [error     ] {e}")
    if args.fail_on:
        hit = ((args.fail_on == "any"
                and any(r["risk_level"] in ("high", "very_high")
                        for r in result["ranked"]))
               or any(r["risk_level"] == args.fail_on
                      for r in result["ranked"]))
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
