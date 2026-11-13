"""[SCORE] cvss_score — kalkulator CVSS v3.1 base score, fail-closed.

Kenapa secai butuh ini: findings.json punya severity (high/medium/...)
dan template nuclei punya cvss-score — tapi tidak ada alat yang
MENGHITUNG skor dari vektor (laporan harus reproducible: skor
dihitung dari vektor, bukan diketik manual). Fail-closed:
  - vektor tidak lengkap (8 metric wajib)  -> error exit 2
  - metric di luar nilai valid              -> error exit 2
  - urutan/duplikat metric diharuskan?      -> duplikat ditolak
Exit: 0 skor tercetak (+ JSON bila --out); 2 vektor tidak valid.

Pemakaian:
  python tools/cvss_score.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  python tools/cvss_score.py --vector "..." --out cvss.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

SCHEMA = "secai.cvss-score/1"

# metric -> {value: (bobot/singkatan)} — dari spesifikasi CVSS v3.1
AV = {"N": 0.85, "A": 0.77, "L": 0.55, "P": 0.62}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}          # scope unchanged
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}          # scope changed
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
ALLOWED = {
    "AV": set(AV), "AC": set(AC),
    "PR": set(PR_U), "UI": set(UI), "S": {"C", "U"},
    "C": set(CIA), "I": set(CIA), "A": set(CIA),
}


def _roundup(x: float) -> float:
    """Spec: round UP ke 1 desimal; gunakan toleransi float spesifikasi."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    """Parse + validasi vektor CVSS v3.1 — error eksplisit (fail-closed)."""
    v = (vector or "").strip()
    if v.upper().startswith("CVSS:3.1/"):
        v = v[len("CVSS:3.1/"):]
    parts = [p for p in v.split("/") if p]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"metric tidak valid (harus KEY:VALUE): {part!r}")
        k, val = part.split(":", 1)
        k, val = k.upper(), val.upper()
        if k not in ALLOWED:
            raise ValueError(f"metric tidak dikenal: {k!r} (allowed: "
                             f"{','.join(ALLOWED)})")
        if k in metrics:
            raise ValueError(f"metric duplikat: {k}")
        if val not in ALLOWED[k]:
            raise ValueError(f"nilai tidak valid untuk {k}: {val!r} "
                             f"(allowed: {','.join(sorted(ALLOWED[k]))})")
        metrics[k] = val
    missing = [k for k in REQUIRED if k not in metrics]
    if missing:
        raise ValueError(f"metric wajib hilang: {','.join(missing)}")
    return metrics


def score_vector(metrics: dict) -> dict:
    """Hitung base score sesuai spesifikasi CVSS v3.1."""
    iss_prod = 1.0
    for m in ("C", "I", "A"):
        iss_prod *= (1.0 - CIA[metrics[m]])
    iss = 1.0 - iss_prod  # ISS = 1 - (1-C)(1-I)(1-A)
    scope_changed = metrics["S"] == "C"
    pr_table = PR_C if scope_changed else PR_U
    if iss <= 0:
        impact = 0.0
    elif scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (8.22 * AV[metrics["AV"]] * AC[metrics["AC"]]
                      * pr_table[metrics["PR"]] * UI[metrics["UI"]])
    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    score = _roundup(base)
    # severity band v3.1
    if score == 0.0:
        severity = "NONE"
    elif score <= 3.9:
        severity = "LOW"
    elif score <= 6.9:
        severity = "MEDIUM"
    elif score <= 8.9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"
    return {
        "schema": SCHEMA,
        "vector": "CVSS:3.1/" + "/".join(
            f"{k}:{metrics[k]}" for k in REQUIRED),
        "base_score": score,
        "severity": severity,
        "iss": round(iss, 4),
        "impact": round(impact, 4),
        "exploitability": round(exploitability, 4),
        "scope_changed": scope_changed,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="cvss_score — kalkulator CVSS v3.1 base score "
                    "(fail-closed; skor reproducible dari vektor).")
    ap.add_argument("--vector", required=True,
                    help="vektor CVSS v3.1 (boleh dengan awalan CVSS:3.1/)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        metrics = parse_vector(args.vector)
        result = score_vector(metrics)
    except ValueError as exc:
        print(f"[cvss] vektor tidak valid: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[cvss] {result['vector']}")
    print(f"[cvss] base score: {result['base_score']} ({result['severity']})"
          f" | impact {result['impact']} / exploitability "
          f"{result['exploitability']} | scope "
          f"{'CHANGED' if result['scope_changed'] else 'UNCHANGED'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
