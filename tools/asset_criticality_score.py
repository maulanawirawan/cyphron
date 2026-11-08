r"""[AUDIT: read-only] asset_criticality_score — model skor kritikalitas
aset multi-faktor (6 faktor 1-5 -> skor tertimbang -> tier 1-5 ->
modifier SLA remediasi kerentanan) + join opsional ke daftar vuln.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/performing-asset-criticality-scoring-for-vulns' (antrean
SKILL-PORT-QUEUE #0773 — model 6 faktor: business function, data
sensitivity, regulatory scope, network exposure, recoverability, user
population; tabel tier + modifier SLA per tier; atribusi konsep,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH TANPA kode sumber itu
dan TANPA pandas (stdlib): inti deterministiknya adalah ARITMETIKA
penimbangan + tabel tier + modifier SLA — bukan CMDB-nya.

Ranah tool tetangga ditulis eksplisit:
  - vuln_sla_aging : aging/status temuan + eskalasi + KPI dgn kebijakan
    SLA flat per severity (modifier tunggal internet-facing + KEV);
    tool ini MENYUPPLY sisi yang hilang di situ — kritikalitas aset
    multi-faktor sebagai modifier SLA (tanpa mengubah ranah aging);
  - risk_matrix_80030 : matriks risiko kualitatif likelihood x impact
    utk register risiko organisasi (bukan penimbangan aset);
  - cspm_finding_ingest : normalisasi temuan CSPM -> findings.json.

Input -> mekanisme -> output:
  - Input   : --assets FILE (JSON list / objek {"assets": [...]} /
              CSV dgn kolom asset_id + kolom faktor opsional) dan
              --vulns FILE opsional (JSON list / {"findings": [...]} /
              CSV dgn kolom asset_id + severity); --weights FILE JSON
              opsional utk override bobot; --out.
  - Mekanisme: validasi faktor (1-5; absen = default 3 TERFLAG),
              skor = round(sum(faktor x bobot), 2), tier dari tabel
              ambang, modifier SLA per tier, adjusted SLA =
              ceil(base x (1 + modifier)), minimum 1 hari.
  - Output  : JSON {schema, weights_used, tier_table, assets, vulns,
              findings (kualitas data), summary}.

Kebijakan SLA dasar mengikuti vuln_sla_aging (critical 14, high 30,
medium 60, low 90 hari; info = tanpa SLA). Pembulatan CEIL (tenggat
tidak dipangkas oleh pembulatan) — konsisten dgn faktor facing di
vuln_sla_aging.

Fail-closed:
  - file tidak ada / JSON-CSV tidak valid / --weights invalid (bukan
    6 faktor, negatif, jumlah != 1.0)      -> exit 2;
  - faktor di luar 1-5 / bukan angka / asset_id kosong / severity tak
    dikenal / duplikat asset_id -> tercatat di findings + baris
    TERSEBUT tidak pernah dihitung diam-diam (aset: state error dan
    dikeluarkan dari scoring; vuln: tidak di-join);
  - vuln mengacu aset yang tidak ada di --assets -> TIDAK diam-diam
    dianggap Standard: dihitung baseline tier 3 + temuan eksplisit
    vuln-asset-unmapped (medium).

Pemakaian:
  python tools/asset_criticality_score.py --assets assets.json --out skor.json
  python tools/asset_criticality_score.py --assets assets.csv \
      --vulns vulns.csv --weights weights.json
Exit: 0 selesai; 2 input error.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

SCHEMA = "secai.asset-criticality-score/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

# Model sumber: bobot 6 faktor (jumlah = 1.0), skor 1-5 per faktor.
FACTORS: dict[str, float] = {
    "business_function": 0.25,
    "data_sensitivity": 0.25,
    "regulatory_scope": 0.15,
    "network_exposure": 0.15,
    "recoverability": 0.10,
    "user_population": 0.10,
}
DEFAULT_FACTOR = 3  # faktor absen = tengah (1-5), selalu TERFLAG
FACTOR_MIN, FACTOR_MAX = 1.0, 5.0

# (ambang skor, tier, label, modifier SLA) — dari model sumber.
TIERS: tuple[tuple[float, int, str, float], ...] = (
    (4.5, 1, "Crown Jewels", -0.50),
    (3.5, 2, "High Value", -0.25),
    (2.5, 3, "Standard", 0.00),
    (1.5, 4, "Low Impact", 0.25),
    (1.0, 5, "Minimal", 0.50),
)
BASELINE_TIER = (2.5, 3, "Standard", 0.00)

# SLA dasar = kebijakan vuln_sla_aging (konsistensi lintas tool).
BASE_SLA_DAYS = {"critical": 14, "high": 30, "medium": 60, "low": 90}
SEVERITIES = tuple(BASE_SLA_DAYS) + ("info",)
NO_SLA = "info"

TIER_TABLE = [
    {"min_score": t[0], "tier": t[1], "label": t[2], "sla_modifier": t[3]}
    for t in TIERS
]


class InputError(ValueError):
    """Input tidak bisa dipakai -> exit 2."""


def load_records(path: Path, list_key: str) -> list[dict]:
    """Baca JSON (list / objek berisi list_key) atau CSV -> list record."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise InputError(f"{path}: file terlalu besar (> {MAX_FILE_BYTES} byte)")
    text = raw.decode("utf-8-sig", errors="replace")
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames:
            raise InputError(f"{path}: CSV tanpa header")
        return [dict(row) for row in reader]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: JSON tidak valid: {exc}") from exc
    if isinstance(data, dict):
        data = data.get(list_key)
    if not isinstance(data, list):
        raise InputError(f"{path}: JSON harus list atau objek berisi "
                         f"'{list_key}'")
    return data


def _to_factor(value: object) -> float | None:
    """Konversi nilai faktor -> float 1-5; None = tidak layak dipakai."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        num = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not (FACTOR_MIN <= num <= FACTOR_MAX):
        return None
    return num


def tier_for(score: float) -> tuple[float, int, str, float]:
    """Tier utk skor (ambang pertama yang dilampaui)."""
    for row in TIERS:
        if score >= row[0]:
            return row
    return TIERS[-1]


def score_asset(asset_id: str, factors: dict[str, object],
                weights: dict[str, float]) -> dict:
    """Skor satu aset -> skor, tier, modifier; faktor absen = TERFLAG.

    Faktor tidak valid TIDAK didiam-diamkan: melempar ValueError utk
    penelepon mencatat state error.
    """
    used: dict[str, float] = {}
    defaulted: list[str] = []
    for name in FACTORS:
        raw = factors.get(name)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            used[name] = DEFAULT_FACTOR
            defaulted.append(name)
            continue
        val = _to_factor(raw)
        if val is None:
            raise ValueError(f"faktor {name} tidak valid: {raw!r}")
        used[name] = val
    total = round(sum(used[f] * weights[f] for f in FACTORS), 2)
    _, tier, label, modifier = tier_for(total)
    return {"asset_id": asset_id, "factors": used, "defaulted": defaulted,
            "score": total, "tier": tier, "label": label,
            "sla_modifier": modifier}


def load_weights(path: Path) -> dict[str, float]:
    """Baca override bobot (JSON objek saja); strict: 6 faktor, >=0,
    jumlah = 1.0."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise InputError(f"{path}: file terlalu besar (> {MAX_FILE_BYTES} byte)")
    try:
        obj = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: JSON tidak valid: {exc}") from exc
    if not isinstance(obj, dict):
        raise InputError(f"{path}: bobot harus objek faktor -> angka")
    if set(obj) != set(FACTORS):
        raise InputError(f"{path}: bobot wajib berisi tepat faktor "
                         f"{sorted(FACTORS)}; dapat {sorted(obj)}")
    weights: dict[str, float] = {}
    for key, val in obj.items():
        try:
            num = float(val)
        except (TypeError, ValueError):
            raise InputError(f"{path}: bobot {key} bukan angka: {val!r}")
        if num < 0:
            raise InputError(f"{path}: bobot {key} negatif: {num}")
        weights[key] = num
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise InputError(f"{path}: jumlah bobot {total} != 1.0")
    return weights


def assess(assets: list[dict], vulns: list[dict],
           weights: dict[str, float]) -> dict:
    """Skor semua aset + join vuln -> laporan JSON (deterministik)."""
    findings: list[dict] = []
    scored: dict[str, dict] = {}
    excluded = 0
    seen: set[str] = set()

    for idx, rec in enumerate(assets):
        ref = str(rec.get("asset_id", "") or "").strip()
        if not ref:
            excluded += 1
            findings.append({
                "check": "asset-no-id", "severity": "medium",
                "asset_id": None,
                "message": f"baris aset #{idx} tanpa asset_id — dilewati"})
            continue
        if ref in seen:
            excluded += 1
            findings.append({
                "check": "asset-duplicate", "severity": "medium",
                "asset_id": ref,
                "message": f"asset_id {ref!r} duplikat (baris #{idx}) — "
                           f"baris berikutnya diabaikan"})
            continue
        seen.add(ref)
        try:
            row = score_asset(ref, rec, weights)
        except ValueError as exc:
            excluded += 1
            findings.append({
                "check": "asset-factor-invalid", "severity": "medium",
                "asset_id": ref, "message": f"{exc} — aset tidak diskor"})
            continue
        if row["defaulted"]:
            findings.append({
                "check": "asset-factor-defaulted", "severity": "low",
                "asset_id": ref,
                "message": "faktor absen diberi default "
                           f"{DEFAULT_FACTOR}: "
                           f"{','.join(row['defaulted'])}"})
        scored[ref] = row

    # Catatan tiering tak informatif: mayoritas aset "kritis".
    tiers = [r["tier"] for r in scored.values()]
    if len(tiers) >= 4:
        top = sum(1 for t in tiers if t <= 2)
        if top / len(tiers) >= 0.8:
            findings.append({
                "check": "tiering-saturation", "severity": "low",
                "asset_id": None,
                "message": f"{top}/{len(tiers)} aset masuk tier 1-2 — "
                           "tiering tidak informatif (semua 'kritis' = "
                           "tidak ada prioritas)"})

    joined: list[dict] = []
    mapped = unmapped = 0
    for idx, rec in enumerate(vulns):
        ref = str(rec.get("asset_id", "") or "").strip()
        severity = str(rec.get("severity", "") or "").strip().lower()
        if severity not in SEVERITIES:
            findings.append({
                "check": "vuln-severity-unknown", "severity": "medium",
                "asset_id": ref or None,
                "message": f"vuln #{idx}: severity tak dikenal: "
                           f"{rec.get('severity')!r} — tidak di-join"})
            continue
        if not ref or ref not in scored:
            unmapped += 1
            findings.append({
                "check": "vuln-asset-unmapped", "severity": "medium",
                "asset_id": ref or None,
                "message": f"vuln #{idx} mengacu aset "
                           f"{ref!r} yang tidak ada di --assets — "
                           f"baseline tier {BASELINE_TIER[1]} "
                           "(tanpa modifier) + TANDA eksplisit"})
            row = {"tier": BASELINE_TIER[1], "label": BASELINE_TIER[2],
                   "sla_modifier": BASELINE_TIER[3]}
        else:
            mapped += 1
            row = scored[ref]
        base = BASE_SLA_DAYS.get(severity)
        if base is None:
            adjusted = None  # info = tanpa SLA
        else:
            adjusted = max(1, math.ceil(base * (1 + row["sla_modifier"])))
        joined.append({
            "asset_id": ref or None, "severity": severity,
            "base_sla_days": base, "tier": row["tier"],
            "label": row["label"], "sla_modifier": row["sla_modifier"],
            "adjusted_sla_days": adjusted})

    tier_counts = {str(t[1]): sum(1 for r in scored.values()
                                  if r["tier"] == t[1]) for t in TIERS}
    return {
        "schema": SCHEMA,
        "weights_used": dict(weights),
        "tier_table": TIER_TABLE,
        "assets": sorted(scored.values(), key=lambda r: r["asset_id"]),
        "vulns": joined,
        "findings": findings,
        "summary": {
            "assets_total": len(assets),
            "assets_scored": len(scored),
            "assets_excluded": excluded,
            "tier_counts": tier_counts,
            "vulns_total": len(vulns),
            "vulns_mapped": mapped,
            "vulns_unmapped": unmapped,
        },
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Skor kritikalitas aset multi-faktor -> tier 1-5 -> "
                    "modifier SLA vuln (read-only, nol jaringan).")
    ap.add_argument("--assets", required=True,
                    help="JSON/CSV aset (kolom asset_id + faktor opsional)")
    ap.add_argument("--vulns",
                    help="JSON/CSV vuln opsional (asset_id + severity) — "
                         "di-join utk adjusted SLA")
    ap.add_argument("--weights", help="JSON override bobot 6 faktor "
                                      "(jumlah wajib 1.0)")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    try:
        weights = dict(FACTORS)
        if args.weights:
            weights = load_weights(Path(args.weights))
        assets = load_records(Path(args.assets), "assets")
        vulns = load_records(Path(args.vulns), "findings") \
            if args.vulns else []
    except (InputError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out = assess(assets, vulns, weights)
    text = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
