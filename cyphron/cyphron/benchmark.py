"""benchmark — metrik kuantitatif Cyphron (Unity U6).

Bahasa klaim yang disiplin butuh ANGKA, bukan slogan. Modul ini menghitung:

- Precision / Recall / F1 atas pencocokan CVE (predicted vs gold);
- CPE-resolution accuracy (fingerprint -> vendor/product benar);
- version-resolution accuracy (keputusan match/no-match per kasus versi,
  termasuk penolakan ambigu yang dihitung terpisah — bukan FP);
- exploit-validation rate (temuan ber-exploit publik yang benar-benar
  terverifikasi deterministik).

Sumber kebenaran benchmark: dataset GOLD internal (fixture) + KB lokal.
Pipeline yang diukur adalah pipeline NYATA (fingerprint.to_cpe ->
nvd_sqlite.query_cves_for_product), bukan tiruan. Prinsip yang diukur dan
dilaporkan: "High-confidence deterministic matching with ambiguity
rejection" — ambigu DITOLAK, bukan ditebak; itu menaikkan precision dan
bisa menurunkan recall, dan kami laporkan apa adanya.
"""

from __future__ import annotations

from pathlib import Path

from .kb import fingerprint as _fp
from .kb import nvd_sqlite
from .kb.paths import resolve_kb_dir

# ------------------------------------------------------------- GOLD dataset
# Kasus bawaan (bisa diperluas lewat args). Setiap kasus: teks fingerprint
# mentah, CPE yang diharapkan (vendor/product), dan CVE gold yang HARUS
# cocok di KB (list kosong = memang tidak boleh ada klaim dari kasus ini).
GOLD_CASES: list[dict] = [
    {"text": "WordPress 6.4.3", "vendor": "wordpress", "product": "wordpress",
     "expect_cves": ["CVE-2024-4439"], "expect_match": True},
    {"text": "Open Journal Systems 3.3.0",
     "vendor": "public_knowledge_project", "product": "open_journal_systems",
     "expect_cves": ["CVE-2022-24181"], "expect_match": True},
    {"text": "Open Journal Systems 3.4.0.7",
     "vendor": "public_knowledge_project", "product": "open_journal_systems",
     "expect_cves": [], "expect_match": False},
    {"text": "nginx/1.20.1", "vendor": "f5", "product": "nginx",
     "expect_cves": [], "expect_match": False},
    {"text": "WordPress 6.5.3", "vendor": "wordpress", "product": "wordpress",
     "expect_cves": [], "expect_match": False},
    {"text": "WordPress", "vendor": "wordpress", "product": "wordpress",
     "expect_cves": [], "expect_match": False, "expect_versioned": False},
]


# ------------------------------------------------------------------ metrik
def precision_recall_f1(predicted: set[str], gold: set[str]) -> dict:
    tp = len(predicted & gold)
    fp = len(predicted - gold)
    fn = len(gold - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def cpe_resolution(resolved: dict[str, tuple[str, str] | None],
                   gold: dict[str, tuple[str, str]]) -> dict:
    """resolved: fingerprint -> (vendor, product) | None. gold: -> (v, p)."""
    total = len(gold)
    if not total:
        return {"accuracy": 1.0, "correct": 0, "total": 0}
    correct = sum(1 for k, g in gold.items()
                  if resolved.get(k) == g)
    return {"accuracy": round(correct / total, 4), "correct": correct,
            "total": total}


def exploit_validation_rate(with_public_exploit: set[str],
                            deterministically_verified: set[str]) -> dict:
    """Dari temuan yang punya exploit publik, berapa yang terbukti
    terverifikasi deterministik (bukan cuma cocok versi)."""
    total = len(with_public_exploit)
    verified = len(with_public_exploit & deterministically_verified)
    return {"rate": round(verified / total, 4) if total else 1.0,
            "verified": verified, "with_public_exploit": total}


# ------------------------------------------------------------------ runner
def run_cve_benchmark(kb_dir=None, cases: list[dict] | None = None) -> dict:
    """Jalankan pipeline pencocokan NYATA atas kasus GOLD; kembalikan metrik.

    kb_dir None = folder KB bawaan (butuh cpe.sqlite hasil `kb sync nvd`).
    Kasus dengan versi ambigu ditolak matcher tercatat sebagai
    ``ambiguous_rejected`` — BUKAN false positive (itulah disiplinnya)."""
    db = resolve_kb_dir(kb_dir) / "cpe.sqlite"
    if not db.exists():
        raise FileNotFoundError(
            "cpe.sqlite tidak ditemukan — jalankan `python -m cyphron kb "
            "--source nvd` atau berikan --kb-dir berisi fixture")
    rows_out: list[dict] = []
    predicted_all: set[str] = set()
    gold_all: set[str] = set()
    ambiguous_total = 0
    version_correct = 0
    resolved_map: dict[str, tuple[str, str] | None] = {}
    gold_cpe: dict[str, tuple[str, str]] = {}

    for case in (cases or GOLD_CASES):
        text = case["text"]
        gold_cpe[text] = (case["vendor"], case["product"])
        matches = _fp.to_cpe([text])
        match = next((m for m in matches if m.cpe23), None)
        resolved_map[text] = ((match.vendor, match.product)
                              if match is not None else None)
        predicted: set[str] = set()
        matched_rows: list[str] = []
        ambiguous = 0
        versioned = bool(match is not None and match.versioned)
        if versioned:
            try:
                rows, ambiguous = nvd_sqlite.query_cves_for_product(
                    db, match.vendor, match.product, match.version)
            except Exception:
                rows = []
            predicted = {r["id"] for r in rows}
            matched_rows = sorted(predicted)
        ambiguous_total += ambiguous
        gold_all |= set(case["expect_cves"])
        predicted_all |= predicted
        got_match = bool(predicted)
        if got_match == bool(case.get("expect_match")):
            version_correct += 1
        rows_out.append({
            "text": text, "cpe": resolved_map[text], "versioned": versioned,
            "predicted": matched_rows, "gold": list(case["expect_cves"]),
            "ambiguous_rejected": ambiguous, "ok": got_match == bool(
                case.get("expect_match")),
        })

    return {
        "matching": precision_recall_f1(predicted_all, gold_all),
        "cpe_resolution": cpe_resolution(resolved_map, gold_cpe),
        "version_resolution": {
            "accuracy": round(version_correct / len(rows_out), 4),
            "correct": version_correct, "total": len(rows_out)},
        "ambiguous_rejected": ambiguous_total,
        "cases": rows_out,
    }


def render_markdown(results: dict, title: str = "Benchmark Cyphron") -> str:
    """Hasil metrik -> markdown siap docs (angka, bukan slogan)."""
    m = results["matching"]
    c = results["cpe_resolution"]
    v = results["version_resolution"]
    lines = [
        f"# {title}", "",
        "Metrik dihitung dari pipeline pencocokan nyata (fingerprint -> CPE "
        "-> KB NVD lokal) atas dataset gold internal. Bahasa klaim resmi: "
        "**High-confidence deterministic CVE matching with ambiguity "
        "rejection** — kasus ambigu DITOLAK (tercatat terpisah, bukan "
        "false positive); konsekuensinya recall bisa lebih rendah, dan "
        "angkanya dilaporkan jujur di sini.", "",
        "| Metrik | Nilai |", "|---|---|",
        f"| Precision (CVE matching) | {m['precision']:.2f} |",
        f"| Recall (CVE matching) | {m['recall']:.2f} |",
        f"| F1 | {m['f1']:.2f} |",
        f"| False positive | {m['fp']} |",
        f"| False negative | {m['fn']} |",
        f"| CPE-resolution accuracy | {c['accuracy']:.2f} "
        f"({c['correct']}/{c['total']}) |",
        f"| Version-resolution accuracy | {v['accuracy']:.2f} "
        f"({v['correct']}/{v['total']}) |",
        f"| Kasus ambigu ditolak | {results['ambiguous_rejected']} |", "",
        "## Rincian kasus", "",
        "| Fingerprint | CPE | Prediksi | Gold | Ambigu ditolak | OK |",
        "|---|---|---|---|---|---|",
    ]
    for r in results["cases"]:
        lines.append(
            f"| {r['text']} | {r['cpe'][0]}/{r['cpe'][1] if r['cpe'] else '-'} "
            f"| {', '.join(r['predicted']) or '-'} | "
            f"{', '.join(r['gold']) or '-'} | {r['ambiguous_rejected']} | "
            f"{'ya' if r['ok'] else 'TIDAK'} |")
    lines.append("")
    return "\n".join(lines)
