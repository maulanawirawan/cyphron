"""[F24] Triage advisor — learning loop dari outcomes laporan.

Membaca findings/learning/outcomes-learning.json (data triage nyata:
accept/reject per kelas temuan) -> statistik per finding_class:
accepted_fixing vs rejected_duplicate vs rejected_impact. Sinyal ini
dipakai SEBELUM laporan berikutnya dikirim:
  - kelas yang historinya ditolak DUPLIKAT -> peringatan duplicate-risk
    (wajib novelty-check / cek known-list);
  - kelas yang historinya ditolak DAMPAK -> peringatan wajib impact
    narrative + bukti terukur;
  - kelas yang historinya diterima -> konfirmasi standar bukti.

READ-ONLY terhadap data learning — modul ini tidak pernah menulis
outcomes. Integrasi: tools/impact_narrative.py (peringatan + hint) dan
tools/report_pdf.py (tabel riwayat kelas di laporan).

Pemakaian:
  python tools/triage_advisor.py [--learning f.json ...] [--class-name X]
      [--out advisory.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

DEFAULT_LEARNING = ROOT / "findings" / "learning" / "outcomes-learning.json"

# nilai outcome yang dikenal (sisanya masuk "other" + dicatat namanya)
KNOWN_OUTCOMES = ("ACCEPTED_FIXING", "REJECTED_DUPLICATE", "REJECTED_IMPACT")

TOOL = "triage-advisor"


def load_outcomes(paths: list[Path]) -> tuple[list[dict], list[str]]:
    """Baca satu/lebih dokumen outcomes (read-only). File tidak ada /
    cacat = dilewati dengan catatan (advisory tetap jalan dengan data
    yang ada — fail-soft untuk data samping, bukan data inti)."""
    outcomes: list[dict] = []
    notes: list[str] = []
    for p in paths:
        if not p.exists():
            notes.append(f"learning tidak ada (dilewati): {p}")
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            notes.append(f"learning cacat (dilewati): {p}: {exc}")
            continue
        recs = doc.get("outcomes")
        if not isinstance(recs, list):
            notes.append(f"learning tanpa 'outcomes' list (dilewati): {p}")
            continue
        for r in recs:
            if isinstance(r, dict) and r.get("finding_class"):
                outcomes.append(r)
    return outcomes, notes


def stats_per_class(outcomes: list[dict]) -> dict[str, dict]:
    """Statistik per finding_class. Outcome tak dikenal masuk 'other'
    (dengan nama) — tidak pernah dihitung diterima/ditolak (fail-closed)."""
    out: dict[str, dict] = {}
    for r in outcomes:
        cls = str(r.get("finding_class") or "?")
        s = out.setdefault(cls, {"seen": 0, "accepted_fixing": 0,
                                 "rejected_duplicate": 0,
                                 "rejected_impact": 0, "other": 0,
                                 "other_outcomes": []})
        s["seen"] += 1
        o = str(r.get("outcome") or "").upper()
        if o == "ACCEPTED_FIXING":
            s["accepted_fixing"] += 1
        elif o == "REJECTED_DUPLICATE":
            s["rejected_duplicate"] += 1
        elif o == "REJECTED_IMPACT":
            s["rejected_impact"] += 1
        else:
            s["other"] += 1
            if o and o not in s["other_outcomes"]:
                s["other_outcomes"].append(o)
    for s in out.values():
        s["acceptance_rate"] = (round(s["accepted_fixing"] / s["seen"], 3)
                                if s["seen"] else None)
    return out


def advise(finding_class: str, outcomes: list[dict]) -> dict:
    """Advisory satu kelas: peringatan berbasis riwayat, tanpa tebakan
    (kelas tanpa riwayat = 'belum ada sinyal', bukan hijau)."""
    stats = stats_per_class(outcomes)
    s = stats.get(finding_class)
    warnings: list[str] = []
    hint_extra: str | None = None
    if not s:
        return {"finding_class": finding_class, "seen": 0,
                "accepted_fixing": 0, "rejected_duplicate": 0,
                "rejected_impact": 0, "acceptance_rate": None,
                "warnings": ["belum ada riwayat kelas ini — belum ada "
                             "sinyal (bukan hijau, cek manual)"],
                "hint_extra": None}
    n, d, i, a = s["seen"], s["rejected_duplicate"], s["rejected_impact"], \
        s["accepted_fixing"]
    if d:
        warnings.append(
            f"duplicate-risk: {d}/{n} laporan kelas ini ditolak karena "
            "DUPLIKAT — wajib novelty-check + cek known-list program "
            "sebelum submit")
    if i:
        warnings.append(
            f"impact-risk: {i}/{n} laporan kelas ini ditolak karena dampak "
            "tidak jelas — WAJIB impact narrative + bukti dampak terukur "
            "sebelum submit")
    if a and not d and not i:
        hint_extra = (f"kelas historinya diterima triage ({a}/{n}) — "
                      "pertahankan standar bukti terukur")
    return {"finding_class": finding_class, **{
                k: s[k] for k in ("seen", "accepted_fixing",
                                  "rejected_duplicate", "rejected_impact",
                                  "acceptance_rate")},
            "warnings": warnings, "hint_extra": hint_extra}


def enrich_narrative(data: dict, learning_paths: list[Path]) -> dict:
    """Integrasi impact_narrative: sisipkan peringatan learning + hint
    otomatis ke data narrative. Tanpa data learning = data apa adanya."""
    outcomes, _ = load_outcomes(learning_paths)
    if not outcomes:
        return data
    adv = advise(data.get("finding_class", ""), outcomes)
    if adv["seen"] == 0:
        return data
    data["learning"] = {k: adv[k] for k in
                        ("seen", "accepted_fixing", "rejected_duplicate",
                         "rejected_impact", "acceptance_rate", "warnings")}
    if adv["hint_extra"]:
        base = data.get("acceptance_hint", "")
        data["acceptance_hint"] = (base + " | " if base else "") + adv["hint_extra"]
    return data


def class_history_rows(outcomes: list[dict], limit: int = 8) -> list[dict]:
    """Baris tabel 'riwayat kelas' untuk laporan PDF (urut terbanyak)."""
    stats = stats_per_class(outcomes)
    rows = sorted(stats.items(), key=lambda kv: (-kv[1]["seen"], kv[0]))[:limit]
    return [{"finding_class": cls,
             "seen": s["seen"],
             "accepted_fixing": s["accepted_fixing"],
             "rejected_duplicate": s["rejected_duplicate"],
             "rejected_impact": s["rejected_impact"],
             "acceptance_rate_display": (f"{s['acceptance_rate']:.0%}"
                                         if s["acceptance_rate"] is not None
                                         else "—")}
            for cls, s in rows]


def main_with_args(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--learning", action="append", default=None,
                    help=f"file outcomes (boleh diulang; default: {DEFAULT_LEARNING})")
    ap.add_argument("--class-name", dest="cls", default=None,
                    help="advisory untuk satu kelas saja")
    ap.add_argument("--out", default=None,
                    help="simpan advisory sebagai findings.json (kontrak)")
    args = ap.parse_args(argv)

    paths = ([Path(p) for p in args.learning] if args.learning
             else [DEFAULT_LEARNING])
    outcomes, notes = load_outcomes(paths)
    stats = stats_per_class(outcomes)

    if args.cls:
        adv = advise(args.cls, outcomes)
        payload = {"ok": True, "advisory": adv, "notes": notes,
                   "sources": [str(p) for p in paths]}
        rows = None
    else:
        payload = {"ok": True, "classes": {k: stats[k] for k in sorted(stats)},
                   "notes": notes, "sources": [str(p) for p in paths]}
        rows = None
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    if args.out:
        if args.cls:
            adv = payload["advisory"]
            row = make_finding(
                tool=TOOL,
                title=f"Triage advisory — {args.cls} "
                      f"({adv['seen']} riwayat)",
                severity="info",
                description="Learning loop: statistik outcome kelas ini "
                            "dari laporan sebelumnya. Peringatan wajib "
                            "dipatuhi sebelum laporan berikutnya dikirim.",
                target_url=None,
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "REPORTING", "safety_class": "read-only",
                       **{k: adv[k] for k in ("seen", "accepted_fixing",
                                              "rejected_duplicate",
                                              "rejected_impact",
                                              "acceptance_rate")},
                       "warnings": adv["warnings"],
                       "hint_extra": adv["hint_extra"]})
            rows = [row]
        else:
            rows = [make_finding(
                tool=TOOL,
                title=f"Triage advisory — ringkasan {len(stats)} kelas",
                severity="info",
                description="Learning loop: statistik outcome per kelas "
                            "dari outcomes-learning (read-only).",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "REPORTING", "safety_class": "read-only",
                       "classes": {k: stats[k] for k in sorted(stats)}})]
        write_findings(args.out, rows,
                       {"run": TOOL, "safety_class": "read-only",
                        "sources": [str(p) for p in paths]})
        print(f"advisory -> {args.out}")
    return 0


def main() -> int:
    return main_with_args(None)


if __name__ == "__main__":
    raise SystemExit(main())
