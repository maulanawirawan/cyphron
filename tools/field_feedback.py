"""[F13] Field feedback loop — temuan lapangan yang valid masuk produk.

Konsep: assessment bukan sekali jalan. Setiap run menyisakan temuan;
loop ini membaca RIWAYAT run (banyak findings.json) dan mengeluarkan
"tuning entries":
  - STABLE CONFIRMED : id sama, verdict >= L3 di >= 2 run -> pola valid
    terkonfirmasi; kandidat fixture test / KB skill.
  - FP CANDIDATE     : dulu L3+ lalu hilang/turun di run terbaru ->
    kandidat false positive; WAJIB jadi regression test (Fp-suite).
  - NEW              : hanya muncul di run terbaru -> butuh review manual.
Semua keluaran tetap findings.json satu pintu (category=LEARNING) —
loop ini juga bisa dijadwalkan lewat worker.

Pemakaian:
  python tools/field_feedback.py --runs findings/run-a findings/run-b \
      --out findings/learning/tuning.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402


def load_runs(runs: list[str]) -> list[dict]:
    """Baca findings.json dari tiap run dir (urut mtime)."""
    docs = []
    for r in runs:
        p = Path(r)
        f = p / "findings.json" if p.is_dir() else p
        if not f.exists():
            print(f"SKIP (tidak ada): {f}", file=sys.stderr)
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        if not doc.get("ok"):
            continue
        docs.append({"path": str(f), "findings": doc.get("findings", [])})
    return docs


def analyze(docs: list[dict]) -> tuple[list[dict], dict]:
    """Korelasikan temuan lintas run by id."""
    history: dict[str, list[dict]] = {}
    order: list[str] = []
    for i, d in enumerate(docs):
        for f in d["findings"]:
            fid = f.get("id")
            if not fid:
                continue
            if fid not in history:
                history[fid] = []
                order.append(fid)
            history[fid].append({"run": i, "verdict": f.get("verdict", 0),
                                 "tool": f.get("tool"),
                                 "title": f.get("title"),
                                 "severity": f.get("severity")})
    stable, fp_cand, new = [], [], []
    for fid in order:
        hist = history[fid]
        last = hist[-1]
        verdicts = [h["verdict"] for h in hist]
        n_confirmed = sum(1 for v in verdicts if v >= 3)
        appeared_in_last = last["run"] == len(docs) - 1
        if n_confirmed >= 2:
            stable.append((fid, hist))
        elif len(hist) == 1 and appeared_in_last and len(docs) > 1:
            # baru muncul di run terakhir — belum pernah terkonfirmasi
            new.append((fid, hist))
        elif verdicts[0] >= 3 and last["verdict"] < 3:
            # turun kelas di run terbaru — kandidat FP
            fp_cand.append((fid, hist))
        elif len(hist) == 1 and not appeared_in_last:
            # sekali muncul lalu hilang — kandidat FP
            fp_cand.append((fid, hist))
    detail = {
        "runs_analyzed": len(docs),
        "unique_findings": len(history),
        "stable_confirmed": len(stable),
        "fp_candidates": len(fp_cand),
        "new": len(new),
    }
    return (stable, fp_cand, new), detail


def build_findings(stable, fp_cand, new, detail) -> list[dict]:
    rows: list[dict] = []

    def row(tool, title, desc, rec, severity, verdict, status, extra):
        rows.append(make_finding(
            tool=tool, title=title, severity=severity, description=desc,
            recommendation=rec, evidence_kind="file-manifest",
            finding_class="posture", confidence=1.0, status=status,
            verdict=verdict, extra={"category": "LEARNING",
                                    "safety_class": "read-only", **extra}))

    for fid, hist in stable:
        tools = sorted({h["tool"] for h in hist})
        row("field-feedback",
            f"STABLE CONFIRMED: {hist[0]['title']} ({len(hist)} run)",
            "Temuan sama mencapai L3+ di beberapa run — pola valid "
            "terkonfirmasi. Kandidat: fixture test skill + entri KB.",
            "Jadikan fixture regresi + catat di KB skill terkait.",
            "info", 0, "confirmed",
            {"learning_kind": "stable_confirmed", "id": fid,
             "runs": len(hist), "tools": tools})
    for fid, hist in fp_cand:
        row("field-feedback",
            f"FP CANDIDATE: {hist[0]['title']}",
            "Temuan pernah L3+ tetapi hilang/turun di run terbaru — "
            "kandidat false positive. WAJIB dianalisis dan menjadi "
            "regression test (Fp-suite) bila terbukti FP.",
            "Analisis: reproduksi ulang; bila FP -> perbaiki skill + "
            "tambah test Fp baru.",
            "low", 1, "unconfirmed",
            {"learning_kind": "fp_candidate", "id": fid,
             "history": hist[:5]})
    for fid, hist in new:
        row("field-feedback",
            f"NEW FINDING (unreviewed): {hist[0]['title']}",
            "Temuan baru dari run terakhir — belum melintasi lebih dari "
            "satu run; butuh verifikasi manual berotorisasi.",
            "", "info", 1, "unconfirmed",
            {"learning_kind": "new", "id": fid})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs", nargs="+", required=True,
                    help="dir/file findings.json run; urut kronologis")
    ap.add_argument("--out", default="findings/learning/tuning.json")
    args = ap.parse_args()
    docs = load_runs(args.runs)
    (stable, fp_cand, new), detail = analyze(docs)
    rows = build_findings(stable, fp_cand, new, detail)
    write_findings(args.out, rows, {
        "run": "field-feedback", "method": "cross-run-correlation",
        "safety_class": "read-only", "requests": 0, **detail,
    })
    print(json.dumps(detail, ensure_ascii=False))
    print(f"field-feedback: {len(rows)} tuning entries -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
