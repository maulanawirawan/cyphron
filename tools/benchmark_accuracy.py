"""[F72][SAFETY: read-only] benchmark-accuracy — Cyphron Verification
Benchmark: mengukur precision/recall/false-positive-rate terhadap
ground truth yang diketahui kebenarannya (aplikasi uji lokal).

Dua run, satu kode target (tools/benchmark_target.py):
  vulnerable : 10 kondisi keamanan ditanam -> scanner HARUS menemukannya
               (recall + precision)
  hardened   : kondisi sama diperbaiki   -> scanner HARUS diam
               (false-positive-rate; semua temuan di sini = FP)

Aturan hitung (dokumentasi disengaja — metrik harus bisa direplikasi):
  - deteksi = baris findings dengan verdict >= 1 (L0 inventory tidak
    dihitung — itu fakta, bukan alarm)
  - match = level tool (satu kondisi ditanam dipetakan ke satu skill)
  - FP = deteksi yang tool-nya di luar daftar harapan
  - reproducibility = dua run vulnerable; sama jika himpunan
    (tool, title) identik

Pemakaian:
  python tools/benchmark_accuracy.py --run        # scan dua mode + metrik
  python tools/benchmark_accuracy.py --report f.json   # metrik saja dari hasil tersimpan
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from benchmark_target import serve  # noqa: E402

# kondisi ditanam -> skill yang diharapkan menemukannya (vulnerable mode)
GROUND_TRUTH = [
    ("http-security-headers", "header keamanan root tidak diatur"),
    ("clickjacking-protection-checker", "tanpa X-Frame-Options"),
    ("cookie-flags-aggregate", "cookie tanpa Secure/HttpOnly/SameSite"),
    ("server-version-disclosure", "Server header ber-versi"),
    ("directory-listing-detector", "directory listing /files/"),
    ("debug-page-detector", "halaman /debug bocor versi+stack"),
    ("robots-txt-surface", "robots membocorkan /admin/"),
    ("cors-checker", "CORS * + credentials"),
    ("swagger-ui-surface", "swagger terbuka"),
    ("api-docs-surface", "api-docs terbuka"),
    ("error-oracle", "pesan error database tercermin"),
]
EXPECTED_TOOLS = {t for t, _ in GROUND_TRUTH}


def detections(findings_doc: dict) -> list[dict]:
    """Baris findings.json yang termasuk 'deteksi' (verdict >= 1)."""
    return [f for f in findings_doc.get("findings", [])
            if f.get("verdict", 0) >= 1]


def metrics(expected_tools: set[str], rows: list[dict]) -> dict:
    hit_tools = {r.get("tool", "?") for r in rows}
    tp = len(expected_tools & hit_tools)
    fp_rows = [r for r in rows if r.get("tool", "?") not in expected_tools]
    fn = sorted(expected_tools - hit_tools)
    precision = tp / (tp + len(fp_rows)) if (tp + len(fp_rows)) else 1.0
    recall = tp / len(expected_tools) if expected_tools else 1.0
    return {
        "expected_tools": sorted(expected_tools),
        "hit_tools": sorted(expected_tools & hit_tools),
        "tp": tp, "fn": fn,
        "fp_count": len(fp_rows),
        "fp_tools": sorted({r.get("tool", "?") for r in fp_rows}),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "detections": len(rows),
    }


def _run_scan(binary: str, target: str, out_dir: Path, mode: str,
              registry: str | None = None) -> dict:
    out = out_dir / f"scan-{mode}.json"
    cmd = [binary, "scan", "--mode", "tier0", "--target", target,
           "--out", str(out_dir / f"run-{mode}")]
    if registry:
        # registry mini terdokumentasi: 11 skill ground-truth + 5 skill
        # noise (FP probe) — bukan inventaris penuh 92 skill
        cmd += ["--registry", registry]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=600, cwd=str(ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"scan {mode} exit {proc.returncode}: "
                           f"{proc.stderr[-400:]}")
    merged = out_dir / "run-{0}".format(mode) / "findings.json"
    return json.loads(merged.read_text(encoding="utf-8"))


def run_benchmark(binary: str, out_dir: Path,
                  registry: str | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"started_at": time.time(), "registry": registry,
                    "runs": {}}

    for mode in ("vulnerable", "hardened"):
        httpd, port = serve(mode)
        try:
            doc = _run_scan(binary, f"http://127.0.0.1:{port}", out_dir, mode,
                            registry)
        finally:
            httpd.shutdown()
        rows = detections(doc)
        expected = EXPECTED_TOOLS if mode == "vulnerable" else set()
        result["runs"][mode] = metrics(expected, rows)
        result["runs"][mode]["raw_titles"] = [
            f"{r.get('tool')}: {r.get('title', '')[:90]}" for r in rows]

    # reproducibility: vulnerable diulang, himpunan (tool, title) harus sama
    httpd, port = serve("vulnerable")
    try:
        doc2 = _run_scan(binary, f"http://127.0.0.1:{port}", out_dir,
                         "vulnerable-repeat", registry)
    finally:
        httpd.shutdown()
    set1 = {(r.get("tool"), r.get("title")) for r in detections(doc2)}
    set2 = {(t, title) for t, title in
            ((r.get("tool"), r["title"]) for r in
             json.loads((out_dir / "run-vulnerable" / "findings.json")
                        .read_text(encoding="utf-8"))["findings"]
            if r.get("verdict", 0) >= 1)}
    result["reproducible"] = set1 == set2
    result["verdict"] = _verdict(result)
    (out_dir / "accuracy.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def _verdict(result: dict) -> str:
    v = result["runs"]["vulnerable"]
    h = result["runs"]["hardened"]
    if v["recall"] >= 0.8 and h["fp_count"] == 0 and result["reproducible"]:
        return "PASS"
    if v["recall"] >= 0.5:
        return "WARN"
    return "FAIL"


def print_report(result: dict) -> None:
    for mode in ("vulnerable", "hardened"):
        r = result["runs"][mode]
        print(f"[{mode}] deteksi={r['detections']} TP={r['tp']} "
              f"FP={r['fp_count']} FN={len(r['fn'])} "
              f"precision={r['precision']} recall={r['recall']}")
        if r["fn"]:
            print("  FN (tidak ditemukan):", ", ".join(r["fn"]))
        if r["fp_tools"]:
            print("  FP (di luar harapan):", ", ".join(r["fp_tools"]))
    print(f"reproducible: {result.get('reproducible')} | "
          f"verdict: {result.get('verdict')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true",
                    help="jalankan benchmark penuh (dua run scan + repeat)")
    ap.add_argument("--binary", default=str(ROOT / "core-rs" / "target"
                                            / "release" / "cyphron.exe"))
    ap.add_argument("--out", default=str(ROOT / "findings" / "benchmark"))
    ap.add_argument("--report", default=None,
                    help="cetak metrik dari accuracy.json tanpa scan")
    ap.add_argument("--registry", default=str(ROOT / "tools"
                                              / "benchmark_registry.json"),
                    help="registry untuk scan benchmark (default: mini 16 skill)")
    args = ap.parse_args()
    if args.report:
        print_report(json.loads(Path(args.report).read_text(encoding="utf-8")))
        return 0
    if not args.run:
        ap.error("gunakan --run (benchmark penuh) atau --report (metrik)")
    result = run_benchmark(args.binary, Path(args.out), args.registry)
    print_report(result)
    return 0 if result.get("verdict") != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
