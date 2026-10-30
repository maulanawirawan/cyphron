"""[F72][SAFETY: read-only] benchmark-accuracy — Cyphron Verification
Benchmark: mengukur precision/recall/false-positive-rate terhadap
ground truth yang diketahui kebenarannya (aplikasi uji lokal).

Tiga run, satu kode target (tools/benchmark_target.py):
  vulnerable        : 11 kondisi keamanan ditanam -> scanner HARUS
                      menemukannya (recall + precision)
  hardened          : kondisi sama diperbaiki   -> scanner HARUS diam
                      (false-positive-rate; semua temuan di sini = FP)
  vulnerable-repeat : ulang vulnerable -> reproducibility

Pipeline per run (perbaikan sesi benchmark-full-run 2026-10-30):
  1. server uji diangkat (serve_forever di thread daemon — server yang
     tidak menjalankan serve_forever tidak pernah melayani koneksi dan
     shutdown()-nya deadlock; pelajaran run lama yang "Fetch failed");
  2. FASE CAPTURE: 5 GET read-only (root + /files/ + /debug + /swagger +
     /api-docs) — body digabung jadi SATU file evidence (penanda section
     TANPA slash supaya tidak memicu signature skill) + headers root
     disimpan sibling `.headers` (format yang dibaca load_headers skill);
     fetch root gagal = run DIBATALKAN (fail-closed, tanpa metrik);
  3. DUA scan per mode, hasil digabung di sisi harness:
     a. scan bukti `cyphron scan --evidence <capture>` — 11 skill
        requires_evidence konsumsi capture (kebijakan binary: skill
        1-request di-skip saat --evidence, mode bukti nol-request);
     b. scan live tanpa --evidence — 3 skill 1-request fetch sendiri
        (cors-checker, robots-txt-surface, error-oracle);
  4. metrik dihitung dari gabungan findings kedua scan (run dir dibersihkan
     dulu — file skill sisa run lama tidak boleh terhitung).

Aturan hitung (dokumentasi disengaja — metrik harus bisa direplikasi):
  - deteksi = baris findings dengan verdict >= 1 (L0 inventory tidak
    dihitung — itu fakta, bukan alarm)
  - match = level tool (satu kondisi ditanam dipetakan ke satu skill)
  - FP = deteksi yang tool-nya di luar daftar harapan
  - reproducibility = dua run vulnerable; sama jika himpunan
    (tool, title) identik SETELAH URL target (port ephemeral berubah
    antar-run) dinormalisasi menjadi <TARGET>

Registry mini (tools/benchmark_registry.json) = 11 skill ground-truth +
3 skill noise (analytics-tracker-surface, http2-support-checker,
tech-fingerprint — semuanya diam pada fixture). DUA skill noise lama
DIKELUARKAN dengan alasan terdokumentasi: cdn-detector dan
waf-fingerprint memberi verdict 1 BY-ABSENCE (header CDN/WAF tidak ada
= lead) — pada lab lokal tanpa CDN keduanya selalu menyala di KEDUA
mode, sehingga bukan pengukur akurasi deteksi kondisi ditanam melainkan
desain posture-lead; nilai mereka dinilai terpisah dari benchmark ini.

Pemakaian:
  python tools/benchmark_accuracy.py --run        # benchmark penuh + metrik
  python tools/benchmark_accuracy.py --report f.json   # metrik dari hasil tersimpan
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from benchmark_target import serve  # noqa: E402

UA = "Mozilla/5.0 (compatible; cyphron-benchmark/1.0)"
FETCH_TIMEOUT = 15.0

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

# path probe capture (TANPA root) — konvensi permukaan umum, bounded 4;
# nama section di penanda TANPA slash agar tidak memicu signature skill
PROBE_PATHS = ["/files/", "/debug", "/swagger", "/api-docs"]


def detections(findings_doc: dict) -> list[dict]:
    """Baris findings.json yang termasuk 'deteksi' (verdict >= 1)."""
    return [f for f in findings_doc.get("findings", [])
            if f.get("verdict", 0) >= 1]


def _norm(tool: str, title: str, target: str) -> tuple[str, str]:
    """Normalisasi (tool, title): URL target (port ephemeral berubah
    antar-run) diganti <TARGET> supaya perbandingan reproducibility
    mengukur konsistensi deteksi, bukan konsistensi port."""
    return (tool, title.replace(target, "<TARGET>"))


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


def _serve_alive(mode: str):
    """Angkat server uji dan JANGankan: serve_forever di thread daemon.
    Tanpa ini koneksi hanya menumpuk di backlog (tak pernah di-accept —
    penyebab 'Fetch failed' run lama) dan shutdown() deadlock."""
    httpd, port = serve(mode)
    t = threading.Thread(target=httpd.serve_forever,
                         kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return httpd, port


def _fetch(url: str) -> tuple[int, str, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return r.status, r.read(1_000_000).decode("utf-8",
                                                      errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1_000_000).decode("utf-8",
                                                errors="replace"), dict(e.headers)


def _capture_evidence(base: str, capture_dir: Path) -> dict:
    """Fase capture: root (body + headers) + probe path ter-bounded.
    Body digabung ke SATU file (skill menerima satu @EVIDENCE@);
    penanda section tanpa slash. Fail-closed: root gagal = raise."""
    capture_dir.mkdir(parents=True, exist_ok=True)
    code, root_body, headers = _fetch(base + "/")
    if code != 200:
        raise RuntimeError(f"capture root {base}/ gagal: HTTP {code} "
                           f"(server uji tidak sehat — run dibatalkan, "
                           f"tanpa metrik)")
    sections = [f"<!-- cyphron-evidence section=0 name=root -->\n{root_body}"]
    for i, p in enumerate(PROBE_PATHS, start=1):
        code_p, body_p, _ = _fetch(base + p)
        name = p.strip("/").replace("/", "-") or f"probe{i}"
        sections.append(f"<!-- cyphron-evidence section={i} "
                        f"name={name} status={code_p} -->\n{body_p}")
    page = capture_dir / "page.html"
    page.write_text("\n".join(sections), encoding="utf-8")
    # sibling headers — format yang dibaca load_headers skill: JSON dict
    Path(str(page) + ".headers").write_text(
        json.dumps(headers, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"page": str(page), "root_status": code,
            "probes": PROBE_PATHS, "requests": 1 + len(PROBE_PATHS)}


def _run_scan(binary: str, target: str, out_dir: Path, mode: str,
              evidence: Path | None, registry: str | None = None,
              suffix: str = "") -> dict:
    """Satu scan. evidence=None = scan live (skill 1-request jalan,
    skill requires_evidence di-skip binary); evidence terisi = scan bukti
    (kebijakan binary: skill 1-request di-skip saat --evidence — mode
    bukti nol-request). Benchmark butuh KEDUANYA, digabung pemanggil."""
    out = out_dir / f"run-{mode}{suffix}"
    # run dir bersih — file skill sisa run lama tidak boleh terbaca
    # sebagai hasil run baru (kontaminasi metrik)
    shutil.rmtree(out, ignore_errors=True)
    cmd = [binary, "scan", "--mode", "tier0", "--target", target,
           "--out", str(out)]
    if evidence is not None:
        cmd += ["--evidence", str(evidence)]
    if registry:
        cmd += ["--registry", registry]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=600, cwd=str(ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"scan {mode}{suffix} exit {proc.returncode}: "
                           f"{proc.stderr[-400:]}")
    merged = out / "findings.json"
    if not merged.exists():
        raise RuntimeError(f"scan {mode}{suffix}: findings.json tidak "
                           f"tercipta (fail-closed — tanpa metrik)")
    return json.loads(merged.read_text(encoding="utf-8"))


def _scan_both(binary: str, target: str, out_dir: Path, mode: str,
               capture_page: Path, registry: str | None) -> tuple[list, list]:
    """Scan bukti (12 skill evidence) + scan live (3 skill 1-request),
    kembalikan (semua baris findings gabungan, baris deteksi gabungan).
    Skill 1-request saat --evidence di-skip binary (kebijakan mode
    bukti nol-request) — dipisah scan, digabung di sisi harness."""
    doc_e = _run_scan(binary, target, out_dir, mode, capture_page, registry)
    doc_l = _run_scan(binary, target, out_dir, mode, None, registry,
                      suffix="-live")
    rows = (doc_e.get("findings", []) + doc_l.get("findings", []))
    return rows, [r for r in rows if r.get("verdict", 0) >= 1]


def run_benchmark(binary: str, out_dir: Path,
                  registry: str | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"started_at": time.time(), "registry": registry,
                    "harness": "benchmark_accuracy/2 (capture+serve_forever)",
                    "runs": {}}
    norm_sets: dict[str, set] = {}
    targets: dict[str, str] = {}

    for mode in ("vulnerable", "hardened"):
        httpd, port = _serve_alive(mode)
        try:
            base = f"http://127.0.0.1:{port}"
            cap = _capture_evidence(base, out_dir / f"capture-{mode}")
            rows, det = _scan_both(binary, base, out_dir, mode,
                                   Path(cap["page"]), registry)
        finally:
            httpd.shutdown()
            httpd.server_close()
        targets[mode] = base
        # request per mode: 5 capture + 3 live (cors/robots/error-oracle)
        result["runs"][mode] = {"capture": cap, "requests_total": 8}
        expected = EXPECTED_TOOLS if mode == "vulnerable" else set()
        m = metrics(expected, det)
        m["raw_titles"] = [f"{r.get('tool')}: {r.get('title', '')[:90]}"
                           for r in det]
        result["runs"][mode].update(m)
        norm_sets[mode] = {_norm(r.get("tool", "?"), r.get("title", ""), base)
                           for r in det}

    # reproducibility: vulnerable diulang, himpunan (tool, title-norm) sama
    httpd, port = _serve_alive("vulnerable")
    try:
        base2 = f"http://127.0.0.1:{port}"
        cap2 = _capture_evidence(base2, out_dir / "capture-vulnerable-repeat")
        _, det2 = _scan_both(binary, base2, out_dir, "vulnerable-repeat",
                             Path(cap2["page"]), registry)
    finally:
        httpd.shutdown()
        httpd.server_close()
    targets["vulnerable-repeat"] = base2
    norm_sets["vulnerable-repeat"] = {
        _norm(r.get("tool", "?"), r.get("title", ""), base2) for r in det2}
    result["reproducible"] = (norm_sets["vulnerable"]
                              == norm_sets["vulnerable-repeat"])
    result["verdict"] = _verdict(result)
    result["finished_at"] = time.time()
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
              f"precision={r['precision']} recall={r['recall']} "
              f"(requests={r.get('requests_total', '?')})")
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
                    help="registry untuk scan benchmark (default: mini 14 skill)")
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
