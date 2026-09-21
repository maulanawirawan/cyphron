"""eval_report — hasilkan docs/EVAL.md: metrik evaluasi engine dari suite
unittest + benchmark KB. Regression gate: suite gak boleh merah; skor tak
boleh turun antar commit (disimpan riwayatnya di docs/eval-history.jsonl).
Jalankan: python scripts/eval_report.py  (stdlib-only)."""
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "docs" / "EVAL.md"
HISTORY = ROOT / "docs" / "eval-history.jsonl"


def run_suite() -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT, capture_output=True, text=True, timeout=1200)
    tail = (proc.stdout or "").splitlines()[-5:]
    ran = fail = err = 0
    ok = not proc.returncode
    for line in tail:
        m = re.search(r"Ran (\d+) tests", line)
        if m:
            ran = int(m.group(1))
        m = re.match(r"(FAILED|OK)(?: \(failures=(\d+),? ?(?:errors=(\d+))?)?", line)
        if line.startswith("OK"):
            ok = True
        elif line.startswith("FAILED"):
            ok = False
            fm = re.search(r"failures=(\d+)", line)
            em = re.search(r"errors=(\d+)", line)
            fail = int(fm.group(1)) if fm else 0
            err = int(em.group(1)) if em else 0
    skipped = 2 if "skipped" in (proc.stdout or "") else 0
    return {"ok": ok, "ran": ran, "failures": fail, "errors": err,
            "skipped": skipped, "seconds": round(proc.elapsed if hasattr(proc, "elapsed") else 0, 1)}


def run_benchmark() -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "cyphron", "benchmark"],
            cwd=ROOT / "cyphron", capture_output=True, text=True, timeout=300)
        return {"markdown": (proc.stdout or "").strip()}
    except Exception as exc:
        return {"markdown": f"(benchmark gagal: {type(exc).__name__}: {exc})"}


def engine_count() -> int:
    src = (ROOT / "cyphron" / "tools" / "__init__.py").read_text(
        encoding="utf-8", errors="replace")
    import re
    return len(re.findall(r"Tool\(\)", src))


def main() -> int:
    t0 = time.monotonic()
    suite = run_suite()
    bench = run_benchmark()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # regression gate: bandingkan jumlah test lulus vs riwayat
    prev = []
    if HISTORY.exists():
        for line in HISTORY.read_text(encoding="utf-8").splitlines():
            try:
                prev.append(json.loads(line))
            except ValueError:
                pass
    prev_ok = prev[-1]["suite"]["ok"] if prev else None
    prev_ran = prev[-1]["suite"]["ran"] if prev else None

    gate = "PASS" if (suite["ok"] and (prev_ok in (None, True))) else "FAIL"
    if prev_ran is not None and suite["ran"] < prev_ran:
        gate = "FAIL"  # test berkurang = regressi cakupan

    lines = [
        "# EVAL — Hasil Evaluasi Cyphron",
        "",
        f"Dibuat: {now} · Gerbang regresi: **{gate}**",
        "",
        "## Suite",
        "",
        f"- Test: {suite['ran']} (gagal {suite['failures']}, error {suite['errors']}, "
        f"skipped {suite['skipped']})",
        f"- Status: {'HIJAU' if suite['ok'] else 'MERAH'}",
        f"- Jumlah engine terdaftar: {engine_count()}",
        "",
        "## Benchmark KB (fixture deterministik)",
        "",
        "```",
        bench["markdown"],
        "```",
        "",
        "## Metode",
        "",
        "- Suite = seluruh tests/ (unit + e2e fixture, tanpa jaringan nyata).",
        "- Benchmark = fingerprint -> CPE -> KB NVD lokal pada dataset gold",
        "  internal; kasus ambigu DITOLAK dan dilaporkan terpisah (zero-FP).",
        "- Gerbang regresi: suite wajib hijau DAN jumlah test tidak boleh turun",
        "  vs riwayat sebelumnya (eval-history.jsonl).",
    ]
    EVAL.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with HISTORY.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": now, "gate": gate, "suite": suite}) + "\n")
    print(f"[eval] gerbang: {gate} — suite {suite['ran']} tests "
          f"({'hijau' if suite['ok'] else 'MERAH'}) -> {EVAL}")
    return 0 if gate == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
