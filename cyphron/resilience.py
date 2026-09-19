"""resilience — Uji ketahanan bertahap + deteksi titik jenuh (Fullpower §2d).

Ini versi produk dari pertanyaan "apakah website kita bertahan?" — TANPA
modul flood/DDoS: beban diberikan BERTAHAP lewat perf_engine (bounded:
VU cap, durasi cap, rate tetap), lalu dianalisis:

- knee (titik jenuh): stage pertama di mana error-rate naik melewati
  ambang, p95 melompat > 2x baseline, ATAU throughput justru turun saat
  beban naik;
- klasifikasi: SURVIVE (nol knee, error < 1%) / DEGRADE (knee ada tapi
  service masih menjawab mayoritas) / FAIL (mayoritas request gagal);
- laporan markdown siap klien: tabel stage, knee, klasifikasi,
  rekomendasi (autoscaling/rate-limit/timeout tuning).

Pagar: total durasi dan VU dibatasi keras; CLI `resilience` wajib dokumen
otorisasi (gate menilai risk "active"+"load"), sama seperti `perf`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import perf_engine

VU_CAP = 50
STAGE_DURATION_CAP_S = 60
TOTAL_DURATION_CAP_S = 180

DEFAULT_LADDER = [
    {"vus": 2, "duration_s": 6},
    {"vus": 5, "duration_s": 6},
    {"vus": 10, "duration_s": 6},
    {"vus": 20, "duration_s": 6},
]
QUICK_LADDER = [
    {"vus": 2, "duration_s": 3},
    {"vus": 5, "duration_s": 3},
    {"vus": 10, "duration_s": 3},
]

_ERROR_RATE_ALERT = 0.05   # 5% gagal = kandidat knee
_ERROR_RATE_FAIL = 0.5     # 50% gagal = FAIL


def _stage_metrics(m: dict) -> dict:
    total = max(m["total"], 1)
    fail = m["5xx"] + m["net_err"]
    return {
        "vus": m["scenario"]["vus"],
        "duration_s": m["scenario"]["duration_s"],
        "total": m["total"],
        "rps": m["rps"],
        "p95_ms": m["latency_ms"]["p95"],
        "p50_ms": m["latency_ms"]["p50"],
        "ok": m["ok"],
        "5xx": m["5xx"],
        "net_err": m["net_err"],
        "error_rate": round(fail / total, 4),
    }


def detect_knee(stages: list[dict]) -> dict | None:
    """Stage pertama yang menunjukkan degradasi nyata (deterministik).

    Latency sendiri TIDAK cukup jadi knee (antrean normal ikut memanjang
    saat VU naik): knee latency hanya bila p95 meledak BERSAMAAN throughput
    yang turun — itu saturasi sungguhan."""
    if not stages:
        return None
    baseline_p95 = stages[0]["p95_ms"] or 1
    for i in range(1, len(stages)):
        s = stages[i]
        prev = stages[i - 1]
        reasons = []
        if s["error_rate"] >= _ERROR_RATE_ALERT and \
                s["error_rate"] > prev["error_rate"] * 2:
            reasons.append(f"error-rate {s['error_rate']:.0%} "
                           f"(sebelumnya {prev['error_rate']:.0%})")
        if s["p95_ms"] > baseline_p95 * 3 \
                and s["p95_ms"] > prev["p95_ms"] * 1.5 \
                and s["rps"] < prev["rps"] * 0.8:
            reasons.append(f"p95 {s['p95_ms']}ms meledak (>3x baseline) "
                           f"bersama throughput turun {prev['rps']}->"
                           f"{s['rps']} rps (saturasi)")
        if s["rps"] < prev["rps"] * 0.7 and s["vus"] > prev["vus"] \
                and s["error_rate"] > 0:
            reasons.append(f"throughput turun {prev['rps']}->{s['rps']} rps "
                           "saat beban naik (saturasi)")
        if reasons:
            return {"stage_index": i, "vus": s["vus"],
                    "reasons": reasons}
    return None


def classify(stages: list[dict], knee: dict | None) -> tuple[str, str]:
    if not stages:
        return "NO-DATA", "tidak ada sampel"
    final = stages[-1]
    if final["error_rate"] >= _ERROR_RATE_FAIL:
        return ("FAIL",
                f"mayoritas request gagal pada {final['vus']} VU "
                f"(error {final['error_rate']:.0%})")
    if knee is None:
        worst = max(s["error_rate"] for s in stages)
        if worst < 0.01:
            return ("SURVIVE",
                    "semua stage sehat (error < 1%, p95 stabil)")
        if worst >= _ERROR_RATE_ALERT:
            # degradasi tinggi TAPI MERATA tak pernah menghasilkan knee —
            # jangan sebut "masih rendah"
            return ("DEGRADE",
                    f"error puncak {worst:.0%} merata antar stage tanpa titik "
                    "jenuh jelas — layanan stabil-buruk, perbaiki sebelum beban nyata")
        return ("SURVIVE",
                f"nol knee terdeteksi; error puncak {worst:.0%} masih rendah")
    return ("DEGRADE",
            f"titik jenuh di {knee['vus']} VU — service masih menjawab "
            f"tapi menurun (perbaiki sebelum beban nyata)")


def run_resilience(target: str, profile: str = "standard",
                   timeout: float = 8.0) -> dict:
    """Jalankan ladder bertahap + analisis. Caller (CLI) wajib memastikan
    gate otorisasi load/active LULUS sebelum memanggil ini."""
    ladder = QUICK_LADDER if profile == "quick" else DEFAULT_LADDER
    total_s = sum(s["duration_s"] for s in ladder)
    if total_s > TOTAL_DURATION_CAP_S:
        raise ValueError("total durasi ladder melebihi cap")
    stages: list[dict] = []
    for step in ladder:
        vus = min(int(step["vus"]), VU_CAP)
        dur = min(int(step["duration_s"]), STAGE_DURATION_CAP_S)
        m = perf_engine.run_scenario({
            "url": target, "vus": vus, "duration_s": dur,
            "timeout": timeout, "sleep_s": 0.0,
        })
        stages.append(_stage_metrics(m))
    knee = detect_knee(stages)
    verdict, reason = classify(stages, knee)
    return {
        "target": target,
        "profile": profile,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "stages": stages,
        "knee": knee,
        "verdict": verdict,
        "reason": reason,
        "bounded": {"vu_cap": VU_CAP,
                    "total_duration_cap_s": TOTAL_DURATION_CAP_S},
        "note": ("uji ketahanan bounded berotorisasi — bukan modul flood; "
                 "beban bertahap dengan rate tetap, cap keras"),
    }


def render_resilience_report(res: dict) -> str:
    lines = [
        "# Laporan Uji Ketahanan (Resilience)", "",
        f"**Target**: {res['target']}  ",
        f"**Profil**: {res['profile']}  ",
        f"**Waktu**: {res['started_at']}",
        "",
        f"## Verdict: **{res['verdict']}**",
        "",
        f"{res['reason']}.",
        "",
        "## Tahapan beban (bounded, bertahap)",
        "",
        "| VU | Durasi | Request | RPS | p50 (ms) | p95 (ms) | "
        "5xx | net-err | Error-rate |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in res["stages"]:
        lines.append(
            f"| {s['vus']} | {s['duration_s']}s | {s['total']} | {s['rps']} "
            f"| {s['p50_ms']} | {s['p95_ms']} | {s['5xx']} | "
            f"{s['net_err']} | {s['error_rate']:.1%} |")
    knee = res.get("knee")
    lines += ["", "## Titik jenuh (knee)", ""]
    if knee:
        lines.append(f"- **Stage {knee['stage_index'] + 1} "
                     f"({knee['vus']} VU)**:")
        for r in knee["reasons"]:
            lines.append(f"  - {r}")
    else:
        lines.append("- Tidak ada knee pada ladder ini — naikkan beban "
                     "bertahap berikutnya (tetap bounded) untuk mencari "
                     "batas nyata.")
    lines += ["", "## Rekomendasi", ""]
    if res["verdict"] == "SURVIVE":
        lines += [
            "- Pertahankan konfigurasi; jadwalkan ulang resilience test "
            "setelah perubahan infrastruktur besar.",
            "- Catat baseline p95 saat ini sebagai acuan regesi."]
    elif res["verdict"] == "DEGRADE":
        lines += [
            "- Siapkan autoscaling / naikkan kapasitas sebelum knee.",
            "- Pasang rate-limit di edge agar trafik puncak tidak "
            "menghabiskan worker.",
            "- Review timeout & pool koneksi (gejala saturasi umum)."]
    else:
        lines += [
            "- SEGERA: kapasitas tidak memadai pada beban terukur — "
            "tambah kapasitas, aktifkan CDN/cache, dan uji ulang.",
            "- Pertimbangkan circuit breaker + queue untuk proteksi "
            "layanan inti."]
    lines += ["", "## Pagar", "",
              f"- {res['note']}",
              f"- Cap: {res['bounded']['vu_cap']} VU, total durasi <= "
              f"{res['bounded']['total_duration_cap_s']}s; rate tetap, "
              "tanpa eskalasi otomatis.", ""]
    return "\n".join(lines)
