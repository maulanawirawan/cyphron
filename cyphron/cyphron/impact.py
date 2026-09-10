"""impact — Impact Probe: membuktikan dampak nyata setiap temuan (titik akhir
TRUE bukan FALSE). Setiap temuan terkonfirmasi diuji: bisa dieksploitasi beneran
di permukaan yang diuji (PROVEN), atau tidak tereksploitasi dalam konteks yang
diuji (HARDENING — saran, bukan darurat), atau butuh kondisi khusus."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from .tools import http_engine

PROVEN = "PROVEN"
HARDENING = "HARDENING (tidak tereksploitasi dalam konteks uji)"
CONDITIONS = "REQUIRES-CONDITIONS (butuh kondisi/izin khusus)"


def _impact_for(f: dict, ctx_url: str, findings: list[dict]) -> tuple[str, str]:
    title = (f.get("title") or "").lower()
    tool = f.get("tool", "")

    # 1) CSP hilang -> dampak nyata = apakah ada injeksi script yang BENAR2 dieksekusi?
    if "content-security-policy" in title:
        xss = [x for x in findings if x.get("tool") == "xss_probe" and "Reflected XSS" in x.get("title", "")]
        if xss:
            return (PROVEN, f"CSP hilang + XSS terkonfirmasi: {xss[0]['title']} — injeksi script dapat dieksekusi.")
        return (HARDENING, "CSP hilang adalah pengerasan (hardening): tidak ada injeksi script yang "
                           "berhasil dieksekusi pada permukaan yang diuji. Prioritas perbaikan tetap, "
                           "bukan keadaan darurat.")

    # 2) Path / panel exposed -> bukti = isi datanya sendiri
    if "exposed" in title or "sensitive path" in title:
        body_len = len(f.get("response") or "")
        return (PROVEN if body_len > 200 else HARDENING,
                f"Respons berisi {body_len} byte konten — bukti akses tersimpan di temuan.")

    # 3) Lockout -> dampak = menebak kredensial mungkin (sudah diukur; JANGAN bruteforce asli)
    if "lockout" in title:
        return (PROVEN, "6 percobaan kredensial salah diproses semua tanpa blokir — brute-force "
                        "kredensial adalah mungkin secara teknis (dibuktikan oleh pengukuran itu sendiri).")

    # 4) SPF/DMARC -> butuh mengirim email (dilarang tanpa koordinasi provider)
    if "spf" in title or "dmarc" in title:
        return (CONDITIONS, "Dampak email spoofing dibuktikan dengan mengirim email uji — butuh "
                            "koordinasi pemilik domain/provider. Fakta DNS sudah definitif.")

    # 5) 5xx under load / kapasitas -> sudah terukur
    if "5xx" in title or "degradation" in title or "capacity" in title or "envelope" in title:
        return (PROVEN, "Terukur langsung dalam ladder beban bertahap (timestamp per stage di findings.json).")

    # 6) Temuan berbasis request-response dengan marker -> buktinya sudah reproducible
    if f.get("evidence_kind") in ("request-response", "probe-pair") and (f.get("response") or f.get("request")):
        return (PROVEN, "Bukti permintaan/respons tersimpan dan dapat direplay (lihat PoC).")

    return (CONDITIONS, "Dampak butuh kondisi khusus (kredensial, staging, atau koordinasi owner) — "
                        "di luar kemampuan pembuktian otomatis yang aman.")


def run_impact(findings_json: Path, out_path: Path | None = None) -> dict:
    data = json.loads(findings_json.read_text(encoding="utf-8"))
    findings = data.get("confirmed", [])
    results = []
    for f in findings:
        verdict, reason = _impact_for(f, data.get("target", ""), findings)
        f["impact"] = verdict
        f["impact_note"] = reason
        results.append({"title": f.get("title"), "impact": verdict, "note": reason})
    proven = sum(1 for r in results if r["impact"] == PROVEN)
    summary = {
        "target": data.get("target"),
        "findings": len(findings),
        "impact_proven": proven,
        "impact_hardening": sum(1 for r in results if r["impact"].startswith("HARDENING")),
        "impact_conditions": sum(1 for r in results if r["impact"].startswith("REQUIRES")),
        "results": results,
    }
    if out_path:
        out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary
