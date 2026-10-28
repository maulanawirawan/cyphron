"""[F17] Impact narrative builder — obat untuk reject "dampak tidak jelas".

Pelajaran triage lapangan: laporan SSRF XML-RPC pingback + multicall
amplification DITOLAK karena "demonstrated impact is not clear".
Program menuntut: "a clear, high-impact exploitation scenario".

Modul ini menyusun NARASI DAMPAK per kelas temuan dengan CHECKLIST
BUKTI YANG HARUS TERUKUR — laporan tanpa checklist terpenuhi ditandai
belum-siap-kirim. Bukan penggelembungan: yang diminta adalah bukti
terukur, bukan kata-kata bombastis.

Pemakaian:
  python tools/impact_narrative.py --class ssrf-amplification \
      --target event.contoh.id --out narrative.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import make_finding, write_findings  # noqa: E402
import triage_advisor  # noqa: E402  (F24 learning loop)

# Checklist bukti terukur per kelas (dari kriteria triage nyata)
REQUIREMENTS = {
    "ssrf-amplification": {
        "title": "SSRF via XML-RPC pingback / system.multicall",
        "required_evidence": [
            "Bukti pingback menyentuh HOST INTERNAL (IP privat/localhost) "
            "— tangkapan respons atau callback yang diterima",
            "Faktor amplifikasi TERUKUR: 1 request -> N outbound "
            "(ukur: 1 system.multicall berisi k pingback = k request "
            "keluar dari server target; laporkan rasionya)",
            "Skenario dampak konkret: scan internal 10.0.0.0/8 via "
            "pingback, SSRF ke metadata cloud (169.254.169.254) — "
            "Buktikan keterjangkauan, jangan teori",
            "Rate & batas: tunjukkan laporan ini TIDAK DoS (jumlah "
            "request total + window)",
        ],
        "acceptance_hint": "program menuntut 'clear, high-impact "
                           "exploitation scenario' — sertakan minimal 3 "
                           "dari 4 bukti di atas",
    },
    "debug-page-exposure": {
        "title": "Debug/verbose page di produksi",
        "required_evidence": [
            "Marker halaman debug (Whoops/Ignition/Traceback) + konteks",
            "Info yang bocor: path absolut, versi, env vars, kredensial "
            "(blur bila sensitif)",
            "Repro: URL + kondisi pemicu (method/param/error)",
        ],
        "acceptance_hint": "kelas ini DITERIMA triage nyata (-> Fixing)",
    },
    "rate-limit-missing": {
        "title": "Login tanpa rate limit / lockout",
        "required_evidence": [
            "Jumlah percobaan (N) + respons (tanpa 429/lockout/captcha)",
            "Timing per percobaan (tanpa backoff)",
            "Skenario dampak: credential stuffing N akun/detik",
        ],
        "acceptance_hint": "kelas ini DITERIMA triage nyata (-> Fixing)",
    },
    "email-posture": {
        "title": "SPF/DMARC posture",
        "required_evidence": [
            "Query DNS mentah (2 resolver independen)",
            "DUPLICATE-RISK: kelas ini hampir pasti sudah dilaporkan "
            "orang lain di org besar — cek known-list program DULU",
        ],
        "acceptance_hint": "2/5 laporan serupa ditolak triage karena duplikat di kelas ini",
    },
    # --- kelas baru (skill pendamping ada di registry) ---
    "open-redirect": {
        "title": "Open redirect pada parameter navigasi",
        "required_evidence": [
            "URL reproduksi lengkap dengan payload — host-nya TARGET "
            "(bukan link pihak ketiga), redirect nyata teramati "
            "(header Location atau JS) via tangkapan HTTP",
            "Bukti validasi dilewati: whitelist/regex yang dipanjat "
            "(//host-luar, /\\host-luar, double-encoding) — satu kasus cukup",
            "Skenario dampak konkret: phishing memakai reputasi domain "
            "target, atau token SSO/OAuth di query yang ikut terbawa",
            "Batas: redirect murni sering dinilai informatif — cek "
            "kebijakan program dulu; jangan klaim XSS bila buktinya "
            "hanya redirect (zero-FP)",
        ],
        "acceptance_hint": "kuatkan dengan konteks SSO/OAuth atau posisikan "
                           "sebagai satu mata rantai, bukan temuan berdiri sendiri",
    },
    "subdomain-takeover": {
        "title": "Subdomain takeover via CNAME menggantung",
        "required_evidence": [
            "CNAME mentah dari 2 resolver independen menunjuk layanan "
            "yang TIDAK terklaim (NXDOMAIN / halaman not-found layanan)",
            "Fingerprint layanan spesifik dari respons produksi "
            "(markah 'tidak ada halaman di sini' khas layanan tsb) — "
            "bukan tebakan dari nama record",
            "Bukti klaimable: sisi target layanan itu bisa diklaim "
            "ulang lewat akun milik peneliti — tanpa menyentuh halaman "
            "atau data siapa pun",
            "Batas: NOL perubahan pada target — bukti hanya baca; "
            "tanpa fingerprint = LEAD, bukan klaim (fail-closed)",
        ],
        "acceptance_hint": "L3+ hanya bila fingerprint + klaimability "
                           "terbukti berdua; salah satu saja = laporkan sebagai lead",
    },
    "cors-misconfig": {
        "title": "CORS tidak aman (origin dicerminkan + kredensial)",
        "required_evidence": [
            "Pasangan request/response mentah: Origin terkontrol "
            "peneliti + Access-Control-Allow-Origin yang mencerminkan "
            "origin itu + Access-Control-Allow-Credentials: true",
            "Endpoint yang dibaca lintas-origin memuat data sensitif "
            "berbasis sesi/cookie — bukan endpoint publik",
            "PoC baca lintas-origin (fetch with credentials) dari "
            "origin eksternal — tangkapan respons, bukan klaim",
            "Batas: ACAO: * TANPA kredensial bukan temuan (zero-FP) — "
            "jangan dilaporkan",
        ],
        "acceptance_hint": "kunci kelas ini: origin reflektif + kredensial; "
                           "wildcard tanpa kredensial ditolak triage",
    },
    "secret-leakage": {
        "title": "Secret terekspos di artefak klien (JS/sourcemap/apk)",
        "required_evidence": [
            "URL artefak produksi persis + lokasi (baris/regex) + "
            "potongan isi secret (disamarkan sebagian saat publikasi)",
            "Validasi jenis secret: kredensial sungguhan vs placeholder "
            "vs public-by-design — uji non-destruktif keaktifannya bila "
            "kebijakan program mengizinkan",
            "Repro: cara menemukan ulang dari nol (path/permintaan)",
            "DUPLICATE-RISK: kelas ini ramai dilaporkan — cek "
            "known-list program DULU",
        ],
        "acceptance_hint": "public-by-design (mis. client ID OAuth publik) "
                           "bukan temuan — jangan dilaporkan",
    },
}


def build(finding_class: str, target: str) -> dict:
    req = REQUIREMENTS.get(finding_class)
    if not req:
        return {"ok": False,
                "error": f"kelas '{finding_class}' belum ada template — "
                         f"kelas tersedia: {sorted(REQUIREMENTS)}"}
    return {"ok": True, "finding_class": finding_class, "target": target,
            **req}


def main_with_args(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--class-name", dest="cls", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--out", default="impact-narrative.json")
    ap.add_argument("--learning", action="append", default=None,
                    help="file outcomes untuk learning loop (default: "
                         f"{triage_advisor.DEFAULT_LEARNING} bila ada)")
    ap.add_argument("--no-learning", action="store_true",
                    help="matikan integrasi learning loop")
    args = ap.parse_args(argv)
    data = build(args.cls, args.target)
    if not data.get("ok"):
        print(data["error"], file=sys.stderr)
        return 2
    # F24 learning loop: kelas yang historinya ditolak dampak/duplikat
    # mendapat peringatan + acceptance_hint otomatis dari outcomes nyata.
    if not args.no_learning:
        if args.learning:
            paths = [Path(p) for p in args.learning]
        else:
            default = triage_advisor.DEFAULT_LEARNING
            paths = [default] if default.exists() else []
        data = triage_advisor.enrich_narrative(data, paths)
    rows = [make_finding(
        tool="impact-narrative",
        title=f"Impact narrative — {data['title']} on {args.target}",
        severity="info",
        description="Checklist bukti terukur agar laporan memenuhi kriteria "
                    "acceptance program (pelajaran: SSRF ditolak karena "
                    "dampak tidak jelas).",
        target_url=args.target or None,
        evidence_kind="file-manifest", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "REPORTING", "safety_class": "read-only",
               "required_evidence": data["required_evidence"],
               "acceptance_hint": data["acceptance_hint"],
               **({"learning": data["learning"]}
                  if data.get("learning") else {})})]
    write_findings(args.out, rows, {"finding_class": args.cls,
                                    "safety_class": "read-only"})
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    return main_with_args(None)


if __name__ == "__main__":
    raise SystemExit(main())
