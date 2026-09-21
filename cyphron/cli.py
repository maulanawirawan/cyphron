"""Cyphron CLI.

    python -m cyphron scan  --target URL|PATH [--auth auth.json] [--out DIR]
    python -m cyphron check --target URL --auth auth.json
    python -m cyphron skills --query "sql injection di form login"

Exit codes: 0 = no confirmed findings, 2 = confirmed findings present,
3 = refused (authorization/scope), 1 = error."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .config import load
from .orchestrator import ScanOptions, run_scan
from .reporting import write_reports
from .skills.registry import SkillRegistry
from .store import persist


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyphron",
                                     description="Cyphron Core — standalone AI pentest agent (stdlib-only)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run an authorized pentest scan")
    p_scan.add_argument("--target", required=True, help="URL (http(s)://...) or local repo path")
    p_scan.add_argument("--auth", help="authorization document JSON (required for active testing)")
    p_scan.add_argument("--out", default="cyphron_out", help="output directory")
    p_scan.add_argument("--max-steps", type=int, default=40)
    p_scan.add_argument("--max-requests", type=int, default=400)
    p_scan.add_argument("--rate-limit", type=float, default=0.05,
                        help="min seconds between requests (raise for production targets)")
    p_scan.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds")
    p_scan.add_argument("--crawl-pages", type=int, default=15,
                        help="max pages the crawler may visit (deep discovery: 50-100)")
    p_scan.add_argument("--account", metavar="USER:PASS",
                        help="grey-box: login with this test account before probing")
    p_scan.add_argument("--license", help="license.json (tier gate: basic/pro/business/god)")
    p_scan.add_argument("--kimchi", help="path to .kimchi pack (default: auto)")
    p_scan.add_argument("--quiet", action="store_true")

    p_check = sub.add_parser("check", help="validate an authorization document + scope only")
    p_check.add_argument("--target", required=True)
    p_check.add_argument("--auth", required=False, help="omit to see the refusal for an unauthorized target")

    p_skills = sub.add_parser("skills", help="query the skill registry")
    p_skills.add_argument("--query", required=True)
    p_skills.add_argument("--top", type=int, default=3)
    p_skills.add_argument("--kimchi", help="path to .kimchi pack (default: auto)")

    p_perf = sub.add_parser("perf", help="load/perf test dengan engine milik Cyphron (k6-class)")
    p_perf.add_argument("--target", required=True)
    p_perf.add_argument("--auth", required=True)
    p_perf.add_argument("--profile", choices=["quick", "standard", "stress"], default="quick",
                        help="quick=5VU/20s, standard=10VU/30s, stress=20VU/45s")
    p_perf.add_argument("--scenario", help="file JSON skenario manual (vus/duration/urls/method/body) — full control")
    p_perf.add_argument("--out", default="cyphron_out")

    p_verify = sub.add_parser("verify", help="scan ulang lalu bandingkan vs baseline (fixed/open/new)")
    p_verify.add_argument("--target", required=True)
    p_verify.add_argument("--auth", required=True)
    p_verify.add_argument("--baseline", required=True, help="folder hasil scan lama (berisi findings.json)")
    p_verify.add_argument("--out", default="cyphron_verify")

    p_drift = sub.add_parser("drift", help="bandingkan dua snapshot permukaan (added/removed/changed + relevansi keamanan)")
    p_drift.add_argument("--old", required=True, help="JSON snapshot lama (list of {url, status?})")
    p_drift.add_argument("--new", required=True, help="JSON snapshot baru (bentuk sama)")
    p_drift.add_argument("--out", default=None, help="simpan hasil drift ke file JSON")
    p_drift.add_argument("--limit", type=int, default=10, help="panjang antrian re-scan tertarget")

    p_fix = sub.add_parser("fix", help="buat fix packs (rencana penambalan) dari temuan")
    p_fix.add_argument("--from", dest="from_dir", required=True, help="folder hasil scan (berisi findings.json)")
    p_fix.add_argument("--out", default=None, help="folder tujuan (default: sama dengan --from)")

    p_suggest = sub.add_parser("suggest", help="menu rekomendasi langkah berikutnya — pilih nomor")
    p_suggest.add_argument("--from", dest="from_dir", required=True, help="folder hasil scan")

    p_kb = sub.add_parser("kb", help="sinkron knowledge base lokal (nuclei/nvd/edb) — senjata katalog")
    p_kb.add_argument("--source", choices=["all", "nuclei", "nvd", "edb"], default="all",
                      help="sumber yang disinkron (default: all)")
    p_kb.add_argument("--kb-dir", help="folder data KB (default: cyphron/kb/data)")
    p_kb.add_argument("--years", help="rentang tahun feed NVD (default 2018-2026), mis. 2020-2026")
    p_kb.add_argument("--nvd-mode", choices=["auto", "feed", "api"], default="auto",
                      help="auto = feed 1.1 dulu, fallback API 2.0 (default)")
    p_kb.add_argument("--nvd-api-key", help="NVD API key (naikkan kuota 5->50 req/30 dtk; atau env NVD_API_KEY)")
    p_kb.add_argument("--timeout", type=float, default=180.0,
                      help="timeout per unduhan dalam detik")

    p_god = sub.add_parser("god-report",
                           help="laporan tier: temuan live + CVE exposure + referensi exploit publik (pasif)")
    p_god.add_argument("--from", dest="from_dir", required=True,
                       help="folder hasil scan (berisi findings.json)")
    p_god.add_argument("--kb-dir", help="folder data KB (default: cyphron/kb/data)")
    p_god.add_argument("--out", help="file markdown tujuan (default: <from>/GOD-REPORT.md)")
    p_god.add_argument("--top", type=int, default=15, help="jumlah CVE top di tabel")
    p_god.add_argument("--no-quality-gate", action="store_true",
                       help="lewatkan gerbang kualitas anti-slop pada laporan")
    p_god.add_argument("--tech", action="append", default=[],
                       help="tambahan fingerprint manual (bisa diulang)")

    p_bench = sub.add_parser("benchmark",
                             help="metrik Precision/Recall/F1, CPE & version "
                                  "resolution atas dataset gold (angka, bukan slogan)")
    p_bench.add_argument("--kb-dir", help="folder KB berisi cpe.sqlite (default: cyphron/kb/data)")
    p_bench.add_argument("--out", help="tulis hasil ke file markdown")

    p_rt = sub.add_parser("redteam",
                          help="engagement report + coverage matrix MITRE-lite "
                               "+ deteksi-hint per temuan (dari folder hasil scan)")
    p_rt.add_argument("--from", dest="from_dir", required=True,
                      help="folder hasil scan (berisi findings.json + audit.jsonl)")
    p_rt.add_argument("--out", help="file markdown tujuan (default: <from>/ENGAGEMENT-REPORT.md)")

    p_own = sub.add_parser("own",
                           help="bukti kepemilikan domain: hitung token + "
                                "verifikasi DNS TXT / well-known (U10)")
    p_own.add_argument("--target", required=True)
    p_own.add_argument("--auth", required=True, help="dokumen otorisasi JSON")
    p_own.add_argument("--channel", choices=["auto", "dns", "wellknown"],
                       default="auto")
    p_own.add_argument("--timeout", type=float, default=6.0)

    p_ad = sub.add_parser("adapters",
                          help="daftar engine polyglot (manifest adapter) + "
                               "runtime yang terdeteksi di mesin ini")
    p_ad.add_argument("--check", action="store_true",
                      help="uji satu engine adapter dengan args JSON contoh")
    p_ad.add_argument("--name", help="nama adapter utk --check")
    p_ad.add_argument("--args", help="JSON args utk --check, mis. '{\"values\":[\"x\"]}'")

    p_deobf = sub.add_parser("deobf",
                             help="deobfuscation kit: dekode rantai blob + "
                                  "ekstraksi kit + validasi wallet anti-FP")
    p_deobf.add_argument("--from", dest="from_file", required=True,
                         help="file berisi blob/konten (teks)")
    p_deobf.add_argument("--chain", default="b64",
                         help="rantai step dipisah koma: b64,hex,url,rot13,xor,rc4")
    p_deobf.add_argument("--key", default="", help="key utk step rc4/xor")

    p_apk = sub.add_parser("apk-report",
                           help="laporan pentest mobile statis (kit v1 + "
                                "surface probe) dari file APK")
    p_apk.add_argument("--apk", required=True)
    p_apk.add_argument("--out", default="cyphron_apk", help="folder output")

    p_sast = sub.add_parser("sast",
                            help="SAST AST+taint + CI mode (exit code, JSON, SARIF, diff-aware)")
    p_sast.add_argument("--path", required=True, help="folder/berkas yang discan")
    p_sast.add_argument("--out", help="folder output (sast.json + sast.sarif)")
    p_sast.add_argument("--diff", action="store_true",
                        help="hanya berkas berubah vs git HEAD")
    p_sast.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        default="high", help="severity minimum utk exit code 2")
    p_sast.add_argument("--slop", action="store_true",
                        help="tambahkan rule pack slop (kualitas kode) + skor")

    p_rlint = sub.add_parser("report-lint",
                             help="gerbang kualitas laporan (anti-slop) — PASS/FAIL per blok")
    p_rlint.add_argument("file", help="file laporan markdown (.md)")

    p_lic = sub.add_parser("license",
                           help="kelola lisensi: issue (trial/tier) atau show status")
    lic_sub = p_lic.add_subparsers(dest="lic_cmd", required=True)
    p_lic_issue = lic_sub.add_parser("issue", help="generate + sign license.json")
    p_lic_issue.add_argument("--out", default="license.json")
    p_lic_issue.add_argument("--licensee", required=True)
    p_lic_issue.add_argument("--tier", choices=["basic", "pro", "business", "god"],
                             default="basic")
    p_lic_issue.add_argument("--trial", action="store_true",
                             help="lisensi trial: 30 token, report redacted, 7 hari")
    p_lic_issue.add_argument("--days", type=int, default=30)
    p_lic_issue.add_argument("--no-device-bind", action="store_true",
                             help="JANGAN ikat ke mesin ini (tidak disarankan)")
    p_lic_show = lic_sub.add_parser("show", help="tampilkan status lisensi")
    p_lic_show.add_argument("--path", default="license.json")

    p_price = sub.add_parser("pricing",
                             help="tampilkan harga per tier/mode/token + estimasi scan")
    p_price.add_argument("--estimate", type=int, default=None,
                         metavar="STEPS",
                         help="estimasi token untuk N langkah aktif (2 token/step)")

    p_dast = sub.add_parser("dast",
                            help="DAST orchestration profil dev-cicd/standard/full")
    p_dast.add_argument("--target", required=True)
    p_dast.add_argument("--auth", help="dokumen otorisasi (wajib utk profil aktif)")
    p_dast.add_argument("--profile", choices=["dev-cicd", "standard", "full"],
                        default="standard")
    p_dast.add_argument("--out", default="cyphron_out")

    p_iac = sub.add_parser("iac",
                           help="IaC check (Dockerfile/compose/k8s) + SBOM CycloneDX")
    p_iac.add_argument("--path", required=True)
    p_iac.add_argument("--out", help="folder output (iac.json + sbom.json)")

    p_proxy = sub.add_parser("proxy",
                             help="proxy intercept lokal (CLI-first; CONNECT passthrough tanpa dekripsi)")
    p_proxy.add_argument("--listen", default="127.0.0.1:8080")
    p_proxy.add_argument("--auth", help="dokumen otorisasi (scope host tujuan)")
    p_proxy.add_argument("--intercept", action="store_true",
                         help="tahan request sampai disetujui (approve/drop via stdin)")
    p_proxy.add_argument("--out", default="cyphron_proxy")

    p_rtl = sub.add_parser("redteam-lab",
                           help="katalog tradecraft lab (RTL-*) + cakupan "
                                "deteksi purple-team")
    p_rtl.add_argument("--auth", choices=["lab", "engagement"],
                       help="filter katalog per level otorisasi")
    p_rtl.add_argument("--report", help="tulis lab report markdown (butuh --run)")
    p_rtl.add_argument("--run", action="store_true",
                       help="jalankan c2-sim loopback + privesc read-only utk report")

    p_c2 = sub.add_parser("c2-sim",
                          help="C2-simulation loopback (RTL-09): beacon "
                               "berbatas utk validasi protokol + rule deteksi")
    p_c2.add_argument("--lab", action="store_true",
                      help="konfirmasi eksplisit: jalankan di lab loopback")
    p_c2.add_argument("--beacons", type=int, default=3)
    p_c2.add_argument("--interval", type=float, default=0.2)
    p_c2.add_argument("--out", help="tulis hasil simulasi ke file JSON")

    p_lang = sub.add_parser("lang-scan",
                            help="inventaris bahasa repo (deteksi otomatis "
                                 "36 bahasa) + runtime terpasang + versi")
    p_lang.add_argument("--path", required=True)
    p_lang.add_argument("--out", help="tulis inventaris ke JSON")

    p_sync = sub.add_parser("lang-sync",
                            help="lang-sync: hash knowledge pack versioned "
                                 "+ deteksi versi runtime (TANPA instal apa pun)")
    p_sync.add_argument("--out", help="tulis inventaris ke JSON")

    p_res = sub.add_parser("resilience",
                           help="uji ketahanan bertahap: ladder bounded + "
                                "knee detection + verdict SURVIVE/DEGRADE/FAIL "
                                "(butuh --auth; bukan modul flood)")
    p_res.add_argument("--target", required=True)
    p_res.add_argument("--auth", required=True)
    p_res.add_argument("--profile", choices=["quick", "standard"],
                       default="standard")
    p_res.add_argument("--out", default="cyphron_resilience")

    p_fraud = sub.add_parser("fraud-dossier",
                             help="dossier pengaduan penipuan pasif: analisis "
                                  "prefix operator/bank + langkah resmi "
                                  "(TANPA resolusi identitas orang)")
    p_fraud.add_argument("--phone", help="nomor HP pelaku (dianalisis struktur)")
    p_fraud.add_argument("--account", help="nomor rekening pelaku")
    p_fraud.add_argument("--bank-hint", help="indikasi bank dari bukti transfer klien")
    p_fraud.add_argument("--note", default="", help="catatan kasus")
    p_fraud.add_argument("--out", default="cyphron_fraud")

    p_tiers = sub.add_parser("tiers", help="tier pack: 100 skills dalam 4 tingkat severity")
    p_tiers.add_argument("--build", action="store_true", help="generate file skill ke .kimchi/skills-tiers/")
    p_tiers.add_argument("--build-bounty", action="store_true", help="generate Bug Bounty pack (harvest 2026-09-06)")
    p_tiers.add_argument("--pack", choices=["1", "2", "3"],
                         help="pilih generator pack utk --build (default 1; 2/3 = varian lanjutan)")
    p_tiers.add_argument("--list", action="store_true", help="tampilkan semua skill per tier")
    p_tiers.add_argument("--show", help="tampilkan detail satu skill (mis. critical-01)")
    p_tiers.add_argument("--kimchi", help="path to .kimchi pack (default: auto)")

    args = parser.parse_args(argv)

    try:
        if args.command == "skills":
            config = load(Path(args.kimchi) if args.kimchi else None)
            reg = SkillRegistry(config)
            print(f"registry: {len(reg)} skills loaded from {config.kimchi_dir}")
            for skill, score in reg.retrieve(args.query, top_k=args.top):
                print(f"  {score:>5}  skill {skill.id} — {skill.name}  [{skill.mode}]")
            return 0

        if args.command == "perf":
            from .guardrails.authorization import (
                AuthorizationDocument, AuthorizationGate, host_port_of)
            from . import perf_engine
            doc = AuthorizationDocument.load(Path(args.auth))
            gate = AuthorizationGate(doc)
            host, port = host_port_of(args.target)
            decision = gate.evaluate(host, port, {"active", "load"})
            if not decision.allowed:
                print(f"[cyphron] perf REFUSED — {decision.reason}")
                return 3
            if args.scenario:
                scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
                print(f"[cyphron] perf manual scenario: {scenario.get('vus')} VU x "
                      f"{scenario.get('duration_s')}s on {len(scenario.get('urls') or [scenario.get('url')])} url(s)")
            else:
                profiles = {"quick": (5, 20), "standard": (10, 30), "stress": (20, 45)}
                vus, duration = profiles[args.profile]
                scenario = {"url": args.target, "vus": vus, "duration_s": duration,
                            "timeout": 10, "sleep_s": 0}
                print(f"[cyphron] perf profile={args.profile}: {vus} VU x {duration}s "
                      f"(bounded; gunakan --scenario untuk kontrol penuh di staging)")
            metrics = perf_engine.run_scenario(scenario)
            out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "perf-metrics.json").write_text(
                json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
            lat = metrics["latency_ms"]
            print(f"[cyphron] perf done: total={metrics['total']} rps={metrics['rps']} "
                  f"ok={metrics['ok']} 4xx={metrics['4xx']} 5xx={metrics['5xx']} neterr={metrics['net_err']}")
            print(f"[cyphron] latency p50={lat['p50']}ms p90={lat['p90']}ms "
                  f"p95={lat['p95']}ms p99={lat['p99']}ms max={lat['max']}ms")
            print(f"[cyphron] histogram: {metrics['status_histogram']}")
            print(f"[cyphron] metrics: {out_dir / 'perf-metrics.json'}")
            return 0

        if args.command == "verify":
            baseline_path = Path(args.baseline) / "findings.json"
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            base_ids = {f["id"]: f for f in baseline.get("confirmed", [])}
            opts = ScanOptions(target=args.target,
                               auth_path=Path(args.auth),
                               kimchi_dir=None, max_requests=900, crawl_pages=60)
            run = run_scan(opts, verbose=True)
            cur = {f.id: f for f in run.summary.confirmed}
            fixed = [base_ids[i] for i in sorted(base_ids.keys() - cur.keys())]
            still = [cur[i] for i in sorted(cur.keys() & base_ids.keys())]
            new = [cur[i] for i in sorted(cur.keys() - base_ids.keys())]
            out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
            write_reports(out_dir, opts, run.summary, run.world, run.audit)
            lines = ["# Verifikasi Delta (Penambalan)", "",
                     f"Target: {args.target}",
                     f"Baseline: {baseline_path} ({len(base_ids)} temuan)",
                     f"Scan ulang: {len(cur)} temuan terkonfirmasi", "",
                     f"## Sudah Diperbaiki ({len(fixed)})"]
            lines += [f"- {f['title']} ({f['id']})" for f in fixed] or ["- (belum ada)"]
            lines += ["", f"## Masih Terbuka ({len(still)})"]
            lines += [f"- {f.title} ({f.id})" for f in still] or ["- (tidak ada)"]
            lines += ["", f"## Temuan Baru ({len(new)})"]
            lines += [f"- {f.title} ({f.id})" for f in new] or ["- (tidak ada)"]
            (out_dir / "delta.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
            print()
            print(f"[cyphron] delta: fixed={len(fixed)} still_open={len(still)} new={len(new)}")
            print(f"[cyphron] laporan: {out_dir / 'delta.md'}")
            return 2 if (still or new) else 0

        if args.command == "drift":
            import json as _json
            from . import drift as _drift
            with open(args.old, encoding="utf-8") as fh:
                old_rows = _json.load(fh)
            with open(args.new, encoding="utf-8") as fh:
                new_rows = _json.load(fh)
            report = _drift.diff_surface(old_rows, new_rows)
            print(f"added={report['counts']['added']} removed={report['counts']['removed']} "
                  f"changed={report['counts']['changed']} "
                  f"high_priority={len(report['high_priority'])}")
            for r in report["added"]:
                print(f"  + [{r['relevance']:>6}] {r['url']}  tags={r['tags']}")
            for r in report["changed"]:
                print(f"  ~ [{r['relevance']:>6}] {r['url']}  {r['old_status']}->{r['new_status']}  {r['note']}")
            queue = _drift.prioritize(report, limit=args.limit)
            if queue:
                print("targeted re-scan queue:")
                for r in queue:
                    print(f"  -> {r.get('url')}")
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    _json.dump(report, fh, indent=1)
                print(f"drift report -> {args.out}")
            return 0

        if args.command == "fix":
            from .remediate import build_fix_bundles, load_findings
            src = Path(args.from_dir) / "findings.json"
            findings = load_findings(src)
            if not findings:
                print("[cyphron] tidak ada temuan terkonfirmasi untuk dibuatkan fix pack")
                return 0
            out_dir = Path(args.out) if args.out else Path(args.from_dir)
            patches = build_fix_bundles(findings, out_dir)
            print(f"[cyphron] {len(findings)} fix pack ditulis ke {patches}")
            return 0

        if args.command == "tiers":
            if getattr(args, "build_bounty", False):
                from .tierpack_bounty import build_bounty
                kd = load(Path(args.kimchi) if args.kimchi else None).kimchi_dir
                out = build_bounty(kd)
                print(f"[bounty pack] {out['total']} skill ({out['live']} LIVE) -> {out['root']}")
                return 0
            from .config import default_kimchi_dir
            kd = Path(args.kimchi) if args.kimchi else default_kimchi_dir()
            pack = getattr(args, "pack", None) or "1"
            if pack == "2":
                from .tierpack2 import build2 as run_pack
            elif pack == "3":
                from .tierpack3 import build3 as run_pack
            else:
                from .tierpack import build as run_pack
            result = run_pack(kd)
            stats = result["stats"]
            if args.list or args.show:
                text = (kd / "skills-tiers" / "INDEX.md").read_text(encoding="utf-8")
                if args.show:
                    key = args.show.lower()
                    tier, num = key.split("-")[0], int(key.split("-")[1])
                    matches = sorted((kd / "skills-tiers" / tier).glob(f"{tier}-{num:02d}-*.md"))
                    print(matches[0].read_text(encoding="utf-8") if matches else f"tidak ketemu: {key}")
                    return 0
                print(text)
                return 0
            print(f"[cyphron] tier pack: {sum(stats.values())} skill -> {result['root']}")
            print("  " + " | ".join(f"{t}={n}" for t, n in stats.items()))
            print("  lihat INDEX.md; detail: python -m cyphron tiers --show critical-01")
            return 0

        if args.command == "suggest":
            src = Path(args.from_dir)
            data = json.loads((src / "findings.json").read_text(encoding="utf-8"))
            n_conf = len(data.get("confirmed", []))
            print(f"[cyphron] {n_conf} temuan di {src}")
            print()
            print("Menu langkah berikutnya (AI-recommended):")
            print("  1. NAMBAL  - buat fix packs untuk semua temuan (rencana perbaikan)")
            print("  2. BUKTI  - verifikasi delta: scan ulang, tunjukkan fixed/open/new")
            print("  3. UJI BEBAN - perf test terukur (profile bounded, butuh --auth saat eksekusi)")
            print("  4. MASUK LOGIN - fase grey-box terautentikasi (butuh akun uji dari owner)")
            print("  5. MANUAL - kontrol penuh: lihat `python -m cyphron <cmd> --help`")
            choice = input("\nPilih nomor (Enter untuk keluar): ").strip()
            if choice == "1":
                sys.argv = ["cyphron", "fix", "--from", str(src)]
                return main(sys.argv[1:])
            if choice == "2":
                print("Jalankan: python -m cyphron verify --target <host> --auth <doc> "
                      f"--baseline {src} --out {src}-verify")
                return 0
            if choice == "3":
                print("Jalankan: python -m cyphron perf --target <host> --auth <doc> --profile standard")
                return 0
            if choice == "4":
                print("Sediakan akun uji disposable, lalu jalankan ulang scan dengan kredensial "
                      "grey-box (fitur authenticated sedang dijalankan).")
                return 0
            return 0

        if args.command == "kb":
            from .kb.kb_sync import sync, KbSyncError
            years = None
            if args.years:
                try:
                    a, b = args.years.split("-", 1)
                    years = range(int(a), int(b) + 1)
                except ValueError:
                    print("[cyphron] kb: --years harus bentuk MULAI-AKHIR, mis. 2020-2026")
                    return 1
            try:
                api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")
                manifest = sync(source=args.source,
                                kb_dir=Path(args.kb_dir) if args.kb_dir else None,
                                years=years, timeout=args.timeout,
                                nvd_mode=args.nvd_mode, api_key=api_key)
            except KbSyncError as exc:
                print(f"[cyphron] kb GAGAL: {exc}")
                return 1
            for src, info in manifest["sources"].items():
                print(f"[cyphron] kb[{src}] {info.get('summary', '')}")
            for err in manifest.get("errors", []):
                print(f"[cyphron] kb peringatan: {err}")
            print(f"[cyphron] manifest: {manifest.get('manifest_path')}")
            if not manifest["sources"]:
                print("[cyphron] kb: tidak ada sumber yang berhasil — KB lama tetap dipakai")
                return 1
            return 0

        if args.command == "god-report":
            from .god_report import (
                build, collect_technologies, load_scan_data, write_report)
            src = Path(args.from_dir)
            try:
                data = load_scan_data(src / "findings.json")
            except (OSError, ValueError) as exc:
                print(f"[cyphron] god-report: findings.json tidak terbaca: {exc}")
                return 1
            texts = collect_technologies(data, args.tech)
            out = Path(args.out) if args.out else src / "GOD-REPORT.md"
            if args.no_quality_gate:
                md, stats = build(data.get("target", "?"),
                                  data.get("confirmed", []), texts,
                                  kb_dir=Path(args.kb_dir) if args.kb_dir else None,
                                  top=args.top)
                write_report(md, out)
            else:
                # default: laporan GOD wajib lulus gerbang kualitas anti-slop
                from .god_report import build_with_quality_gate
                _, stats = build_with_quality_gate(
                    data.get("target", "?"), data.get("confirmed", []), texts,
                    out, kb_dir=Path(args.kb_dir) if args.kb_dir else None,
                    top=args.top)
                gate = stats.get("gate", {})
                print(f"[cyphron] gerbang kualitas: {gate.get('verdict')} "
                      f"(skor {gate.get('score')})")
            print(f"[cyphron] god-report: {stats['versioned']}/{stats['products']} "
                  f"produk berversi, {stats['cve_rows']} CVE lead, "
                  f"{stats['edb_products']} produk ber-exploit publik")
            print(f"[cyphron] laporan: {out}")
            return 0

        if args.command == "benchmark":
            from .benchmark import render_markdown, run_cve_benchmark
            try:
                results = run_cve_benchmark(
                    kb_dir=Path(args.kb_dir) if args.kb_dir else None)
            except FileNotFoundError as exc:
                print(f"[cyphron] benchmark: {exc}")
                return 1
            print(render_markdown(results, "Benchmark Cyphron (CLI)"))
            if args.out:
                out = Path(args.out)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(render_markdown(results), encoding="utf-8")
                print(f"[cyphron] benchmark -> {out}")
            return 0

        if args.command == "redteam":
            from .redteam import engagement_report
            src = Path(args.from_dir)
            if not (src / "findings.json").exists():
                print(f"[cyphron] redteam: findings.json tidak ada di {src}")
                return 1
            report = engagement_report(src)
            out = Path(args.out) if args.out else src / "ENGAGEMENT-REPORT.md"
            out.write_text(report["markdown"], encoding="utf-8")
            m = report["matrix"]
            print(f"[cyphron] redteam: {m['engines']} engine dieksekusi, "
                  f"{m['tagged']} ter-tag MITRE-lite eksplisit, "
                  f"{len(report['hints'])} deteksi-hint")
            if m["uncovered_phases"]:
                print(f"[cyphron] fase tanpa cakupan run ini: "
                      f"{', '.join(m['uncovered_phases'])}")
            print(f"[cyphron] laporan: {out}")
            return 0

        if args.command == "own":
            from .guardrails.authorization import AuthorizationDocument
            from .ownership import token_for, verify_ownership
            doc = AuthorizationDocument.load(Path(args.auth))
            token = token_for(doc)
            print(f"[cyphron] host   : {args.target}")
            print(f"[cyphron] token  : {token}")
            print("[cyphron] publikasikan dengan salah satu kanal berikut:")
            print(f"           DNS TXT  : <host> IN TXT \"{token}\"")
            print(f"           wellknown: https://<host>/.well-known/"
                  f"cyphron-verify.txt berisi token di baris pertama")
            ok, detail = verify_ownership(args.target, doc,
                                          channel=args.channel,
                                          timeout=args.timeout)
            if ok:
                print(f"[cyphron] verdict: TERVERIFIKASI via {detail.get('method')}")
                return 0
            print(f"[cyphron] verdict: BELUM TERVERIFIKASI "
                  f"({detail.get('error') or 'token tidak ditemukan'})")
            return 1

        if args.command == "adapters":
            from .adapter import detect_runtimes, load_manifests
            manifests, errors = load_manifests()
            runtimes = detect_runtimes()
            print("[cyphron] runtime terdeteksi:")
            for rt, path in sorted(runtimes.items()):
                print(f"           {rt:6} {'ok: ' + path if path else 'absen (engine terkait dilewati anggun)'}")
            print(f"[cyphron] {len(manifests)} manifest adapter:")
            for mf in manifests:
                avail = "SIAP" if runtimes.get(mf["runtime"]) else "SKIP (runtime absen)"
                print(f"           {mf['name']:20} {mf['runtime']:6} {avail} — {mf.get('description', '')[:60]}")
            for err in errors:
                print(f"[cyphron] manifest error: {err}")
            if args.check:
                if not args.name:
                    print("[cyphron] --check butuh --name")
                    return 1
                from .guardrails.authorization import AuditLog, AuthorizationGate
                from .tools.base import ToolContext
                from .adapter import AdapterEngine
                from .world.model import WorldModel
                mf = next((m for m in manifests if m["name"] == args.name), None)
                if mf is None:
                    print(f"[cyphron] adapter tidak ditemukan: {args.name}")
                    return 1
                ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                                  world=WorldModel(), rate_limit_s=0.0)
                res = AdapterEngine(mf).run(json.loads(args.args or "{}"), ctx)
                print(f"[cyphron] ok={res.ok} data={json.dumps(res.data, ensure_ascii=False)} "
                      f"findings={len(res.findings)} error={res.error}")
                return 0 if res.ok else 1
            return 0

        if args.command == "deobf":
            from .guardrails.authorization import AuditLog, AuthorizationGate
            from .tools.base import ToolContext
            from .tools.deobf import (
                ChainDecoderTool, PhishingKitExtractTool, WalletFpGuardTool)
            from .world.model import WorldModel as _WM
            src = Path(args.from_file)
            blob = src.read_text(encoding="utf-8", errors="replace")
            ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                              world=_WM(), rate_limit_s=0.0)
            chain = [c.strip() for c in args.chain.split(",") if c.strip()]
            dec = ChainDecoderTool().run({"blob": blob, "chain": chain,
                                          "key": args.key}, ctx)
            if not dec.ok:
                print(f"[cyphron] deobf: decode gagal — {dec.error}")
                return 1
            text = dec.data.get("decoded", "")
            print(f"[cyphron] chain {' -> '.join(chain)}: {len(text)} karakter "
                  f"({len(dec.data.get('markers', []))} marker loader)")
            wallet = WalletFpGuardTool().run({"texts": [text]}, ctx)
            kit = PhishingKitExtractTool().run({"texts": [text]}, ctx)
            print(f"[cyphron] wallet valid-checksum: "
                  f"{len(wallet.data.get('valid', []))} "
                  f"(kandidat dibuang checksum: "
                  f"{len(wallet.data.get('rejected_by_checksum', []))})")
            for k, v in kit.data.items():
                if v:
                    print(f"[cyphron] kit[{k}]: {str(v)[:160]}")
            for f in dec.findings + wallet.findings + kit.findings:
                print(f"[cyphron] temuan (LEAD): {f.title}")
            print(f"[cyphron] decoded (200 char pertama): {text[:200]!r}")
            return 0

        if args.command == "apk-report":
            from .guardrails.authorization import AuditLog, AuthorizationGate
            from .tools import build_default_registry
            from .tools.apk_kit import render_mobile_report
            from .tools.base import ToolContext
            from .world.model import WorldModel as _WM
            w = _WM()
            ctx = ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                              world=w, rate_limit_s=0.0)
            reg = build_default_registry(ctx)
            kit = reg.execute("apk_pentest_kit", {"path": args.apk})
            if not kit.ok:
                print(f"[cyphron] apk-report: {kit.error}")
                return 1
            surface = reg.execute("apk_surface_probe", {"path": args.apk})
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            md = render_mobile_report({
                "kit": kit.data, "surface":
                    surface.data if surface.ok else {}})
            out = out_dir / "MOBILE-REPORT.md"
            out.write_text(md, encoding="utf-8")
            k = kit.data
            print(f"[cyphron] apk: {k.get('entries')} entri, "
                  f"{len(k.get('permissions_dangerous', []))} perm berbahaya, "
                  f"hardening={k.get('hardening_score')} "
                  f"({k.get('assessment')})")
            for f in kit.findings + (surface.findings if surface.ok else []):
                print(f"[cyphron] temuan (LEAD): {f.title}")
            print(f"[cyphron] laporan: {out}")
            return 0

        if args.command == "sast":
            from .sast import run_ci, slop_score
            slop_on = bool(getattr(args, "slop", False))
            rc = run_ci(Path(args.path),
                        out_dir=Path(args.out) if args.out else None,
                        diff_only=bool(args.diff), fail_on=args.fail_on,
                        slop=slop_on)
            extra = ""
            if slop_on:
                from .sast import scan_path
                slop_rows = [f for f in scan_path(
                    Path(args.path), slop=True)
                    if f.rule_id.startswith("SL-")]
                extra = f" slop_score={slop_score(slop_rows)}"
            print(f"[cyphron] sast exit={rc} "
                  f"({'bersih' if rc == 0 else 'temuan >= ' + args.fail_on})"
                  f"{extra}")
            return rc

        if args.command == "report-lint":
            from .reportslop import lint_report_file, format_result
            res = lint_report_file(args.file)
            print(format_result(res))
            return 2 if res["verdict"] == "FAIL" else 0

        if args.command == "dast":
            from .dast import plan_from_policy, policy_for
            doc = None
            if args.auth:
                from .guardrails.authorization import AuthorizationDocument
                doc = AuthorizationDocument.load(Path(args.auth))
            policy = policy_for(
                args.profile, authorized=doc is not None,
                doc_restrictions=(doc.restrictions if doc else []))
            print(f"[cyphron] dast: {policy['requested']} -> "
                  f"{policy['profile_effective']}"
                  f" (downgraded: {policy['downgraded']}) — {policy['reason']}")
            plan = plan_from_policy(policy, args.target)
            opts = ScanOptions(
                target=plan["target"],
                auth_path=Path(args.auth) if args.auth else None,
                crawl_pages=plan["crawl_pages"], crawl_depth=plan["crawl_depth"],
                max_steps=plan["max_steps"],
                max_requests=plan["max_requests"],
                rate_limit_s=plan["rate_limit_s"], max_time_s=20 * 60)
            run = run_scan(opts, verbose=True)
            out_dir = Path(args.out)
            write_reports(out_dir, opts, run.summary, run.world, run.audit,
                          report_mode=getattr(run, "report_mode", "full"))
            print(f"[cyphron] dast done: confirmed={len(run.summary.confirmed)} "
                  f"-> {out_dir / 'report.md'}")
            return 2 if run.summary.confirmed else 0

        if args.command == "iac":
            from .iac import license_compliance, sbom_generate, scan_iac
            root = Path(args.path)
            rows = scan_iac(root)
            sbom = sbom_generate(root)
            lic = license_compliance(sbom)
            if args.out:
                out_dir = Path(args.out)
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "iac.json").write_text(
                    json.dumps(rows, indent=1, ensure_ascii=False),
                    encoding="utf-8")
                (out_dir / "sbom.json").write_text(
                    json.dumps(sbom, indent=1, ensure_ascii=False),
                    encoding="utf-8")
            print(f"[cyphron] iac: {len(rows)} temuan misconfig")
            for r in rows[:10]:
                print(f"  [{r['severity']:6}] {r['rule']:28} "
                      f"{r.get('file', '')}:{r['line']} {r['message'][:60]}")
            print(f"[cyphron] sbom: {len(sbom['components'])} komponen "
                  f"({', '.join(sbom['_meta']['manifests']) or 'tanpa manifest'})"
                  f" | lisensi: {lic['checked']} dideklarasi, "
                  f"{len(lic['denied'])} denied")
            return 0

        if args.command == "proxy":
            from .guardrails.authorization import AuditLog, AuthorizationGate
            from .proxycore import History, serve_proxy
            doc = None
            if args.auth:
                from .guardrails.authorization import AuthorizationDocument
                doc = AuthorizationDocument.load(Path(args.auth))
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            host, _, port = args.listen.rpartition(":")
            history = History(path=out_dir / "proxy-history.jsonl")
            server, queue = serve_proxy((host or "127.0.0.1", int(port)),
                                        AuthorizationGate(doc), history,
                                        intercept=bool(args.intercept))
            print(f"[cyphron] proxy listen {args.listen} "
                  f"(intercept={bool(args.intercept)}); history -> "
                  f"{history.path}")
            if args.intercept:
                print("[cyphron] perintah: 'a ID' = approve, 'd ID' = drop, 'q' = keluar")
                try:
                    while True:
                        line = input().strip()
                        if line == "q":
                            break
                        cmd, _, rid = line.partition(" ")
                        queue.decide(rid, "approve" if cmd == "a" else "drop")
                        print(f"[cyphron] {rid} -> {cmd}")
                except (EOFError, KeyboardInterrupt):
                    pass
            else:
                try:
                    while True:
                        time.sleep(3600)
                except KeyboardInterrupt:
                    pass
            server.shutdown()
            return 0

        if args.command == "redteam-lab":
            from .redteam_lab import catalog, render_lab_report
            if args.run:
                from .redteam_lab import c2_simulate, privesc_scan
                sim = c2_simulate(beacons=3, interval_s=0.2)
                privesc = privesc_scan()
                md = render_lab_report(sim=sim, privesc=privesc)
            else:
                md = render_lab_report()
            for t in catalog(args.auth):
                print(f"[cyphron] {t['id']} [{t['phase']}] {t['name']} "
                      f"(auth: {t['auth']})")
            if args.report:
                Path(args.report).parent.mkdir(parents=True, exist_ok=True)
                Path(args.report).write_text(md, encoding="utf-8")
                print(f"[cyphron] lab report -> {args.report}")
            return 0

        if args.command == "c2-sim":
            from .redteam_lab import c2_simulate
            if not args.lab:
                print("[cyphron] c2-sim REFUSED: wajib --lab (loopback lab "
                      "milik sendiri; ini simulasi protokol, bukan infra "
                      "serangan)")
                return 3
            sim = c2_simulate(beacons=args.beacons, interval_s=args.interval)
            print(f"[cyphron] c2-sim: {sim['beacons_sent']} beacon -> "
                  f"{sim['acks_ok']} ACK ({sim['duration_s']}s, loopback "
                  f"{sim['listener']})")
            print(f"[cyphron] protokol: {sim['protocol']}")
            print(f"[cyphron] catatan: {sim['note']}")
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(json.dumps(sim, indent=1,
                                                     ensure_ascii=False),
                                          encoding="utf-8")
                print(f"[cyphron] timeline -> {args.out}")
            return 0

        if args.command == "lang-scan":
            from .languages import detect_language, sync_inventory, installed_count
            root = Path(args.path)
            counts: dict[str, int] = {}
            ambiguous = 0
            suffixes = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".java",
                        ".kt", ".scala", ".groovy", ".clj", ".cs", ".fs",
                        ".vb", ".go", ".rs", ".swift", ".dart", ".php",
                        ".rb", ".pl", ".lua", ".r", ".jl", ".f90", ".pas",
                        ".hs", ".ml", ".erl", ".ex", ".zig", ".nim", ".cr",
                        ".d", ".ps1", ".sh", ".sql", ".c", ".cpp", ".h",
                        ".hpp", ".coffee"}
            files = ([root] if root.is_file() else
                     [p for p in sorted(root.rglob("*"))
                      if p.is_file() and ".git" not in p.parts
                      and "__pycache__" not in p.parts
                      and "kb/data" not in str(p)
                      and p.suffix.lower() in suffixes])
            for p in files:
                det = detect_language("", str(p))
                if det["language"]:
                    counts[det["language"]] = counts.get(det["language"], 0) + 1
                elif det["ambiguous"]:
                    ambiguous += 1
            inv = sync_inventory(Path(args.out) if args.out else None)
            have, total = installed_count(inv)
            print(f"[cyphron] lang-scan: {len(files)} berkas teridentifikasi "
                  f"di {len(counts)} bahasa (ambigu ditolak: {ambiguous})")
            for lid, n in sorted(counts.items(), key=lambda kv: -kv[1])[:15]:
                print(f"  {lid:14} {n}")
            print(f"[cyphron] runtime terpasang: {have}/{total} bahasa "
                  f"punya toolchain di mesin ini")
            for lid, info in sorted(inv["runtimes"].items()):
                if info.get("binary"):
                    print(f"  {lid:14} {info.get('version') or '?'} "
                          f"({info['binary']})")
            return 0

        if args.command == "lang-sync":
            from .languages import sync_inventory, installed_count
            inv = sync_inventory(Path(args.out) if args.out else None)
            have, total = installed_count(inv)
            print(f"[cyphron] lang-sync: knowledge pack sha:{inv['knowledge_sha256_16']} "
                  f"({inv['languages']} bahasa)")
            print(f"[cyphron] runtime: {have}/{total} terpasang")
            for lid, info in sorted(inv["runtimes"].items()):
                status = f"{info.get('version') or 'terpasang'}" \
                    if info.get("binary") else "absen (engine terkait skip anggun)"
                print(f"  {lid:14} {status}")
            print("[cyphron] catatan: auto-update = update knowledge pack ini "
                  "via repo (hash di atas); kompiler TIDAK diinstal otomatis")
            return 0

        if args.command == "resilience":
            from .guardrails.authorization import (
                AuthorizationDocument, AuthorizationGate, host_port_of)
            from .resilience import render_resilience_report, run_resilience
            doc = AuthorizationDocument.load(Path(args.auth))
            gate = AuthorizationGate(doc)
            host, port = host_port_of(args.target)
            decision = gate.evaluate(host, port, {"active", "load"})
            if not decision.allowed:
                print(f"[cyphron] resilience REFUSED — {decision.reason}")
                return 3
            print(f"[cyphron] resilience: ladder bounded pada {args.target} "
                  f"(profile {args.profile}; bukan modul flood)")
            res = run_resilience(args.target, profile=args.profile,
                                 timeout=8.0)
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "resilience.json").write_text(
                json.dumps(res, indent=1, ensure_ascii=False),
                encoding="utf-8")
            (out_dir / "RESILIENCE-REPORT.md").write_text(
                render_resilience_report(res), encoding="utf-8")
            for s in res["stages"]:
                print(f"  {s['vus']:>3} VU  rps={s['rps']:>7} p95={s['p95_ms']:>5}ms "
                      f"err={s['error_rate']:.1%}")
            knee = res.get("knee")
            if knee:
                print(f"[cyphron] knee: {knee['vus']} VU — "
                      + "; ".join(knee["reasons"]))
            print(f"[cyphron] verdict: {res['verdict']} — {res['reason']}")
            print(f"[cyphron] laporan: {out_dir / 'RESILIENCE-REPORT.md'}")
            return 0

        if args.command == "fraud-dossier":
            if not (args.phone or args.account):
                print("[cyphron] fraud-dossier: butuh --phone dan/atau --account")
                return 1
            from .fraudintel import build_fraud_case
            case = build_fraud_case(
                phone_raw=args.phone, account_raw=args.account,
                bank_hint=args.bank_hint, case_note=args.note,
                out_dir=Path(args.out))
            if case["phone"]:
                ph = case["phone"]
                op = (ph["candidates"][0]["operator"] if ph["candidates"]
                      else "AMBIGU")
                print(f"[cyphron] phone {ph['e164_masked']}: operator "
                      f"kandidat = {op}")
            if case["account"]:
                ac = case["account"]
                banks = ", ".join(c["bank"] for c in ac["candidates"][:3]) \
                    or "AMBIGU"
                print(f"[cyphron] account {ac['account_masked']}: kandidat "
                      f"bank = {banks}")
            print(f"[cyphron] dossier (teredaksi): "
                  f"{Path(args.out) / 'FRAUD-DOSSIER.md'}")
            print("[cyphron] batas: TIDAK ada resolusi identitas orang — "
                  "jalur resmi = cekrekening.id / bank / OJK 157 / Polri "
                  "Tipid Siber")
            return 0

        if args.command == "check":
            from .guardrails.authorization import (
                AuthorizationDocument, AuthorizationGate, host_port_of)
            doc = AuthorizationDocument.load(Path(args.auth)) if args.auth else None
            gate = AuthorizationGate(doc)
            host, port = host_port_of(args.target)
            decision = gate.evaluate(host, port, {"active"})
            if doc is None:
                print("auth doc : NONE")
            else:
                print(f"auth doc : {doc.id} (expires {doc.expires_at.isoformat()}, by {doc.authorized_by})")
            print(f"target   : {args.target} -> {host}:{port}")
            print(f"decision : {'ALLOWED' if decision.allowed else 'REFUSED'} — {decision.reason}")
            return 0 if decision.allowed else 3

        if args.command == "license":
            from .licensing import License, issue_license
            if args.lic_cmd == "issue":
                payload = issue_license(
                    Path(args.out), licensee=args.licensee, tier=args.tier,
                    kind="trial" if args.trial else "standard",
                    days=7 if args.trial else args.days,
                    token_limit=30 if args.trial else None,
                    bind_device=not args.no_device_bind)
                print(f"[cyphron] lisensi ditulis: {args.out}")
                print(f"  licensee    : {payload['licensee']}")
                print(f"  tier/kind   : {payload['tier']} / {payload['kind']}")
                print(f"  expires     : {payload['expires']}")
                print(f"  token_limit : {payload['token_limit'] or 'unlimited (tier)'}")
                print(f"  device_bind : {'ya' if payload['device_hash'] else 'tidak'}")
                return 0
            lic = License(Path(args.path))
            print(f"licensee    : {lic.licensee}")
            print(f"tier/kind   : {lic.tier} / {lic.kind}")
            print(f"expires     : {lic.expires.isoformat() if lic.expires else '-'}")
            print(f"token_limit : {lic.token_limit or 'unlimited (tier)'}")
            print(f"device_bound: {'ya' if lic.device_hash else 'tidak'}")
            print(f"valid       : {'YA' if lic.valid else 'TIDAK'} — {lic.reason}")
            print(f"report_mode : {'redacted' if lic.is_trial else 'full'}")
            return 0 if lic.valid else 1

        if args.command == "pricing":
            from .pricing import PLANS, price_table
            print(price_table())
            if args.estimate:
                est = int(args.estimate) * 2  # langkah aktif rata-rata 2 token
                print("")
                print(f"estimasi {args.estimate} langkah aktif: ~{est} token "
                      f"(x1.5 mode active = {int(est * 1.5)})")
                for tier, p in PLANS.items():
                    print(f"  {tier:9}: {'CUKUP' if p['token_limit'] >= est else 'kurang'} "
                          f"({p['token_limit']} token/bln)")
            return 0

        # --- scan ---
        opts = ScanOptions(
            target=args.target,
            auth_path=Path(args.auth) if args.auth else None,
            kimchi_dir=Path(args.kimchi) if args.kimchi else None,
            max_steps=args.max_steps,
            max_requests=args.max_requests,
            rate_limit_s=args.rate_limit,
            timeout_s=args.timeout,
            crawl_pages=args.crawl_pages,
            account=args.account,
            license_path=Path(args.license) if args.license else None,
        )
        run = run_scan(opts, verbose=not args.quiet)
        out_dir = Path(args.out)
        paths = write_reports(out_dir, opts, run.summary, run.world, run.audit)
        db_path = persist(out_dir, opts, run.summary, run.audit)
        try:
            from .ledger import record_scan
            record_scan(out_dir)
        except Exception:
            pass  # ledger tidak boleh menggagalkan scan
        counts = run.summary.counts_by_severity()
        print()
        print(f"[cyphron] done in {run.summary.elapsed_s}s — mode={run.summary.mode}, "
              f"steps={run.summary.steps_executed}, refused={run.summary.refused_actions}")
        print(f"[cyphron] confirmed: {sum(counts.values())} " +
              " ".join(f"{k}={v}" for k, v in counts.items() if v)
              + f" | unconfirmed: {len(run.summary.unconfirmed)}")
        print(f"[cyphron] audit chain: {'verified' if run.summary.audit_verified else 'TAMPERED'}")
        print(f"[cyphron] reports: {paths['md']} | {paths['pdf']} | {paths['docx']} | {paths['json']}")
        if run.summary.refused_actions and not run.summary.auth_id:
            print("[cyphron] tip: provide --auth to enable active testing (see examples/authorization.localhost.json)")
            return 3
        return 2 if run.summary.confirmed else 0
    except Exception as exc:
        print(f"[cyphron] error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
