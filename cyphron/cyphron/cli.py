"""Cyphron CLI.

    python -m cyphron scan  --target URL|PATH [--auth auth.json] [--out DIR]
    python -m cyphron check --target URL --auth auth.json
    python -m cyphron skills --query "sql injection di form login"

Exit codes: 0 = no confirmed findings, 2 = confirmed findings present,
3 = refused (authorization/scope), 1 = error."""

from __future__ import annotations

import argparse
import json
import sys
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

    p_tiers = sub.add_parser("tiers", help="tier pack: 100 skills dalam 4 tingkat severity")
    p_tiers.add_argument("--build", action="store_true", help="generate file skill ke .kimchi/skills-tiers/")
    p_tiers.add_argument("--build-bounty", action="store_true", help="generate Bug Bounty pack (harvest 2026-09-06)")
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
            old_rows = _json.load(open(args.old, encoding="utf-8"))
            new_rows = _json.load(open(args.new, encoding="utf-8"))
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
                _json.dump(report, open(args.out, "w", encoding="utf-8"), indent=1)
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
            from . import tierpack
            kd = Path(args.kimchi) if args.kimchi else default_kimchi_dir()
            result = tierpack.build(kd)
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
