"""[F23] Night-run otomatis + drift detection — orchestrator harian.

Loop per program target dari config (nama + domain + budget):
  1. tier0 scan (cap budget per target) via binary cyphron;
  2. diff-since-last vs run sebelumnya (by ID deterministik, pola
     program_sweep) + perubahan verdict per ID (naik/turun);
  3. drift.json per program + ringkasan run + akumulasi ringkasan
     mingguan (weekly-summary.json, atomic write);
  4. PDF ringkasan via tools/report_pdf.py (--no-pdf untuk lewati).

Fail-closed:
  - config konflik (id duplikat, domain kosong, budget < 0, key tak
    dikenal) = error keras exit 2;
  - budget 0 per target = SKIP dengan baris audit (bukan senyap);
  - scan gagal = tercatat di summary + exit 1 (scheduler tahu run gagal);
  - PDF gagal = peringatan + pdf_error di summary (laporan, bukan temuan).

Windows scheduler (schtasks siap-pakai, TIDAK di-install otomatis —
lihat docs/NIGHTRUN.md):
  schtasks /Create /TN "cyphron-nightrun" /SC DAILY /ST 02:00 /TR ^
    "python tools\\nightrun.py --config nightrun.json --out findings\\night-run"

Pemakaian:
  python tools/nightrun.py --config nightrun.json [--out findings/night-run]
      [--run-id 2026-10-18] [--max-requests 32] [--no-pdf] [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess

import egress_preflight
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from atomic import atomic_write_text  # noqa: E402
import program_sweep as ps  # noqa: E402  (reuse load_last_findings/diff pola)
import cve_matcher  # noqa: E402  (F45 lapisan pengetahuan)
import cwe_check  # noqa: E402  (F45 audit referensi CWE)
import threat_model  # noqa: E402  (F74 konteks per program — riset oss-scanner)


class ConfigError(ValueError):
    """Konflik config — error keras (fail-closed), exit 2."""


def resolve_exe() -> Path:
    env = os.environ.get("CYPHRON_EXE")
    if env:
        return Path(env)
    exe = "cyphron.exe" if sys.platform == "win32" else "cyphron"
    return ROOT / "core-rs" / "target" / "release" / exe


def load_config(path: Path) -> list[dict]:
    """Validasi config fail-closed: program unik, domain wajib, budget
    int >= 0, TANPA key tak dikenal (typo config = error, bukan diam)."""
    if not path.exists():
        raise ConfigError(f"config tidak ada: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"config bukan JSON valid: {exc}")
    if not isinstance(doc, dict):
        raise ConfigError("config harus objek JSON")
    unknown = set(doc) - {"programs", "note"}
    if unknown:
        raise ConfigError(f"config key tak dikenal: {sorted(unknown)} — fail-closed")
    progs = doc.get("programs")
    if not isinstance(progs, list) or not progs:
        raise ConfigError("config.programs kosong/tidak ada — tidak ada yang dijalankan")
    seen: set[str] = set()
    for i, p in enumerate(progs):
        if not isinstance(p, dict):
            raise ConfigError(f"programs[{i}] bukan objek")
        bad = set(p) - {"id", "name", "domain", "target", "budget"}
        if bad:
            raise ConfigError(f"programs[{i}]: key tak dikenal {sorted(bad)} — fail-closed")
        pid = str(p.get("id") or "").strip()
        if not pid:
            raise ConfigError(f"programs[{i}]: 'id' wajib")
        if pid in seen:
            raise ConfigError(f"config konflik: id duplikat '{pid}' — error keras")
        seen.add(pid)
        if not str(p.get("domain") or "").strip():
            raise ConfigError(f"programs[{i}] ({pid}): 'domain' wajib")
        budget = p.get("budget")
        if budget is not None and (not isinstance(budget, int)
                                   or isinstance(budget, bool) or budget < 0):
            raise ConfigError(f"programs[{i}] ({pid}): budget harus int >= 0")
    return progs


def drift_diff(old: dict | None, new_doc: dict) -> dict:
    """Drift by ID temuan deterministik + PERUBAHAN VERDICT per ID
    (id sama tapi verdict naik = bukti menguat; turun = bukti melemah —
    dua-duanya penting untuk disiplin verdict ladder)."""
    new_ids = {f.get("id"): f for f in new_doc.get("findings", [])
               if isinstance(f, dict) and f.get("id")}
    if old is None:
        return {"first_run": True, "since_epoch": None,
                "added": [], "removed": [], "verdict_up": [], "verdict_down": [],
                "added_count": 0, "removed_count": 0,
                "verdict_up_count": 0, "verdict_down_count": 0,
                "persist": 0, "total_now": len(new_ids)}
    old_ids = old["ids"]
    added = sorted(set(new_ids) - set(old_ids))
    removed = sorted(set(old_ids) - set(new_ids))
    common = set(old_ids) & set(new_ids)
    vup = [{"id": i, "title": new_ids[i].get("title", ""),
            "from": old_ids[i].get("verdict", 0),
            "to": new_ids[i].get("verdict", 0)}
           for i in common
           if int(new_ids[i].get("verdict", 0) or 0)
           > int(old_ids[i].get("verdict", 0) or 0)]
    vdown = [{"id": i, "title": new_ids[i].get("title", ""),
              "from": old_ids[i].get("verdict", 0),
              "to": new_ids[i].get("verdict", 0)}
             for i in common
             if int(new_ids[i].get("verdict", 0) or 0)
             < int(old_ids[i].get("verdict", 0) or 0)]
    return {
        "first_run": False, "since_epoch": old["mtime"],
        "added": [{"id": i, "title": new_ids[i].get("title", ""),
                   "severity": new_ids[i].get("severity", "")}
                  for i in added[:ps.DIFF_ADDED_CAP]],
        "removed": [{"id": i, "title": old_ids[i].get("title", "")}
                    for i in removed[:ps.DIFF_ADDED_CAP]],
        "verdict_up": vup[:ps.DIFF_ADDED_CAP],
        "verdict_down": vdown[:ps.DIFF_ADDED_CAP],
        "added_count": len(added), "removed_count": len(removed),
        "verdict_up_count": len(vup), "verdict_down_count": len(vdown),
        "persist": len(common), "total_now": len(new_ids),
    }


def run_cmd(argv: list[str], timeout: int = 600) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(argv, capture_output=True, text=True,
                          cwd=str(ROOT), timeout=timeout)


def _week_key(epoch: int) -> str:
    dt = datetime.datetime.fromtimestamp(epoch)
    iso = dt.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def update_weekly(out_root: Path, run_id: str, epoch: int,
                  per_program: list[dict]) -> Path:
    """Akumulasi ringkasan mingguan (atomic): hitungan per ISO week."""
    p = out_root / "weekly-summary.json"
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        doc = {"weeks": {}}
    key = _week_key(epoch)
    week = doc.setdefault("weeks", {}).setdefault(key, {
        "runs": 0, "added_total": 0, "fixed_total": 0,
        "verdict_up_total": 0, "by_program": {}})
    week["runs"] += 1
    week["last_run_id"] = run_id
    for r in per_program:
        if not r.get("scanned"):
            continue
        d = r.get("drift") or {}
        week["added_total"] += d.get("added_count", 0)
        week["fixed_total"] += d.get("removed_count", 0)
        week["verdict_up_total"] += d.get("verdict_up_count", 0)
        bp = week["by_program"].setdefault(r["id"], {"added": 0, "fixed": 0})
        bp["added"] += d.get("added_count", 0)
        bp["fixed"] += d.get("removed_count", 0)
    atomic_write_text(p, json.dumps(doc, indent=2, ensure_ascii=False))
    return p


def render_pdf(run_dir: Path, findings_paths: list[Path], run_id: str,
               date_str: str, compare_path: Path | None = None,
               egress_path: Path | None = None) -> dict:
    """PDF via tools/report_pdf.py (typst). Gagal = info, bukan crash.
    compare_path = gabungan dokumen run SEBELUMNYA (drift delta kolom);
    egress_path = state preflight (kesehatan jalur keluar)."""
    if not findings_paths:
        return {"skipped": "tidak ada findings"}
    argv = [sys.executable, "tools/report_pdf.py",
            "--out", str(run_dir / "nightrun-report.pdf"),
            "--title", f"Nightrun {run_id}",
            "--subtitle", "Drift temuan tier0 per program (by ID deterministik)",
            "--date", date_str]
    for fp in findings_paths:
        argv += ["--findings", str(fp)]
    if compare_path is not None and Path(compare_path).exists():
        argv += ["--compare", str(compare_path)]
    if egress_path is not None and Path(egress_path).exists():
        argv += ["--egress", str(egress_path)]
    r = run_cmd(argv, timeout=300)
    if r.returncode != 0:
        return {"error": (r.stderr or r.stdout)[-300:]}
    return {"ok": True, "out": str(run_dir / "nightrun-report.pdf")}


def archive_run_doc(out_root: Path, pid: str, run_id: str,
                    doc: dict) -> Path:
    """Arsip dokumen findings SATU RUN ke state/<pid>/runs/<run_id>.json —
    bukti historis per run (bahan --compare run berikutnya)."""
    runs_dir = out_root / "state" / pid / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    fp = runs_dir / f"{run_id}.json"
    fp.write_text(json.dumps(doc, indent=1, ensure_ascii=False),
                  encoding="utf-8")
    return fp


def main_with_args(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True,
                    help="JSON daftar program: {programs: [{id, domain, "
                         "target?, budget?, name?}]}")
    ap.add_argument("--out", default="findings/night-run")
    ap.add_argument("--run-id", default=None,
                    help="default: tanggal lokal YYYY-MM-DD")
    ap.add_argument("--max-requests", type=int, default=None,
                    help="default budget bila program tanpa budget sendiri")
    ap.add_argument("--no-pdf", action="store_true")
    ap.add_argument("--no-knowledge", action="store_true",
                    help="lewati lapisan pengetahuan (cve-matcher KEV + "
                         "audit CWE) — default ON, NOL request")
    ap.add_argument("--dry-run", action="store_true",
                    help="validasi config + cetak rencana, TANPA scan")
    args = ap.parse_args(argv)

    progs = load_config(Path(args.config))
    run_id = args.run_id or datetime.date.today().isoformat()
    out_root = Path(args.out)
    run_dir = out_root / run_id
    # state per program STABIL lintas-run (pola program_sweep: findings.json
    # per program di satu tempat, diff dihitung SEBELUM ditimpa) — run-id
    # hanya untuk ringkasan run + PDF.
    def state_dir(pid: str) -> Path:
        return out_root / "state" / pid

    if args.dry_run:
        plan = {"dry_run": True, "run_id": run_id, "out": str(run_dir),
                "pdf": not args.no_pdf,
                "programs": [{"id": p["id"], "domain": p["domain"],
                              "target": p.get("target")
                              or f"https://{p['domain']}/",
                              "budget": p.get("budget", args.max_requests)}
                             for p in progs]}
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return 0

    exe = resolve_exe()
    run_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(time.time())
    results: list[dict] = []
    ok_findings: list[Path] = []
    hard_fail = False
    # preflight egress SEKALI per run (2-3 request ke infra publik,
    # NOL ke target) — kesehatan jalur keluar tercatat di summary+PDF
    egress_path: Path | None = None
    try:
        st = egress_preflight.run_preflight()
        egress_path = run_dir / "egress-state.json"
        egress_path.write_text(json.dumps(st, indent=1),
                               encoding="utf-8")
        if not st["all_ok"]:
            print(json.dumps({"audit": "egress", "blocked": st["blocked"],
                              "impact": st["impact"]}, ensure_ascii=False),
                  file=sys.stderr)
    except Exception as exc:
        print(f"[nightrun] peringatan: preflight gagal: {exc!r}",
              file=sys.stderr)
    # dokumen gabungan run SEBELUMNYA (bahan --compare drift kolom)
    prev_docs: list[dict] = []

    for p in progs:
        pid, domain = p["id"], p["domain"]
        target = p.get("target") or f"https://{domain}/"
        budget = p.get("budget", args.max_requests)
        out_dir = state_dir(pid)
        summary: dict = {"id": pid, "domain": domain}
        # [F74] threat model per program (opsional — riset oss-scanner):
        # konteks triage operator di meta summary; TIDAK mengubah
        # findings/verdict (classification tetap dari bukti).
        try:
            tmm = threat_model.load_for_program(p)
        except Exception as exc:
            summary["threat_model"] = f"error: {exc!r}"[:120]
        else:
            if tmm is None:
                summary["threat_model"] = "none"
            elif tmm.get("rejected"):
                summary["threat_model"] = tmm["rejected"]
            else:
                summary["threat_model"] = {
                    "path": tmm["path"], "sha256": tmm["sha256"],
                    "title": tmm["title"], "sections": tmm["sections"]}
        if budget is not None and budget <= 0:
            # budget 0 = skip DENGAN baris audit (bukan senyap)
            summary.update({"scanned": False, "skipped": "budget=0"})
            print(json.dumps({"audit": "skip", "reason": "budget=0",
                              "id": pid}, ensure_ascii=False))
            results.append(summary)
            continue
        last = ps.load_last_findings(out_dir)  # snapshot SEBELUM scan
        if last:
            prev_docs.append(last)
        argv_scan = [str(exe), "scan", "--mode", "tier0",
                     "--domain", domain, "--target", target,
                     "--out", str(out_dir)]
        if budget is not None:
            argv_scan += ["--max-requests", str(budget)]
        t0 = time.perf_counter()
        try:
            r = run_cmd(argv_scan)
        except Exception as exc:
            summary.update({"scanned": False, "error": repr(exc)[:200]})
            hard_fail = True
            results.append(summary)
            print(json.dumps(summary, ensure_ascii=False))
            continue
        summary["elapsed_s"] = round(time.perf_counter() - t0, 1)
        if r.returncode != 0:
            summary.update({"scanned": False,
                            "error": (r.stderr or r.stdout)[-300:]})
            hard_fail = True
            results.append(summary)
            print(json.dumps(summary, ensure_ascii=False))
            continue
        fp = out_dir / "findings.json"
        doc = json.loads(fp.read_text(encoding="utf-8"))
        summary.update({"scanned": True,
                        "findings": doc.get("data", {}).get("total_findings", 0),
                        "requests": doc.get("requests", 0)})
        drift = drift_diff(last, doc)
        (out_dir / "drift.json").write_text(json.dumps(
            {"program": pid, "method":
             "finding-id-deterministik + verdict-compare", **drift},
            indent=2, ensure_ascii=False), encoding="utf-8")
        summary["drift"] = {k: drift[k] for k in
                            ("first_run", "added_count", "removed_count",
                             "verdict_up_count", "verdict_down_count",
                             "persist", "total_now")}
        try:
            archive_run_doc(Path(args.out), pid, run_id, doc)
        except Exception as exc:
            summary["archive_error"] = repr(exc)[:120]
        # [F45] lapisan pengetahuan (default ON): baris CVE-MATCH (KEV,
        # L1 lead) digabung ke SALINAN untuk laporan — state scan &
        # drift TIDAK tersentuh (kebisingan feed harian tidak masuk
        # sinyal drift target).
        if not args.no_knowledge:
            kev = cve_matcher.load_kev_entries()
            if kev is None:
                summary["cve_matches"] = "skipped: kev tidak tersedia"
                ok_findings.append(fp)
            else:
                try:
                    enriched, meta_cv = cve_matcher.enrich_findings_doc(
                        doc, kev)
                    fk = out_dir / "findings-knowledge.json"
                    atomic_write_text(fk, json.dumps(
                        enriched, indent=1, ensure_ascii=False))
                    summary["cve_matches"] = meta_cv["matches"]
                    ok_findings.append(fk)
                except Exception as exc:
                    summary["cve_matches"] = f"error: {exc!r}"[:120]
                    ok_findings.append(fp)
        else:
            ok_findings.append(fp)
        results.append(summary)
        print(json.dumps(summary, ensure_ascii=False))

    weekly_path = update_weekly(out_root, run_id, epoch, results)
    summary_doc = {
        "run_id": run_id, "started_at_epoch": epoch,
        "mode": "tier0-public-data",
        "programs": results,
        "scanned": sum(1 for r in results if r.get("scanned")),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "failed": sum(1 for r in results if r.get("error")),
        "new_findings_total": sum(
            (r.get("drift") or {}).get("added_count", 0)
            for r in results if r.get("scanned")),
        "weekly_summary": str(weekly_path),
        "pdf": None,
    }
    # [F45] audit referensi CWE SEKALI per run (repo-wide, NOL request)
    # — referensi usang/unknown = pengetahuan jaman dulu, dicatat.
    if not args.no_knowledge:
        try:
            from findings import write_findings  # noqa: E402 (kontrak)
            rows_k, meta_k = cwe_check.knowledge_audit()
            write_findings(run_dir / "cwe-check.json", rows_k,
                           {**meta_k, "run": "nightrun-cwe-check",
                            "safety_class": "read-only", "requests": 0})
            summary_doc["cwe_check"] = {
                k: meta_k[k] for k in ("unknown", "deprecated", "clean",
                                       "catalog_missing") if k in meta_k}
        except Exception as exc:
            summary_doc["cwe_check"] = f"error: {exc!r}"[:120]
            print(f"[nightrun] peringatan: cwe-check gagal: {exc!r}",
                  file=sys.stderr)
    if not args.no_pdf:
        compare_path: Path | None = None
        if prev_docs and ok_findings:
            # last = snapshot {ids: {id: finding}} dari program_sweep
            combined = {"ok": True, "findings": [
                row for d in prev_docs
                for row in (d.get("ids") or {}).values()]}
            compare_path = run_dir / "prev-findings.json"
            compare_path.write_text(json.dumps(combined, indent=1),
                                    encoding="utf-8")
        pdf = render_pdf(run_dir, ok_findings, run_id,
                         datetime.date.today().isoformat(),
                         compare_path=compare_path,
                         egress_path=egress_path)
        summary_doc["pdf"] = pdf
        if pdf.get("error"):
            print(f"[nightrun] peringatan: PDF gagal: {pdf['error']}",
                  file=sys.stderr)
    atomic_write_text(run_dir / "nightrun-summary.json",
                      json.dumps(summary_doc, indent=2, ensure_ascii=False))
    print(json.dumps({"ok": not hard_fail, "run_id": run_id,
                      "summary": str(run_dir / "nightrun-summary.json"),
                      "scanned": summary_doc["scanned"],
                      "skipped": summary_doc["skipped"],
                      "failed": summary_doc["failed"],
                      "new_findings_total": summary_doc["new_findings_total"]},
                     ensure_ascii=False))
    return 1 if hard_fail else 0


def main() -> int:
    try:
        return main_with_args(None)
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
