"""[F37] Report pack — satu perintah: preflight egress -> scan tier0 per
program (dari programs/index.json, hanya yang accepted) -> render PDF per
program (judul/subjudul dari program + --egress + --compare vs snapshot
scan sebelumnya).

Latar: demo live-target 2026-10-19 butuh 4 langkah manual per program
(scan, render, egress, compare). Perintah ini menyatukannya — dan
mengunci urutan yang benar: kesehatan jalur keluar dinilai DULU, baru
klaim apa pun ditulis.

Pemakaian:
  python tools/report_pack.py --programs programs/index.json \
      --only google.com,apple.com --out findings/reports/2026-10-20
  python tools/report_pack.py --programs programs/index.json   # semua accepted

Fail-closed: program tanpa accepted=true dilewati dengan baris audit;
scan gagal = PDF program itu dilewati (bukan PDF setengah jadi).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import egress_preflight  # noqa: E402
import cve_matcher  # noqa: E402  (F45 lapisan pengetahuan)
from atomic import atomic_write_text  # noqa: E402
from findings import write_findings  # noqa: E402 (kontrak satu pintu)
import cwe_check  # noqa: E402  (F45 audit referensi CWE)


def resolve_exe() -> Path:
    return (ROOT / "core-rs" / "target" / "release" /
            ("cyphron.exe" if sys.platform == "win32" else "cyphron"))


def load_programs(path: Path, only: list[str] | None) -> list[dict]:
    d = json.loads(path.read_text(encoding="utf-8"))
    progs = d.get("programs", d if isinstance(d, list) else [])
    out = []
    for p in progs:
        if not p.get("accepted"):
            print(json.dumps({"audit": "skip", "id": p.get("id"),
                              "reason": "accepted=false"},
                             ensure_ascii=False))
            continue
        if only and str(p.get("domain")) not in only:
            continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--programs", default="programs/index.json")
    ap.add_argument("--only", default=None,
                    help="domain tertentu, pisah koma (default: semua accepted)")
    ap.add_argument("--out", default=None,
                    help="folder output (default findings/reports/<tanggal>)")
    ap.add_argument("--max-requests", type=int, default=32)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--no-knowledge", action="store_true",
                    help="lewati lapisan pengetahuan (cve-matcher KEV + "
                         "audit CWE) — default ON, NOL request")
    args = ap.parse_args()

    date_str = time.strftime("%Y-%m-%d")
    out_root = Path(args.out) if args.out else Path("findings/reports") / date_str
    out_root.mkdir(parents=True, exist_ok=True)
    progs = load_programs(Path(args.programs),
                          [d.strip() for d in args.only.split(",")]
                          if args.only else None)
    if not progs:
        print("tidak ada program yang lolos filter — selesai", file=sys.stderr)
        return 2

    # 1) preflight egress dulu — kesehatan jalur keluar adalah konteks
    #    wajib sebelum klaim apa pun ditulis
    egress_path = out_root / "egress-state.json"
    if args.no_preflight:
        egress_path = None
        print("[pack] preflight dilewati (--no-preflight)")
    else:
        st = egress_preflight.run_preflight()
        atomic_write_text(egress_path, json.dumps(st, indent=1))
        print(egress_preflight.render_text(st))
        if not st["all_ok"]:
            print("[pack] peringatan: sebagian jalur egress terblokir — "
                  "skill terdampak akan masuk section fail-closed",
                  file=sys.stderr)

    exe = resolve_exe()
    if not exe.exists():
        print(f"binary tidak ada: {exe} — build dulu (cargo build --release)",
              file=sys.stderr)
        return 2

    results = []
    # [F45] audit referensi CWE sekali per pack (repo-wide, NOL request)
    cwe_note = "disabled"
    if not args.no_knowledge:
        try:
            rows_k, meta_k = cwe_check.knowledge_audit()
            write_findings(out_root / "cwe-check.json", rows_k,
                           {**meta_k, "run": "pack-cwe-check",
                            "safety_class": "read-only", "requests": 0})
            cwe_note = {k: meta_k[k] for k in ("unknown", "deprecated",
                                               "clean", "catalog_missing")
                        if k in meta_k}
        except Exception as exc:
            cwe_note = f"error: {exc!r}"[:120]
            print(f"[pack] peringatan: cwe-check gagal: {exc!r}",
                  file=sys.stderr)
    for p in progs:
        pid = p.get("id") or p.get("domain")
        domain = p.get("domain")
        state_dir = ROOT / "findings" / "night-run" / "state" / pid
        prev_snapshot = state_dir / "findings.json"
        scan_dir = out_root / f"scan-{pid}"
        t0 = time.perf_counter()
        r = subprocess.run(
            [str(exe), "scan", "--mode", "tier0", "--domain", domain,
             "--target", f"https://{domain}/", "--out", str(scan_dir),
             "--max-requests", str(args.max_requests)],
            capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            results.append({"id": pid, "ok": False,
                            "error": (r.stderr or r.stdout)[-200:]})
            print(json.dumps(results[-1], ensure_ascii=False))
            continue
        findings_path = scan_dir / "findings.json"
        # [F45] lapisan pengetahuan: salinan + baris CVE-MATCH utk PDF —
        # state scan (drift/compare) tetap scan-only.
        pdf_findings = findings_path
        entry_note = "disabled"
        if not args.no_knowledge:
            kev = cve_matcher.load_kev_entries()
            if kev is None:
                entry_note = "skipped: kev tidak tersedia"
            else:
                try:
                    doc = json.loads(
                        findings_path.read_text(encoding="utf-8"))
                    enriched, meta_cv = cve_matcher.enrich_findings_doc(
                        doc, kev)
                    pdf_findings = scan_dir / "findings-knowledge.json"
                    atomic_write_text(pdf_findings, json.dumps(
                        enriched, indent=1, ensure_ascii=False))
                    entry_note = meta_cv["matches"]
                except Exception as exc:
                    entry_note = f"error: {exc!r}"[:120]
                    pdf_findings = findings_path
        # compare: snapshot scan SEBELUMNYA dari state nightrun (bila ada)
        compare_path = None
        if prev_snapshot.exists():
            try:
                prev = json.loads(prev_snapshot.read_text(encoding="utf-8"))
                combined = {"ok": True, "findings": prev.get("findings", [])}
                compare_path = scan_dir / "prev-findings.json"
                atomic_write_text(compare_path,
                                  json.dumps(combined, indent=1))
            except Exception:
                compare_path = None
        pdf_out = out_root / f"laporan-{pid}.pdf"
        argv_pdf = [sys.executable, str(ROOT / "tools" / "report_pdf.py"),
                    "--findings", str(pdf_findings),
                    "--out", str(pdf_out),
                    "--title", f"Assessment Tier0 — {p.get('name') or pid}",
                    "--subtitle",
                    (f"{p.get('name', pid)} ({domain}) — hanya data publik, "
                     f"policy: {p.get('policy_url', 'n/a')}"),
                    "--date", date_str]
        if egress_path:
            argv_pdf += ["--egress", str(egress_path)]
        if compare_path:
            argv_pdf += ["--compare", str(compare_path)]
        r2 = subprocess.run(argv_pdf, capture_output=True, text=True,
                            timeout=300)
        entry = {"id": pid, "domain": domain, "ok": r2.returncode == 0,
                 "elapsed_s": round(time.perf_counter() - t0, 1),
                 "pdf": str(pdf_out) if r2.returncode == 0 else None,
                 "cve_matches": entry_note}
        if r2.returncode != 0:
            entry["error"] = (r2.stderr or r2.stdout)[-200:]
        results.append(entry)
        print(json.dumps(entry, ensure_ascii=False))

    pack_summary = {"date": date_str, "out": str(out_root),
                    "programs": results, "cwe_check": cwe_note,
                    "ok": sum(1 for r in results if r.get("ok")),
                    "failed": sum(1 for r in results if not r.get("ok"))}
    atomic_write_text(out_root / "pack-summary.json",
                      json.dumps(pack_summary, indent=1, ensure_ascii=False))
    print(json.dumps({"ok": pack_summary["failed"] == 0,
                      "out": str(out_root),
                      "pdf": pack_summary["ok"]}, ensure_ascii=False))
    return 0 if pack_summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
