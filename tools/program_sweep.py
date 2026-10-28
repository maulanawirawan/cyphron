"""[F15] Program sweep — TIER 0 (data publik) ke semua program terbuka.

Membaca programs/index.json, menjalankan `cyphron scan --mode tier0`
untuk domain tiap program (DNS/CT/RDAP/security.txt/banner/TLS — semua
data publik, nol testing aktif), lalu:
  - findings per program  : findings/programs/<id>/findings.json
  - security.txt ditemukan: dicatat balik ke programs/index.json
    (field "discovered") sebagai kanal lapor resmi per program
  - summary sweep         : findings/programs/sweep-summary.json

Tier-0 sah untuk domain apa pun (data publik). Testing aktif TIDAK
dijalankan di sini — butuh policy dibaca + accepted=true per program.

Pemakaian:
  python tools/program_sweep.py [--only id1,id2] [--out findings/programs]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "core-rs" / "target" / "release" / "cyphron.exe"
INDEX = ROOT / "programs" / "index.json"
DIFF_ADDED_CAP = 50  # jaga diff.json tetap ringkas (id deterministik tetap utuh)


def load_last_findings(out_dir: Path) -> dict | None:
    """Snapshot temuan run sebelumnya dari <out_dir>/findings.json —
    {mtime_epoch, ids: {id: finding}}; None bila belum ada/cacat."""
    p = out_dir / "findings.json"
    if not p.exists():
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        ids = {f.get("id"): f for f in doc.get("findings", [])
               if isinstance(f, dict) and f.get("id")}
        return {"mtime": int(p.stat().st_mtime), "ids": ids}
    except Exception:
        return None


def diff_since_last(old: dict | None, new_doc: dict) -> dict:
    """Diff berbasis ID temuan deterministik (sha256
    tool|title|target|file|param) — judul yang berubah teks dihitung
    temuan berbeda; catatan itu ikut di field metodologi."""
    new_ids = {f.get("id"): f for f in new_doc.get("findings", [])
               if isinstance(f, dict) and f.get("id")}
    if old is None:
        return {"first_sweep": True, "since_epoch": None,
                "added": [], "fixed": [],
                "added_count": 0, "fixed_count": 0,
                "persist": 0, "total_now": len(new_ids)}
    old_ids, new_idset = set(old["ids"]), set(new_ids)
    added = sorted(new_idset - old_ids)
    fixed = sorted(old_ids - new_idset)
    return {
        "first_sweep": False,
        "since_epoch": old["mtime"],
        "added": [{"id": i, "title": new_ids[i].get("title", ""),
                   "severity": new_ids[i].get("severity", "")}
                  for i in added[:DIFF_ADDED_CAP]],
        "fixed": [{"id": i, "title": old["ids"][i].get("title", "")}
                  for i in fixed[:DIFF_ADDED_CAP]],
        "added_count": len(added),
        "fixed_count": len(fixed),
        "persist": len(old_ids & new_idset),
        "total_now": len(new_ids),
    }


def evidence_scan(prog_id: str, domain: str, target: str, out_dir: Path,
                  root: Path, exe: Path) -> dict:
    """Mode bukti (F19): SATU GET banner disimpan sebagai evidence
    (--save-raw), lalu `cyphron scan --evidence` menjalankan keluarga
    skill read-only berbasis bukti dengan NOL request ke target.
    Return ringkasan {findings, requests, family_quorum} atau {error}."""
    ev_dir = out_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    banner_html = ev_dir / "banner.html"
    probe = subprocess.run(
        [sys.executable, "skills/banner_posture.py", "--url", target,
         "--save-raw", str(banner_html),
         "--out", str(ev_dir / "banner-probe.json")],
        capture_output=True, text=True, cwd=str(root), timeout=120)
    if probe.returncode != 0 or not banner_html.exists():
        return {"error": (probe.stderr or probe.stdout)[-200:]}
    ev = subprocess.run(
        [str(exe), "scan", "--mode", "tier0", "--evidence", str(banner_html),
         "--domain", domain, "--target", target, "--out", str(ev_dir)],
        capture_output=True, text=True, cwd=str(root), timeout=600)
    if ev.returncode != 0:
        return {"error": (ev.stderr or ev.stdout)[-200:]}
    doc = json.loads((ev_dir / "findings.json").read_text(encoding="utf-8"))
    return {"findings": doc["data"].get("total_findings", 0),
            "requests": doc.get("requests", 0),
            "family_quorum": sum(1 for f in doc.get("findings", [])
                                 if f.get("family_quorum"))}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", default=None, help="id program tertentu (koma)")
    ap.add_argument("--out", default="findings/programs")
    ap.add_argument("--max-requests", type=int, default=None,
                    help="budget request per program ke cyphron scan "
                         "(default: biarkan orchestrator pakai default 64)")
    ap.add_argument("--with-evidence", action="store_true",
                    help="tambah mode bukti per program: 1 GET banner "
                         "disimpan, lalu scan --evidence (nol request) "
                         "untuk keluarga skill read-only berbasis bukti")
    args = ap.parse_args()

    idx = json.loads(INDEX.read_text(encoding="utf-8"))
    only = {x.strip() for x in args.only.split(",")} if args.only else None

    cmd_budget = (["--max-requests", str(args.max_requests)]
                  if args.max_requests else [])

    results = []
    for prog in idx.get("programs", []):
        pid = prog.get("id", "")
        if only and pid not in only:
            continue
        domain = prog.get("domain") or prog.get("id")  # fallback
        target = prog.get("target") or f"https://{domain}/"
        out_dir = Path(args.out) / pid
        last = load_last_findings(out_dir)  # snapshot SEBELUM scan menimpa
        t0 = time.perf_counter()
        r = subprocess.run(
            [str(EXE), "scan", "--mode", "tier0",
             "--domain", domain, "--target", target,
             "--out", str(out_dir)] + cmd_budget,
            capture_output=True, text=True, cwd=str(ROOT), timeout=600)
        elapsed = round(time.perf_counter() - t0, 1)
        ok = r.returncode == 0
        summary = {"id": pid, "domain": domain, "ok": ok,
                   "elapsed_s": elapsed}
        if ok:
            doc = json.loads((out_dir / "findings.json")
                             .read_text(encoding="utf-8"))
            summary["findings"] = doc["data"].get("total_findings", 0)
            summary["requests"] = doc.get("requests", 0)
            budget = doc["data"].get("budget") or {}
            if budget.get("skipped"):
                summary["budget_skipped"] = budget["skipped"]
            # ambil security.txt yang ditemukan (kanal lapor resmi)
            sectxt = [f for f in doc["findings"]
                      if f.get("tool") == "security-txt"
                      and f.get("title", "").startswith("security.txt found")]
            if sectxt:
                summary["report_channel_discovered"] = {
                    k: sectxt[0].get(k) for k in ("contact", "policy")
                    if sectxt[0].get(k)}
            # diff-since-last otomatis per target (F18): id deterministik,
            # bukan judul — tahan perubahan redaksi
            d = diff_since_last(last, doc)
            diff_path = out_dir / "diff.json"
            diff_path.write_text(json.dumps(
                {"program": pid, "method": "finding-id-deterministik",
                 **d}, indent=2, ensure_ascii=False), encoding="utf-8")
            summary["diff"] = {"first_sweep": d["first_sweep"],
                               "added": d["added_count"],
                               "fixed": d["fixed_count"],
                               "persist": d["persist"]}
            if args.with_evidence:
                summary["evidence"] = evidence_scan(
                    pid, domain, target, out_dir, ROOT, EXE)
        else:
            summary["error"] = (r.stderr or r.stdout)[-300:]
        results.append(summary)
        print(json.dumps(summary, ensure_ascii=False))

    # catat kanal lapor ditemukan ke index (field "discovered")
    for prog in idx.get("programs", []):
        match = next((r for r in results if r["id"] == prog.get("id")
                      and r.get("report_channel_discovered")), None)
        if match:
            prog["discovered"] = match["report_channel_discovered"]
    idx["last_sweep_epoch"] = int(time.time())
    INDEX.write_text(json.dumps(idx, indent=2, ensure_ascii=False),
                     encoding="utf-8")

    out = Path(args.out) / "sweep-summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "sweep_at_epoch": int(time.time()),
        "mode": "tier0-public-data",
        "results": results,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"sweep selesai: {len(results)} program -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
