"""[SAFETY: active-probe — LAB-ONLY] Adapter nuclei -> kontrak findings.json.

Mesin pindai pihak ketiga (nuclei) di belakang kontrak yang sama:
JSONL hasil nuclei dipetakan ke findings.json satu pintu. Template
komunitas jadi AMUNISI kita — sedangkan verdict ladder, bukti, dan
metrik presisi tetap milik kita (lapisan yang template tidak punya).

Pemetaan (zero-FP):
  - hanya baris matcher-status=true yang jadi temuan
  - match nuclei = KANDIDAT (status unconfirmed, L1 LEAD) — bukan L3.
    Template komunitas kualitasnya bervariasi (matcher kata di halaman
    publik bisa salah sasaran); "Proof, not claims" = mesin pihak ketiga
    tidak boleh menaikkan verdict. Verifikasi independen yang menaikkan.
  - severity template dipetakan langsung; metadata template (id, tags,
    url, matched-at, curl-command) dibawa sebagai bukti & extension

Fail-closed: tanpa --lab / LAB=1 -> menolak jalan (active-probe).

Pemakaian:
  python skills/nuclei_runner.py --target http://127.0.0.1:3000 \
      --templates assets/intel/nuclei-templates --out f.json \
      [--tags exposure,panel] [--severity critical,high,medium] [--lab]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "info": "info", "unknown": "info"}


def stage_kev_templates(tpl_dir: Path, kev_path: Path,
                        staging: Path) -> tuple[int, int]:
    """F9 — prioritas intel: hanya template yang menyasar CVE di CISA KEV
    yang di-stage (dieksploitasi liar di dunia nyata = jalan duluan).
    Return (jumlah template ter-stage, jumlah CVE di KEV)."""
    kev = json.loads(Path(kev_path).read_text(encoding="utf-8"))
    cves = {v["cveID"] for v in kev.get("vulnerabilities", [])
            if v.get("cveID")}
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staged = 0
    for y in list(tpl_dir.rglob("*.yaml")) + list(tpl_dir.rglob("*.yml")):
        try:
            text = y.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = set(re.findall(r"CVE-\d{4}-\d{4,7}", text))
        if hits & cves:
            dest = staging / y.relative_to(tpl_dir)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(y, dest)
            staged += 1
    return staged, len(cves)


def parse_jsonl(raw: str) -> tuple[list[dict], list[str]]:
    """Baris JSONL valid + daftar baris rusak (bukan dibuang senyap).
    Audit 2026-10: hasil parsial tidak boleh menyamar sebagai scan
    lengkap — status parse masuk metadata run (complete/partial)."""
    rows, bad = [], []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            bad.append(line[:120])
    if bad:
        print(f"WARN: {len(bad)} baris JSONL tidak valid dilewati", file=sys.stderr)
    return rows, bad


def to_findings(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        if r.get("matcher-status") is not True:
            continue  # nuclei juga menulis percobaan yang tidak match
        info = r.get("info", {}) or {}
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "info")
        tid = r.get("template-id") or r.get("template") or "unknown"
        name = info.get("name") or tid
        matched = r.get("matched-at") or r.get("host") or ""
        out.append(make_finding(
            tool="nuclei",
            title=f"[{tid}] {name}",
            severity=sev,
            description=str(info.get("description") or
                            "Match dari template nuclei (request-response deterministik)."),
            recommendation="",
            target_url=r.get("host") or "",
            request=r.get("curl-command"),
            response=json.dumps({"matched-at": matched,
                                 "extracted": r.get("extracted-results")})[:400],
            poc=r.get("curl-command"),
            evidence_kind="request-response",   # kandidat: L1 (gerbang bukti)
            finding_class="weakness",
            confidence=0.6,
            status="unconfirmed",
            lab_only=True,
            extra={
                "category": "NUCLEI",
                "safety_class": "active-probe",
                "template_id": tid,
                "template_path": r.get("template"),
                "cve_ids": info.get("classification", {}).get("cve-id"),
                "tags": info.get("tags", []),
                "matcher_name": r.get("matcher-name"),
                "type": r.get("type"),
            },
        ))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True)
    ap.add_argument("--templates", required=True,
                    help="folder corpus template (hasil intel-sync)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tags", default=None, help="filter tag template (koma)")
    ap.add_argument("--severity", default="critical,high,medium",
                    help="filter severity template (default: critical,high,medium)")
    ap.add_argument("--rate-limit", type=int, default=50)
    ap.add_argument("--timeout", type=int, default=1200,
                    help="timeout total detik (default 1200)")
    ap.add_argument("--nuclei", default="nuclei",
                    help="path binary nuclei")
    ap.add_argument("--kev-only", action="store_true",
                    help="hanya template yang menyasar CVE di CISA KEV "
                         "(prioritas intel — dieksploitasi liar = duluan)")
    ap.add_argument("--kev", default=str(ROOT / "assets/intel/kev.json"),
                    help="path feed KEV (hasil intel-sync)")
    ap.add_argument("--lab", action="store_true",
                    help="WAJIB: konfirmasi target adalah lab milik sendiri")
    args = ap.parse_args()

    import os
    if not args.lab and os.environ.get("LAB") != "1":
        print("DITOLAK: skill active-probe butuh --lab / LAB=1 "
              "(fail-closed — tanpa otorisasi lab, tidak jalan)", file=sys.stderr)
        return 3

    tpl_dir = Path(args.templates)
    if not tpl_dir.exists():
        print(f"corpus template tidak ada: {tpl_dir} — jalankan "
              "tools/intel_sync.py dulu (fail-closed)", file=sys.stderr)
        return 2

    kev_note = {"kev_only": False, "kev_templates": None}
    if args.kev_only:
        kev_path = Path(args.kev)
        if not kev_path.exists():
            print(f"feed KEV tidak ada: {kev_path} — jalankan "
                  "tools/intel_sync.py dulu (fail-closed)", file=sys.stderr)
            return 2
        staged, total_cves = stage_kev_templates(
            tpl_dir, kev_path, ROOT / "assets/intel/.kev-staging")
        if staged == 0:
            print("tidak ada template yang menyasar CVE di KEV — "
                  "fail-closed (bukan scan kosong senyap)", file=sys.stderr)
            return 4
        tpl_dir = ROOT / "assets/intel/.kev-staging"
        kev_note = {"kev_only": True, "kev_templates": staged,
                    "kev_cves": total_cves}
        print(f"KEV priority: {staged} template "
              f"dari {total_cves} CVE dieksploitasi-liar")

    argv = [args.nuclei, "-u", args.target, "-templates", str(tpl_dir),
            "-jsonl", "-silent", "-nc",
            "-rl", str(args.rate_limit),
            "-severity", args.severity,
            "-no-color"]
    if args.tags:
        argv += ["-tags", args.tags]

    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=args.timeout)
    if proc.returncode not in (0, 1):
        # nuclei exit 1 = ada match di beberapa versi; selain itu error
        print(f"nuclei exit {proc.returncode}: "
              f"{(proc.stderr or '')[-400:]}", file=sys.stderr)
        return 1

    rows, bad_lines = parse_jsonl(proc.stdout)
    findings = to_findings(rows)
    write_findings(args.out, findings, {
        "target": args.target,
        "templates_dir": str(tpl_dir),
        "tags": args.tags,
        "severity_filter": args.severity,
        "method": "nuclei-jsonl",
        "requests": 0,  # skeleton: jumlah request nuclei belum dilacak; kuartet metrik menyusul
        "requests_untracked": True,
        # audit 2026-10: scan parsial tidak menyamar jadi lengkap
        "parse_status": "partial" if bad_lines else "complete",
        "parse_bad_lines": bad_lines,
        "safety_class": "active-probe",
        "lab": bool(args.lab or os.environ.get("LAB") == "1"),
        **kev_note,
    })
    print(f"nuclei-runner: {len(findings)} temuan "
          f"({len(rows)} baris jsonl, parse {bad_lines and 'PARTIAL: ' or ''}"
          f"{len(bad_lines)} baris rusak) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
