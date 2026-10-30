"""[F74][SAFETY: local-source audit] audit-offline — review sumber lokal
dengan jaringan DITOLAK sebelum koneksi (enforced).

Pola anthropics/oss-scanner (docs/RISET-OSS-SCANNER-2026-10.md): build/
persiapan boleh online, AUDIT berjalan tanpa internet. Cyphron memakai
net-guard (Fase 2-B) untuk menegakkan itu: setiap proses skill di-spawn
runner mewarisi env CYPHRON_NET_GUARD=1 + budget file LIMIT 0 — koneksi
apapun (TCP/UDP) DITOLAK SEBELUM connect(); yang lolos hanya skill yang
benar-benar 0-request (needs=source).

Pemakaian:
  python tools/audit_offline.py --source <dir> --out <dir>

Fail-closed: --source tidak ada = exit 2; scan gagal = exit 1 tanpa
metrik; summary JSON selalu membawa bukti enforcement (jumlah upaya
koneksi yang ditolak dari audit log net-guard).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

# Kontrak env net-guard (HARUS sama dgn core/net_guard.py — dua
# implementasi satu kontrak, pola anthropics/oss-scanner). Tidak
# di-import: `import net_guard` bisa tertelan namespace package
# tools/net_guard/ (berisi sitecustomize) alih-alih core/net_guard.py.
GUARD_ENV = "CYPHRON_NET_GUARD"
BUDGET_ENV = "CYPHRON_NET_BUDGET_FILE"
AUDIT_ENV = "CYPHRON_NET_AUDIT"


def build_env(source_dir: Path, out_dir: Path,
              base_env: dict | None = None) -> tuple[dict, Path, Path]:
    """Env untuk proses scan offline + path budget/audit file.
    Budget LIMIT 0 = semua koneksi ditolak (deny-all enforced)."""
    env = dict(base_env if base_env is not None else os.environ)
    out_dir.mkdir(parents=True, exist_ok=True)
    budget = out_dir / "offline-budget.json"
    audit = out_dir / "offline-audit.jsonl"
    budget.write_text(json.dumps({"limit": 0, "used": 0}), encoding="utf-8")
    env[GUARD_ENV] = "1"
    env[BUDGET_ENV] = str(budget)
    env[AUDIT_ENV] = str(audit)
    # sitecustomize net-guard dimuat Python via PYTHONPATH (root repo
    # dulu agar `core.net_guard` import; lalu tools/net_guard untuk
    # entry sitecustomize-nya)
    root_s = str(ROOT)
    ng_s = str(ROOT / "tools" / "net_guard")
    existing = env.get("PYTHONPATH", "")
    parts = [p for p in existing.split(os.pathsep) if p]
    for p in (root_s, ng_s):
        if p not in parts:
            parts.insert(0 if p == root_s else len(parts), p)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env, budget, audit


def denied_count(audit_file: Path) -> int:
    """Jumlah upaya koneksi yang DITOLAK net-guard (bukti enforcement)."""
    if not audit_file.exists():
        return 0
    n = 0
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        try:
            if not json.loads(line).get("allowed", True):
                n += 1
        except Exception:
            continue
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True,
                    help="folder sumber lokal yang diaudit (needs=source)")
    ap.add_argument("--out", required=True,
                    help="folder output (findings + bukti enforcement)")
    ap.add_argument("--registry", default=str(ROOT / "skills" / "registry.json"))
    ap.add_argument("--binary", default=str(ROOT / "core-rs" / "target"
                                            / "release" / "cyphron.exe"))
    ap.add_argument("--evidence", default=None,
                    help="opsional: capture evidence untuk skill read-only")
    args = ap.parse_args()

    src = Path(args.source).resolve()
    if not src.is_dir():
        print(f"FAIL-CLOSED: folder sumber tidak ada: {src}", file=sys.stderr)
        return 2
    binary = Path(args.binary)
    if not binary.exists():
        print(f"FAIL-CLOSED: binary tidak ada: {binary} "
              f"(cargo build --release dulu)", file=sys.stderr)
        return 2
    out_dir = Path(args.out).resolve()
    env, budget, audit = build_env(src, out_dir)

    cmd = [str(binary), "scan", "--mode", "tier0", "--source", str(src),
           "--out", str(out_dir / "run"), "--registry", args.registry]
    if args.evidence:
        cmd += ["--evidence", args.evidence]
    print(f"[audit-offline] scan (jaringan DITOLAK): {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=1800, cwd=str(ROOT), env=env)
    except subprocess.TimeoutExpired:
        print("FAIL-CLOSED: scan melebihi 30 menit", file=sys.stderr)
        return 1
    if proc.returncode != 0:
        print(f"FAIL-CLOSED: scan exit {proc.returncode}: "
              f"{(proc.stderr or proc.stdout)[-400:]}", file=sys.stderr)
        return 1
    merged = out_dir / "run" / "findings.json"
    if not merged.exists():
        print("FAIL-CLOSED: findings.json tidak tercipta", file=sys.stderr)
        return 1

    doc = json.loads(merged.read_text(encoding="utf-8"))
    denied = denied_count(audit)
    skills = sorted({str(s.get("skill"))
                     for s in doc.get("data", {}).get("sources", [])
                     if s.get("skill")})
    summary = {
        "mode": "offline-audit",
        "source": str(src),
        "offline_enforced": True,
        "budget": {"limit": 0, "file": str(budget)},
        "denied_connections": denied,
        "total_findings": doc.get("data", {}).get("total_findings", 0),
        "requests": doc.get("requests", 0),
        "skills_run": skills,
    }
    (out_dir / "offline-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"[audit-offline] selesai: {summary['total_findings']} temuan, "
          f"{denied} upaya koneksi DITOLAK (deny-all enforced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
