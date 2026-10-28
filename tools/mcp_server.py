"""MCP server untuk skills cyphron — pakai skills dari Claude Code/Cursor.

Registry (skills/registry.json) adalah ALLOWLIST: hanya skill yang
terdaftar yang bisa dijalankan, dan hanya kelas mode tier0 (read-only /
1-request / bounded-requests) yang diekspos. Kelas lab (active-probe,
credential-bearing, state-changing) TIDAK diekspos — fail-closed, sama
sepati gerbang mode di orchestrator.

Eksekusi: subprocess tanpa shell, timeout keras, output ke findings/mcp/,
hasil divalidasi terhadap kontrak (core/findings.py) SEBELUM dikembalikan
— dokumen yang melanggar kontrak tidak pernah sampai ke klien.

Pemakaian (dikonfigurasi di Claude Code / Cursor):
  command: python
  args:    [tools/mcp_server.py]

Dependensi: pip install "mcp[cli]"
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(os.environ.get("CYPHRON_ROOT",
                           Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT / "core"))
from findings import validate_finding  # noqa: E402

REGISTRY_PATH = ROOT / "skills" / "registry.json"
OUT_DIR = ROOT / "findings" / "mcp"

# Kelas yang boleh diekspos via MCP = gerbang tier0 (satu sumber kebenaran
# dengan orchestrator.rs allowed_safety_classes).
TIER0_CLASSES = ("read-only", "1-request", "bounded-requests")
LAB_CLASSES = ("active-probe", "credential-bearing", "state-changing")

DEFAULT_TIMEOUT_S = 180


def load_registry(path: Path | None = None) -> dict:
    p = Path(path) if path else REGISTRY_PATH
    reg = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(reg, dict) or not reg.get("skills"):
        raise ValueError("registry invalid — fail-closed")
    return reg


def selectable_skills(reg: dict) -> list[dict]:
    """Skill yang BOLEH diekspos via MCP: kelas tier0 saja (fail-closed)."""
    out = []
    for s in reg.get("skills", []):
        if s.get("safety_class") not in TIER0_CLASSES:
            continue
        if s.get("lab_only"):
            continue
        out.append({
            "name": s["name"],
            "safety_class": s.get("safety_class"),
            "needs": s.get("needs"),
            "requires_evidence": bool(s.get("requires_evidence")),
            "desc": s.get("desc", ""),
        })
    return out


def resolve_skill(reg: dict, name: str) -> dict:
    """Ambil satu skill dari allowlist. Tidak ada di registry = error
    (tidak ada eksekusi perintah arbitrer)."""
    for s in reg.get("skills", []):
        if s.get("name") == name:
            return s
    raise LookupError(
        f"skill '{name}' tidak ada di registry — allowlist, fail-closed")


def gate_skill(s: dict, target: str | None, domain: str | None,
               evidence: str | None) -> None:
    """Gerbang fail-closed sebelum eksekusi. Raise ValueError dengan
    alasan spesifik."""
    cls = s.get("safety_class")
    if cls in LAB_CLASSES or s.get("lab_only"):
        raise ValueError(f"kelas '{cls}' hanya lab — tidak diekspos via MCP")
    if cls not in TIER0_CLASSES:
        raise ValueError(f"kelas '{cls}' di luar gerbang tier0 — fail-closed")
    if s.get("requires_evidence") and not evidence:
        raise ValueError(f"skill '{s['name']}' butuh bukti (--evidence) — "
                         "mode nol-request tidak berlaku di sini")
    if evidence and cls == "1-request":
        raise ValueError("kebijakan nol-request saat mode bukti: skill "
                         "1-request tidak dijalankan dengan --evidence")
    need = s.get("needs")
    if need == "target" and not target:
        raise ValueError(f"skill '{s['name']}' butuh parameter target")
    if need == "domain" and not domain:
        raise ValueError(f"skill '{s['name']}' butuh parameter domain")


def build_argv(s: dict, target: str | None, domain: str | None,
               evidence: str | None, out_path: Path,
               python_exe: str | None = None) -> list[str]:
    """Ekspansi placeholder @TARGET@/@DOMAIN@/@EVIDENCE@/@OUT@ — identik
    orchestrator.rs. python -> interpreter yang sedang jalan."""
    py = python_exe or sys.executable
    argv = []
    for a in s["cmd"]:
        if a in ("python", "python3"):
            a = py
        argv.append(a
                    .replace("@TARGET@", target or "")
                    .replace("@DOMAIN@", domain or "")
                    .replace("@EVIDENCE@", evidence or "")
                    .replace("@OUT@", str(out_path)))
    return argv


def run_skill(name: str, target: str | None = None,
              domain: str | None = None, evidence: str | None = None,
              timeout_s: int = DEFAULT_TIMEOUT_S,
              registry_path: Path | None = None) -> str:
    """Jalankan satu skill dari allowlist + validasi kontrak. Return JSON
    (str). Dokumen yang gagal kontrak TIDAK dikembalikan (fail-closed)."""
    reg = load_registry(registry_path)
    try:
        s = resolve_skill(reg, name)
        gate_skill(s, target, domain, evidence)
    except (LookupError, ValueError) as e:
        return json.dumps({"ok": False, "error": str(e)})

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{name}-{int(time.time())}.json"
    argv = build_argv(s, target, domain, evidence, out_path)
    t0 = time.time()
    try:
        proc = subprocess.run(argv, cwd=str(ROOT), shell=False,
                              capture_output=True, text=True,
                              timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return json.dumps({"ok": False,
                           "error": f"timeout {timeout_s}s — fail-closed"})
    if proc.returncode != 0:
        return json.dumps({"ok": False,
                           "error": f"exit {proc.returncode}",
                           "stderr": proc.stderr[-2000:]})
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    if not doc.get("ok"):
        return json.dumps({"ok": False,
                           "error": "skill melaporkan ok=false — fail-closed"})
    # Validasi kontrak per baris — baris invalid = error keras, bukan diam.
    errs: list[str] = []
    for i, f in enumerate(doc.get("findings", [])):
        errs.extend(f"findings[{i}]: {e}" for e in validate_finding(f))
    if errs:
        return json.dumps({"ok": False,
                           "error": "hasil melanggar kontrak — fail-closed",
                           "details": errs[:10]})
    rows = doc.get("findings", [])
    return json.dumps({
        "ok": True,
        "skill": name,
        "out": str(out_path),
        "elapsed_s": round(time.time() - t0, 2),
        "total_findings": len(rows),
        "reportable": sum(1 for f in rows if f.get("reportable")),
        "requests": doc.get("requests", 0),
        "findings": rows,
    }, ensure_ascii=False)


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("paket 'mcp' belum terpasang: pip install 'mcp[cli]' — "
              "fail-closed", file=sys.stderr)
        raise SystemExit(2)
    mcp = FastMCP("cyphron")

    @mcp.tool()
    def cyphron_list_skills() -> str:
        """Daftar skill cyphron yang boleh dijalankan (allowlist tier0)."""
        reg = load_registry()
        return json.dumps({
            "ok": True,
            "registry_version": reg.get("version"),
            "count": len(selectable_skills(reg)),
            "skills": selectable_skills(reg),
            "verdict_ladder": "0 OBSERVED, 1 SUSPECTED, 2 REPRODUCED, "
                              "3 DETERMINISTICALLY_VERIFIED, 4 IMPACT_VERIFIED, "
                              "5 BLIND_VALIDATED, -1 REJECTED (L3+ = reportable)",
        }, ensure_ascii=False)

    @mcp.tool()
    def cyphron_run_skill(name: str, target: str = "", domain: str = "",
                          evidence: str = "") -> str:
        """Jalankan satu skill cyphron terhadap target/domain. Skill
        read-only/1-request/bounded-requests saja (kelas lab tidak
        diekspos). Hasil divalidasi kontrak sebelum dikembalikan."""
        return run_skill(
            name,
            target=target or None,
            domain=domain or None,
            evidence=evidence or None,
        )

    mcp.run()


if __name__ == "__main__":
    main()
