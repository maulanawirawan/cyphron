"""[F48] Agent-tooling safety audit — audit statis codebase MCP/CLI
AI-agent (inspirasi kelas dari review tooling agent 2026; CLEAN-ROOM,
NOL request, read-only).

Kelas yang diperiksa (hanya pola SPESIFIK yang terverifikasi berbahaya
— zero-FP, tanpa heuristik kabur):
  1. exec/spawn dengan template-literal interplolasi (CWE-78) — bentuk
     `exec...(`...${...}...)` di baris yang sama;
  2. eval()/new Function( di kode produksi (CWE-95);
  3. spawn dengan opsi shell:true (CWE-78);
  4. Math.random dekat penamaan token/secret/nonce/capability (CWE-338)
     — jarak <=3 baris, penamaan eksplisit;
  5. installer curl|bash (catatan rantai pasok, fakta bukan klaim
     kerentanan — keberadaan pola saja).
Semua temuan = lead L1 (wajib review manusia); bersih = satu baris
AMAN; path tidak ada = exit 2 fail-closed. File test/fixture tetap
dipindai tapi diberi tanda di meta.

Pemakaian:
  python tools/agent_tool_audit.py --repo <path-codebase> \\
      --out findings/agent-tool-audit.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

from findings import make_finding, write_findings  # noqa: E402

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build",
             "__pycache__", "target"}
SCAN_EXT = {".ts", ".js", ".mjs", ".cjs", ".py", ".sh", ".bash"}
MAX_FILES = 5000  # bounded; lebih besar = dilewati tercatat di meta
MAX_FILE_BYTES = 512_000

_RE_EXEC_TPL = re.compile(
    r"\b(exec|execSync|execFile|execFileSync|spawn|spawnSync)\w*\s*\("
    r"[^)]*`[^`]*\$\{")
_RE_EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
_RE_SHELL_TRUE = re.compile(r"shell\s*:\s*true")
_RE_MATHRANDOM = re.compile(r"Math\.random\s*\(")
_RE_TOKEN_NAME = re.compile(
    r"\b(token|secret|nonce|capability|api[_-]?key)s?\b", re.I)
_RE_CURL_PIPE = re.compile(
    r"curl[^|&;]*\|\s*(sudo\s+)?(ba)?sh\b|wget[^|&;]*\|\s*(sudo\s+)?(ba)?sh\b")
_RE_GUARD_HINT = re.compile(r"truncation|unterminated|set\s+-euo")


_RE_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__)(/|$)|[.]test[.]|[.]spec[.]")


def _iter_files(root: Path) -> list[Path]:
    """File produksi saja — file test bukan permukaan risiko (eval di
    test adalah cara kerja test, bukan temuan)."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            f = Path(dirpath) / fn
            rel = f.relative_to(root).as_posix()
            if Path(fn).suffix not in SCAN_EXT or _RE_TEST_PATH.search(
                    "/" + rel):
                continue
            files.append(f)
            if len(files) >= MAX_FILES:
                return files
    return files


def _lead(rel: str, lineno: int, title: str, desc: str, cwe: str | None,
          extra: dict) -> dict:
    """Satu baris lead (L1) — kategori AGENT-TOOL-AUDIT."""
    return make_finding(
        tool="agent-tool-audit", title=title, severity="medium",
        description=f"{desc} ({rel}:{lineno})",
        recommendation="Review manual + lapor privat via kanal "
                       "SECURITY.md proyek.",
        cwe=cwe, target_url=f"repo:{rel}",
        evidence_kind="file-manifest", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1,
        extra={"category": "AGENT-TOOL-AUDIT", **extra})


def audit_codebase(root: Path) -> tuple[list[dict], dict]:
    """Murni: pindai pola statis -> (rows, meta) kontrak. Lead L1 maks;
    tanpa pola = satu baris AMAN."""
    rows: list[dict] = []
    if not root.is_dir():
        return rows, {"error": f"repo tidak ada: {root}"}
    files = _iter_files(root)
    truncated = len(files) >= MAX_FILES
    checked = 0
    for f in files:
        rel = f.relative_to(root).as_posix()
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        checked += 1
        is_installer = rel in ("install.sh", "install.bash",
                               "setup.sh", "bootstrap.sh")
        stripped = text.splitlines()
        for lineno, line in enumerate(stripped, 1):
            code = line.lstrip()
            if code.startswith(("//", "*", "/*", "#")):
                continue  # baris komentar bukan kode (anti-FP eval di doc)
            if _RE_EXEC_TPL.search(line):
                rows.append(_lead(rel, lineno, 
                    "exec/spawn dengan interpolasi template-literal",
                    "Proses anak dipanggil lewat string yang "
                    "diinterpolasi — kanal injeksi argumen/perintah "
                    "klasik bila input mencapai string ini.",
                    "CWE-78", {"pattern": "exec-template-literal",
                               "line": lineno}))
            if _RE_EVAL.search(line):
                rows.append(_lead(rel, lineno, 
                    "eval()/new Function() di kode produksi",
                    "Eksekusi kode dinamis — payload teks bisa menjadi "
                    "kode bila input mencapai sini.",
                    "CWE-95", {"pattern": "eval", "line": lineno}))
            if _RE_SHELL_TRUE.search(line):
                rows.append(_lead(rel, lineno, 
                    "spawn dengan shell:true",
                    "Proses anak lewat shell — argumen yang mengandung "
                    "metakarakter dieksekusi, bukan diteruskan.",
                    "CWE-78", {"pattern": "shell-true", "line": lineno}))
            if (_RE_MATHRANDOM.search(line)
                    and (_RE_TOKEN_NAME.search(line)
                         or _RE_TOKEN_NAME.search(
                             _nearby(text, lineno)))):
                rows.append(_lead(rel, lineno, 
                    "Math.random dekat penamaan token/secret",
                    "PRNG non-kripto di dekat nilai yang tampak "
                    "token/secret — keterdugaan harus diverifikasi "
                    "manual (bisa false positive untuk jitter/delay).",
                    "CWE-338", {"pattern": "mathrandom-near-token",
                                "line": lineno}))
            if is_installer and _RE_CURL_PIPE.search(line):
                guarded = bool(_RE_GUARD_HINT.search(text))
                rows.append(_lead(rel, lineno, 
                    "Installer memakai pola curl|bash",
                    "Pola curl|bash = keputusan rantai pasok (eksekusi "
                    "konten remote); status guard unduhan terpotong: "
                    + ("TERDETEKSI - mitigasi" if guarded else
                       "TIDAK terdeteksi - risiko eksekusi setengah "
                       "jadi") + ".",
                    None, {"pattern": "curl-pipe-shell", "line": lineno,
                           "guard_hint": guarded}))
    if not rows:
            rows.append(make_finding(
                tool="agent-tool-audit",
                title="Tidak ada pola berisiko yang cocok",
                severity="info",
                description=f"{checked} file diperiksa (batas "
                            f"{MAX_FILES}) — kelas exec-template, eval, "
                            "shell:true, Math.random-token, curl|bash "
                            "tidak ditemukan (AMAN/inventaris).",
                target_url=f"repo:{root.name}",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "AMAN"}))
    meta = {"root": str(root), "files_checked": checked,
            "files_found": len(files), "truncated": truncated,
            # hitung LEAD saja — baris ringkasan AMAN bukan temuan
            "findings": sum(1 for r in rows
                            if r.get("category") == "AGENT-TOOL-AUDIT")}
    return rows, meta


def _nearby(text: str, lineno: int, window: int = 3) -> str:
    lines = text.splitlines()
    lo = max(0, lineno - 1 - window)
    hi = min(len(lines), lineno + window)
    return "\n".join(lines[lo:hi])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True,
                    help="path codebase (MCP/CLI/agent tooling)")
    ap.add_argument("--out", default="findings/agent-tool-audit.json")
    args = ap.parse_args()
    root = Path(args.repo)
    if not root.is_dir():
        print(f"repo tidak ada: {root} (fail-closed)", file=sys.stderr)
        return 2
    rows, meta = audit_codebase(root)
    write_findings(args.out, rows,
                   {**meta, "run": "agent-tool-audit",
                    "safety_class": "read-only", "requests": 0})
    print(f"agent-tool-audit: {meta['files_checked']} file -> "
          f"{meta['findings']} temuan -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
