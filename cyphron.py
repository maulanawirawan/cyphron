#!/usr/bin/env python3
"""cyphron — satu pintu: mode dengan pilihan masing-masing.

Alat di repo ini berdiri sendiri (skills/, tools/, core-rs/). File ini
bukan mesin baru — dia papan nama: satu command, beberapa mode, dan tiap
mode punya --help sendiri yang merinci pilihannya. Tanpa argumen, papan
nama ini yang tampil.

Pemakaian:
  python cyphron.py                       # papan mode + contoh
  python cyphron.py <mode> --help         # pilihan lengkap satu mode
  python cyphron.py scout https://lab.lokal
  python cyphron.py contrib sweep --since 2026-11-06T00:00:00
  python cyphron.py skills --class read-only --text cors

Mode:
  scan      scan tier0 via core native (butuh build Rust; ada pesan bantuan)
  validate  cek findings.json vs kontrak (core native, fallback Python)
  scout     recon murah 2 GET -> tier SOFT/GUARDED/UNREACHABLE per target
  night     night-run harian per program + drift + PDF
  intel     sinkron intel KEV/NVD/OSV/CWE
  fresh     umur cakupan deteksi vs TTL
  contrib   pipeline kontribusi (submode: sweep | antidup)
  ledger    memori sesi tiga lapis (fakta/intent/recall)
  report    kemas findings jadi paket laporan
  mcp       jalankan MCP server (Claude Code / Cursor)
  skills    daftar 93 skill + kelas amannya
  lab       jalankan target lab lokal untuk latihan

Rambu tetap sama dengan repo: target berizin saja, fail-closed, no
proof no report. Mode scan dan skills berkelas lab tidak pernah melewati
gerbang dari sini.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORE_BIN = ROOT / "core-rs" / "target" / "release"
CORE_NAME = "cyphron.exe" if sys.platform == "win32" else "cyphron"
REGISTRY = ROOT / "skills" / "registry.json"
TIER0_CLASSES = ("read-only", "1-request", "bounded-requests")

# mode -> (deskripsi satu baris, script yang dieksekusi, stderr bila
# alatnya butuh langkah build). None pada script = mode special.
MODES: dict[str, dict] = {
    "scan": {
        "desc": "scan tier0 via core native (butuh build Rust)",
        "script": None, "special": "core",
        "core_args": ["scan"],
        "hint": "cargo build --release --manifest-path core-rs/Cargo.toml",
    },
    "validate": {
        "desc": "cek findings.json vs kontrak bukti",
        "script": None, "special": "validate",
        "hint": "cargo build --release --manifest-path core-rs/Cargo.toml",
    },
    "scout": {
        "desc": "recon murah 2 GET -> tier tenaga per target",
        "script": "tools/target_scout.py",
    },
    "night": {
        "desc": "night-run harian per program + drift + PDF",
        "script": "tools/nightrun.py",
    },
    "intel": {
        "desc": "sinkron intel KEV/NVD/OSV/CWE",
        "script": "tools/intel_sync.py",
    },
    "fresh": {
        "desc": "umur cakupan deteksi vs TTL",
        "script": "tools/detection_freshness.py",
    },
    "contrib": {
        "desc": "pipeline kontribusi — submode: sweep | antidup",
        "script": None, "special": "contrib",
    },
    "ledger": {
        "desc": "memori sesi tiga lapis (fakta/intent/recall)",
        "script": "tools/session_ledger.py",
    },
    "report": {
        "desc": "kemas findings jadi paket laporan",
        "script": "tools/report_pack.py",
    },
    "mcp": {
        "desc": "jalankan MCP server (Claude Code / Cursor)",
        "script": "tools/mcp_server.py",
    },
    "guard": {
        "desc": "tandai prompt-injection di bukti sebelum dibaca",
        "script": "tools/injection_guard.py",
    },
    "shield": {
        "desc": "tamper-evidence file panduan agent (pin/verify/scan)",
        "script": "tools/agent_shield.py",
    },
    "gate": {
        "desc": "verify gate — klaim status wajib bukti fresh (fail-closed)",
        "script": "tools/verify_gate.py",
    },
    "skills": {
        "desc": "daftar skill terdaftar + kelas amannya",
        "script": None, "special": "skills",
    },
    "lab": {
        "desc": "target lab lokal untuk latihan (127.0.0.1)",
        "script": "tools/lab_target.py",
    },
}

CONTRIB_SUBMODES = {
    "sweep": ("sweep NVD + triage kandidat kontribusi", "tools/cve_sweep.py"),
    "antidup": ("pre-flight 5 cek anti-duplikat", "tools/antidup_check.py"),
}


def core_binary() -> Path | None:
    """Path binary core native bila sudah dibuild."""
    path = CORE_BIN / CORE_NAME
    return path if path.exists() else None


def run_script(script: str, args: list[str], runner=None) -> int:
    """Eksekusi script via interpreter ini; runner bisa disuntik (test)."""
    argv = [sys.executable, str(ROOT / script), *args]
    if runner is not None:
        return runner(argv)
    completed = subprocess.run(argv, check=False)
    return completed.returncode


def run_core(args: list[str], runner=None) -> int:
    """Jalankan core native; belum dibuild = pesan bantuan, exit 2."""
    binary = core_binary()
    if binary is None:
        print(f"core native belum dibuild: core-rs/target/release/{CORE_NAME}",
              file=sys.stderr)
        print(f"  build dulu : {MODES['scan']['hint']}",
              file=sys.stderr)
        print("  atau pakai mode Python murni: scout | skills | ledger | "
              "contrib | intel | fresh | lab", file=sys.stderr)
        return 2
    argv = [str(binary), *args]
    if runner is not None:
        return runner(argv)
    completed = subprocess.run(argv, check=False)
    return completed.returncode


def validate_python_fallback(args: list[str]) -> int:
    """Validasi kontrak tanpa build: core/findings.py validate_finding.

    Sumber aturan yang sama dipakai test suite — cukup untuk cek cepat;
    core native tetap validator kanonik untuk gerbang CI.
    """
    if not args:
        print("pakai: python cyphron.py validate findings.json", file=sys.stderr)
        return 2
    sys.path.insert(0, str(ROOT / "core"))
    from findings import validate_finding  # noqa: E402
    bad = 0
    for path in args:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[ERROR   ] {path}: {exc}", file=sys.stderr)
            bad += 1
            continue
        items = document if isinstance(document, list) else [document]
        for i, finding in enumerate(items):
            errors = validate_finding(finding)
            label = path if len(items) == 1 else f"{path}[{i}]"
            if errors:
                bad += 1
                print(f"[INVALID ] {label}: {'; '.join(errors)}",
                      file=sys.stderr)
            else:
                print(f"[OK      ] {label}")
    return 1 if bad else 0


def mode_skills(args: list[str]) -> int:
    """Daftar skill dari registry (ALLOWLIST) + kelas aman + filter."""
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    skills = registry.get("skills") or []
    text, only_class = None, None
    rest: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--class" and i + 1 < len(args):
            only_class = args[i + 1]
            i += 2
        elif args[i] == "--text" and i + 1 < len(args):
            text = args[i + 1].lower()
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if rest:
        print(f"argumen tak dikenal: {rest} (pakai --class / --text)",
              file=sys.stderr)
        return 2
    rows = []
    for skill in skills:
        if only_class and skill.get("safety_class") != only_class:
            continue
        hay = f"{skill.get('name', '')} {skill.get('desc', '')}".lower()
        if text and text not in hay:
            continue
        rows.append(skill)
    tier0 = sum(1 for s in skills if s.get("safety_class") in TIER0_CLASSES)
    print(f"{len(rows)} skill (dari {len(skills)} terdaftar; "
          f"{tier0} kelas tier0 aman-MCP)")
    for skill in rows:
        desc = (skill.get("desc") or "").strip().replace("\n", " ")
        print(f"  {skill.get('name', ''):<34} "
              f"{skill.get('safety_class', ''):<20} {desc[:64]}")
    return 0


def mode_contrib(args: list[str], runner=None) -> int:
    """Submode pipeline kontribusi: sweep | antidup."""
    if not args or args[0] in ("-h", "--help"):
        print("mode contrib — pilih submode:")
        for name, (desc, _) in CONTRIB_SUBMODES.items():
            print(f"  python cyphron.py contrib {name:<8} # {desc}")
        print("tiap submode punya --help sendiri.")
        return 0
    sub, rest = args[0], args[1:]
    entry = CONTRIB_SUBMODES.get(sub)
    if entry is None:
        print(f"submode contrib tidak dikenal: {sub} "
              f"(pilihan: {', '.join(CONTRIB_SUBMODES)})", file=sys.stderr)
        return 2
    return run_script(entry[1], rest, runner=runner)


def dispatch(argv: list[str], runner=None) -> int:
    """Papan nama -> mode. Tanpa argumen = menu."""
    if not argv:
        print("cyphron — proof, not claims. Pilih mode:\n")
        width = max(len(name) for name in MODES)
        for name, entry in MODES.items():
            print(f"  {name:<{width}}  {entry['desc']}")
        print("\nlanjutan:")
        print(f"  python cyphron.py <mode> --help   # pilihan lengkap mode")
        print("  python cyphron.py skills --class read-only --text cors")
        print("  python cyphron.py contrib sweep --since 2026-11-06T00:00:00")
        print("  python cyphron.py scout https://lab.lokal")
        print("\nrambu: target berizin saja · fail-closed · no proof, no report")
        return 0
    mode, rest = argv[0], argv[1:]
    if mode in ("-h", "--help", "help"):
        return dispatch([])
    entry = MODES.get(mode)
    if entry is None:
        print(f"mode tidak dikenal: {mode}", file=sys.stderr)
        print(f"pilihan: {', '.join(MODES)} (atau tanpa argumen untuk menu)",
              file=sys.stderr)
        return 2
    special = entry.get("special")
    if special == "core":
        return run_core([*entry.get("core_args", []), *rest], runner=runner)
    if special == "validate":
        binary = core_binary()
        if binary is not None:
            return run_core(["validate", *rest], runner=runner)
        return validate_python_fallback(rest)
    if special == "contrib":
        return mode_contrib(rest, runner=runner)
    if special == "skills":
        return mode_skills(rest)
    return run_script(entry["script"], rest, runner=runner)


def main(argv: list[str] | None = None) -> int:
    return dispatch(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    sys.exit(main())
