"""[GATE] Verify gate — klaim butuh bukti FRESH sebelum boleh diucapkan.

Konsep "verification-before-completion" (Iron Law: NO COMPLETION CLAIMS
WITHOUT FRESH VERIFICATION EVIDENCE) dipopulerkan repo obra/superpowers
(313k+ stars, MIT). SecAI sudah punya kontrak "No proof, no report"
untuk temuan; tool ini menutup sisanya — klaim STATUS pekerjaan ("suite
hijau", "CI lulus", "regresi ditutup") juga wajib bukti. Dibangun
from scratch (tidak ada kode dari repo tersebut); atribusi konsep di
docstring ini. Lisensi secai: PolyForm NC.

Fail-closed tegas:
  - gate tanpa definisi cek            -> BLOCKED (bukan VERIFIED)
  - satu cek saja gagal                -> BLOCKED
  - bukti artefak lebih tua dari run   -> BLOCKED (bukti basi = bukan bukti)
  - perintah timeout                   -> BLOCKED
Output machine-readable (evidence JSON) + verdict; exit 0 hanya bila
VERIFIED (konvensi repo: 2 = input tidak valid).

Mekanisme gate function (lima langkah, semua wajib):
  1. IDENTIFY : cek didefinisikan eksplisit di gate file (JSON), bukan
     di kepala — daftar perintah yang MEMBUKTIKAN klaim.
  2. RUN      : SETIAP perintah dieksekusi FRESH saat gate jalan
     (output lama tidak pernah dipercaya).
  3. READ     : exit code + stdout/stderr ditangkap utuh.
  4. VERIFY   : expect_exit cocok + expect_regex (opsional) ada di
     output + artefak bukti (opsional) ada & fresh (mtime >= mulai run).
  5. ONLY THEN: verdict VERIFIED + stempel waktu; selain itu BLOCKED
     dengan daftar penyebab.

Format gate file (JSON):
  {
    "claim": "suite secai hijau untuk PR ini",
    "checks": [
      {
        "name": "unittest inti",
        "cmd": ["python", "-m", "pytest", "tests/test_f25_exploit.py", "-q"],
        "expect_exit": 0,                      // opsional, default 0
        "expect_regex": "[0-9]+ passed",        // opsional
        "artifacts": ["build/output.bin"],      // opsional, harus fresh
        "timeout_sec": 300                      // opsional, default 300
      }
    ]
  }
  cmd: list argv (disarankan, tanpa shell) ATAU string (di-shlex.split,
  tanpa shell). Path Windows pakai forward slash (python menerimanya).

Pemakaian:
  python tools/verify_gate.py --gate gate.json --out gate-evidence.json
  python tools/verify_gate.py --claim "x" --cmd "python -m pytest -q" \
      --expect-regex "[0-9]+ passed"
  (mode `gate` di secai.py meneruskan ke sini.)
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_TIMEOUT_SEC = 300
VERDICT_VERIFIED = "VERIFIED"
VERDICT_BLOCKED = "BLOCKED"


def _as_argv(cmd: "str | list[str]") -> list[str]:
    """Normalisasi cmd ke argv list; string di-shlex.split (tanpa shell)."""
    if isinstance(cmd, list):
        if not cmd or not all(isinstance(x, str) for x in cmd):
            raise ValueError("cmd list harus berisi string dan tidak kosong")
        return list(cmd)
    if isinstance(cmd, str) and cmd.strip():
        parts = shlex.split(cmd)
        if not parts:
            raise ValueError("cmd string kosong setelah parsing")
        return parts
    raise ValueError("cmd wajib list argv atau string tidak kosong")


def _read_check(check: dict) -> dict:
    """Validasi satu cek; lempar ValueError dengan pesan jelas."""
    if not isinstance(check, dict):
        raise ValueError("setiap cek harus objek")
    name = check.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("cek tanpa 'name'")
    # idempotent: cek mentah punya 'cmd', hasil normalisasi punya 'argv'
    raw_cmd = check.get("cmd", check.get("argv"))
    if raw_cmd is None:
        raise ValueError(f"cek '{name}' tanpa 'cmd'")
    out = {
        "name": name,
        "argv": _as_argv(raw_cmd),
        "expect_exit": int(check.get("expect_exit", 0)),
        "expect_regex": check.get("expect_regex"),
        "artifacts": list(check.get("artifacts") or []),
        "timeout_sec": float(check.get("timeout_sec", DEFAULT_TIMEOUT_SEC)),
    }
    if out["timeout_sec"] <= 0:
        raise ValueError(f"cek '{name}': timeout_sec harus > 0")
    if out["expect_regex"] is not None:
        try:
            re.compile(out["expect_regex"])
        except re.error as exc:
            raise ValueError(f"cek '{name}': regex tidak valid: {exc}")
    return out


def load_gate(path: str) -> dict:
    """Baca + validasi gate file. Fail-closed: rusak/kosong = error (exit 2)."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"gate file tidak ada: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"gate file bukan JSON valid: {exc}")
    if not isinstance(data, dict):
        raise ValueError("gate file harus objek JSON")
    claim = data.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        raise ValueError("gate tanpa 'claim' (klaim apa yang dibuktikan?)")
    checks_raw = data.get("checks")
    if not isinstance(checks_raw, list) or not checks_raw:
        raise ValueError("gate tanpa 'checks' — gate tanpa cek = BLOCKED, "
                         "bukan VERIFIED (fail-closed)")
    return {"claim": claim, "checks": [_read_check(c) for c in checks_raw]}


def _check_artifacts(argv_paths: list[str], run_start: float,
                     cwd: Path) -> "tuple[list[str], list[str]]":
    """Cek artefak bukti: ada + mtime >= run_start (fresh).

    Return (daftar ok, daftar alasan gagal). Path relatif dievaluasi
    terhadap cwd gate run.
    """
    ok, bad = [], []
    for art in argv_paths:
        p = (cwd / art).resolve() if not Path(art).is_absolute() else Path(art)
        if not p.is_file():
            bad.append(f"artefak bukti tidak ada: {art}")
            continue
        try:
            mtime = p.stat().st_mtime
        except OSError as exc:
            bad.append(f"artefak bukti tak terbaca: {art}: {exc}")
            continue
        if mtime < run_start:
            ok.append(f"{art} (basi: mtime < mulai run)")  # tetap dicatat
            bad.append(f"bukti basi: {art} lebih tua dari mulai run "
                       f"(mtime {mtime:.0f} < {run_start:.0f})")
        else:
            ok.append(f"{art} fresh (mtime {mtime:.0f})")
    return ok, bad


def run_gate(gate: dict, now: "float | None" = None) -> dict:
    """Jalankan semua cek gate. Fail-closed: satu gagal = BLOCKED.

    now: injeksi waktu untuk uji deterministik (None = waktu nyata).
    Return evidence dict machine-readable.
    """
    if not gate.get("checks"):
        # fail-closed: gate tanpa cek tidak boleh VERIFIED
        return {
            "schema": "secai.verify-gate/1",
            "verdict": VERDICT_BLOCKED,
            "claim": str(gate.get("claim", "")),
            "started_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now if now is not None
                                                  else time.time())),
            "finished_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "checks_total": 0, "checks_passed": 0, "results": [],
            "blocked_by": [{"name": "(gate)", "failures":
                            ["gate tanpa cek — tidak ada bukti apa pun"]}],
        }
    # normalisasi idempotent: gate mentah (cmd string/list) atau hasil
    # load_gate sama-sama diterima — kontrak fail-closed yang sama.
    checks = [_read_check(c) for c in gate["checks"]]
    started = now if now is not None else time.time()
    started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started))
    results: list[dict] = []
    verdict = VERDICT_VERIFIED
    for check in checks:
        entry: dict = {"name": check["name"], "cmd": check["argv"]}
        t0 = time.time()
        try:
            proc = subprocess.run(
                check["argv"], capture_output=True, text=True,
                timeout=check["timeout_sec"], shell=False, check=False,
            )
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
            entry["timed_out"] = False
        except subprocess.TimeoutExpired:
            exit_code, stdout, stderr = None, "", ""
            entry["timed_out"] = True
        except OSError as exc:
            exit_code, stdout, stderr = None, "", str(exc)
            entry["timed_out"] = False
        entry["duration_sec"] = round(time.time() - t0, 3)
        entry["exit_code"] = exit_code
        failures: list[str] = []
        if entry["timed_out"]:
            failures.append(f"timeout {check['timeout_sec']}s")
        if exit_code != check["expect_exit"]:
            failures.append(f"exit_code {exit_code} != expect "
                            f"{check['expect_exit']}")
        if check["expect_regex"] is not None and not re.search(
                check["expect_regex"], stdout or stderr or ""):
            failures.append(f"expect_regex '{check['expect_regex']}' "
                            "tidak ada di output")
        art_ok, art_bad = [], []
        if check["artifacts"]:
            art_ok, art_bad = _check_artifacts(
                check["artifacts"], started, Path.cwd())
            failures.extend(art_bad)
        if art_ok:
            entry["artifacts"] = art_ok
        entry["failures"] = failures
        entry["status"] = "pass" if not failures else "fail"
        results.append(entry)
        if failures:
            verdict = VERDICT_BLOCKED  # fail-closed: tidak ada short-circuit
    evidence = {
        "schema": "secai.verify-gate/1",
        "verdict": verdict,
        "claim": gate["claim"],
        "started_utc": started_iso,
        "finished_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks_total": len(results),
        "checks_passed": sum(1 for r in results if r["status"] == "pass"),
        "results": results,
    }
    if verdict != VERDICT_VERIFIED:
        evidence["blocked_by"] = [
            {"name": r["name"], "failures": r["failures"]}
            for r in results if r["failures"]
        ]
    return evidence


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify gate — klaim butuh bukti fresh (fail-closed).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--gate", help="gate file JSON (claim + checks)")
    src.add_argument("--claim", help="klaim satu baris (mode cepat 1 cek)")
    ap.add_argument("--cmd", help="perintah verifikasi (mode cepat)")
    ap.add_argument("--expect-exit", type=int, default=0,
                    help="exit code yang diharapkan (default 0)")
    ap.add_argument("--expect-regex", help="regex wajib ada di output")
    ap.add_argument("--artifact", action="append", dest="artifacts",
                    help="artefak bukti yang harus fresh (bisa berulang)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SEC,
                    help="timeout per perintah detik (default 300)")
    ap.add_argument("--out", help="tulis evidence JSON ke file")
    args = ap.parse_args(argv)

    try:
        if args.gate:
            gate = load_gate(args.gate)
        else:
            if not args.cmd:
                print("--claim butuh --cmd (perintah yang membuktikan)",
                      file=sys.stderr)
                return 2
            gate = {"claim": args.claim, "checks": [_read_check({
                "name": args.cmd[:60], "cmd": args.cmd,
                "expect_exit": args.expect_exit,
                "expect_regex": args.expect_regex,
                "artifacts": args.artifacts or [],
                "timeout_sec": args.timeout,
            })]}
    except (ValueError, FileNotFoundError) as exc:
        print(f"[gate] input tidak valid: {exc}", file=sys.stderr)
        return 2

    evidence = run_gate(gate)
    rendered = json.dumps(evidence, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    for r in evidence["results"]:
        mark = "PASS" if r["status"] == "pass" else "FAIL"
        print(f"[{mark}] {r['name']} (exit={r['exit_code']}, "
              f"{r['duration_sec']}s)")
        for f in r["failures"]:
            print(f"       alasan: {f}")
    print(f"[gate] {evidence['verdict']}: {evidence['claim']}")
    print(f"[gate] cek {evidence['checks_passed']}/"
          f"{evidence['checks_total']} lulus; bukti"
          f"{' di ' + args.out if args.out else ' hanya di stdout'}")
    return 0 if evidence["verdict"] == VERDICT_VERIFIED else 1


if __name__ == "__main__":
    sys.exit(main())
