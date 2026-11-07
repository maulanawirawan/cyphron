"""[GATE: read-only pada repo target] patch_proof — pembuktian tiga-lengan
perbaikan bug (baseline GAGAL -> patched LULUS -> control LULUS di keduanya).

Konsep "three-arm proof" (representative wajib GAGAL di baseline dan LULUS
di patched; control LULUS di kedua lengan; tiap lengan disimpan sebagai
receipt) mengacu pada skill prove-patch di repo trailofbits/skills (8k+
stars, CC-BY-SA-4.0) — dibangun from scratch TANPA kode dari repo itu.
Lisensi cyphron: PolyForm NC.

Masalah yang dijawab: klaim "bug sudah diperbaiki" sering hanya diuji satu
sisi (lulus sesudah patch) tanpa membuktikan lengan sebelumnya memang GAGAL
— patch yang tidak pernah merah tidak membuktikan apa pun. patch_proof
mengeksekusi harness yang SAMA di dua checkout bersih (git worktree) pada
SHA baseline dan SHA patched, lalu memutuskan fail-closed.

Kontrak harness (diberlakukan ketat; pelanggaran = INCONCLUSIVE):
  - harness = satu file Python; dijalankan dengan interpreter yang sama,
    cwd = worktree; tool tidak pernah mengubah harness.
  - stdout berisi nol atau lebih baris `PATCH_CASE {json}` dengan field
    wajib: id (str), role ("representative"|"control"), pass (bool).
  - baris stdout non-kosong TERAKHIR harus persis `PATCH_REACHED` — bukti
    harness mencapai titik vonis, bukan mati di tengah jalan.
  - exit code: 0 = semua kasus lulus; non-nol = ada yang gagal.

Putusan (fail-closed, diuji berurutan):
  1. kegagalan operasional (worktree gagal, timeout, marker hilang,
     PATCH_CASE rusak/melebihi batas)      -> INCONCLUSIVE
  2. himpunan kasus (id+role) beda antar lengan -> NOT_PROVED
  3. tanpa representative                   -> NOT_PROVED
  4. control gagal di salah satu lengan      -> NOT_PROVED
  5. representative LULUS di baseline        -> NOT_PROVED (bug tak reproduksi)
  6. representative GAGAL di patched         -> NOT_PROVED (patch tak memperbaiki)
  7. exit patched != 0 ATAU exit baseline == 0 -> NOT_PROVED (kontrak exit)
  8. selain itu                              -> PROVED

Read-only terhadap repo target: checkout aktif tidak disentuh — pembuktian
lewat `git worktree add --detach` terpisah yang selalu dibersihkan (finally).
NOL jaringan. Output: bukti JSON (schema cyphron.patch-proof/1) + ringkasan.
Exit: 0 PROVED; 1 NOT_PROVED; 2 input error; 3 INCONCLUSIVE.

Pemakaian:
  python tools/patch_proof.py --repo path/ke/repo --baseline <sha> \
      --patched <sha> --harness path/ke/harness.py --out proof.json
  python tools/patch_proof.py ... --timeout-sec 60    # per lengan
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA = "cyphron.patch-proof/1"
CASE_PREFIX = "PATCH_CASE "
REACHED_MARKER = "PATCH_REACHED"
ROLES = ("representative", "control")
MAX_CASES = 1000
MAX_STREAM_CHARS = 64 * 1024
DEFAULT_TIMEOUT_SEC = 120

EXIT_PROVED = 0
EXIT_NOT_PROVED = 1
EXIT_INPUT_ERROR = 2
EXIT_INCONCLUSIVE = 3


class InputError(Exception):
    """Input tidak valid -> exit 2."""


class Inconclusive(Exception):
    """Kegagalan operasional -> fail-closed, exit 3. .record = receipt lengan."""

    record: dict | None = None


def _bail(rec: dict, msg: str) -> "Inconclusive":
    """Bangun Inconclusive yang membawa receipt lengan parsial."""
    exc = Inconclusive(msg)
    exc.record = rec
    return exc


def resolve_sha(repo: Path, ref: str) -> str:
    """Resolve ref/SHA ke SHA commit penuh; gagal = input error."""
    r = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise InputError(f"ref tidak resolve ke commit: {ref!r} ({r.stderr.strip()[:120]})")
    return r.stdout.strip()


def _tail(text: str, limit: int = MAX_STREAM_CHARS) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[-limit:], True


def parse_cases(stdout: str) -> tuple[list[dict], bool, list[str]]:
    """Parse baris PATCH_CASE + marker PATCH_REACHED dari satu lengan.

    Return (cases, reached, problems); cases = [{id, role, pass, line}].
    """
    problems: list[str] = []
    cases: list[dict] = []
    lines = stdout.splitlines()
    nonempty = [ln for ln in lines if ln.strip()]
    reached = bool(nonempty) and nonempty[-1].strip() == REACHED_MARKER
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith(CASE_PREFIX):
            continue
        raw = s[len(CASE_PREFIX):]
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            problems.append(f"PATCH_CASE baris {i + 1}: bukan JSON valid")
            continue
        if not isinstance(obj, dict):
            problems.append(f"PATCH_CASE baris {i + 1}: bukan objek")
            continue
        cid, role, passed = obj.get("id"), obj.get("role"), obj.get("pass")
        if not isinstance(cid, str) or not cid:
            problems.append(f"PATCH_CASE baris {i + 1}: field id wajib string non-kosong")
            continue
        if role not in ROLES:
            problems.append(f"PATCH_CASE baris {i + 1}: role tidak dikenal: {role!r}")
            continue
        if not isinstance(passed, bool):
            problems.append(f"PATCH_CASE baris {i + 1}: field pass wajib bool")
            continue
        if len(cases) >= MAX_CASES:
            problems.append(f"jumlah PATCH_CASE melebihi batas {MAX_CASES}")
            break
        cases.append({"id": cid, "role": role, "pass": passed, "line": i + 1})
    return cases, reached, problems


def run_arm(repo: Path, sha: str, harness: Path, work_root: Path,
            timeout_sec: float) -> dict:
    """Eksekusi satu lengan: worktree bersih pada `sha`, jalankan harness.

    Worktree selalu dibersihkan (finally). Kegagalan operasional -> Inconclusive.
    """
    arm_dir = work_root / f"arm-{sha[:12]}"
    rec: dict = {"sha": sha, "worktree": None, "command": None, "exit": None,
                 "duration_sec": None, "stdout_tail": "", "stderr_tail": "",
                 "stdout_truncated": False, "stderr_truncated": False,
                 "timeout": False}
    added = False
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach",
             str(arm_dir), sha],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise Inconclusive(
                f"worktree add gagal untuk {sha[:12]}: {r.stderr.strip()[:200]}")
        added = True
        rec["worktree"] = str(arm_dir)
        cmd = [sys.executable, str(harness)]
        rec["command"] = cmd
        start = time.monotonic()
        try:
            run = subprocess.run(cmd, cwd=str(arm_dir), capture_output=True,
                                 text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired as e:
            rec["timeout"] = True
            rec["duration_sec"] = round(time.monotonic() - start, 3)
            out = (e.stdout or "")
            err = (e.stderr or "")
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            rec["stdout_tail"], rec["stdout_truncated"] = _tail(out)
            rec["stderr_tail"], rec["stderr_truncated"] = _tail(err)
            raise _bail(rec, f"harness timeout di lengan {sha[:12]} "
                             f"setelah {timeout_sec}s")
        rec["exit"] = run.returncode
        rec["duration_sec"] = round(time.monotonic() - start, 3)
        rec["stdout_tail"], rec["stdout_truncated"] = _tail(run.stdout)
        rec["stderr_tail"], rec["stderr_truncated"] = _tail(run.stderr)
        cases, reached, problems = parse_cases(run.stdout)
        rec["cases"] = cases
        rec["patch_reached"] = reached
        rec["parse_problems"] = problems
        if not reached:
            raise _bail(rec, f"marker {REACHED_MARKER} tidak ada sebagai baris "
                             f"terakhir di lengan {sha[:12]} — harness mati "
                             "sebelum titik vonis")
        if problems:
            raise _bail(rec, f"kontrak harness dilanggar di lengan {sha[:12]}: "
                             f"{problems[0]}"
                             + (f" (+{len(problems) - 1} lain)" if len(problems) > 1
                                else ""))
        return rec
    finally:
        if added:
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "remove", "--force",
                 str(arm_dir)], capture_output=True, text=True, timeout=60)
            subprocess.run(["git", "-C", str(repo), "worktree", "prune"],
                           capture_output=True, text=True, timeout=60)


def _case_keys(cases: list[dict]) -> list[tuple[str, str]]:
    return sorted((c["id"], c["role"]) for c in cases)


def decide(base: dict, patched: dict) -> tuple[str, list[str]]:
    """Tangga putusan fail-closed (lihat docstring) -> (verdict, reasons)."""
    reasons: list[str] = []
    bcases, pcases = base["cases"], patched["cases"]
    if _case_keys(bcases) != _case_keys(pcases):
        reasons.append(
            "himpunan kasus (id+role) berbeda antar lengan — harness tidak "
            f"stabil (baseline={len(bcases)}, patched={len(pcases)})")
        return "NOT_PROVED", reasons
    reps = [c for c in pcases if c["role"] == "representative"]
    ctrls = [c for c in pcases if c["role"] == "control"]
    if not reps:
        reasons.append("tidak ada kasus representative — tidak ada diferensial "
                       "yang bisa dibuktikan")
        return "NOT_PROVED", reasons
    bmap = {(c["id"], c["role"]): c["pass"] for c in bcases}
    for c in ctrls:
        if not c["pass"] or not bmap[(c["id"], c["role"])]:
            reasons.append(
                f"control {c['id']!r} gagal di "
                f"{'patched' if not c['pass'] else 'baseline'} — control wajib "
                "lulus di keduanya")
            return "NOT_PROVED", reasons
    failed_base = [c["id"] for c in reps if not bmap[(c["id"], c["role"])]]
    if len(failed_base) != len(reps):
        reasons.append(
            "representative tidak GAGAL di baseline: "
            f"{[c['id'] for c in reps if bmap[(c['id'], c['role'])]]} — bug "
            "tidak ter-reproduksi, tidak ada yang bisa dibuktikan")
        return "NOT_PROVED", reasons
    failed_patch = [c["id"] for c in reps if not c["pass"]]
    if failed_patch:
        reasons.append(
            f"representative masih GAGAL di patched: {failed_patch} — patch "
            "tidak memperbaiki")
        return "NOT_PROVED", reasons
    if patched["exit"] != 0:
        reasons.append(
            f"exit patched = {patched['exit']} (kontrak: 0 saat semua lulus)")
        return "NOT_PROVED", reasons
    if base["exit"] == 0:
        reasons.append(
            "exit baseline = 0 padahal representative gagal (kontrak: non-nol) "
            "— vonis harness tidak konsisten")
        return "NOT_PROVED", reasons
    reasons.append(
        f"{len(reps)} representative gagal di baseline dan lulus di patched; "
        f"{len(ctrls)} control lulus di keduanya; kontrak exit terpenuhi")
    return "PROVED", reasons


def run_proof(repo: Path, baseline_ref: str, patched_ref: str, harness: Path,
              timeout_sec: float) -> tuple[dict, int]:
    """Jalankan pembuktian penuh -> (proof dict, exit code)."""
    if not repo.is_dir():
        raise InputError(f"repo tidak ada: {repo}")
    if not (repo / ".git").exists():
        raise InputError(f"bukan repositori git: {repo}")
    if not harness.is_file():
        raise InputError(f"harness tidak ada: {harness}")
    harness = harness.resolve()
    base_sha = resolve_sha(repo, baseline_ref)
    patch_sha = resolve_sha(repo, patched_ref)
    if base_sha == patch_sha:
        raise InputError(
            f"baseline == patched ({base_sha[:12]}) — tidak ada diferensial "
            "yang bisa dibuktikan")
    work_root = Path(tempfile.mkdtemp(prefix="patch-proof-"))
    base: dict | None = None
    patched: dict | None = None
    try:
        base = run_arm(repo, base_sha, harness, work_root, timeout_sec)
        patched = run_arm(repo, patch_sha, harness, work_root, timeout_sec)
    except Inconclusive as e:
        # fail-closed: kegagalan operasional TETAP menghasilkan bukti
        # (receipt lengan yang sudah jalan/parsial), verdict INCONCLUSIVE.
        failed_arm = getattr(e, "record", None)
        if base is None:
            base = failed_arm
        else:
            patched = failed_arm
        proof = {"schema": SCHEMA, "verdict": "INCONCLUSIVE",
                 "reasons": [str(e)], "repo": str(repo),
                 "harness": str(harness), "baseline": base,
                 "patched": patched, "timeout_sec": timeout_sec}
        return proof, EXIT_INCONCLUSIVE
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    verdict, reasons = decide(base, patched)
    proof = {"schema": SCHEMA, "verdict": verdict, "reasons": reasons,
             "repo": str(repo), "harness": str(harness),
             "baseline": base, "patched": patched,
             "timeout_sec": timeout_sec}
    exits = {"PROVED": EXIT_PROVED, "NOT_PROVED": EXIT_NOT_PROVED,
             "INCONCLUSIVE": EXIT_INCONCLUSIVE}
    return proof, exits[verdict]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="patch_proof — pembuktian tiga-lengan perbaikan bug "
                    "(baseline GAGAL / patched LULUS / control LULUS keduanya)")
    ap.add_argument("--repo", required=True, help="path repositori git target")
    ap.add_argument("--baseline", required=True, help="SHA/ref baseline (S0)")
    ap.add_argument("--patched", required=True, help="SHA/ref patched (S1)")
    ap.add_argument("--harness", required=True,
                    help="file harness Python (kontrak PATCH_CASE/PATCH_REACHED)")
    ap.add_argument("--out", default=None, help="tulis bukti JSON ke file ini")
    ap.add_argument("--timeout-sec", type=float, default=DEFAULT_TIMEOUT_SEC,
                    help=f"timeout per lengan (default {DEFAULT_TIMEOUT_SEC})")
    args = ap.parse_args(argv)
    try:
        proof, code = run_proof(Path(args.repo), args.baseline, args.patched,
                                Path(args.harness), args.timeout_sec)
    except InputError as e:
        print(f"[INPUT-ERROR] {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except Inconclusive as e:
        print(f"[INCONCLUSIVE] {e}", file=sys.stderr)
        return EXIT_INCONCLUSIVE
    payload = json.dumps(proof, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    tag = {"PROVED": "L3", "NOT_PROVED": "L1"}.get(proof["verdict"], "L0")
    print(f"patch_proof: {proof['verdict']} ({tag}) — {proof['reasons'][-1]}",
          file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
