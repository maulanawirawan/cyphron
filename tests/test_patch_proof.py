"""Test patch_proof — pembuktian tiga-lengan perbaikan bug.

NOL jaringan: semua skenario memakai repositori git lokal sementara
(tmp_path) dan harness Python sintetis yang mematuhi/melanggar kontrak
PATCH_CASE/PATCH_REACHED sesuai kebutuhan kasus.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import patch_proof as pp  # noqa: E402

BUGGY = "def clamp(x):\n    return x\n"
FIXED = "def clamp(x):\n    return max(0, min(x, 10))\n"

# Harness standar: representative = clamp benar, control selalu lulus.
HARNESS_OK = """\
import json, sys
sys.path.insert(0, ".")
from calc import clamp

def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))

try:
    ok = (clamp(-5) == 0 and clamp(42) == 10 and clamp(5) == 5)
except Exception:
    ok = False
emit("rep-clamp", "representative", ok)
emit("ctl-pass", "control", True)
print("PATCH_REACHED")
sys.exit(0 if ok else 1)
"""


def _git(*args: str, cwd: Path) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), check=True,
                       capture_output=True, text=True)
    return r.stdout.strip()


def make_repo(tmp_path: Path, buggy: str = BUGGY, fixed: str = FIXED,
              name: str = "tgt") -> tuple[Path, str, str]:
    """Repo git dua commit: baseline (buggy) -> patched (fixed)."""
    repo = tmp_path / name
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@example.test", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / "calc.py").write_text(buggy, encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "baseline", cwd=repo)
    base = _git("rev-parse", "HEAD", cwd=repo)
    (repo / "calc.py").write_text(fixed, encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix", cwd=repo)
    patched = _git("rev-parse", "HEAD", cwd=repo)
    return repo, base, patched


def write_harness(tmp_path: Path, body: str = HARNESS_OK,
                  name: str = "harness.py") -> Path:
    h = tmp_path / name
    h.write_text(body, encoding="utf-8")
    return h


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOLS / "patch_proof.py"), *args],
        capture_output=True, text=True, timeout=120)


# ---------------------------------------------------------------- PROVED

def test_proved_full_protocol(tmp_path):
    repo, base, patched = make_repo(tmp_path)
    harness = write_harness(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, timeout_sec=60)
    assert code == pp.EXIT_PROVED
    assert proof["verdict"] == "PROVED"
    roles = {(c["id"], c["role"]) for c in proof["patched"]["cases"]}
    assert ("rep-clamp", "representative") in roles
    assert proof["baseline"]["patch_reached"] and proof["patched"]["patch_reached"]
    # worktree dibersihkan — tidak ada sisa worktree di repo target
    out = subprocess.run(["git", "-C", str(repo), "worktree", "list"],
                         capture_output=True, text=True).stdout
    assert len([ln for ln in out.splitlines() if ln.strip()]) == 1


def test_proved_via_cli_exit0_and_out_file(tmp_path):
    repo, base, patched = make_repo(tmp_path)
    harness = write_harness(tmp_path)
    out_file = tmp_path / "proof.json"
    r = run_cli("--repo", str(repo), "--baseline", base, "--patched", patched,
                "--harness", str(harness), "--out", str(out_file))
    assert r.returncode == pp.EXIT_PROVED
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["schema"] == "cyphron.patch-proof/1"
    assert saved["verdict"] == "PROVED"


# ------------------------------------------------------------ NOT_PROVED

def test_not_proved_rep_passes_on_baseline(tmp_path):
    # representative dianggap lulus di mana pun -> bug tak ter-reproduksi
    harness = write_harness(tmp_path, """\
import json, sys
def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))
emit("rep-x", "representative", True)
emit("ctl", "control", True)
print("PATCH_REACHED")
sys.exit(0)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "tidak GAGAL di baseline" in " ".join(proof["reasons"])


def test_not_proved_rep_still_fails_on_patched(tmp_path):
    # bug tidak pernah diperbaiki: representative gagal di kedua lengan
    harness = write_harness(tmp_path, """\
import json, sys
def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))
emit("rep-x", "representative", False)
emit("ctl", "control", True)
print("PATCH_REACHED")
sys.exit(1)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "masih GAGAL di patched" in " ".join(proof["reasons"])


def test_not_proved_control_fails_on_baseline(tmp_path):
    # representative diferensial benar, tapi control gagal di baseline
    harness = write_harness(tmp_path, """\
import json, sys
sys.path.insert(0, ".")
from calc import clamp
def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))
emit("rep", "representative", clamp(-5) == 0)
emit("ctl", "control", False)
print("PATCH_REACHED")
sys.exit(0 if clamp(-5) == 0 else 1)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "control" in " ".join(proof["reasons"])


def test_not_proved_no_representative(tmp_path):
    harness = write_harness(tmp_path, """\
import json, sys
print("PATCH_CASE " + json.dumps({"id": "ctl", "role": "control", "pass": True}))
print("PATCH_REACHED")
sys.exit(0)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "representative" in " ".join(proof["reasons"])


def test_not_proved_case_set_mismatch(tmp_path):
    # harness menambah satu kasus hanya saat file extra.py ada (baseline saja)
    harness = write_harness(tmp_path, """\
import json, os, sys
sys.path.insert(0, ".")
from calc import clamp
def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))
ok = clamp(-5) == 0
emit("rep", "representative", ok)
if os.path.exists("extra.py"):
    emit("rep-extra", "representative", ok)
emit("ctl", "control", True)
print("PATCH_REACHED")
sys.exit(0 if ok else 1)
""")
    repo, base, patched = make_repo(tmp_path)
    (repo / "extra.py").write_text("# marker\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "extra", cwd=repo)
    new_base = _git("rev-parse", "HEAD", cwd=repo)
    proof, code = pp.run_proof(repo, new_base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "berbeda antar lengan" in " ".join(proof["reasons"])


def test_not_proved_exit_contract_violation(tmp_path):
    # baseline: representative gagal tapi harness exit 0 — vonis tak konsisten
    harness = write_harness(tmp_path, """\
import json, sys
sys.path.insert(0, ".")
from calc import clamp
def emit(cid, role, ok):
    print("PATCH_CASE " + json.dumps({"id": cid, "role": role, "pass": bool(ok)}))
emit("rep", "representative", clamp(-5) == 0)
emit("ctl", "control", True)
print("PATCH_REACHED")
sys.exit(0)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_NOT_PROVED
    assert "exit baseline = 0" in " ".join(proof["reasons"])


# --------------------------------------------------------- INCONCLUSIVE

def test_inconclusive_missing_marker(tmp_path):
    harness = write_harness(tmp_path, """\
import json, sys
print("PATCH_CASE " + json.dumps({"id": "rep", "role": "representative", "pass": True}))
sys.exit(0)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_INCONCLUSIVE
    assert "PATCH_REACHED" in " ".join(proof["reasons"])


def test_inconclusive_malformed_case(tmp_path):
    harness = write_harness(tmp_path, """\
print("PATCH_CASE bukan-json")
print("PATCH_REACHED")
sys.exit(0)
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, 60)
    assert code == pp.EXIT_INCONCLUSIVE
    assert "kontrak harness dilanggar" in " ".join(proof["reasons"])


def test_inconclusive_timeout(tmp_path):
    harness = write_harness(tmp_path, """\
import time
time.sleep(30)
print("PATCH_REACHED")
""")
    repo, base, patched = make_repo(tmp_path)
    proof, code = pp.run_proof(repo, base, patched, harness, timeout_sec=1.0)
    assert code == pp.EXIT_INCONCLUSIVE
    assert proof["baseline"]["timeout"] is True


# ------------------------------------------------------------ parse_cases

def test_parse_cases_ok_and_reached():
    cases, reached, problems = pp.parse_cases(
        'PATCH_CASE {"id": "a", "role": "control", "pass": true}\n'
        "PATCH_REACHED\n")
    assert not problems and reached
    assert cases == [{"id": "a", "role": "control", "pass": True, "line": 1}]


def test_parse_cases_role_and_pass_rejected():
    _, reached, problems = pp.parse_cases(
        'PATCH_CASE {"id": "a", "role": "juri", "pass": true}\n'
        'PATCH_CASE {"id": "b", "role": "control", "pass": "yes"}\n'
        "PATCH_REACHED\n")
    assert reached and len(problems) == 2


# ------------------------------------------------------------ input error

def test_input_error_same_sha(tmp_path):
    repo, base, patched = make_repo(tmp_path)
    harness = write_harness(tmp_path)
    with pytest.raises(pp.InputError, match="tidak ada diferensial"):
        pp.run_proof(repo, base, base, harness, 60)


def test_input_error_not_a_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    harness = write_harness(tmp_path)
    with pytest.raises(pp.InputError, match="bukan repositori git"):
        pp.run_proof(plain, "HEAD", "HEAD~1", harness, 60)


def test_input_error_bad_ref(tmp_path):
    repo, base, patched = make_repo(tmp_path)
    harness = write_harness(tmp_path)
    with pytest.raises(pp.InputError, match="tidak resolve"):
        pp.run_proof(repo, "bukan-sha-valid", patched, harness, 60)


def test_input_error_missing_harness(tmp_path):
    repo, base, patched = make_repo(tmp_path)
    with pytest.raises(pp.InputError, match="harness tidak ada"):
        pp.run_proof(repo, base, patched, tmp_path / "hilang.py", 60)
