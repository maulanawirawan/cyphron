"""test_gha_workflow_audit — audit OFFLINE workflow GitHub Actions utk
risiko supply chain CI/CD (#0463), nol jaringan. Fixture YAML sintetis.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import gha_workflow_audit as gha  # noqa: E402

SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def _audit(text: str) -> tuple[list[dict], list[str]]:
    return gha.audit_workflow(text, "wf.yml")


def _checks(res: tuple) -> list[str]:
    return [f["check"] for f in res[0]]


# ------------------------------------------------------- unpinned
def test_unpinned_tag():
    res = _audit(f"- uses: actions/checkout@v4\n")
    assert "unpinned-action" in _checks(res)
    f = res[0][0]
    assert f["severity"] == "medium"


def test_unpinned_branch_high():
    res = _audit("- uses: evil/action@main\n")
    assert "unpinned-action-branch" in _checks(res)
    assert res[0][0]["severity"] == "high"


def test_sha_pinned_clean():
    res = _audit(f"- uses: actions/checkout@{SHA}\n")
    assert "unpinned-action" not in _checks(res)


def test_docker_and_local_skipped():
    res = _audit("- uses: docker://alpine:3\n"
                 "- uses: ./.github/actions/local\n")
    assert res[0] == []


# ------------------------------------------------------- injection
def test_script_injection_inline():
    res = _audit("      run: echo \"PR: ${{ github.event.pull_request."
                 "title }}\"\n")
    assert "script-injection" in _checks(res)


def test_script_injection_block():
    yml = (
        "  steps:\n"
        "    - run: |\n"
        "        echo \"${{ github.head_ref }}\"\n"
        "        make build\n"
        "    - name: next\n"
        "      run: echo ok\n")
    res = _audit(yml)
    assert "script-injection" in _checks(res)


def test_env_mapping_not_flagged():
    yml = (
        "  steps:\n"
        "    - run: |\n"
        "        make build\n"
        "      env:\n"
        "        PR_TITLE: ${{ github.event.pull_request.title }}\n")
    res = _audit(yml)
    assert "script-injection" not in _checks(res)


def test_no_injection_clean():
    res = _audit("      run: make build && make test\n")
    assert res[0] == []


# ------------------------------------------------------- permissions
def test_permissions_write_all():
    res = _audit("permissions: write-all\n")
    assert "permissions-write-all" in _checks(res)
    assert res[0][0]["severity"] == "high"


def test_permissions_read_clean():
    res = _audit("permissions: read-all\njobs: {}\n")
    assert res[0] == []


# ------------------------------------------------------- pr-target
def test_pr_target_trigger():
    yml = ("on:\n  pull_request_target:\n"
           "jobs:\n  x:\n    steps:\n"
           "      - run: make test\n")
    res = _audit(yml)
    assert "pr-target-trigger" in _checks(res)


def test_pr_trigger_without_run_clean():
    yml = "on: pull_request\njobs:\n  x:\n    steps:\n      - run: make\n"
    res = _audit(yml)
    assert "pr-target-trigger" not in _checks(res)


# ------------------------------------------------------- secret
def test_secret_in_run():
    res = _audit("      run: curl -H \"Auth: ${{ secrets.TOKEN }}\" "
                 "https://x\n")
    assert "secret-in-run" in _checks(res)


# ------------------------------------------------------- fail-closed
def test_missing_dir_exit2():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gha_workflow_audit.py"),
         "--dir", "TIDAK-ADA/"],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_empty_dir_exit2(tmp_path):
    d = tmp_path / "workflows"
    d.mkdir()
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gha_workflow_audit.py"),
         "--dir", str(d)],
        capture_output=True, text=True)
    assert proc.returncode == 2 and "nol file" in proc.stderr


def test_no_args_exit2():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gha_workflow_audit.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_dir_end_to_end(tmp_path):
    d = tmp_path / "workflows"
    d.mkdir()
    (d / "good.yml").write_text(
        f"- uses: actions/checkout@{SHA}\n"
        "  - run: make build\n", encoding="utf-8")
    (d / "bad.yml").write_text(
        "- uses: evil/action@main\n"
        "permissions: write-all\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gha_workflow_audit.py"),
         "--dir", str(d)],
        capture_output=True, text=True)
    out = json.loads(proc.stdout)
    files = {f["file"].replace("\\", "/").split("/")[-1]
             for f in out["findings"]}
    assert files == {"bad.yml"}
    assert proc.returncode == 1
    assert out["stats"]["files_scanned"] == 2
