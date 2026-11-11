"""test_lfi_rce_playbook — nol jaringan. php/linux ladder->L1 lab_only tanpa
token destruktif, generic->L1, stack tak dikenal->fail-closed, validasi, CLI.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(CORE))

import lfi_rce_playbook as L  # noqa: E402
from findings import validate_finding  # noqa: E402

BAD = ("rm -", "mkfs", "dd if=", ":(){", "format c:", "del /f")


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_php_linux_ladder_is_L1_labonly():
    r = L.analyze("file", "linux", "php")
    f = r["findings"][0]
    assert f["verdict"] == 1 and f["status"] == "unconfirmed"
    assert f["lab_only"] is True and f["cwe"] == "CWE-98"
    assert "secai-lfi-poc" in (f["poc"] or "")
    assert f["extra_rungs"] if "extra_rungs" in f else f["rungs"]
    assert _valid(r)


def test_no_destructive_tokens():
    for stack in ("php", "java", "python", "node", "generic"):
        for osname in ("linux", "windows"):
            r = L.analyze("p", osname, stack)
            blob = json.dumps(r).lower()
            assert not any(b in blob for b in BAD), (stack, osname)
            assert _valid(r)


def test_generic_still_produces_read_ladder():
    r = L.analyze("page", "linux", "generic")
    assert r["findings"][0]["verdict"] == 1
    assert r["stats"]["rungs"] >= 1


def test_unknown_stack_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        L.analyze("p", "linux", "cobol")


def test_deterministic():
    a = json.dumps(L.analyze("f", "linux", "php"), sort_keys=True)
    b = json.dumps(L.analyze("f", "linux", "php"), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "lfi_rce_playbook.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_bad_stack_exit2(tmp_path):
    # argparse choices menolak -> exit 2
    assert _cli(tmp_path, "--stack", "cobol").returncode == 2


def test_cli_out_contract_failon(tmp_path):
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--param", "file", "--os", "linux", "--stack", "php",
             "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
