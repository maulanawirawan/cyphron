"""test_cors_poc_gen — nol jaringan. reflection+creds->L1, wildcard+creds->L0,
locked origin->L0 (anti-FP), reflection no-creds->L1 low, validasi, CLI, determinisme.
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

import cors_poc_gen as C  # noqa: E402
from findings import validate_finding  # noqa: E402

ATT = "https://attacker.example"


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_reflection_plus_credentials_is_L1_with_poc():
    r = C.analyze("https://api.target.tld/me", ATT, True, ATT)
    f = r["findings"][0]
    assert f["verdict"] == 1 and f["severity"] == "high"
    assert f["lab_only"] is True and f["cwe"] == "CWE-942"
    assert "credentials" in (f["poc"] or "") and "include" in (f["poc"] or "")
    assert _valid(r)


def test_wildcard_plus_credentials_is_L0_not_exploitable():
    r = C.analyze("https://api.target.tld/me", "*", True, ATT)
    f = r["findings"][0]
    assert f["verdict"] == 0 and f["severity"] == "info"
    assert "not exploitable" in f["title"].lower()
    assert _valid(r)


def test_locked_origin_is_L0_no_false_positive():
    r = C.analyze("https://api.target.tld/me", "https://trusted.example", True, ATT)
    f = r["findings"][0]
    assert f["verdict"] == 0 and f["severity"] == "info"
    assert _valid(r)


def test_reflection_no_credentials_is_low_L1():
    r = C.analyze("https://api.target.tld/me", ATT, False, ATT)
    f = r["findings"][0]
    assert f["verdict"] == 1 and f["severity"] == "low"
    assert "omit" in (f["poc"] or "")
    assert _valid(r)


def test_deterministic():
    a = json.dumps(C.analyze("https://x/y", ATT, True, ATT), sort_keys=True)
    b = json.dumps(C.analyze("https://x/y", ATT, True, ATT), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "cors_poc_gen.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_missing_args_exit2(tmp_path):
    assert _cli(tmp_path, "--url", "https://x/y").returncode == 2  # --acao wajib


def test_cli_out_contract_failon(tmp_path):
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--url", "https://api.t/me", "--acao", ATT, "--acac",
             "--origin", ATT, "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
