"""test_nosql_injection_analyzer — nol jaringan, fixture runtime. Mencakup:
bypass differential->L2, operator->L1, bersih->L0 (anti-FP), FP guard ("$5"),
validasi kontrak, CLI exit-code, determinisme.
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

import nosql_injection_analyzer as N  # noqa: E402
from findings import validate_finding  # noqa: E402

OP = "$" + "ne"  # hindari literal operator mentah


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_bypass_differential_is_L2():
    recs = [{"method": "POST", "path": "/login",
             "body": json.dumps({"username": "admin", "password": {OP: None}}),
             "status": 200, "control_status": 401}]
    r = N.analyze(recs)
    f = [x for x in r["findings"] if x.get("kind") == "nosqli"][0]
    assert f["verdict"] == 2 and f["status"] == "confirmed"
    assert f["cwe"] == "CWE-943" and "BYPASS" in (f["poc"] or "")
    assert _valid(r)


def test_operator_present_is_L1():
    recs = [{"method": "POST", "path": "/login",
             "body": json.dumps({"username": "admin", "password": {OP: None}}),
             "status": 200}]
    r = N.analyze(recs)
    f = [x for x in r["findings"] if x.get("kind") == "nosqli"][0]
    assert f["verdict"] == 1 and f["status"] == "unconfirmed"
    assert f["lab_only"] is True
    assert _valid(r)


def test_bracket_param_name_detected():
    recs = [{"method": "GET", "path": "/search",
             "params": {"user[" + OP + "]": ""}, "status": 200}]
    r = N.analyze(recs)
    assert any(x.get("kind") == "nosqli" for x in r["findings"])
    assert _valid(r)


def test_clean_request_is_L0_no_false_positive():
    recs = [{"method": "GET", "path": "/search",
             "params": {"q": "hello world", "price": "$5 off"},
             "body": json.dumps({"user": "bob", "note": "cost is $5"}),
             "status": 200}]
    r = N.analyze(recs)
    assert len(r["findings"]) == 1
    assert r["findings"][0]["verdict"] == 0 and r["findings"][0]["severity"] == "info"
    assert _valid(r)


def test_deterministic():
    recs = [{"method": "POST", "path": "/login",
             "body": json.dumps({"password": {OP: None}}), "status": 200}]
    a = json.dumps(N.analyze(recs), sort_keys=True)
    b = json.dumps(N.analyze(recs), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "nosql_injection_analyzer.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_missing_file_exit2(tmp_path):
    assert _cli(tmp_path, "--captures", str(tmp_path / "no.json")).returncode == 2


def test_cli_out_contract_and_failon(tmp_path):
    cap = tmp_path / "c.jsonl"
    cap.write_text(json.dumps({"method": "POST", "path": "/login",
                   "body": json.dumps({"password": {OP: None}}),
                   "status": 200, "control_status": 401}), encoding="utf-8")
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--captures", str(cap), "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True and doc["requests"] == 0
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
