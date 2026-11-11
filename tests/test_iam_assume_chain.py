"""test_iam_assume_chain — nol jaringan. jalur 2-hop ke admin->L2, tanpa jalur
->L0 (anti-FP), validasi, CLI, determinisme.
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

import iam_assume_chain as I  # noqa: E402
from findings import validate_finding  # noqa: E402

ACCT = "111111111111"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _arn(t, n):
    return "arn:aws:iam::%s:%s/%s" % (ACCT, t, n)


def _assume(resource):
    return {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                           "Resource": resource}]}


def _trust(who):
    return {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                           "Principal": {"AWS": who}}]}


def _chain_auth():
    alice, r1, r2 = _arn("user", "alice"), _arn("role", "R1"), _arn("role", "R2")
    return {
        "UserDetailList": [{"UserName": "alice", "Arn": alice,
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": _assume(r1)}]}],
        "RoleDetailList": [
            {"RoleName": "R1", "Arn": r1,
             "AssumeRolePolicyDocument": _trust(alice),
             "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": _assume(r2)}]},
            {"RoleName": "R2", "Arn": r2,
             "AssumeRolePolicyDocument": _trust(r1),
             "AttachedManagedPolicies": [{"PolicyArn": ADMIN}]},
        ],
        "Policies": [],
    }


def test_two_hop_path_to_admin_is_L2():
    r = I.analyze(_chain_auth())
    chain = [f for f in r["findings"] if f.get("kind") == "iam-chain"]
    assert len(chain) == 1
    f = chain[0]
    assert f["verdict"] == 2 and f["cwe"] == "CWE-269"
    assert f["extra_hops"] == 2 if "extra_hops" in f else f["hops"] == 2
    assert "alice -> R1 -> R2" in (f["poc"] or "")
    assert validate_finding(f) == []


def test_no_path_is_L0_no_false_positive():
    alice, r1 = _arn("user", "alice"), _arn("role", "R1")
    auth = {
        "UserDetailList": [{"UserName": "alice", "Arn": alice,
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": _assume(r1)}]}],
        "RoleDetailList": [{"RoleName": "R1", "Arn": r1,
            "AssumeRolePolicyDocument": _trust(alice)}],  # R1 not admin, no further
        "Policies": [],
    }
    r = I.analyze(auth)
    assert not [f for f in r["findings"] if f.get("kind") == "iam-chain"]
    assert r["findings"][0]["verdict"] == 0
    assert validate_finding(r["findings"][0]) == []


def test_trust_required_no_edge_without_trust():
    # alice policy allows assuming R1, tapi trust R1 TIDAK mengizinkan alice
    alice, r1, r2 = _arn("user", "alice"), _arn("role", "R1"), _arn("role", "R2")
    auth = {
        "UserDetailList": [{"UserName": "alice", "Arn": alice,
            "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": _assume(r1)}]}],
        "RoleDetailList": [
            {"RoleName": "R1", "Arn": r1,
             "AssumeRolePolicyDocument": _trust(_arn("role", "someoneelse")),
             "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": _assume(r2)}]},
            {"RoleName": "R2", "Arn": r2, "AssumeRolePolicyDocument": _trust(r1),
             "AttachedManagedPolicies": [{"PolicyArn": ADMIN}]},
        ], "Policies": [],
    }
    r = I.analyze(auth)
    assert not [f for f in r["findings"] if f.get("kind") == "iam-chain"]


def test_deterministic():
    a = json.dumps(I.analyze(_chain_auth()), sort_keys=True)
    b = json.dumps(I.analyze(_chain_auth()), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "iam_assume_chain.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_missing_file_exit2(tmp_path):
    assert _cli(tmp_path, "--auth", str(tmp_path / "no.json")).returncode == 2


def test_cli_out_contract_failon(tmp_path):
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps(_chain_auth()), encoding="utf-8")
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--auth", str(auth), "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
