"""test_bola_bfla_prover — BOLA/BFLA authz prover, nol jaringan. Fixtures
dibangun runtime. Mencakup: BOLA proven->L2, BOLA lead->L1, BOLA enforced->L0
(kontrol anti-FP), BFLA proven->L2, BFLA enforced->L0, <2 peran fail-closed,
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

import bola_bfla_prover as B  # noqa: E402
from findings import validate_finding  # noqa: E402

VMARK = "victim-" + "unique-" + "data-7731"
AMARK = "admin-" + "panel-" + "token-9920"


def _all_valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_bola_proven_is_L2():
    recs = [
        {"role": "victim", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": "{...%s...}" % VMARK},
        {"role": "attacker", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": "{...%s...}" % VMARK},
    ]
    r = B.analyze(recs, owners={"1001": "victim"}, markers={"victim": VMARK})
    brk = [f for f in r["findings"] if f.get("kind") == "bola"]
    assert len(brk) == 1
    f = brk[0]
    assert f["verdict"] == 2 and f["status"] == "confirmed"
    assert f["verdict_tag"].startswith("L2")
    assert f["cwe"] == "CWE-639"
    assert "PROVEN" in (f["poc"] or "")
    assert _all_valid(r)


def test_bola_lead_without_marker_is_L1():
    recs = [
        {"role": "victim", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001"},
        {"role": "attacker", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": "{}"},
    ]
    r = B.analyze(recs, owners={"1001": "victim"})  # no markers
    f = [x for x in r["findings"] if x.get("kind") == "bola"][0]
    assert f["verdict"] == 1 and f["status"] == "unconfirmed"
    assert "LEAD" in (f["poc"] or "")
    assert _all_valid(r)


def test_bola_enforced_403_is_L0_no_false_positive():
    recs = [
        {"role": "victim", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": VMARK},
        {"role": "attacker", "method": "GET", "path": "/api/orders/1001",
         "status": 403, "obj_id": "1001", "body": "forbidden"},
    ]
    r = B.analyze(recs, owners={"1001": "victim"}, markers={"victim": VMARK})
    assert not [f for f in r["findings"] if f.get("kind") in ("bola", "bfla")]
    summ = r["findings"][0]
    assert summ["verdict"] == 0 and summ["severity"] == "info"
    assert r["stats"]["bola_denied"] == 1
    assert _all_valid(r)


def test_bfla_proven_is_L2():
    recs = [
        {"role": "admin", "method": "GET", "path": "/admin/users",
         "status": 200, "body": AMARK},
        {"role": "user", "method": "GET", "path": "/admin/users",
         "status": 200, "body": "list...%s..." % AMARK},
    ]
    r = B.analyze(recs, privileged=["/admin"], admin_roles=["admin"],
                  markers={"admin": AMARK})
    f = [x for x in r["findings"] if x.get("kind") == "bfla"][0]
    assert f["verdict"] == 2 and f["cwe"] == "CWE-862"
    assert _all_valid(r)


def test_bfla_enforced_is_L0():
    recs = [
        {"role": "admin", "method": "GET", "path": "/admin/users", "status": 200},
        {"role": "user", "method": "GET", "path": "/admin/users", "status": 403},
    ]
    r = B.analyze(recs, privileged=["/admin"], admin_roles=["admin"])
    assert not [f for f in r["findings"] if f.get("kind") == "bfla"]
    assert r["stats"]["bfla_denied"] == 1
    assert _all_valid(r)


def test_requires_two_roles_fail_closed():
    import pytest
    recs = [{"role": "solo", "method": "GET", "path": "/x", "status": 200}]
    with pytest.raises(ValueError):
        B.analyze(recs)


def test_always_at_least_one_finding():
    recs = [{"role": "a", "method": "GET", "path": "/x", "status": 200},
            {"role": "b", "method": "GET", "path": "/y", "status": 200}]
    r = B.analyze(recs)  # no owners/privileged -> L0 summary
    assert len(r["findings"]) == 1 and r["findings"][0]["verdict"] == 0
    assert _all_valid(r)


def test_deterministic():
    recs = [
        {"role": "victim", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": VMARK},
        {"role": "attacker", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": VMARK},
    ]
    a = json.dumps(B.analyze(recs, owners={"1001": "victim"},
                             markers={"victim": VMARK}), sort_keys=True)
    b = json.dumps(B.analyze(recs, owners={"1001": "victim"},
                             markers={"victim": VMARK}), sort_keys=True)
    assert a == b


# --------------------------------------------------------------- CLI
def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "bola_bfla_prover.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def _wr(tmp, name, obj):
    p = tmp / name
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")
    return p


def test_cli_missing_captures_exit2(tmp_path):
    assert _cli(tmp_path, "--captures", str(tmp_path / "no.json")).returncode == 2


def test_cli_jsonl_out_contract_and_failon(tmp_path):
    jsonl = "\n".join(json.dumps(x) for x in [
        {"role": "victim", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": VMARK},
        {"role": "attacker", "method": "GET", "path": "/api/orders/1001",
         "status": 200, "obj_id": "1001", "body": VMARK},
    ])
    cap = _wr(tmp_path, "cap.jsonl", jsonl)
    owners = _wr(tmp_path, "owners.json", {"1001": "victim"})
    markers = _wr(tmp_path, "markers.json", {"victim": VMARK})
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--captures", str(cap), "--owners", str(owners),
             "--markers", str(markers), "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True and doc["requests"] == 0
    for fd in doc["findings"]:
        assert validate_finding(fd) == []


def test_cli_single_role_exit2(tmp_path):
    cap = _wr(tmp_path, "cap.json", [{"role": "solo", "method": "GET",
                                      "path": "/x", "status": 200}])
    assert _cli(tmp_path, "--captures", str(cap)).returncode == 2
