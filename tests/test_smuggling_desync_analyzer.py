"""test_smuggling_desync_analyzer — nol jaringan. CL+TE->L1, dup CL->L1,
front/back divergence->L2, bersih->L0 (anti-FP), validasi, CLI, determinisme.
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

import smuggling_desync_analyzer as S  # noqa: E402
from findings import validate_finding  # noqa: E402

CL_TE = ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n"
         "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
DUP_CL = ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n"
          "Content-Length: 5\r\n\r\nhello")
CLEAN = "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_cl_and_te_is_L1():
    r = S.analyze(CL_TE)
    f = [x for x in r["findings"] if x.get("kind") == "smuggle"][0]
    assert f["verdict"] == 1 and f["cwe"] == "CWE-444"
    assert f["lab_only"] is True
    assert _valid(r)


def test_duplicate_cl_is_L1():
    r = S.analyze(DUP_CL)
    assert any(x.get("variant") == "CL.CL" for x in r["findings"])
    assert _valid(r)


def test_front_back_divergence_is_L2():
    front = "POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\nabcdef"
    back = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde"
    r = S.analyze(CL_TE, front, back)
    div = [x for x in r["findings"] if x.get("variant") == "divergence"][0]
    assert div["verdict"] == 2 and div["status"] == "confirmed"
    assert _valid(r)


def test_clean_request_is_L0_no_false_positive():
    r = S.analyze(CLEAN)
    assert len(r["findings"]) == 1
    assert r["findings"][0]["verdict"] == 0 and r["findings"][0]["severity"] == "info"
    assert _valid(r)


def test_deterministic():
    a = json.dumps(S.analyze(CL_TE), sort_keys=True)
    b = json.dumps(S.analyze(CL_TE), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "smuggling_desync_analyzer.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_no_input_exit2(tmp_path):
    assert _cli(tmp_path).returncode == 2


def test_cli_out_contract_failon(tmp_path):
    req = tmp_path / "r.txt"; req.write_bytes(CL_TE.encode("utf-8"))
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--request", str(req), "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
