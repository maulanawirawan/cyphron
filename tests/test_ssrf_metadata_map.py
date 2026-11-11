"""test_ssrf_metadata_map — nol jaringan. aws+plain-get->L1(+unreachable L0),
gcp+plain-get->gated L0 (butuh header), gcp+header-control->L1, provider tak
dikenal->fail-closed, validasi, CLI, determinisme.
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

import ssrf_metadata_map as M  # noqa: E402
from findings import validate_finding  # noqa: E402


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_aws_plain_get_reaches_imdsv1_L1():
    r = M.analyze(["aws"], "plain-get")
    reach = [f for f in r["findings"] if f.get("kind") == "ssrf"]
    assert any("imdsv1" in f["param"] for f in reach)
    assert all(f["verdict"] == 1 and f["lab_only"] for f in reach)
    # imdsv2 (needs PUT+header) harus masuk unreachable (L0), bukan L1
    assert any(f["verdict"] == 0 and "imdsv2" in f["description"]
               for f in r["findings"])
    assert _valid(r)


def test_gcp_plain_get_is_gated_L0_no_false_positive():
    r = M.analyze(["gcp"], "plain-get")
    assert not [f for f in r["findings"] if f.get("kind") == "ssrf"]
    assert any(f["verdict"] == 0 for f in r["findings"])
    assert _valid(r)


def test_gcp_header_control_reaches_L1():
    r = M.analyze(["gcp"], "header-control")
    reach = [f for f in r["findings"] if f.get("kind") == "ssrf"]
    assert len(reach) == 1 and reach[0]["verdict"] == 1
    assert "Metadata-Flavor: Google" in (reach[0]["poc"] or "")
    assert _valid(r)


def test_unknown_provider_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        M.analyze(["notaprovider"], "plain-get")


def test_bad_capability_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        M.analyze(["aws"], "exec-anything")


def test_deterministic():
    a = json.dumps(M.analyze(["all"], "header-control"), sort_keys=True)
    b = json.dumps(M.analyze(["all"], "header-control"), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "ssrf_metadata_map.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_no_provider_exit2(tmp_path):
    assert _cli(tmp_path, "--capability", "plain-get").returncode == 2


def test_cli_out_contract_failon(tmp_path):
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--provider", "aws", "--capability", "plain-get",
             "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
