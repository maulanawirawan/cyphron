"""test_attack_navigator_export — nol jaringan. techniques->layer+L0,
coverage dict, tid tak valid->fail-closed, validasi, CLI tulis layer.
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

import attack_navigator_export as X  # noqa: E402
from findings import validate_finding  # noqa: E402


def test_parse_and_export_layer_L0():
    techs = X._parse_techniques("T1059:100,T1071:30,T1566")
    r = X.analyze(techs, "test")
    assert len(r["layer"]["techniques"]) == 3
    for t in r["layer"]["techniques"]:
        assert t["techniqueID"].startswith("T") and "color" in t and "score" in t
    assert r["findings"][0]["verdict"] == 0
    assert validate_finding(r["findings"][0]) == []


def test_color_by_score():
    techs = X._parse_techniques("T1059:100,T1071:50,T1566:0")
    by = {t["techniqueID"]: t["color"] for t in X.build_layer(techs, "x")["techniques"]}
    assert by["T1059"] != by["T1566"]            # covered vs gap beda warna


def test_coverage_states():
    cov = {"techniques": [{"id": "T1059", "state": "covered"},
                          {"id": "T1071", "state": "gap"}]}
    techs = X._from_coverage(cov)
    scores = {t["techniqueID"]: t["score"] for t in techs}
    assert scores["T1059"] == 100 and scores["T1071"] == 0


def test_invalid_tid_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        X._parse_techniques("NOTATECH")


def test_deterministic():
    techs = X._parse_techniques("T1071,T1059")
    a = json.dumps(X.analyze(techs, "x"), sort_keys=True)
    b = json.dumps(X.analyze(techs, "x"), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "attack_navigator_export.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_no_input_exit2(tmp_path):
    assert _cli(tmp_path).returncode == 2


def test_cli_writes_layer_and_contract(tmp_path):
    layer = tmp_path / "layer.json"
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--techniques", "T1059:100,T1071", "--out-layer",
             str(layer), "--out", str(out))
    assert p.returncode == 0
    lj = json.loads(layer.read_text(encoding="utf-8"))
    assert lj["domain"] == "enterprise-attack" and len(lj["techniques"]) == 2
    doc = json.loads(out.read_text(encoding="utf-8"))
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
