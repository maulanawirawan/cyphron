"""test_detection_rule_gen — nol jaringan. gen Sigma+YARA dari temuan -> L0,
string YARA >=4 byte, validasi kontrak, CLI.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(CORE))

import detection_rule_gen as D  # noqa: E402
from findings import make_finding, validate_finding  # noqa: E402


def _finding():
    return make_finding(
        tool="jwt-crypto-attack", title="JWT HS256 signed with a weak secret",
        description="weak HMAC secret recovered offline", severity="high",
        cwe="CWE-321", status="confirmed", verdict=3,
        evidence_kind="arithmetic", poc="proof", param="abc123fp")


def test_generates_sigma_and_yara_L0():
    r = D.analyze([_finding()])
    f = r["findings"][0]
    assert f["verdict"] == 0 and f["severity"] == "info"
    assert "title:" in (f["poc"] or "") and "rule secai_" in (f["poc"] or "")
    assert validate_finding(f) == []


def test_yara_strings_are_at_least_4_bytes():
    r = D.analyze([_finding()])
    poc = r["findings"][0]["poc"]
    yara = poc.split("### YARA", 1)[1]
    strs = re.findall(r'"([^"]+)"\s+ascii', yara)
    assert strs and all(len(s) >= 4 for s in strs)


def test_empty_findings_fail_closed():
    import pytest
    with pytest.raises(ValueError):
        D.analyze([])


def test_deterministic():
    a = json.dumps(D.analyze([_finding()]), sort_keys=True)
    b = json.dumps(D.analyze([_finding()]), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "detection_rule_gen.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_out_contract(tmp_path):
    from findings import write_findings
    src = tmp_path / "src.json"
    write_findings(str(src), [_finding()], meta={"requests": 0})
    out = tmp_path / "rules.json"
    p = _cli(tmp_path, "--finding", str(src), "--out", str(out),
             "--out-dir", str(tmp_path / "rules"))
    assert p.returncode == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
    assert (tmp_path / "rules").exists()


def test_cli_missing_file_exit2(tmp_path):
    assert _cli(tmp_path, "--finding", str(tmp_path / "no.json")).returncode == 2
