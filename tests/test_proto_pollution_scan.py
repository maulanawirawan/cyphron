"""test_proto_pollution_scan — static JS prototype-pollution, nol jaringan.
Mencakup: sink kuat tak-berpenjaga->L2 (+nomor baris), berpenjaga->L1,
kandidat lemah->L1 low, bersih->L0 (anti-FP), validasi kontrak, CLI exit-code.
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

import proto_pollution_scan as P  # noqa: E402
from findings import validate_finding  # noqa: E402

SINK_JS = """function setValue(obj, path, val) {
  obj.__proto__[path] = val;
  return obj;
}
"""

GUARDED_JS = """function setValue(obj, path, val) {
  if (path === "__proto__") return;
  obj.__proto__[path] = val;
  const safe = Object.create(null);
}
"""

WEAK_JS = """function apply(cfg, a, b, v) {
  cfg[a][b] = v;
  return cfg;
}
"""

CLEAN_JS = """export function add(a, b) { return a + b; }
const m = new Map(); m.set('k', 1);
"""


def _valid(r):
    return all(validate_finding(f) == [] for f in r["findings"])


def test_unguarded_sink_is_L2_with_lineno():
    r = P.scan([("set.js", SINK_JS)])
    f = [x for x in r["findings"] if x.get("kind") == "proto"][0]
    assert f["verdict"] == 2 and f["status"] == "confirmed"
    assert f["severity"] == "high" and f["cwe"] == "CWE-1321"
    assert f["line_start"] == 2       # baris sink nyata
    assert _valid(r)


def test_guarded_sink_downgraded_to_L1():
    r = P.scan([("set.js", GUARDED_JS)])
    f = [x for x in r["findings"] if x.get("kind") == "proto"][0]
    assert f["verdict"] == 1 and f["status"] == "unconfirmed"
    assert _valid(r)


def test_weak_nested_assign_is_low_L1():
    r = P.scan([("apply.js", WEAK_JS)])
    f = [x for x in r["findings"] if x.get("kind") == "proto"][0]
    assert f["verdict"] == 1 and f["severity"] == "low"
    assert _valid(r)


def test_clean_js_is_L0_no_false_positive():
    r = P.scan([("clean.js", CLEAN_JS)])
    assert len(r["findings"]) == 1
    assert r["findings"][0]["verdict"] == 0 and r["findings"][0]["severity"] == "info"
    assert _valid(r)


def test_deterministic():
    a = json.dumps(P.scan([("set.js", SINK_JS)]), sort_keys=True)
    b = json.dumps(P.scan([("set.js", SINK_JS)]), sort_keys=True)
    assert a == b


def _cli(tmp, *argv):
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "proto_pollution_scan.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_missing_exit2(tmp_path):
    assert _cli(tmp_path, "--file", str(tmp_path / "no.js")).returncode == 2


def test_cli_out_contract_failon(tmp_path):
    js = tmp_path / "set.js"; js.write_text(SINK_JS, encoding="utf-8")
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--file", str(js), "--fail-on", "high", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True
    for fd in doc["findings"]:
        assert validate_finding(fd) == []
