"""test_waf_sqli_triage — triase OFFLINE log WAF utk kampanye SQLi
(#0461), nol jaringan.

Fixture = audit log ModSecurity sintetis + JSONL generik dari
spesifikasi konsep sumber (UNION SELECT, OR 1=1, SLEEP/BENCHMARK).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import waf_sqli_triage as wst  # noqa: E402


def _tx(txid: str, ip: str, uri: str, ts: str = "08/Nov/2026:10:00:00 +0000",
        msg: str = "", status: str = "403", ua: str = "") -> str:
    ua_line = f"User-Agent: {ua}\n" if ua else ""
    msg_line = (f"Message: Warning. Pattern match \"x\" {msg}\n"
                if msg else "")
    return (
        f"--{txid}-A--\n[{ts}] {txid} {ip} 45123 10.0.0.1 80\n"
        f"--{txid}-B--\nGET {uri} HTTP/1.1\nHost: lab.local\n{ua_line}"
        f"--{txid}-F--\nHTTP/1.1 {status}\n"
        f"--{txid}-H--\n{msg_line}Stopwatch: 1\n"
        f"--{txid}-Z--\n")


def _file(tmp_path, text: str) -> Path:
    p = tmp_path / "waf.log"
    p.write_text(text, encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "waf_sqli_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> list[str]:
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- parser modsec
def test_parse_modsec_transaction(tmp_path):
    text = _tx("3f8a1c2a", "10.0.0.5", "/index.html")
    txs, _ = wst.parse_modsec(text, "x")
    assert len(txs) == 1
    assert txs[0]["ip"] == "10.0.0.5"
    assert txs[0]["method"] == "GET"
    assert txs[0]["status"] == 403
    assert txs[0]["time"] is not None


def test_parse_modsec_empty_raises(tmp_path):
    try:
        wst.parse_modsec("--abc-A--\n[bad] x\n--abc-Z--\n", "x")
    except ValueError as exc:
        assert "nol transaksi" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- klasifikasi
def test_union_select(tmp_path):
    f = _file(tmp_path, _tx(
        "aa1", "10.0.0.5",
        "/api/users?id=1%27%20UNION%20SELECT%20username,password%20"
        "FROM%20users--",
        msg='[id "942100"] [msg "SQL Injection Attack Detected"] '
            '[severity "CRITICAL"]'))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1
    fnd = out["findings"][0]
    assert fnd["family"] == "union-select"
    assert fnd["severity"] == "high"
    assert fnd["rule_id"] == "942100"


def test_boolean_tautology(tmp_path):
    f = _file(tmp_path, _tx("aa2", "10.0.0.6",
                            "/login?u=admin%27%20OR%201%3D1--"))
    rc, out, _ = _run("--log", str(f))
    assert "sqli-attempt" in _checks(out)
    assert out["findings"][0]["family"] == "boolean-taut"


def test_time_based(tmp_path):
    f = _file(tmp_path, _tx("aa3", "10.0.0.7",
                            "/item?id=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--"))
    _, out, _ = _run("--log", str(f))
    assert out["findings"][0]["family"] == "time-based"


def test_error_based(tmp_path):
    f = _file(tmp_path, _tx("aa4", "10.0.0.8",
                            "/x?q=1%27%20AND%20extractvalue(1,1)--"))
    _, out, _ = _run("--log", str(f))
    fams = {f_["family"] for f_ in out["findings"]
            if f_["check"] == "sqli-attempt"}
    assert "error-based" in fams or "boolean-taut" in fams


def test_benign_request_clean(tmp_path):
    f = _file(tmp_path, _tx("aa5", "10.0.0.9", "/products?page=2"))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


def test_sqlmap_ua(tmp_path):
    f = _file(tmp_path, _tx("aa6", "10.0.0.10", "/products?page=2",
                            ua="sqlmap/1.8"))
    _, out, _ = _run("--log", str(f))
    assert "sqlmap-ua" in _checks(out)


# ------------------------------------------------------- bypass
def test_waf_bypass_possible_2xx(tmp_path):
    f = _file(tmp_path, _tx("aa7", "10.0.0.11",
                            "/login?u=admin%27%20OR%201%3D1--",
                            status="200"))
    _, out, _ = _run("--log", str(f))
    assert "waf-bypass-possible" in _checks(out)


def test_blocked_403_no_bypass(tmp_path):
    f = _file(tmp_path, _tx("aa8", "10.0.0.12",
                            "/login?u=admin%27%20OR%201%3D1--",
                            status="403"))
    _, out, _ = _run("--log", str(f))
    assert "waf-bypass-possible" not in _checks(out)


# ------------------------------------------------------- kampanye
def test_campaign_threshold(tmp_path):
    text = "".join(
        _tx(f"bb{i:02d}", "10.0.0.13",
            f"/login?u=admin%27%20OR%201%3D1--",
            ts=f"08/Nov/2026:10:0{i // 6}:{i % 60:02d} +0000")
        for i in range(6))
    rc, out, _ = _run("--log", str(_file(tmp_path, text)))
    assert "sqli-campaign" in _checks(out)
    camp = next(f_ for f_ in out["findings"]
                if f_["check"] == "sqli-campaign")
    assert camp["burst"] == 6


def test_campaign_below_threshold(tmp_path):
    text = "".join(
        _tx(f"cc{i:02d}", "10.0.0.14", "/login?u=admin%27%20OR%201%3D1--",
            ts=f"08/Nov/2026:1{i // 60}:{i % 60:02d} +0000")
        for i in range(3))
    _, out, _ = _run("--log", str(_file(tmp_path, text)))
    assert "sqli-campaign" not in _checks(out)
    assert out["stats"]["sqli_attempts"] == 3


# ------------------------------------------------------- JSON WAF
def test_json_waf_records(tmp_path):
    recs = [
        {"timestamp": "2026-11-08T10:00:00Z", "ip": "10.1.1.1",
         "uri": "/api/x?id=1%20UNION%20SELECT%20null--",
         "message": "SQLi match", "status": 403},
        {"timestamp": "2026-11-08T10:00:01Z", "ip": "10.1.1.2",
         "uri": "/normal", "message": "", "status": 200},
    ]
    f = _file(tmp_path, "\n".join(json.dumps(r) for r in recs))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1
    assert out["findings"][0]["family"] == "union-select"
    assert out["stats"]["records_total"] == 2


def test_json_waf_aws_shape(tmp_path):
    rec = {
        "timestamp": 1731050400000,
        "httpRequest": {"uri": "/a?x=1%27%20OR%20%271%27%3D%271",
                        "headers": [{"name": "User-Agent",
                                     "value": "sqlmap"}],
                        "clientIp": "10.2.2.2"},
        "terminatingRuleId": "AWSManagedRulesSQLiRuleSet",
        "action": "BLOCK",
    }
    f = _file(tmp_path, json.dumps(rec))
    _, out, _ = _run("--log", str(f))
    assert any(f_["check"] == "sqlmap-ua" for f_ in out["findings"])
    assert out["findings"][0]["ip"] == "10.2.2.2"


# ------------------------------------------------------- fail-closed
def test_missing_file_exit2():
    rc, out, err = _run("--log", "TIDAK-ADA.log")
    assert rc == 2 and out is None


def test_unknown_format_exit2(tmp_path):
    p = tmp_path / "waf.log"
    p.write_text("baris biasa bukan log\n" * 3, encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and "nol event" in err


def test_unparsed_recorded(tmp_path):
    text = _tx("dd1", "10.0.0.15", "/x") \
        + "--zz9-B--\nbaris aneh tanpa transaksi aktif\n"
    f = _file(tmp_path, text)
    _, out, _ = _run("--log", str(f))
    assert isinstance(out["meta"]["unparsed"], list)
