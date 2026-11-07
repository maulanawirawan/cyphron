"""test_win_logon_triage — brute force logon RDP/NLA dari XML Security
4625/4624 (#0452), nol jaringan.

Fixture = ekspor Windows Security XML sintetis dari spesifikasi konsep
sumber (LogonType 10/3, SubStatus 0xC0000064/0xC000006A, 4624 sukses).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import win_logon_triage as wlt  # noqa: E402


def _ev(eid: int, user: str, ip: str, ltype: int,
        sub: str = "", time: str = "2026-01-01T10:00:00.000Z") -> str:
    extra = f'<Data Name="SubStatus">{sub}</Data>' if sub else ""
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/windows/'
        f'events/log"><System><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{time}"/></System><EventData>'
        f'<Data Name="TargetUserName">{user}</Data>'
        f'<Data Name="IpAddress">{ip}</Data>'
        f'<Data Name="LogonType">{ltype}</Data>{extra}'
        "</EventData></Event>")


def _file(tmp_path, *events: str) -> Path:
    p = tmp_path / "sec.xml"
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "win_logon_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> list[str]:
    return [f["check"] for f in out["findings"]]


def _min_secd(minute: int) -> str:
    return f"2026-01-01T10:{minute:02d}:00.000Z"


# ------------------------------------------------------- parsing
def test_parse_filters_and_sorts():
    xml = "<Events>" + _ev(4624, "u", "::ffff:10.0.0.9", 5,
                           time="2026-01-01T10:01:00.000Z") \
        + _ev(4625, "u", "::ffff:10.0.0.9", 10,
              time="2026-01-01T10:00:00.000Z") + "</Events>"
    events = wlt.parse_events(xml, "x")
    assert [e["eid"] for e in events] == [4625, 4624]
    assert events[0]["ip"] == "10.0.0.9"


def test_parse_invalid_xml_raises():
    try:
        wlt.parse_events("<Events><Event>", "x")
    except ValueError as exc:
        assert "tidak valid" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- brute force
def test_brute_force_threshold(tmp_path):
    evs = [_ev(4625, "admin", "10.0.0.5", 10, "0xC000006A",
               time=_min_secd(m)) for m in range(12)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 1 and "brute-force" in _checks(out)


def test_below_threshold_info_only(tmp_path):
    evs = [_ev(4625, "admin", "10.0.0.5", 10, "0xC000006A",
               time=_min_secd(m)) for m in range(3)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    checks = _checks(out)
    assert "failed-logon" in checks and "brute-force" not in checks
    assert rc == 0


def test_outside_window_not_burst(tmp_path):
    # 12 kegagalan tapi tersebar 30 menit dgn window default 600s ->
    # burst maks 2/menit < ambang 10
    evs = [_ev(4625, "admin", "10.0.0.5", 10, "0xC000006A",
               time=f"2026-01-01T{10 + m // 30:02d}:{m % 30:02d}:00.000Z")
           for m in range(0, 30, 1)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)),
                      "--threshold", "25")
    assert "brute-force" not in _checks(out)
    assert rc == 0


def test_logon_type_filter(tmp_path):
    # 12 kegagalan type 2 (interactive lokal) — di luar cakupan default
    evs = [_ev(4625, "admin", "10.0.0.5", 2, "0xC000006A",
               time=_min_secd(m)) for m in range(12)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 0 and out["findings"] == []
    rc2, out2, _ = _run("--log", str(_file(tmp_path, *evs)),
                        "--logon-types", "2", "--fail-on", "medium")
    assert rc2 == 1 and "brute-force" in _checks(out2)


# ------------------------------------------------------- spray
def test_username_spray(tmp_path):
    users = [f"user{i:02d}" for i in range(6)]
    evs = [_ev(4625, u, "10.0.0.7", 3, "0xC0000064",
               time=_min_secd(m)) for m, u in enumerate(users)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert "username-spray" in _checks(out) and rc == 1


# ------------------------------------------------------- kompromi
def test_success_after_fail(tmp_path):
    evs = [_ev(4625, "admin", "10.0.0.9", 10, "0xC000006A",
               time=_min_secd(m)) for m in range(11)]
    evs.append(_ev(4624, "admin", "10.0.0.9", 10,
                   time="2026-01-01T10:20:00.000Z"))
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    checks = _checks(out)
    assert "success-after-fail" in checks and rc == 1
    f = next(f_ for f_ in out["findings"]
             if f_["check"] == "success-after-fail")
    assert f["account"] == "admin"


def test_success_before_fail_no_compromise(tmp_path):
    evs = [_ev(4624, "admin", "10.0.0.9", 10,
               time="2026-01-01T10:00:00.000Z")]
    evs += [_ev(4625, "admin", "10.0.0.9", 10, "0xC000006A",
                time=_min_secd(m)) for m in range(1, 12)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert "success-after-fail" not in _checks(out)


def test_no_success_event_note(tmp_path):
    evs = [_ev(4625, "admin", "10.0.0.5", 10, "0xC000006A",
               time=_min_secd(m)) for m in range(12)]
    _, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert any("4624" in n for n in out["notes"])


# ------------------------------------------------------- substatus
def test_account_not_found_low(tmp_path):
    evs = [_ev(4625, f"u{i}", "10.0.0.8", 3, "0xC0000064",
               time=_min_secd(m)) for m, i in enumerate(range(12))]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert "account-not-found" in _checks(out)


# ------------------------------------------------------- fail-closed
def test_missing_file_exit2():
    rc, out, err = _run("--log", "TIDAK-ADA.xml")
    assert rc == 2 and out is None


def test_invalid_xml_exit2(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and "tidak valid" in err


def test_zero_logon_events_exit2(tmp_path):
    p = tmp_path / "sec.xml"
    p.write_text(
        "<Events><Event><System><EventID>7045</EventID>"
        '<TimeCreated SystemTime="2026-01-01T10:00:00.000Z"/>'
        "</System></Event></Events>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and "nol event" in err


def test_no_4625_note(tmp_path):
    f = _file(tmp_path, _ev(4624, "admin", "10.0.0.5", 10))
    _, out, _ = _run("--log", str(f))
    assert any("4625" in n for n in out["notes"])
