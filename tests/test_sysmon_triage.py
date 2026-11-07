"""test_sysmon_triage — triase OFFLINE log Sysmon XML utk T1003/T1055/
T1548.002/T1546.003 (#0466 #0467 #0468 #0471), nol jaringan.

Fixture = ekspor Sysmon XML sintetis dari spesifikasi konsep sumber
(access mask Windows, event ID Sysmon, token cmdline alat dump).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import sysmon_triage as st  # noqa: E402

TS = "2026-01-01T10:00:00.000Z"


def _ev(eid: int, data: "dict[str, str] | None" = None,
        time: str = TS, computer: str = "LAB-PC") -> str:
    fields = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in (data or {}).items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/windows/'
        f'events/log"><System><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{time}"/>'
        f'<Computer>{computer}</Computer></System><EventData>{fields}'
        "</EventData></Event>")


def _file(tmp_path, *events: str) -> Path:
    p = tmp_path / "sysmon.xml"
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "sysmon_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> list[str]:
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- parsing
def test_parse_filters_watched_eids_and_sorts():
    xml = "<Events>" + _ev(3, {"DestinationIp": "10.0.0.1"}) \
        + _ev(10, {"GrantedAccess": "0x1010"}, time="2026-01-01T10:05:00Z") \
        + _ev(1, {"Image": "a.exe"}, time="2026-01-01T10:00:00Z") + "</Events>"
    events = st.parse_events(xml, "x")
    assert [e["eid"] for e in events] == [1, 10]


def test_parse_invalid_xml_raises():
    try:
        st.parse_events("<Events><Event>", "x")
    except ValueError as exc:
        assert "tidak valid" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- T1003
def test_lsass_access(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\Users\\u\\evil.exe",
        "GrantedAccess": "0x1010"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1
    assert "lsass-access" in _checks(out)
    fnd = out["findings"][0]
    assert fnd["severity"] == "high"
    assert fnd["granted_access"] == "0x1010"


def test_lsass_access_allowlisted_source_suppressed(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\Windows\\MsMpEng.exe",
        "GrantedAccess": "0x1010"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


def test_lsass_access_custom_allow(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\tools\\myedr.exe",
        "GrantedAccess": "0x1fffff"}))
    rc, out, _ = _run("--log", str(f), "--allow-source", "myedr.exe")
    assert rc == 0 and out["findings"] == []


def test_lsass_unparseable_access_still_flagged(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\Users\\u\\evil.exe",
        "GrantedAccess": "oops"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "lsass-access" in _checks(out)


# ------------------------------------------------------- T1055
def test_cross_process_write_high_value(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\svchost.exe",
        "SourceImage": "C:\\Users\\u\\evil.exe",
        "GrantedAccess": "0x1fffff"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "cross-process-write" in _checks(out)


def test_remote_thread(tmp_path):
    f = _file(tmp_path, _ev(8, {
        "TargetImage": "C:\\Windows\\explorer.exe",
        "SourceImage": "C:\\Users\\u\\evil.exe"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "remote-thread" in _checks(out)


def test_remote_thread_system_source_suppressed(tmp_path):
    f = _file(tmp_path, _ev(8, {
        "TargetImage": "C:\\Windows\\explorer.exe",
        "SourceImage": "C:\\Windows\\csrss.exe"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


def test_process_tampering(tmp_path):
    f = _file(tmp_path, _ev(25, {"Image": "C:\\Windows\\svchost.exe",
                                 "Type": "Image is replaced"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "process-tampering" in _checks(out)


def test_dll_unusual_path(tmp_path):
    f = _file(tmp_path, _ev(7, {
        "Image": "C:\\Windows\\system32\\svchost.exe",
        "ImageLoaded": "C:\\Users\\u\\AppData\\Local\\Temp\\x.dll"}))
    rc, out, _ = _run("--log", str(f), "--fail-on", "medium")
    assert rc == 1 and "dll-unusual-path" in _checks(out)


def test_dll_system_path_clean(tmp_path):
    f = _file(tmp_path, _ev(7, {
        "Image": "C:\\Windows\\system32\\svchost.exe",
        "ImageLoaded": "C:\\Windows\\system32\\cryptsp.dll"}))
    rc, out, _ = _run("--log", str(f), "--fail-on", "medium")
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- cmdline
def test_dump_cmdline_comsvcs(tmp_path):
    f = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\Windows\\system32\\comsvcs"
                       ".dll, MiniDump 700 C:\\dump.bin full"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "dump-cmdline" in _checks(out)


def test_dump_cmdline_mimikatz_and_regsave(tmp_path):
    f = _file(tmp_path,
              _ev(1, {"CommandLine": "mimikatz # sekurlsa::logonpasswords"}),
              _ev(1, {"CommandLine": "reg.exe save hklm\\sam C:\\sam"}))
    rc, out, _ = _run("--log", str(f))
    checks = _checks(out)
    assert checks.count("dump-cmdline") == 2


def test_dump_cmdline_benign_clean(tmp_path):
    f = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


def test_auto_elevate_parent(tmp_path):
    f = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\System32\\fodhelper.exe",
        "ParentImage": "C:\\Users\\u\\cmd.exe"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "auto-elevate-parent" in _checks(out)


def test_auto_elevate_explorer_parent_clean(tmp_path):
    f = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\System32\\fodhelper.exe",
        "ParentImage": "C:\\Windows\\explorer.exe"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- T1548.002
def test_uac_registry_hijack(tmp_path):
    f = _file(tmp_path, _ev(13, {
        "TargetObject": "HKCU\\Software\\Classes\\ms-settings\\shell"
                        "\\open\\command",
        "Details": "cmd.exe /c evil.exe"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 1 and "uac-registry-hijack" in _checks(out)


def test_uac_registry_benign_clean(tmp_path):
    f = _file(tmp_path, _ev(13, {
        "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\"
                        "CurrentVersion\\Run"}))
    rc, out, _ = _run("--log", str(f))
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- T1546.003
def test_wmi_consumer_and_binding_escalate(tmp_path):
    f = _file(tmp_path,
              _ev(20, {"Name": "EvilConsumer",
                       "Type": "Command Line Event Consumer"}),
              _ev(21, {"Filter": "__EventFilter.Name='F'",
                       "Consumer": "EvilConsumer"}))
    rc, out, _ = _run("--log", str(f))
    checks = _checks(out)
    assert "wmi-consumer" in checks
    binding = next(f_ for f_ in out["findings"]
                   if f_["check"] == "wmi-binding")
    assert binding["severity"] == "high"


def test_wmi_binding_without_consumer_medium(tmp_path):
    f = _file(tmp_path, _ev(21, {"Filter": "F", "Consumer": "C"}))
    rc, out, _ = _run("--log", str(f))
    binding = out["findings"][0]
    assert binding["severity"] == "medium"
    assert rc == 0  # medium < fail-on high default


def test_wmi_filter_timer(tmp_path):
    f = _file(tmp_path, _ev(19, {
        "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60"}))
    _, out, _ = _run("--log", str(f))
    assert "wmi-filter-timer" in _checks(out)


# ------------------------------------------------------- fail-closed
def test_invalid_xml_exit2(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "tidak valid" in err


def test_missing_file_exit2():
    rc, out, err = _run("--log", "TIDAK-ADA.xml")
    assert rc == 2 and out is None


def test_zero_watched_events_exit2(tmp_path):
    f = _file(tmp_path, _ev(3, {"DestinationIp": "10.0.0.1"}))
    rc, out, err = _run("--log", str(f))
    assert rc == 2 and "nol event" in err


def test_notes_for_absent_eids(tmp_path):
    f = _file(tmp_path, _ev(10, {
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\Users\\u\\evil.exe",
        "GrantedAccess": "0x1010"}))
    _, out, _ = _run("--log", str(f))
    joined = " ".join(out["notes"])
    assert "EID 1" in joined and "EID 20" in joined


def test_medium_only_zero_exit_with_high_gate(tmp_path):
    f = _file(tmp_path, _ev(21, {"Filter": "F", "Consumer": "C"}))
    rc, out, _ = _run("--log", str(f), "--fail-on", "medium")
    assert rc == 1
