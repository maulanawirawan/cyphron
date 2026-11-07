"""test_dcom_lateral_scan — triase Sysmon EID 1/3 utk DCOM lateral
movement (#0540), nol jaringan.

Fixture = ekspor Sysmon XML sintetis dari pola artefak DCOM publik
(MMC20.Application / ShellWindows / COM surrogate / port 135); bukan
salinan kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import dcom_lateral_scan as dls  # noqa: E402

TS = "2026-01-01T10:00:00.000Z"


def _ev(eid: int, data: "dict[str, str] | None" = None,
        time: str = TS, computer: str = "SRV-01") -> str:
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


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "dcom_lateral_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- parsing
def test_invalid_xml_exit2(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "tidak valid" in err


def test_no_watched_events_exit2(tmp_path):
    p = _file(tmp_path, _ev(10, {"GrantedAccess": "0x1010"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 2


# ------------------------------------------------------- EID 1 chains
def test_mmc_child_of_dcomlaunch(tmp_path):
    p = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\mmc.exe",
        "ParentImage": "C:\\Windows\\system32\\svchost.exe",
        "ParentCommandLine": "svchost.exe -k DcomLaunch -p",
        "CommandLine": "mmc.exe -Embedding"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "dcom-mmc-child" in _checks(out)


def test_mmc_local_not_dcomlaunch_clean(tmp_path):
    p = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\mmc.exe",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe"}))
    rc, out, _ = _run("--log", str(p))
    assert "dcom-mmc-child" not in _checks(out)


def test_dllhost_shell_child(tmp_path):
    p = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\cmd.exe",
        "ParentImage": "C:\\Windows\\system32\\dllhost.exe",
        "CommandLine": "cmd.exe /c whoami"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "dcom-dllhost-child" in _checks(out)


def test_explorer_shell_spawn_medium_and_allowlist(tmp_path):
    p = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\cmd.exe",
        "ParentImage": "C:\\Windows\\explorer.exe"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 0  # medium di bawah default high
    rc2, out2, _ = _run("--log", str(p), "--fail-on", "medium")
    assert "dcom-explorer-shell" in _checks(out2) and rc2 == 1
    rc3, out3, _ = _run("--log", str(p), "--fail-on", "medium",
                        "--allow-explorer-child", "cmd.exe")
    assert "dcom-explorer-shell" not in _checks(out3) and rc3 == 0


# ------------------------------------------------------- EID 3
def test_rpc_egress_port135_and_dynamic(tmp_path):
    p = _file(tmp_path, _ev(3, {
        "Image": "C:\\Windows\\system32\\dllhost.exe",
        "DestinationPort": "135"}),
        _ev(3, {
            "Image": "C:\\Windows\\system32\\mmc.exe",
            "DestinationPort": "49670"}))
    rc, out, _ = _run("--log", str(p), "--fail-on", "medium")
    assert _checks(out).count("dcom-rpc-egress") == 2


def test_http_egress_not_flagged(tmp_path):
    p = _file(tmp_path, _ev(3, {
        "Image": "C:\\Windows\\system32\\dllhost.exe",
        "DestinationPort": "443"}))
    rc, out, _ = _run("--log", str(p))
    assert out["findings"] == []


# ------------------------------------------------------- korelasi chain
def test_chain_high_on_same_host(tmp_path):
    p = _file(
        tmp_path,
        _ev(1, {
            "Image": "C:\\Windows\\system32\\mmc.exe",
            "ParentImage": "C:\\Windows\\system32\\svchost.exe",
            "ParentCommandLine": "svchost.exe -k DcomLaunch"}),
        _ev(3, {
            "Image": "C:\\Windows\\system32\\mmc.exe",
            "DestinationPort": "49670"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "dcom-lateral-chain" in _checks(out)


def test_no_chain_across_hosts(tmp_path):
    p = _file(
        tmp_path,
        _ev(1, {
            "Image": "C:\\Windows\\system32\\mmc.exe",
            "ParentImage": "C:\\Windows\\system32\\svchost.exe",
            "ParentCommandLine": "svchost.exe -k DcomLaunch"},
            computer="HOST-A"),
        _ev(3, {
            "Image": "C:\\Windows\\system32\\mmc.exe",
            "DestinationPort": "49670"}, computer="HOST-B"))
    rc, out, _ = _run("--log", str(p))
    assert "dcom-lateral-chain" not in _checks(out)


# ------------------------------------------------------- telemetri
def test_missing_eid3_note(tmp_path):
    p = _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\cmd.exe",
        "ParentImage": "C:\\Windows\\system32\\dllhost.exe"}))
    rc, out, _ = _run("--log", str(p))
    assert any("EID 3" in n for n in out["notes"])
    assert any("sysmon_triage" in n for n in out["notes"])


def test_missing_eid1_note(tmp_path):
    p = _file(tmp_path, _ev(3, {
        "Image": "C:\\Windows\\system32\\dllhost.exe",
        "DestinationPort": "135"}))
    rc, out, _ = _run("--log", str(p))
    assert any("EID 1" in n for n in out["notes"])


# ------------------------------------------------------- misc
def test_dir_mode(tmp_path):
    _file(tmp_path, _ev(1, {
        "Image": "C:\\Windows\\system32\\mmc.exe",
        "ParentImage": "C:\\Windows\\system32\\svchost.exe",
        "ParentCommandLine": "-k DcomLaunch"}))
    (tmp_path / "sub").mkdir()
    p2 = tmp_path / "sub" / "b.xml"
    p2.write_text("<Events>" + _ev(3, {
        "Image": "C:\\Windows\\system32\\mmc.exe",
        "DestinationPort": "135"}) + "</Events>", encoding="utf-8")
    rc, out, _ = _run("--dir", str(tmp_path))
    assert out["files"] == 2 and rc == 1


def test_deterministic(tmp_path):
    evs = [_ev(1, {"Image": "C:\\Windows\\system32\\cmd.exe",
                   "ParentImage": "C:\\Windows\\system32\\dllhost.exe"}),
           _ev(3, {"Image": "C:\\Windows\\system32\\dllhost.exe",
                   "DestinationPort": "135"})]
    p = _file(tmp_path, *evs)
    parsed = dls.parse_events(p)
    a = dls.scan(parsed, frozenset())
    b = dls.scan(parsed, frozenset())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
