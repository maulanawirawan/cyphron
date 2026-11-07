"""test_dcsync_triage — triase log Windows Security XML utk DCSync
(#0541), nol jaringan.

Fixture = ekspor Windows Security XML sintetis (4662) sesuai spesifikasi
konsep sumber: GUID replikasi DS-Replication-Get-Changes[-All] +
AccessMask 0x100 dari akun non-DC, saringan akun mesin, allowlist
principal replikasi sah, korelasi IP DC. Ranah 4768/4769 (Kerberos)
sengaja TIDAK disentuh (kerberos_log_triage B14) — diuji sebagai
pembagian ranah.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import dcsync_triage as dt  # noqa: E402

GC = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GCA = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def _ev(eid: int, **data: str) -> str:
    t = data.pop("time", "2026-03-18T01:00:00.000Z")
    host = data.pop("host", "DC01.corp.local")
    body = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/'
            f'windows/events/log"><System><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{t}"/>'
            f'<Computer>{host}</Computer></System>'
            f'<EventData>{body}</EventData></Event>')


def _dcsync(subject: str, guid: str = GCA, mask: str = "0x100",
            ip: str = "10.0.0.9", domain: str = "CORP",
            obj_name: str = "CN=domainDNS,CN=...",
            host: str = "DC01.corp.local") -> str:
    return _ev(4662, host=host, SubjectUserName=subject,
               SubjectDomainName=domain, ObjectServer="DS",
               ObjectType=f"%{{{guid}}}", ObjectName=obj_name,
               OperationType="Object Access", AccessMask=mask,
               IpAddress=ip, IpPort="49152")


def _file(tmp_path: Path, *events: str, name: str = "sec.xml") -> Path:
    p = tmp_path / name
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "dcsync_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


# ------------------------------------------------------- parsing
def test_dcsync_high_accessmask_0x100(tmp_path):
    p = _file(tmp_path, _dcsync("janedoe"))
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1 and out is not None, err
    f = [x for x in out["findings"] if x["check"] == "dcsync-replication"]
    assert len(f) == 1
    assert f[0]["severity"] == "high"
    assert f[0]["subject"] == "CORP\\janedoe"
    assert f[0]["guid"] == GCA
    assert "T1003.006" in f[0]["message"]


def test_named_guid_in_objectname_detected(tmp_path):
    ev = _ev(4662, SubjectUserName="janedoe", SubjectDomainName="CORP",
             ObjectServer="DS", ObjectType="domainDNS",
             ObjectName="DS-Replication-Get-Changes-All",
             OperationType="Object Access", AccessMask="0x100",
             IpAddress="10.0.0.9", IpPort="49152")
    p = _file(tmp_path, ev)
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 1, err
    f = [x for x in out["findings"]
         if x["check"] == "dcsync-replication"]
    assert len(f) == 1
    assert f[0]["guid"].startswith("named:")


def test_machine_account_excluded(tmp_path):
    p = _file(tmp_path, _dcsync("DC02$"), _dcsync("WS-123$"))
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0 and out is not None, err
    assert out["findings"] == []


def test_allow_account_excluded_and_noted(tmp_path):
    p = _file(tmp_path, _dcsync("MSOL_abc123"))
    rc, out, err = _run("--log", str(p), "--json",
                        "--allow-account", "CORP\\MSOL_abc123")
    assert rc == 0, err
    assert out["findings"] == []
    assert any("MSOL_abc123" in n for n in out["notes"])


def test_guid_without_control_access_is_medium(tmp_path):
    p = _file(tmp_path, _dcsync("janedoe", mask="0x10"))
    rc, out, err = _run("--log", str(p), "--fail-on", "medium", "--json")
    assert rc == 1, err
    f = [x for x in out["findings"] if x["check"] == "replication-access"]
    assert len(f) == 1 and f[0]["severity"] == "medium"


def test_ip_non_dc_correlated(tmp_path):
    p = _file(tmp_path, _dcsync("janedoe", ip="203.0.113.7"))
    rc, out, err = _run("--log", str(p), "--json",
                        "--dc-ip", "10.0.0.1,10.0.0.2")
    checks = {x["check"] for x in out["findings"]}
    assert "dcsync-ip-non-dc" in checks
    ipf = [x for x in out["findings"]
           if x["check"] == "dcsync-ip-non-dc"][0]
    assert ipf["severity"] == "info" and ipf["ip"] == "203.0.113.7"


def test_ip_dc_matched_not_flagged(tmp_path):
    p = _file(tmp_path, _dcsync("janedoe", ip="10.0.0.1"))
    rc, out, err = _run("--log", str(p), "--json",
                        "--dc-ip", "10.0.0.1")
    assert rc == 1
    assert "dcsync-ip-non-dc" not in {
        x["check"] for x in out["findings"]}


# ------------------------------------------------------- fail-closed
def test_bad_xml_fails_closed(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<Events><Event>...", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None


def test_4662_without_guid_not_dark_not_flagged(tmp_path):
    # 4662 ada di log (tanpa GUID replikasi) -> bukan kegelapan, bukan
    # temuan; note kegelapan hanya utk 4662 absen total
    p = _file(tmp_path, _ev(4662, SubjectUserName="x",
                            ObjectType="CN=some,object",
                            AccessMask="0x1", IpAddress="10.0.0.9"))
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0
    assert out["findings"] == []
    assert not any("4662 tidak ada" in n for n in out["notes"])


def test_absent_4662_coverage_note(tmp_path):
    p = _file(tmp_path, _ev(4768, TargetUserName="u"))
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0
    assert any("4662 tidak ada" in n for n in out["notes"])


def test_zero_events_fails_closed(tmp_path):
    p = tmp_path / "empty.xml"
    p.write_text("<Events></Events>", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2


def test_kerberos_events_delegated_to_other_tool(tmp_path):
    # 4768/4769 = ranah kerberos_log_triage (B14) — di sini hanya stats
    p = _file(tmp_path, _ev(4768, TargetUserName="u"),
              _ev(4769, TargetUserName="u", ServiceName="cifs"))
    rc, out, err = _run("--log", str(p), "--json")
    assert rc == 0 and out["findings"] == []
    assert any("4662 tidak ada" in n for n in out["notes"])


# ------------------------------------------------------- modes
def test_dir_mode_and_determinism(tmp_path):
    d = tmp_path / "exports"
    d.mkdir()
    (d / "a.xml").write_text(
        "<Events>" + _dcsync("janedoe") + "</Events>", encoding="utf-8")
    (d / "b.xml").write_text(
        "<Events>" + _ev(4768, TargetUserName="u") + "</Events>",
        encoding="utf-8")
    rc1, out1, _ = _run("--dir", str(d), "--json")
    rc2, out2, _ = _run("--dir", str(d), "--json")
    assert rc1 == rc2 == 1
    assert out1 == out2


def test_out_file_and_short_mode(tmp_path):
    p = _file(tmp_path, _dcsync("janedoe"))
    outp = tmp_path / "rep.json"
    rc, out, err = _run("--log", str(p), "--out", str(outp))
    assert rc == 1 and out is not None
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        dt.SCHEMA


def test_guid_parser_unit():
    assert dt._guid_in_text(f"%{{{GCA}}}") == GCA
    assert dt._guid_in_text(
        "DS-Replication-Get-Changes-In-Filtered-Set") is not None
    assert dt._guid_in_text("%{00000000-0000-0000-0000-000000000000}") \
        is None
    assert dt._guid_in_text("CN=Users") is None
    assert dt._access_mask_is_control("0x100")
    assert dt._access_mask_is_control("256")
    assert not dt._access_mask_is_control("0x1")
