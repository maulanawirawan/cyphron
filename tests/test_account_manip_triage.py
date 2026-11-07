"""test_account_manip_triage — triase manipulasi akun Windows Security
(#0562, T1098), nol jaringan.

Fixture = ekspor XML sintetis 4720/4724/4728/4732/4756/4738/4765/4766/
5136. Pembagian ranah diuji: 4624/4625 (win_logon_triage/win_auth_triage)
dan 4662 (dcsync_triage, blok ini) tidak diduplikasi.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import account_manip_triage as amt  # noqa: E402


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


def _file(tmp_path: Path, *events: str, name: str = "sec.xml") -> Path:
    p = tmp_path / name
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "account_manip_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _findings(out, check):
    return [x for x in out["findings"] if x["check"] == check]


# ------------------------------------------------------- grup ber-hak
def test_group_priv_add(tmp_path):
    ev = _ev(4728, SubjectUserName="CORP\\admin",
             MemberName="CN=jdoe,CN=Users,DC=corp,DC=local",
             MemberSid="S-1-5-21-1-1001",
             TargetUserName="Domain Admins")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 1, err
    f = _findings(out, "group-priv-add")
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert "jdoe -> Domain Admins" == f[0]["target"]
    assert "T1098" in f[0]["message"]


def test_all_priv_group_variants(tmp_path):
    evs = (_ev(4732, SubjectUserName="CORP\\a", MemberName="m1",
               TargetUserName="Administrators"),
           _ev(4756, SubjectUserName="CORP\\a", MemberName="m2",
               TargetUserName="Backup Operators"),
           _ev(4728, SubjectUserName="CORP\\a", MemberName="m3",
               TargetUserName="Domain Admins"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert len(_findings(out, "group-priv-add")) == 3


def test_non_priv_group_not_flagged(tmp_path):
    ev = _ev(4728, SubjectUserName="CORP\\admin", MemberName="CN=m1,",
             TargetUserName="Marketing Team")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    assert rc == 0 and out["findings"] == []


def test_allow_group_and_member_anti_fp(tmp_path):
    ev = _ev(4728, SubjectUserName="CORP\\admin", MemberName="CN=svc,",
             TargetUserName="Domain Admins")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json",
                        "--allow-group", "Domain Admins")
    assert rc == 0 and out["findings"] == []
    rc2, out2, _ = _run("--log", str(_file(tmp_path, ev, name="b.xml")),
                        "--json", "--allow-member", "svc")
    assert rc2 == 0 and out2["findings"] == []


# ------------------------------------------------------- korelasi
def test_created_then_privileged(tmp_path):
    evs = (_ev(4720, time="2026-03-18T01:00:00.000Z",
               SubjectUserName="CORP\\admin", TargetUserName="bdoor"),
           _ev(4732, time="2026-03-18T02:00:00.000Z",
               SubjectUserName="CORP\\admin", MemberName="CN=bdoor,",
               TargetUserName="Administrators"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert rc == 1, err
    f = _findings(out, "created-then-priv")
    assert len(f) == 1 and "backdoor" in f[0]["message"]


def test_created_then_priv_window_excluded(tmp_path):
    evs = (_ev(4720, time="2026-03-18T01:00:00.000Z",
               SubjectUserName="CORP\\admin", TargetUserName="olduser"),
           _ev(4732, time="2026-03-19T01:00:00.000Z",
               SubjectUserName="CORP\\admin", MemberName="CN=olduser,",
               TargetUserName="Administrators"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json",
                        "--correlate-minutes", "60")
    assert _findings(out, "created-then-priv") == []
    assert len(_findings(out, "group-priv-add")) == 1  # tetap LEAD


# ------------------------------------------------------- SID history
def test_sid_history_add(tmp_path):
    evs = (_ev(4765, SubjectUserName="CORP\\a", TargetUserName="bob"),
           _ev(4766, SubjectUserName="CORP\\a", TargetUserName="alice"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    f = _findings(out, "sid-history-add")
    assert len(f) == 2 and all(x["severity"] == "high" for x in f)


# ------------------------------------------------------- atribut/reset
def test_account_attr_suspicious(tmp_path):
    ev = _ev(4738, SubjectUserName="CORP\\a", TargetUserName="bob",
             ChangedAttributes=(
                 "Admin Count:  0 -> 1.  Changed Attributes:\n"
                 "Password Never Expires:  0 -> 1."))
    rc, out, err = _run("--log", str(_file(tmp_path, ev)),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "acct-attr-suspicious")
    assert len(f) == 1 and "shadow admin" in f[0]["message"]


def test_reset_burst(tmp_path):
    evs = [_ev(4724, time=f"2026-03-18T01:0{i}:00.000Z",
               SubjectUserName="CORP\\helpdesk", TargetUserName=f"u{i}")
           for i in range(5)]
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)),
                        "--fail-on", "medium", "--json")
    assert len(_findings(out, "reset-burst")) == 1
    evs4 = evs[:4]
    rc2, out2, _ = _run("--log", str(_file(tmp_path, *evs4,
                                           name="b.xml")),
                        "--fail-on", "medium", "--json")
    assert _findings(out2, "reset-burst") == []


def test_5136_adminsdholder(tmp_path):
    ev = _ev(5136, SubjectUserName="CORP\\a",
             ObjectDN="CN=AdminSDHolder,CN=System,DC=corp,DC=local",
             AttributeLDAPDisplayName="nTSecurityDescriptor")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "ds-adminsdholder-mod")
    assert len(f) == 1 and f[0]["severity"] == "medium"
    # objek DS lain tidak ditandai
    ev2 = _ev(5136, SubjectUserName="CORP\\a",
              ObjectDN="CN=SomeApp,CN=Users,DC=corp,DC=local",
              AttributeLDAPDisplayName="description")
    rc2, out2, _ = _run("--log", str(_file(tmp_path, ev2,
                                           name="b.xml")), "--json")
    assert _findings(out2, "ds-adminsdholder-mod") == []


# ------------------------------------------------------- ranah lain
def test_4624_4662_delegated(tmp_path):
    evs = (_ev(4624, TargetUserName="u", IpAddress="10.0.0.9",
               LogonType="3"),
           _ev(4662, SubjectUserName="u", ObjectType="%{1131f6ad-9c07-"
               "11d1-f79f-00c04fc2dcd2}", AccessMask="0x100"))
    rc, out, err = _run("--log", str(_file(tmp_path, *evs)), "--json")
    assert rc == 0 and out["findings"] == []
    assert out["stats"]["events_total"] == 0


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
    ev = _ev(4765, SubjectUserName="CORP\\a", TargetUserName="bob")
    rc, out, err = _run("--log", str(_file(tmp_path, ev)), "--json")
    notes = " ".join(out["notes"])
    assert "4728/4732/4756" in notes and "4720" in notes


# ------------------------------------------------------- modes
def test_dir_mode_determinism_out(tmp_path):
    d = tmp_path / "exp"
    d.mkdir()
    (d / "a.xml").write_text("<Events>" + _ev(
        4728, SubjectUserName="CORP\\admin",
        MemberName="CN=jdoe,CN=Users,DC=corp,DC=local",
        TargetUserName="Domain Admins") + "</Events>", encoding="utf-8")
    (d / "b.xml").write_text("<Events>" + _ev(
        4765, SubjectUserName="CORP\\a", TargetUserName="bob")
        + "</Events>", encoding="utf-8")
    rc1, o1, _ = _run("--dir", str(d), "--json")
    rc2, o2, _ = _run("--dir", str(d), "--json")
    assert rc1 == rc2 == 1 and o1 == o2
    outp = tmp_path / "rep.json"
    rc3, _, _ = _run("--dir", str(d), "--out", str(outp))
    assert rc3 == 1
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        amt.SCHEMA


def test_short_name_and_dn_unit():
    assert amt._short("CN=jdoe,CN=Users,DC=corp,DC=local") == "jdoe"
    assert amt._short("plainuser") == "plainuser"
    assert amt._short("") == ""
