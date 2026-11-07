"""test_win_auth_triage — triase log Windows Security XML utk lateral
movement / NTLM abuse (#0425 #0426 #0440 #0442), nol jaringan.

Fixture = ekspor Windows Security XML sintetis (4624/4625/4648/4776/7045)
sesuai spesifikasi konsep sumber: NTLM type-3 multi-host (pass-the-hash),
NTLMv1 downgrade, relay mismatch (WorkstationName vs inventory), pivot
RDP, service PsExec, akun svc- interaktif. Brute force/4625-spray sengaja
TIDAK diduplikasi (ranah win_logon_triage #0452, B16) — diuji sebagai
pembagian ranah.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import win_auth_triage as wat  # noqa: E402


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


def _file(tmp_path: Path, *events: str, name: str = "sec.xml") -> Path:
    p = tmp_path / name
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "win_auth_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _ntlm4624(user: str, host: str, ip: str = "10.0.0.9",
              lt: str = "3", lm: str = "NTLM V2", ws: str = "",
              t: str = "2026-03-18T01:00:00.000Z") -> str:
    return _ev(4624, host=host, time=t, TargetUserName=user,
               IpAddress=ip, LogonType=lt,
               AuthenticationPackageName="NTLM", LmPackageName=lm,
               WorkstationName=ws)


# ------------------------------------------------------- parsing
def test_parse_fields_and_strip_ipv6_prefix(tmp_path):
    ev = _ev(4624, TargetUserName="CORP\\alice", IpAddress="::ffff:10.0.0.5",
             LogonType="3", AuthenticationPackageName="NTLM",
             LmPackageName="NTLM V2", host="FS-01")
    events, total = wat.parse_events("<Events>" + ev + "</Events>", "s")
    assert total == 1 and len(events) == 1
    e = events[0]
    assert e["ip"] == "10.0.0.5" and e["host"] == "FS-01"
    assert e["user"] == "CORP\\alice"
    assert wat._bare("CORP\\alice") == "alice"


def test_irrelevant_eid_skipped_fail_closed(tmp_path):
    p = _file(tmp_path, _ev(1102, FilePath="x"))
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "nol event relevan" in err


def test_bad_xml_fails_closed(tmp_path):
    p = tmp_path / "x.xml"
    p.write_text("<Events><Event><EventID>4624", encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and "XML tidak valid" in err


# ------------------------------------------------------- cek
def test_pth_spray_multi_host(tmp_path):
    evs = [_ntlm4624("alice", f"SRV-{i:02d}", t=f"2026-03-18T01:{i:02d}:00Z")
           for i in range(6)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    hits = [f for f in out["findings"] if f["check"] == "pth-spray"]
    assert rc == 0 and len(hits) == 1
    assert hits[0]["user"] == "alice" and hits[0]["unique_hosts"] == 6


def test_machine_account_excluded(tmp_path):
    evs = [_ntlm4624("PC-09$", f"SRV-{i:02d}") for i in range(6)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 0
    assert [f for f in out["findings"] if f["check"] == "pth-spray"] == []


def test_ntlm_v1_downgrade(tmp_path):
    ev = _ntlm4624("bob", "FS-01", lm="NTLM V1")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    hits = [f for f in out["findings"] if f["check"] == "ntlm-v1"]
    assert rc == 0 and len(hits) == 1 and hits[0]["severity"] == "high"


def test_relay_mismatch_needs_inventory(tmp_path):
    ev = _ntlm4624("bob", "FS-01", ip="10.0.0.66", ws="PC-VICTIM")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    checks = [f["check"] for f in out["findings"]]
    assert "relay-mismatch" not in checks
    assert any("DILEWATI" in n for n in out["notes"])

    inv = tmp_path / "inv.csv"
    inv.write_text("hostname,ip\nPC-VICTIM,10.0.0.5\n", encoding="utf-8")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)),
                      "--inventory", str(inv))
    hits = [f for f in out["findings"] if f["check"] == "relay-mismatch"]
    assert rc == 0 and len(hits) == 1
    assert hits[0]["expected_ip"] == "10.0.0.5" and hits[0]["src"] == "10.0.0.66"


def test_relay_match_is_not_flagged(tmp_path):
    ev = _ntlm4624("bob", "FS-01", ip="10.0.0.5", ws="PC-VICTIM")
    inv = tmp_path / "inv.csv"
    inv.write_text("hostname,ip\nPC-VICTIM,10.0.0.5\n", encoding="utf-8")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)),
                      "--inventory", str(inv))
    assert [f for f in out["findings"]
            if f["check"] == "relay-mismatch"] == []


def test_rdp_chain(tmp_path):
    evs = [_ntlm4624("alice", f"APP-{i}", ip="10.9.9.9", lt="10")
           for i in range(4)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    hits = [f for f in out["findings"] if f["check"] == "rdp-chain"]
    assert len(hits) == 1 and hits[0]["src"] == "10.9.9.9"
    assert hits[0]["unique_hosts"] == 4


def test_psexec_and_suspicious_service(tmp_path):
    evs = [
        _ev(7045, ServiceName="PSEXESVC", ImagePath=
            "%SystemRoot%\\PSEXESVC.exe",
            AccountName="LocalSystem"),
        _ev(7045, ServiceName="svcupdater",
            ImagePath="\\\\attacker\\share\\implant.exe",
            AccountName=".\\adm"),
        _ev(7045, ServiceName="WSearch", ImagePath=
            "C:\\Windows\\system32\\SearchIndexer.exe",
            AccountName="LocalSystem"),
    ]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    checks = [f["check"] for f in out["findings"]]
    assert "psexec-service" in checks
    assert "suspicious-service" in checks
    # service sah (system32, bukan dir writable) tidak ditandai
    assert not any("WSearch" in f["detail"] for f in out["findings"])


def test_4625_delegated_to_win_logon_triage(tmp_path):
    # brute force/spray = ranah win_logon_triage (#0452, B16) — di sini
    # 4625 hanya masuk stats + catatan eksplisit, NOL temuan duplikat
    evs = [_ev(4625, TargetUserName=f"user{i}", IpAddress="10.5.5.5",
               LogonType="3") for i in range(12)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    assert rc == 0
    assert out["findings"] == []
    assert out["stats"]["eid_4625"] == 12
    assert any("win_logon_triage" in n for n in out["notes"])


def test_svc_interactive(tmp_path):
    ev = _ntlm4624("svc_backup", "PC-77", lt="2")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    hits = [f for f in out["findings"] if f["check"] == "svc-interactive"]
    assert len(hits) == 1 and hits[0]["user"] == "svc_backup"


def test_expl_cred_burst(tmp_path):
    evs = [_ev(4648, TargetUserName="alice", TargetServerName="FS-01",
               IpAddress="10.0.0.5") for _ in range(20)]
    rc, out, _ = _run("--log", str(_file(tmp_path, *evs)))
    hits = [f for f in out["findings"] if f["check"] == "expl-cred-burst"]
    assert len(hits) == 1 and hits[0]["src"] == "FS-01"


def test_4776_counted_in_stats_only(tmp_path):
    ev = _ev(4776, TargetUserName="alice", WorkstationName="PC-1",
             Status="0x0")
    rc, out, _ = _run("--log", str(_file(tmp_path, ev)))
    assert rc == 0 and out["stats"]["eid_4776"] == 1
    assert out["findings"] == []


def test_deterministic_and_dir_mode(tmp_path):
    evs = [_ntlm4624("alice", f"SRV-{i:02d}") for i in range(5)]
    d = tmp_path / "ev"
    d.mkdir()
    (d / "a.xml").write_text("<Events>" + "".join(evs[:3]) + "</Events>",
                             encoding="utf-8")
    (d / "b.xml").write_text("<Events>" + "".join(evs[3:]) + "</Events>",
                             encoding="utf-8")
    rc, out1, _ = _run("--dir", str(d))
    rc2, out2, _ = _run("--dir", str(d))
    assert rc == 0 == rc2
    assert json.dumps(out1) == json.dumps(out2)
    assert out1["stats"]["files"] == 2
    hits = [f for f in out1["findings"] if f["check"] == "pth-spray"]
    assert len(hits) == 1 and hits[0]["unique_hosts"] == 5


def test_out_file(tmp_path):
    ev = _ntlm4624("bob", "FS-01", lm="NTLM V1")
    p = _file(tmp_path, ev)
    outp = tmp_path / "t.json"
    rc, _, _ = _run("--log", str(p), "--out", str(outp))
    assert rc == 0 and outp.is_file()
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        wat.SCHEMA
