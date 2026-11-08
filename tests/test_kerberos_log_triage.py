"""test_kerberos_log_triage — triase log Kerberos XML utk indikasi
golden ticket (#0418 #0419), nol jaringan.

Fixture = ekspor Windows Security XML sintetis (Event 4768/4769/4771)
dari spesifikasi konsep sumber: RC4 di lingkungan AES-only, TGS tanpa
TGT, lifetime anomali.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import kerberos_log_triage as klt  # noqa: E402


def _ev(eid: int, user: str, etype: str, ip: str = "::ffff:10.0.0.5",
        time: str = "2026-01-01T10:00:00.000Z",
        extra: str = "") -> str:
    return (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/windows/'
        f'events/log"><System><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{time}"/></System><EventData>'
        f'<Data Name="TargetUserName">{user}</Data>'
        f'<Data Name="IpAddress">{ip}</Data>'
        f'<Data Name="TicketEncryptionType">{etype}</Data>'
        f'{extra}</EventData></Event>')


def _file(tmp_path, *events: str) -> Path:
    p = tmp_path / "sec.xml"
    p.write_text("<Events>" + "".join(events) + "</Events>",
                 encoding="utf-8")
    return p


def _run(*args: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "kerberos_log_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


# ------------------------------------------------------- parsing
def test_parse_event_order_and_fields(tmp_path):
    p = _file(tmp_path,
              _ev(4769, "bob@CORP", "0x12",
                  time="2026-01-01T10:05:00.000Z"),
              _ev(4768, "bob@CORP", "0x12"))
    events = klt.parse_events(p.read_text(encoding="utf-8"), "sec.xml")
    assert [e["eid"] for e in events] == [4768, 4769]  # terurut waktu
    assert events[0]["user"] == "bob@CORP"
    assert events[0]["ip"] == "10.0.0.5"  # prefix ::ffff: di-strip


def test_unrelated_events_ignored_and_fail_closed(tmp_path):
    p = tmp_path / "lain.xml"
    p.write_text('<Events><Event><System><EventID>4624</EventID>'
                 '</System></Event></Events>', encoding="utf-8")
    try:
        klt.parse_events(p.read_text(encoding="utf-8"), "lain.xml")
        raise AssertionError("harusnya ValueError")
    except ValueError:
        pass


# ------------------------------------------------------- deteksi
def test_rc4_downgrade_severity_by_policy(tmp_path):
    p = _file(tmp_path,
              _ev(4768, "bob@CORP", "0x17"),
              _ev(4769, "bob@CORP", "0x12"))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"),
                   enforce_aes=True, max_lifetime_h=10.0)
    rc4 = [f for f in r["findings"] if f["type"] == "rc4-downgrade"]
    assert len(rc4) == 1 and rc4[0]["severity"] == "high"
    assert r["rc4_by_user"] == {"bob@CORP": 1}

    r2 = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                     "sec.xml"),
                    enforce_aes=False, max_lifetime_h=10.0)
    rc4b = [f for f in r2["findings"] if f["type"] == "rc4-downgrade"]
    assert rc4b[0]["severity"] == "medium"


def test_aes_only_no_finding(tmp_path):
    p = _file(tmp_path, _ev(4768, "bob@CORP", "0x12"),
              _ev(4769, "bob@CORP", "0x12"))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"), True, 10.0)
    assert r["findings"] == []
    # satu-satunya catatan = batasan telemetri lifetime (bukan temuan)
    assert all("TicketStartTime" in n for n in r["notes"])


def test_tgs_without_tgt(tmp_path):
    # hanya 4769 (bob) + TGT milik lain -> bob = indikasi
    p = _file(tmp_path,
              _ev(4768, "alice@CORP", "0x12"),
              _ev(4769, "bob@CORP", "0x12"))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"), False, 10.0)
    orphan = [f for f in r["findings"] if f["type"] == "tgs-tanpa-tgt"]
    assert len(orphan) == 1
    assert orphan[0]["user"] == "bob@CORP"
    assert orphan[0]["severity"] == "high"
    # alice punya TGT -> tidak di-flag
    assert all(f["user"] != "alice@CORP" for f in orphan)


def test_tgs_without_tgt_note_when_no_4768(tmp_path):
    p = _file(tmp_path, _ev(4769, "bob@CORP", "0x12"))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"), False, 10.0)
    assert any("tidak ada Event 4768" in n for n in r["notes"])


def test_lifetime_anomaly_detected_when_fields_present(tmp_path):
    extra = ('<Data Name="TicketStartTime">2026-01-01T00:00:00.000Z</Data>'
             '<Data Name="TicketEndTime">2026-01-11T00:00:00.000Z</Data>')
    p = _file(tmp_path, _ev(4768, "bob@CORP", "0x12", extra=extra))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"), False, 10.0)
    lt = [f for f in r["findings"] if f["type"] == "lifetime-anomali"]
    assert len(lt) == 1 and lt[0]["etime"] == 240.0


def test_lifetime_skipped_without_fields(tmp_path):
    p = _file(tmp_path, _ev(4768, "bob@CORP", "0x12"))
    r = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                    "sec.xml"), False, 10.0)
    assert any("TicketStartTime" in n for n in r["notes"])


def test_deterministic_sorted_output(tmp_path):
    p = _file(tmp_path, _ev(4769, "bob@CORP", "0x17"),
              _ev(4769, "alice@CORP", "0x12"))
    r1 = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                     "sec.xml"), False, 10.0)
    r2 = klt.triage(klt.parse_events(p.read_text(encoding="utf-8"),
                                     "sec.xml"), False, 10.0)
    assert r1 == r2
    keys = [(f["type"], f["user"], f["ip"]) for f in r1["findings"]]
    assert keys == sorted(keys)


# ------------------------------------------------------- CLI
def test_cli_end_to_end(tmp_path):
    p = _file(tmp_path, _ev(4769, "bob@CORP", "0x17"))
    out = tmp_path / "triase.json"
    rc, payload = _run("--log", str(p), "--enforce-aes",
                       "--out", str(out))
    assert rc == 0
    assert payload["schema"] == "secai.kerberos-log-triage/1"
    assert payload["stats"]["tgs_4769"] == 1
    assert out.read_text(encoding="utf-8").startswith("{")


def test_cli_fail_closed(tmp_path):
    rc, _ = _run("--log", str(tmp_path / "hilang.xml"))
    assert rc == 2
    bad = tmp_path / "bad.xml"
    bad.write_text("<Events><Event>", encoding="utf-8")
    rc, _ = _run("--log", str(bad))
    assert rc == 2
