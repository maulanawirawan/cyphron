"""test_linux_auth_triage — triase log autentikasi Linux offline (#0844),
nol jaringan, tanpa host nyata.

Fixture = baris log sintetis mengikuti format publik syslog/sshd/pam
(Debian auth.log + gaya jurnal ISO-8601); bukan salinan kode alat sumber
dan bukan dump host nyata.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import linux_auth_triage as lat  # noqa: E402

AUTH_LOG = """Nov  8 03:10:01 web01 CRON[4101]: (root) CMD (/usr/local/bin/backup.sh)
Nov  8 03:11:02 web01 sshd[4200]: Failed password for invalid user admin from 203.0.113.50 port 40122 ssh2
Nov  8 03:11:03 web01 sshd[4200]: Failed password for invalid user admin from 203.0.113.50 port 40122 ssh2
Nov  8 03:11:04 web01 sshd[4201]: Failed password for invalid user root from 203.0.113.50 port 40124 ssh2
Nov  8 03:11:05 web01 sshd[4201]: Invalid user oracle from 203.0.113.50 port 40126
Nov  8 03:11:06 web01 sshd[4202]: Failed password for alice from 203.0.113.50 port 40130 ssh2
Nov  8 03:11:07 web01 sshd[4202]: Failed password for alice from 203.0.113.50 port 40130 ssh2
Nov  8 03:11:08 web01 sshd[4202]: Failed password for alice from 203.0.113.50 port 40130 ssh2
Nov  8 03:12:00 web01 sshd[4203]: Connection closed by 10.0.0.9 port 51000 [preauth]
Nov  8 03:12:30 web01 sshd[4210]: Accepted publickey for deploy from 203.0.113.50 port 40150 ssh2
Nov  8 03:12:45 web01 sshd[4211]: Accepted password for alice from 203.0.113.50 port 40152 ssh2
Nov  8 03:13:00 web01 sshd[4210]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Nov  8 03:14:00 web01 sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id
Nov  8 03:15:00 web01 su[4301]: (to root) deploy on pts/0
Nov  8 03:16:00 web01 su[4310]: FAILED su for root by bob
Nov  8 03:17:00 web01 su[4320]: (pam_unix) authentication failure; logname= uid=1002 euid=0 tty=pts/2 ruser=bob rhost=  user=root
Nov  8 03:18:00 web01 useradd[4400]: new user: name=svcbackup, UID=1003, GID=1003, home=/home/svcbackup, shell=/bin/bash
Nov  8 03:19:00 web01 groupadd[4401]: new group: name=ops (GID=1005)
Nov  8 03:20:00 web01 usermod[4402]: add 'svcbackup' to group 'sudo'
Nov  8 03:21:00 web01 userdel[4403]: delete user 'tempintern'
Nov  8 03:22:00 web01 sshd[4500]: Accepted password for root from 198.51.100.7 port 50100 ssh2
Nov  8 03:23:00 web01 systemd-logind[900]: New session 42 of user alice.
"""

ISO_LOG = """2026-11-08T04:00:00.123456+00:00 web02 sshd[500]: Accepted publickey for root from 198.51.100.9 port 55000 ssh2
2026-11-08T04:01:00.123456+00:00 web02 sudo:  root : TTY=unknown ; PWD=/root ; USER=root ; COMMAND=/bin/ls
"""

UNKNOWN_SSHD = ("Nov  8 03:30:00 web01 sshd[4600]: "
                "kx-blah-unknown-format-9999 from 1.2.3.4\n")


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "linux_auth_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "linux_auth_triage.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--log", str(tmp_path / "nope.log"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_not_a_log_exit2(tmp_path):
    p = _write(tmp_path, "rand.txt", "hallo dunia\nbaris kedua\n")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "fail-closed" in err


# ------------------------------------------------------- parse
def test_accepted_failed_invalid_counted(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    rc, out, _ = _run("--log", str(p), "--fail-on", "info")
    assert rc == 1
    st = out["stats"]["events"]
    assert st["accepted"] == 3
    assert st["failed"] == 6
    assert st["invalid_user"] == 1
    assert st["sudo_commands"] == 1
    assert st["su_sessions"] == 1
    assert st["cron_execs"] == 1
    assert st["account_changes"] == 3


def test_iso_header_style(tmp_path):
    p = _write(tmp_path, "iso.log", ISO_LOG)
    rc, out, _ = _run("--log", str(p), "--fail-on", "low")
    assert rc == 0
    assert out["stats"]["events"]["accepted"] == 1
    pk = [f for f in out["findings"]
          if f["check"] == "publickey-root-login"]
    assert len(pk) == 1
    ev = out["events"][0]
    assert ev["ts"].startswith("2026-11-08T04:00:00")
    assert ev["method"] == "publickey"


def test_pam_session_noise_ignored(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    # pam_unix(sshd:session) + logind "New session" = noise global
    assert out["stats"]["lines_ignored_noise"] >= 2
    assert out["stats"]["lines_other_proc"] == 0


# ------------------------------------------------------- temuan
def test_bruteforce_source(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--min-fail", "5")
    bf = [f for f in out["findings"]
          if f["check"] == "bruteforce-source"
          and f.get("source_ip") == "203.0.113.50"]
    assert len(bf) == 1
    # 6 gagal (< 2x ambang 5), 3 user unik (< 5) -> medium
    assert bf[0]["severity"] == "medium"


def test_bruteforce_success_after_fails(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    bs = [f for f in out["findings"] if f["check"] == "bruteforce-success"]
    assert len(bs) == 1
    assert bs[0]["user"] == "alice"
    assert bs[0]["source_ip"] == "203.0.113.50"


def test_root_password_login(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p))
    rp = [f for f in out["findings"]
          if f["check"] == "root-password-login"]
    assert len(rp) == 1
    assert rp[0]["source_ip"] == "198.51.100.7"
    assert rp[0]["severity"] == "high"


def test_sudo_group_add(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p))
    sg = [f for f in out["findings"] if f["check"] == "sudo-group-add"]
    assert len(sg) == 1
    assert sg[0]["user"] == "svcbackup"
    assert sg[0]["group"] == "sudo"


def test_new_account_interactive_shell(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    na = [f for f in out["findings"] if f["check"] == "new-account"]
    assert len(na) == 1
    assert na[0]["shell"] == "/bin/bash"
    assert na[0]["severity"] == "medium"


def test_su_failure(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    sf = [f for f in out["findings"] if f["check"] == "su-failure"]
    assert len(sf) == 2  # FAILED su + pam failure
    assert all(f["severity"] == "medium" for f in sf)


def test_account_removal_info(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    ar = [f for f in out["findings"] if f["check"] == "account-removal"]
    assert len(ar) == 1 and ar[0]["user"] == "tempintern"


def test_line_unparsed_fail_closed(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG + UNKNOWN_SSHD)
    _, out, _ = _run("--log", str(p), "--fail-on", "info")
    lu = [f for f in out["findings"] if f["check"] == "line-unparsed"]
    assert len(lu) == 1 and lu[0]["severity"] == "high"
    assert out["stats"]["line_unparsed"] == 1


# ------------------------------------------------------- anti-FP
def test_allow_ip_filters(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p), "--min-fail", "5",
                     "--allow-ip", "203.0.113.50", "--fail-on", "info")
    ips = [f.get("source_ip") for f in out["findings"]]
    assert "203.0.113.50" not in ips
    assert out["stats"]["allowed_filtered"] >= 2


def test_single_fail_then_success_no_beacon_finding(tmp_path):
    # 1 kegagalan (typo) lalu sukses = NORMAL, bukan bruteforce-success
    p = _write(tmp_path, "ok.log",
               "Nov  8 09:00:00 lab sshd[1]: Failed password for alice "
               "from 10.1.1.5 port 40000 ssh2\n"
               "Nov  8 09:00:05 lab sshd[1]: Accepted password for alice "
               "from 10.1.1.5 port 40001 ssh2\n")
    rc, out, _ = _run("--log", str(p))
    assert rc == 0
    assert "bruteforce-success" not in _checks(out)


def test_benign_log_clean(tmp_path):
    benign = (
        "Nov  8 09:00:00 lab sshd[1]: Server listening on 0.0.0.0 port 22.\n"
        "Nov  8 09:01:00 lab sshd[2]: Accepted publickey for alice from "
        "10.1.1.5 port 40000 ssh2\n"
        "Nov  8 09:02:00 lab sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/apt update\n"
        "Nov  8 09:03:00 lab su[9]: (to root) alice on pts/0\n"
    )
    p = _write(tmp_path, "benign.log", benign)
    rc, out, _ = _run("--log", str(p))
    assert rc == 0
    assert "line-unparsed" not in _checks(out)
    assert out["stats"]["events"]["accepted"] == 1


# ------------------------------------------------------- kontrak output
def test_fail_on_high(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    rc, out, _ = _run("--log", str(p), "--fail-on", "high")
    assert rc == 1
    # laporan memuat SEMUA temuan; exit diatur ambang — high ada di antaranya
    highs = [f for f in out["findings"]
             if lat.SEV_ORDER[f["severity"]]
             >= lat.SEV_ORDER["high"]]
    assert len(highs) >= 3  # bruteforce-success, root-password, sudo-group


def test_multiple_logs_merged(tmp_path):
    a = _write(tmp_path, "a.log", ISO_LOG)
    b = _write(tmp_path, "b.log",
               "Nov  8 05:00:00 web03 sshd[10]: Accepted publickey for "
               "root from 198.51.100.9 port 55001 ssh2\n")
    rc, out, _ = _run("--log", str(a), "--log", str(b),
                      "--fail-on", "info")
    assert rc == 1  # publickey-root-login (info) masuk saat fail-on info
    assert out["stats"]["events"]["accepted"] == 2


def test_schema_and_sorted_findings(tmp_path):
    p = _write(tmp_path, "auth.log", AUTH_LOG)
    _, out, _ = _run("--log", str(p))
    assert out["schema"] == lat.SCHEMA
    sevs = [lat.SEV_ORDER[f["severity"]] for f in out["findings"]]
    assert sevs == sorted(sevs, reverse=True)
    assert all({"check", "severity", "message", "evidence"}
               <= set(f) for f in out["findings"])
    assert any("linux_persist_scan" in n for n in out["notes"])
