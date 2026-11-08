"""test_linux_privesc_audit — audit vektor privesc Linux offline
(#0876), nol jaringan.

Fixture = rootfs sintetis + daftar find/ls/getcap sintetis dibangun
runtime (tanpa salinan dump host nyata). Cek berbasis mode POSIX
(SUID/SGID/world-writable) hanya bisa dibuat & divalidasi di platform
POSIX — di Windows chmod tidak menyetel bit tersebut, jadi kasus mode
di-skip eksplisit (bukan didiam-diamkan).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import linux_privesc_audit as lpa  # noqa: E402

POSIX = sys.platform != "win32"


def _write(p: Path, text: str, mode: "int | None" = None) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    if mode is not None and POSIX:
        os.chmod(p, mode)
    return p


SUDOERS = """\
Defaults env_reset
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL:ALL) ALL
Cmnd_Alias LOGTOOLS = /usr/bin/less, /usr/bin/more
alice ALL=(root) NOPASSWD: LOGTOOLS
deploy ALL=(root) NOPASSWD: /usr/bin/vim /etc/nginx/nginx.conf
backup ALL=(root) NOPASSWD: ALL
svc ALL=(root) /usr/bin/systemctl restart app
@includedir /etc/sudoers.d
"""

PASSWD = """\
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:backdoor account:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/sh
"""

SHADOW = """\
root:$6$rootpwd:18000:0:99999:7:::
alice:$6$alicepwd:18000:0:99999:7:::
svcacct::18000:0:99999:7:::
"""

GROUP = """\
root:x:0:
docker:x:998:bob
wheel:x:10:alice
users:x:100:
"""

EXPORTS = """\
/srv/share *(rw,no_root_squash,sync)
/data 10.0.0.0/8(ro,sync)
"""


def build_rootfs(base: Path) -> Path:
    root = base / "rootfs"
    _write(root / "etc" / "sudoers", SUDOERS)
    _write(root / "etc" / "sudoers.d" / "10-ops",
           "ops ALL=(root) NOPASSWD: /usr/bin/less /var/log/syslog\n")
    # file dgn '.' di nama = diabaikan semantik sudo
    _write(root / "etc" / "sudoers.d" / "ignore.me",
           "nope ALL=(root) NOPASSWD: /usr/bin/tar\n")
    _write(root / "etc" / "passwd", PASSWD)
    _write(root / "etc" / "shadow", SHADOW)
    _write(root / "etc" / "group", GROUP)
    _write(root / "etc" / "exports", EXPORTS)
    _write(root / "etc" / "crontab",
           "0 2 * * * root /usr/local/sbin/backup.sh *\n"
           "30 3 * * * root /etc/cron-scripts/cleanup.sh\n"
           "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n")
    _write(root / "etc" / "cron-scripts" / "cleanup.sh",
           "#!/bin/sh\nrm -rf /tmp/cache\n", mode=0o666)
    _write(root / "usr" / "local" / "sbin" / "backup.sh",
           "#!/bin/sh\ntar czf /backup.tgz /data\n", mode=0o755)
    _write(root / "etc" / "app.conf", "key=value\n", mode=0o666)
    _write(root / "etc" / "systemd" / "system" / "collector.service",
           "[Service]\nExecStart=/opt/collector\n", mode=0o666)
    _write(root / "etc" / "profile",
           'PATH="/usr/local/sbin:/usr/local/bin:/opt/tools/bin"\n')
    (root / "opt" / "tools" / "bin").mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(root / "opt" / "tools" / "bin", 0o777)
    # SUID: standar (su), tak lazim (backup-helper), parent writable,
    # berkas world-writable
    _write(root / "usr" / "bin" / "su", "ELF...", mode=0o4755)
    _write(root / "usr" / "local" / "bin" / "backup-helper", "ELF...",
           mode=0o4755)
    (root / "var" / "tmp").mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(root / "var" / "tmp", 0o1777)  # sticky — aman
    _write(root / "var" / "tmp" / "staged", "ELF...", mode=0o4755)
    (root / "home" / "alice").mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(root / "home" / "alice", 0o777)  # tanpa sticky
    _write(root / "home" / "alice" / "sneaky", "ELF...", mode=0o4755)
    _write(root / "usr" / "local" / "bin" / "writable-suid", "ELF...",
           mode=0o4777)
    # SGID di luar prefiks standar
    _write(root / "opt" / "agent" / "helper-sgid", "ELF...", mode=0o2755)
    return root


def _ids(res: dict) -> "list[str]":
    return [f["id"] for f in res["findings"]]


def test_content_findings(tmp_path: Path) -> None:
    root = build_rootfs(tmp_path)
    rc = lpa.main(["--root", str(root), "--out",
                   str(tmp_path / "out.json")])
    res = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    ids = _ids(res)
    # sudo
    assert "sudo-nopasswd-risky" in ids          # less (alias) + vim
    assert "sudo-nopasswd-all" in ids            # backup NOPASSWD: ALL
    risky = [f for f in res["findings"]
             if f["id"] == "sudo-nopasswd-risky"]
    joined = " ".join(f["poc"] for f in risky)
    assert "less" in joined and "vim" in joined
    # sudoers.d dengan '.' tidak ikut (tar tidak boleh muncul)
    assert "/usr/bin/tar" not in joined
    assert "/usr/bin/less" in joined
    assert "sudo-wildcard-arg" not in ids        # tidak ada wildcard sudo
    # passwd/shadow/group
    assert "uid-0-account" in ids
    assert "shadow-empty-password" in ids
    assert "risky-group-membership" in ids
    sev = {f["poc"]: f["severity"] for f in res["findings"]
           if f["id"] == "risky-group-membership"}
    assert any("docker" in k for k in sev)
    assert all(sev[k] == "medium"
               for k in sev if "wheel" in k)     # alice human -> review
    # nfs
    assert "nfs-no-root-squash" in ids
    assert "nfs-world-export" not in ids
    # cron
    assert "cron-wildcard-args" in ids            # backup.sh *
    assert "cron-writable-target" in ids          # cleanup.sh 0666
    # anti-FP: baris root/%wheel standar TIDAK jadi temuan
    runas_all = [f for f in res["findings"]
                 if f["id"] == "sudo-runas-all"]
    assert not runas_all
    assert res["stats"]["sudo_files"] == 2        # sudoers + 10-ops
    assert rc == 1


def test_mode_findings_posix(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("bit SUID/SGID/writable tak bisa disetel di Windows")
    root = build_rootfs(tmp_path)
    rc = lpa.main(["--root", str(root), "--out",
                   str(tmp_path / "out.json")])
    res = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "suid-unexpected-location" in ids      # backup-helper, dst.
    assert "suid-writable-dir" in ids             # home/alice 0777
    assert "suid-writable-file" in ids            # writable-suid 04777
    assert "sgid-unexpected-location" in ids      # opt/agent/helper-sgid
    assert "worldwritable-etc" in ids             # etc/app.conf
    assert "worldwritable-unit" in ids            # systemd collector
    assert "path-dir-writable" in ids             # /opt/tools/bin
    # SUID standar /usr/bin/su TIDAK ditemukan; parent /usr/bin normal
    su_findings = [f for f in res["findings"]
                   if "su" == Path(f["poc"]).name]
    assert not su_findings
    # var/tmp sticky TIDAK dianggap writable-dir
    sticky = [f for f in res["findings"]
              if f["id"] == "suid-writable-dir" and "var/tmp" in f["poc"]]
    assert not sticky
    assert res["stats"]["suid_found"] == 5
    assert rc == 1
    # allow-path: pengecualian tercatat
    rc2 = lpa.main(["--root", str(root),
                    "--allow-path", "/usr/local/bin/backup-helper",
                    "--out", str(tmp_path / "out2.json")])
    res2 = json.loads((tmp_path / "out2.json").read_text(encoding="utf-8"))
    assert "backup-helper" not in " ".join(
        f["poc"] for f in res2["findings"])
    assert rc2 == 1


def test_cap_list(tmp_path: Path) -> None:
    capf = tmp_path / "getcap.out"
    capf.write_text(
        "/usr/bin/ping = cap_net_raw+ep\n"
        "/usr/local/bin/pywrap = cap_setuid+ep\n",
        encoding="utf-8")
    rc = lpa.main(["--cap-list", str(capf)])
    assert rc == 1
    # versi file-out utk inspeksi
    out = tmp_path / "cap.json"
    lpa.main(["--cap-list", str(capf), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "filecap-risky" in ids
    poc = [f["poc"] for f in res["findings"]
           if f["id"] == "filecap-risky"]
    assert any("pywrap" in p for p in poc)
    assert res["stats"]["cap_list_entries"] == 2
    # /usr/bin/ping cap_net_raw di prefiks standar = bukan risky
    assert not any("ping" in p for p in poc)


def test_suid_list_formats(tmp_path: Path) -> None:
    # format find (path polos) + format ls -l (dgn bit 's')
    lf = tmp_path / "find.out"
    lf.write_text(
        "/usr/local/bin/backup-helper\n"
        "-rwsr-xr-x 1 root root 12345 Jan  1 12:00 /opt/agent/agent-suid\n"
        "-rwxr-sr-x 1 root root  9999 Jan  1 12:00 /opt/agent/agent-sgid\n"
        "drwxr-xr-x 2 root root  4096 Jan  1 12:00 /opt/agent\n",
        encoding="utf-8")
    out = tmp_path / "suid.json"
    rc = lpa.main(["--suid-list", str(lf), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "suid-unexpected-location" in ids
    pocs = " ".join(f["poc"] for f in res["findings"])
    assert "backup-helper" in pocs
    assert "agent-suid" in pocs
    assert "agent-sgid" in pocs                   # bit s grup
    assert "/opt/agent\n" not in pocs and "4096" not in pocs  # dir dibuang
    assert res["stats"]["suid_list_entries"] == 3
    assert rc == 1
    # suid-list tak terbaca = fail-closed
    rc2 = lpa.main(["--suid-list", str(tmp_path / "missing.txt")])
    assert rc2 == 2


def test_fail_closed(tmp_path: Path) -> None:
    # tanpa sumber -> exit 2
    assert lpa.main([]) == 2
    # root tak ada -> exit 2
    assert lpa.main(["--root", str(tmp_path / "nope")]) == 2
    # --root tanpa sudoers -> sudoers-missing medium (fail-closed)
    empty = tmp_path / "empty"
    (empty / "etc").mkdir(parents=True)
    out = tmp_path / "empty.json"
    rc = lpa.main(["--root", str(empty), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert "sudoers-missing" in _ids(res)
    assert res["verdict"] == "findings"
    assert rc == 1
    # NOPASSWD perintah netral = temuan low (sudo-nopasswd-other);
    # skenario verdict clean (butuh mode POSIX) ada di
    # test_clean_verdict_posix
    clean = tmp_path / "clean"
    _write(clean / "etc" / "sudoers",
           "ops ALL=(root) NOPASSWD: /usr/bin/logrotate "
           "/etc/logrotate.d/app\n")
    out2 = tmp_path / "clean.json"
    lpa.main(["--root", str(clean), "--out", str(out2)])
    res2 = json.loads(out2.read_text(encoding="utf-8"))
    assert "sudo-nopasswd-other" in _ids(res2)


def test_cli_subprocess(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("fixture SUID butuh POSIX mode bits")
    root = build_rootfs(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "linux_privesc_audit.py"),
         "--root", str(root), "--fail-on", "high"],
        capture_output=True, text=True, timeout=120)
    res = json.loads(proc.stdout)
    assert res["schema"] == lpa.SCHEMA
    # --fail-on high: temuan high tetap ada -> rc 1; clean tak mungkin
    assert proc.returncode == 1
    assert any(f["severity"] == "high" for f in res["findings"])


def test_xattr_capability(tmp_path: Path) -> None:
    if not hasattr(os, "setxattr"):
        pytest.skip("os.setxattr tidak tersedia di platform ini")
    root = tmp_path / "rootfs"
    _write(root / "etc" / "sudoers", "root ALL=(ALL:ALL) ALL\n")
    pywrap = _write(root / "usr" / "local" / "bin" / "pywrap", "ELF...")
    try:
        os.setxattr(str(pywrap), "security.capability",
                    bytes.fromhex("0000000002000000800000000000000000"))
    except OSError:
        pytest.skip("xattr security.capability tak bisa disetel di sini")
    out = tmp_path / "xattr.json"
    lpa.main(["--root", str(root), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    ids = _ids(res)
    assert "filecap-risky" in ids
    assert any("pywrap" in f["poc"] and "cap_setuid" in f["message"]
               for f in res["findings"] if f["id"] == "filecap-risky")
