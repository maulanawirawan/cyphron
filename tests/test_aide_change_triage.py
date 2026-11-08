"""test_aide_change_triage — triase laporan 'aide --check' offline
(#0626), nol jaringan, tanpa menjalankan AIDE.

Fixture = laporan AIDE sintetis (format klasik 0.15/0.16 + gaya ringkas
baru) yang ditulis dari struktur output publik; bukan salinan kode alat
sumber dan bukan hasil dari host nyata.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import aide_change_triage as act  # noqa: E402

CLASSIC = """AIDE 0.16.2 found differences between database and filesystem!!
Start timestamp: 2026-11-08 03:00:00

Summary:
  Total number of entries:\t20144
  Added entries:\t\t2
  Removed entries:\t\t1
  Changed entries:\t\t4

---------------------------------------------------
Added entries:
---------------------------------------------------

f  /usr/local/bin/suspect-update
f  /etc/chrony.conf.new

---------------------------------------------------
Removed entries:
---------------------------------------------------

f  /boot/vmlinuz-backup

---------------------------------------------------
Changed entries:
---------------------------------------------------

f  /usr/bin/whoami       md5,sha256,size
f  /etc/passwd          md5,sha256
d  /etc                 mtime
f  /var/log/audit.log   mtime
"""


def _write(tmp_path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "aide_change_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


def _by_path(out: dict, path: str) -> "list[dict]":
    return [f for f in out["findings"] if f["path"] == path]


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "aide_change_triage.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--report", str(tmp_path / "nope.txt"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_not_aide_output_exit2(tmp_path):
    p = _write(tmp_path, "rand.txt", "hallo dunia\nbaris kedua\n")
    rc, out, _ = _run("--report", str(p))
    assert rc == 2 and out is None


def test_looks_okay_clean(tmp_path):
    p = _write(tmp_path, "ok.txt",
               "AIDE, version 0.16.2, Looks okay!\n")
    rc, out, _ = _run("--report", str(p))
    assert rc == 0 and out["stats"]["looks_okay"] is True
    assert any("Looks okay" in n for n in out["notes"])


# ------------------------------------------------------- klasifikasi
def test_classic_report_full(tmp_path):
    p = _write(tmp_path, "classic.txt", CLASSIC)
    rc, out, _ = _run("--report", str(p))
    checks = _checks(out)
    assert out["stats"]["added"] == 2
    assert out["stats"]["removed"] == 1
    assert out["stats"]["changed"] == 4
    assert "added-binary-path" in checks          # /usr/local/bin/*
    assert "added-etc-path" in checks             # /etc/chrony.conf.new
    assert "removed-binary-path" in checks        # /boot/vmlinuz-backup
    assert "changed-content-hash" in checks       # whoami + /etc/passwd
    assert checks.count("changed-content-hash") == 2
    assert "changed-etc-path" in checks           # /etc mtime (tanpa hash)
    assert "changed-metadata" in checks           # audit.log mtime
    assert rc == 1  # temuan high ada


def test_severity_assignment(tmp_path):
    p = _write(tmp_path, "classic.txt", CLASSIC)
    _, out, _ = _run("--report", str(p))
    assert _by_path(out, "/usr/local/bin/suspect-update")[0]["severity"] == "high"
    assert _by_path(out, "/etc/chrony.conf.new")[0]["severity"] == "medium"
    assert _by_path(out, "/etc/passwd")[0]["severity"] == "high"
    assert _by_path(out, "/var/log/audit.log")[0]["severity"] == "low"


def test_tmp_addition_medium(tmp_path):
    rep = CLASSIC.replace("/etc/chrony.conf.new", "/tmp/.cache-7821")
    p = _write(tmp_path, "tmp.txt", rep)
    _, out, _ = _run("--report", str(p))
    assert "added-tmp-path" in _checks(out)


def test_hash_attr_beats_metadata(tmp_path):
    rep = CLASSIC.replace("f  /var/log/audit.log   mtime",
                          "f  /var/log/audit.log   sha256,size")
    p = _write(tmp_path, "hash.txt", rep)
    _, out, _ = _run("--report", str(p))
    assert _by_path(out, "/var/log/audit.log")[0]["check"] == \
        "changed-content-hash"


def test_removed_etc_medium(tmp_path):
    rep = CLASSIC.replace("f  /boot/vmlinuz-backup", "f  /etc/cron.deny")
    p = _write(tmp_path, "rm.txt", rep)
    _, out, _ = _run("--report", str(p))
    assert "removed-etc-path" in _checks(out)


def test_new_style_summary(tmp_path):
    """Format ringkas AIDE 0.17: 'added: 1' dst."""
    p = _write(tmp_path, "new.txt", """AIDE 0.17.3 found differences between database and filesystem!!
added:   1
removed: 0
changed: 1

added:
f  /usr/bin/strange

changed:
f  /etc/passwd: sha256,size
""")
    rc, out, _ = _run("--report", str(p))
    checks = _checks(out)
    assert out["stats"]["added"] == 1 and out["stats"]["changed"] == 1
    assert "added-binary-path" in checks
    assert "changed-content-hash" in checks
    assert rc == 1


# ------------------------------------------------------- fail-closed
def test_summary_mismatch_medium(tmp_path):
    rep = CLASSIC.replace("Added entries:\t\t2", "Added entries:\t\t5")
    p = _write(tmp_path, "mis.txt", rep)
    rc, out, _ = _run("--report", str(p))
    assert "summary-mismatch" in _checks(out)
    assert out["stats"]["mismatch"]
    assert any("fail-closed" in n for n in out["notes"])


def test_unparsed_entry_high(tmp_path):
    rep = CLASSIC.replace("f  /etc/chrony.conf.new",
                          "bukan-entry-absolut")
    p = _write(tmp_path, "unp.txt", rep)
    rc, out, _ = _run("--report", str(p))
    assert "entry-unparsed" in _checks(out) and rc == 1
    assert out["stats"]["unparsed"] == 1


def test_clean_report_zero_changes(tmp_path):
    p = _write(tmp_path, "clean.txt", """AIDE 0.16.2 found differences between database and filesystem!!
Summary:
  Total number of entries:\t20144
  Added entries:\t\t0
  Removed entries:\t\t0
  Changed entries:\t\t0
""")
    rc, out, _ = _run("--report", str(p))
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- anti-FP
def test_allow_path_filters_and_records(tmp_path):
    p = _write(tmp_path, "classic.txt", CLASSIC)
    rc, out, _ = _run("--report", str(p),
                      "--allow-path", "/var/log",
                      "--allow-path", "/etc",
                      "--allow-path", "/usr/local/bin")
    remaining = _checks(out)
    assert "added-etc-path" not in remaining
    assert "added-binary-path" not in remaining
    assert "changed-etc-path" not in remaining
    assert "changed-metadata" not in remaining
    # /usr/bin/whoami (hash) & /boot tetap
    assert "changed-content-hash" in remaining
    assert "removed-binary-path" in remaining
    assert out["stats"]["allowed_filtered"] == 5
    assert any("--allow-path" in n for n in out["notes"])


# ------------------------------------------------------- unit
def test_parse_entry_line_unit():
    got = act._parse_entry_line("f  /usr/bin/whoami  md5,sha256,size")
    assert got is not None and got[0] == "/usr/bin/whoami"
    assert got[1] == {"md5", "sha256", "size"}
    got2 = act._parse_entry_line("d  /etc  mtime")
    assert got2 is not None and got2[0] == "/etc"
    assert act._parse_entry_line("bukan-entry") is None


def test_classify_kind_unit():
    assert act._classify_kind("added", "/usr/bin/x", set())[0] == \
        "added-binary-path"
    assert act._classify_kind("changed", "/etc/app.conf",
                              {"mtime"})[0] == "changed-etc-path"
    assert act._classify_kind("changed", "/home/x.txt",
                              {"sha256"})[0] == "changed-content-hash"
    assert act._classify_kind("added", "/tmp/x", set())[0] == \
        "added-tmp-path"
    assert act._classify_kind("added", "/srv/data", set())[0] == \
        "added-path"
