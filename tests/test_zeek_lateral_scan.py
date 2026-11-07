"""test_zeek_lateral_scan — triase log Zeek TSV/JSONL utk lateral
movement: admin share, SMB spread, DCE-RPC service/WMI, NTLM spray
(#0427), nol jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import zeek_lateral_scan as zls  # noqa: E402


def _tsv(path: Path, fields: "list[str]", rows: "list[list[str]]") -> Path:
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields)]
    lines += ["\t".join(r) for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _dir(tmp_path: Path) -> Path:
    d = tmp_path / "zeek"
    d.mkdir()
    return d


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "zeek_lateral_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


# ------------------------------------------------------- parsing
def test_tsv_and_json_mixed(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "conn.log", ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
         [["1700000000.1", "10.0.0.1", "10.0.0.2", "445"]])
    (d / "ntlm.log").write_text(
        '{"ts":1,"id":{"orig_h":"10.0.0.1","resp_h":"10.0.0.5"},'
        '"username":"alice","success":"T"}\n', encoding="utf-8")
    rc, out, _ = _run("--dir", str(d))
    assert rc == 0
    assert out["stats"]["parsed_conn"] == 1
    assert out["stats"]["parsed_ntlm"] == 1


def test_unknown_dir_fails_closed(tmp_path):
    d = tmp_path / "kosong"
    d.mkdir()
    rc, out, err = _run("--dir", str(d))
    assert rc == 2 and "tidak ada log Zeek" in err


def test_missing_logs_noted(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "conn.log", ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
         [["1", "10.0.0.1", "10.0.0.2", "80"]])
    rc, out, _ = _run("--dir", str(d))
    assert rc == 0
    assert any("smb_mapping.log tidak tersedia" in n
               for n in out["notes"])


# ------------------------------------------------------- cek SMB
def test_admin_share_access(tmp_path):
    d = _dir(tmp_path)
    rows = [["1", "10.0.0.9", f"10.0.0.{i}", f"\\\\{(chr(67))}$"]
            for i in range(10, 13)]
    _tsv(d / "smb_mapping.log",
         ["ts", "id.orig_h", "id.resp_h", "path"], rows)
    rc, out, _ = _run("--dir", str(d))
    hits = [f for f in out["findings"] if f["check"] ==
            "admin-share-access"]
    assert len(hits) == 1 and hits[0]["src"] == "10.0.0.9"
    assert hits[0]["unique_hosts"] == 3


def test_admin_share_below_threshold(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "smb_mapping.log",
         ["ts", "id.orig_h", "id.resp_h", "path"],
         [["1", "10.0.0.9", "10.0.0.2", "\\\\C$"]])
    rc, out, _ = _run("--dir", str(d), "--share-hosts", "3")
    assert [f for f in out["findings"] if f["check"] ==
            "admin-share-access"] == []


def test_smb_spread(tmp_path):
    d = _dir(tmp_path)
    rows = [["1", "10.0.0.9", f"10.0.0.{i}", "445"] for i in range(15)]
    rows.append(["1", "10.0.0.9", "10.0.0.99", "80"])  # bukan 445
    _tsv(d / "conn.log", ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
         rows)
    rc, out, _ = _run("--dir", str(d))
    hits = [f for f in out["findings"] if f["check"] == "smb-spread"]
    assert len(hits) == 1 and hits[0]["unique_hosts"] == 15


# ------------------------------------------------------- cek DCE-RPC
def test_dce_remote_service_and_wmi(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "dce_rpc.log",
         ["ts", "id.orig_h", "id.resp_h", "endpoint", "operation"],
         [["1", "10.0.0.9", "10.0.0.2", "svcctl", "CreateServiceW"],
          ["1", "10.0.0.9", "10.0.0.3", "atsvc", "SchEnumerate"],
          ["1", "10.0.0.9", "10.0.0.4", "IWbemServices", "ExecMethod"],
          ["1", "10.0.0.9", "10.0.0.5", "IWbemServices", "GetObject"]])
    rc, out, _ = _run("--dir", str(d))
    checks = [f["check"] for f in out["findings"]]
    assert "dce-remote-service" in checks
    assert "dce-wmi" in checks  # 2 host wbem >= 2
    svc = [f for f in out["findings"]
           if f["check"] == "dce-remote-service"]
    assert len(svc) == 2  # (src,dst) 2 pasangan svcctl+atsvc


# ------------------------------------------------------- cek NTLM
def test_ntlm_spray(tmp_path):
    d = _dir(tmp_path)
    rows = [["1", "10.0.0.9", f"10.0.0.{i}", "svc-backup", "T"]
            for i in range(4)]
    _tsv(d / "ntlm.log",
         ["ts", "id.orig_h", "id.resp_h", "username", "success"], rows)
    rc, out, _ = _run("--dir", str(d))
    hits = [f for f in out["findings"] if f["check"] == "ntlm-spray"]
    assert len(hits) == 1 and hits[0]["unique_hosts"] == 4


def test_ntlm_fail_burst(tmp_path):
    d = _dir(tmp_path)
    rows = [["1", "10.0.0.9", "10.0.0.2", f"u{i}", "F"] for i in range(11)]
    _tsv(d / "ntlm.log",
         ["ts", "id.orig_h", "id.resp_h", "username", "success"], rows)
    rc, out, _ = _run("--dir", str(d))
    hits = [f for f in out["findings"] if f["check"] == "ntlm-fail-burst"]
    assert len(hits) == 1 and hits[0]["src"] == "10.0.0.9"


# ------------------------------------------------------- cek smb_files
def test_smb_file_write_admin_share(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "smb_files.log",
         ["ts", "id.orig_h", "id.resp_h", "path", "name", "action"],
         [["1", "10.0.0.9", "10.0.0.2", "\\\\ADMIN$", "implant.exe",
           "SMB::FILE_WRITE"],
          ["1", "10.0.0.9", "10.0.0.2", "\\\\docs", "report.docx",
           "SMB::FILE_WRITE"]])
    rc, out, _ = _run("--dir", str(d))
    hits = [f for f in out["findings"] if f["check"] == "smb-file-write"]
    assert len(hits) == 1
    assert "implant.exe" in hits[0]["detail"]


# ------------------------------------------------------- umum
def test_clean_verdict_and_determinism(tmp_path):
    d = _dir(tmp_path)
    for name, fields, rows in [
        ("conn.log", ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
         [["1", "10.0.0.1", "10.0.0.2", "80"]]),
        ("smb_mapping.log",
         ["ts", "id.orig_h", "id.resp_h", "path"],
         [["1", "10.0.0.1", "10.0.0.2", "\\\\docs"]]),
        ("dce_rpc.log",
         ["ts", "id.orig_h", "id.resp_h", "endpoint", "operation"],
         [["1", "10.0.0.1", "10.0.0.2", "EPH", "OpNum1"]]),
        ("ntlm.log",
         ["ts", "id.orig_h", "id.resp_h", "username", "success"],
         [["1", "10.0.0.1", "10.0.0.2", "alice", "T"]]),
    ]:
        _tsv(d / name, fields, rows)
    rc, out, _ = _run("--dir", str(d))
    rc2, out2, _ = _run("--dir", str(d))
    assert rc == 0 and out["verdict"] == "CLEAN_NO_LATERAL_LEAD"
    assert json.dumps(out) == json.dumps(out2)


def test_out_file_written(tmp_path):
    d = _dir(tmp_path)
    _tsv(d / "conn.log", ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
         [["1", "10.0.0.1", "10.0.0.2", "80"]])
    outp = tmp_path / "t.json"
    rc, _, _ = _run("--dir", str(d), "--out", str(outp))
    assert rc == 0 and outp.is_file()
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        zls.SCHEMA


def test_explicit_files_mode(tmp_path):
    conn = _tsv(tmp_path / "c.log",
                ["ts", "id.orig_h", "id.resp_h", "id.resp_p"],
                [["1", "10.0.0.1", "10.0.0.2", "80"]])
    rc, out, _ = _run("--conn", str(conn))
    assert rc == 0 and out["stats"]["parsed_conn"] == 1
