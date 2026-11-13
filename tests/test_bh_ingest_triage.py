"""test_bh_ingest_triage — triase pasif ekspor BloodHound, nol jaringan.

Fixture = JSON sintetis format BloodHound 4.x ({"data":[...],"meta":...})
dengan kontrol false-positive (objek AD bersih tidak boleh memicu temuan).
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import bh_ingest_triage as bht  # noqa: E402


def _run(*args: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "bh_ingest_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _user(name: str, **props) -> dict:
    base = {"type": "user", "name": name,
            "Properties": {"name": name, "enabled": True}}
    base["Properties"].update(props)
    return base


def _fixture() -> dict:
    return {
        "data": [
            {"type": "user",
             "Properties": {"name": "SVC_BACKUP@CORP.LOCAL",
                            "dontreqpreauth": True}},
            {"type": "user",
             "Properties": {"name": "TEMP1@CORP.LOCAL",
                            "passwordnotrequired": True}},
            {"type": "user",
             "Properties": {"name": "LEGACY@CORP.LOCAL",
                            "pwdneverexpires": True}},
            {"type": "user",
             "Properties": {"name": "SQL@CORP.LOCAL",
                            "serviceprincipalnames": ["MSSQLSvc/sql.corp.local"]}},
            {"type": "computer",
             "Properties": {"name": "DC01.CORP.LOCAL",
                            "unconstraineddelegation": True}},
            {"type": "gpo",
             "Properties": {"name": "GPP-OLD",
                            "gpcmachineextensionnames":
                                "{3542E497-}Groups.xml/{...}"}},
            {"type": "domain",
             "Properties": {"name": "CORP.LOCAL"},
             "Aces": [
                 {"PrincipalName": "HELPDESK@CORP.LOCAL",
                  "RightName": "ExtendedRight",
                  "AceType": "All",
                  "PrincipalSID": "S-1-5-21-1"}]},
        ],
        "meta": {"version": 4, "type": "domains"},
    }


def _write_dir(tmp_path: Path, doc: dict) -> Path:
    d = tmp_path / "bh"
    d.mkdir()
    by_type: dict[str, list] = {}
    for it in doc["data"]:
        by_type.setdefault(it["type"], []).append(it)
    for name, key in [("users.json", "user"), ("computers.json", "computer"),
                      ("gpos.json", "gpo"), ("domains.json", "domain")]:
        (d / name).write_text(json.dumps(by_type.get(key, [])),
                              encoding="utf-8")
    return d


# ---------- end-to-end ----------

def test_risky_config_found(tmp_path):
    d = _write_dir(tmp_path, _fixture())
    code, out = _run("--dir", str(d))
    assert code == 0 and out["items_total"] == 7
    types = {f["type"] for f in out["findings"]}
    assert {"asrep-roastable", "pwd-not-required", "unconstrained-del",
            "gpp-password", "dcsync-capable", "spn-kerberoastable"} <= types
    asrep = [f for f in out["findings"] if f["type"] == "asrep-roastable"]
    assert "SVC_BACKUP@CORP.LOCAL" in asrep[0]["evidence"]["users"]


def test_zip_input(tmp_path):
    d = tmp_path / "bh.zip"
    doc = _fixture()
    with zipfile.ZipFile(d, "w") as z:
        z.writestr("20261113120014_users.json",
                   json.dumps(doc["data"][0:4]))
    code, out = _run("--zip", str(d))
    assert code == 0 and out["items_total"] == 4
    assert any(f["type"] == "asrep-roastable" for f in out["findings"])


def test_false_positive_control_clean_ad(tmp_path):
    clean = {"data": [
        {"type": "user",
         "Properties": {"name": "JDOE@CORP.LOCAL"}},
        {"type": "computer",
         "Properties": {"name": "PC1.CORP.LOCAL"}},
        {"type": "domain",
         "Properties": {"name": "CORP.LOCAL"},
         "Aces": [{"PrincipalName": "DOMAIN ADMINS@CORP.LOCAL",
                   "RightName": "ExtendedRight",
                   "AceType": "All",
                   "PrincipalSID": "S-1-5-21-512"}]},
    ]}
    d = _write_dir(tmp_path, clean)
    code, out = _run("--dir", str(d), "--spn", "off")
    assert code == 0
    assert out["finding_count"] == 0


def test_fail_closed(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "notbh.json").write_text('{"foo": 1}', encoding="utf-8")
    code, out = _run("--dir", str(d))
    assert code == 2 and out is None
    code2, _ = _run("--dir", str(tmp_path / "missing"))
    assert code2 == 2


def test_list_format_legacy(tmp_path):
    # format lama: JSON list langsung
    d = tmp_path / "legacy"
    d.mkdir()
    (d / "users.json").write_text(
        json.dumps([{"type": "user",
                     "Properties": {"name": "X@C.L",
                                    "dontreqpreauth": True}}]),
        encoding="utf-8")
    code, out = _run("--dir", str(d))
    assert code == 0
    assert any(f["type"] == "asrep-roastable" for f in out["findings"])
