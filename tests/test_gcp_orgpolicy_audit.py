"""test_gcp_orgpolicy_audit — audit cakupan org policy GCP offline
(#0629), nol jaringan, tanpa kredensial gcloud.

Fixture = ekspor JSON gcloud sintetis dari bentuk policy publik
(booleanPolicy/listPolicy/restoreDefault/dryRunSpec); bukan salinan
kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import gcp_orgpolicy_audit as goa  # noqa: E402

BOOL = "constraints/iam.disableServiceAccountKeyCreation"
LIST = "constraints/compute.vmExternalIpAccess"
OSLOGIN = "constraints/compute.requireOsLogin"
LOCS = "constraints/gcp.resourceLocations"


def _write(tmp_path, name: str, doc) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gcp_orgpolicy_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


def _bool(constraint: str, enforced: bool = True) -> dict:
    return {"constraint": constraint, "booleanPolicy": {"enforced": enforced}}


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "gcp_orgpolicy_audit.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--policies", str(tmp_path / "nope.json"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_invalid_json_exit2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{bukan json", encoding="utf-8")
    rc, out, _ = _run("--policies", str(p))
    assert rc == 2 and out is None


def test_not_list_exit2(tmp_path):
    p = _write(tmp_path, "obj.json", {"constraint": BOOL})
    rc, out, _ = _run("--policies", str(p))
    assert rc == 2 and out is None


def test_empty_list_exit2(tmp_path):
    p = _write(tmp_path, "empty.json", [])
    rc, out, _ = _run("--policies", str(p))
    assert rc == 2 and out is None


# ------------------------------------------------------- baseline
def test_full_baseline_clean(tmp_path):
    doc = [
        {"constraint": LIST, "listPolicy": {"allValues": "DENY"}},
        {"constraint": LOCS,
         "listPolicy": {"allowedValues": ["in:us-locations"]}},
        _bool(BOOL),
        _bool("constraints/iam.automaticIamGrantsForDefaultServiceAccounts"),
        _bool(OSLOGIN),
        _bool("constraints/compute.disableSerialPortAccess"),
        _bool("constraints/storage.uniformBucketLevelAccess"),
        _bool("constraints/sql.restrictPublicIp"),
        {"constraint": "constraints/compute.trustedImageProjects",
         "listPolicy": {"allowedValues": ["projects/trusted"]}},
    ]
    p = _write(tmp_path, "full.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert rc == 0 and out["findings"] == []
    assert out["stats"]["constraints_enforced"] == 7  # LOCS = exceptions
    assert out["stats"]["extra_constraints"] == 1


def test_missing_constraints_high(tmp_path):
    p = _write(tmp_path, "one.json", [_bool(BOOL)])
    rc, out, _ = _run("--policies", str(p))
    checks = _checks(out)
    assert checks.count("constraint-missing") >= 5
    assert "constraint-missing" in checks and rc == 1


def test_boolean_not_enforced_weak(tmp_path):
    doc = [
        _bool(BOOL, enforced=False),
        {"constraint": LIST, "listPolicy": {"allValues": "DENY"}},
        {"constraint": LOCS, "listPolicy": {"allowedValues": ["in:eu"]}},
        _bool("constraints/iam.automaticIamGrantsForDefaultServiceAccounts"),
        _bool(OSLOGIN),
        _bool("constraints/compute.disableSerialPortAccess"),
        _bool("constraints/storage.uniformBucketLevelAccess"),
        _bool("constraints/sql.restrictPublicIp"),
    ]
    p = _write(tmp_path, "weak.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert "constraint-weak" in _checks(out) and rc == 1
    f = [f for f in out["findings"] if f["constraint"] == BOOL]
    assert f and f[0]["severity"] == "high"


def test_list_allow_is_weak(tmp_path):
    doc = [
        {"constraint": LIST, "listPolicy": {"allValues": "ALLOW"}},
    ]
    p = _write(tmp_path, "allow.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert "constraint-weak" in _checks(out) and rc == 1


def test_restore_default_is_weak(tmp_path):
    doc = [
        {"constraint": LIST, "listPolicy": {"allValues": "DENY"}},
        {"constraint": OSLOGIN, "restoreDefault": {}},
    ]
    p = _write(tmp_path, "restore.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert "constraint-weak" in _checks(out) and rc == 1


def test_list_deny_with_exceptions_medium(tmp_path):
    doc = [
        {"constraint": LIST,
         "listPolicy": {"allowedValues":
                        ["projects/dev/zones/us-central1-a/instances/"
                         "bastion-host"]}},
    ]
    p = _write(tmp_path, "exc.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert "constraint-exceptions" in _checks(out)
    assert rc == 1  # sisanya constraint-missing (high)


def test_valid_entry_beats_weak_entry(tmp_path):
    """Dua entry utk constraint sama: yang valid menang."""
    doc = [
        _bool(OSLOGIN, enforced=False),
        _bool(OSLOGIN, enforced=True),
    ]
    p = _write(tmp_path, "both.json", doc)
    rc, out, _ = _run("--policies", str(p))
    weak = [f for f in out["findings"]
            if f["constraint"] == OSLOGIN and f["check"] == "constraint-weak"]
    missing = [f for f in out["findings"]
               if f["constraint"] == OSLOGIN
               and f["check"] == "constraint-missing"]
    assert not weak and not missing


def test_dry_run_only_medium(tmp_path):
    doc = [
        _bool(BOOL),
        {"constraint": LIST, "listPolicy": {"allValues": "DENY"}},
        {"constraint": LOCS, "listPolicy": {"allowedValues": ["in:us"]}},
        _bool("constraints/iam.automaticIamGrantsForDefaultServiceAccounts"),
        _bool(OSLOGIN),
        _bool("constraints/compute.disableSerialPortAccess"),
        _bool("constraints/storage.uniformBucketLevelAccess"),
        # sql.restrictPublicIp hanya dry-run (belum enforce)
        {"constraint": "constraints/sql.restrictPublicIp",
         "dryRunSpec": {"booleanPolicy": {"enforced": True}}},
    ]
    p = _write(tmp_path, "dry.json", doc)
    rc, out, _ = _run("--policies", str(p))
    checks = _checks(out)
    assert "constraint-dry-run" in checks
    assert "constraint-missing" not in checks
    assert out["stats"]["entries_dryrun"] == 1
    assert out["stats"]["constraints_dryrun_only"] == 1
    assert rc == 0  # hanya medium — tidak memicu default high


# ------------------------------------------------------- fail-closed
def test_unparsed_entry_high(tmp_path):
    doc = [_bool(BOOL), "bukan-policy", {"updateTime": "2026-01-01"}]
    p = _write(tmp_path, "mix.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert _checks(out).count("entry-unparsed") == 2 and rc == 1
    assert out["stats"]["unparsed"] == 2
    assert any("fail-closed" in n for n in out["notes"])


def test_no_constraint_field_unparsed(tmp_path):
    doc = [{"booleanPolicy": {"enforced": True}}]
    p = _write(tmp_path, "nocons.json", doc)
    rc, out, _ = _run("--policies", str(p))
    assert "entry-unparsed" in _checks(out) and rc == 1


# ------------------------------------------------------- anti-FP
def test_skip_constraint_filters_and_records(tmp_path):
    p = _write(tmp_path, "one.json", [_bool(BOOL)])
    rc, out, _ = _run("--policies", str(p), "--skip-constraint",
                      "constraints/compute.vmExternalIpAccess")
    missing = [f for f in out["findings"]
               if f["constraint"] == "constraints/compute.vmExternalIpAccess"]
    assert not missing
    assert out["stats"]["skipped_constraints"] == 1
    assert any("--skip-constraint" in n for n in out["notes"])


# ------------------------------------------------------- unit
def test_classify_spec_unit():
    assert goa._classify_spec({"booleanPolicy": {"enforced": True}}) == "valid"
    assert goa._classify_spec({"booleanPolicy": {"enforced": False}}) == "weak"
    assert goa._classify_spec(
        {"listPolicy": {"allValues": "DENY"}}) == "valid"
    assert goa._classify_spec(
        {"listPolicy": {"allValues": "ALLOW"}}) == "weak"
    assert goa._classify_spec(
        {"listPolicy": {"allowedValues": ["x"]}}) == "exceptions"
    assert goa._classify_spec({"restoreDefault": {}}) == "restore"
    assert goa._classify_spec({"updateTime": "x"}) is None
