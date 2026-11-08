"""test_oauth_grant_audit — audit inventaris OAuth grant offline
(#0860), nol jaringan.

Fixture = JSON inventaris sintetis mengikuti bentuk publik Graph API
oauth2PermissionGrants/servicePrincipals + array generik; bukan salinan
kode alat sumber dan bukan dump tenant nyata.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import oauth_grant_audit as oga  # noqa: E402

GRAPH_GRANTS = {
    "value": [
        {"clientId": "11111111-1111", "scope": "Mail.ReadWrite "
         "Files.ReadWrite.All", "consentType": "AllPrincipals"},
        {"clientId": "22222222-2222", "scope": "User.Read openid",
         "consentType": "Principal"},
        {"clientId": "33333333-3333", "scope": "Directory.Read.All",
         "consentType": "AllPrincipals"},
    ]
}

PRINCIPALS = {
    "value": [
        {"id": "11111111-1111", "displayName": "ShadyMailSync",
         "appOwnerOrganizationId": "99999999-external"},
        {"id": "22222222-2222", "displayName": "LegitViewer",
         "appOwnerOrganizationId": "tenant-own"},
        {"id": "33333333-3333", "displayName": "AuditorApp",
         "appOwnerOrganizationId": "tenant-own"},
    ]
}

CATALOG = {
    "AuditorApp": {"approved_scopes": ["Directory.Read",
                                       "AuditLog.Read.All"]},
    "LegitViewer": {"approved_scopes": ["User.Read", "openid"]},
}


def _write(tmp_path: Path, name: str, obj) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "oauth_grant_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "oauth_grant_audit.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--grants", str(tmp_path / "no.json"))
    assert rc == 2 and "tidak ada" in err


def test_bad_json_exit2(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{bukan json", encoding="utf-8")
    rc, out, err = _run("--grants", str(p))
    assert rc == 2 and "rusak" in err


def test_unrecognized_shape_exit2(tmp_path):
    p = _write(tmp_path, "odd.json", {"foo": [{"bar": 1}]})
    rc, out, err = _run("--grants", str(p))
    assert rc == 2 and "nol grant" in err


def test_flat_generic_shape(tmp_path):
    p = _write(tmp_path, "flat.json", [
        {"app_name": "SyncTool", "permission_type": "application",
         "scope": "Files.ReadWrite.All", "consent": "admin"},
    ])
    rc, out, _ = _run("--grants", str(p))
    assert rc == 1
    assert "app-permission-critical" in _checks(out)
    assert out["apps"][0]["app"] == "SyncTool"


# ------------------------------------------------------- klasifikasi
def test_scope_risk_classification():
    assert oga.classify_scope("Directory.ReadWrite.All")[0] == "critical"
    assert oga.classify_scope("Mail.Send")[0] == "critical"
    assert oga.classify_scope("User.Read")[0] == "low"
    assert oga.classify_scope("openid")[0] == "low"
    assert oga.classify_scope("Directory.Read.All")[0] == "high"
    assert oga.classify_scope("Calendar.ReadWrite")[0] == "medium"
    assert oga.classify_scope("Sites.FullControl.All")[0] == "critical"
    assert oga.classify_scope("Some.New.Random.Scope")[0] == "high"
    assert oga.classify_scope("Some.New.Random.Scope")[1] is True


def test_unknown_scope_flagged(tmp_path):
    p = _write(tmp_path, "g.json", {"value": [
        {"clientId": "abc", "scope": "Tenant.Mystery.Power",
         "consentType": "Principal"}]})
    rc, out, _ = _run("--grants", str(p))
    su = [f for f in out["findings"] if f["check"] == "scope-unknown"]
    assert len(su) == 1 and su[0]["severity"] == "high"
    assert out["stats"]["unknown"] == 1


# ------------------------------------------------------- temuan
def test_admin_consent_critical(tmp_path):
    p = _write(tmp_path, "g.json", GRAPH_GRANTS)
    _, out, _ = _run("--grants", str(p), "--principals",
                     str(_write(tmp_path, "sp.json", PRINCIPALS)))
    ac = [f for f in out["findings"]
          if f["check"] == "admin-consent-critical"]
    # Directory.Read.All = high (bukan critical) -> hanya ShadyMailSync
    apps = {f["app"] for f in ac}
    assert apps == {"ShadyMailSync"}
    assert out["apps"][0]["app"] == "ShadyMailSync"
    assert out["apps"][0]["aggregate"] in ("CRITICAL", "HIGH")


def test_unapproved_and_excessive(tmp_path):
    p = _write(tmp_path, "g.json", GRAPH_GRANTS)
    c = _write(tmp_path, "cat.json", CATALOG)
    sp = _write(tmp_path, "sp.json", PRINCIPALS)
    _, out, _ = _run("--grants", str(p), "--principals", str(sp),
                     "--catalog", str(c))
    ch = _checks(out)
    assert "unapproved-app" in ch  # ShadyMailSync tak di katalog
    un = [f for f in out["findings"] if f["check"] == "unapproved-app"]
    assert {f["app"] for f in un} == {"ShadyMailSync"}
    ex = [f for f in out["findings"]
          if f["check"] == "excessive-scope" and f["app"] == "AuditorApp"]
    assert len(ex) == 1  # Directory.Read.All di luar approved
    lv = [f for f in out["findings"]
          if f["check"] == "excessive-scope" and f["app"] == "LegitViewer"]
    assert lv == []


def test_over_broad_downgrade(tmp_path):
    cat = {"h1": {"approved_scopes": ["Mail.Read"]}}
    grants = {"value": [
        {"clientId": "h1", "scope": "Mail.ReadWrite",
         "consentType": "Principal"}]}
    p = _write(tmp_path, "g.json", grants)
    c = _write(tmp_path, "cat.json", cat)
    _, out, _ = _run("--grants", str(p), "--catalog", str(c),
                     "--fail-on", "info")
    ob = [f for f in out["findings"]
          if f["check"] == "over-broad-scope"]
    # Mail.ReadWrite belum ada di approved -> excessive dulu;
    # downgrade pair hanya relevan bila ReadWrite itu sendiri approved
    assert not ob
    ex = [f for f in out["findings"] if f["check"] == "excessive-scope"]
    assert len(ex) == 1


def test_over_broad_when_readwrite_approved(tmp_path):
    cat = {"h1": {"approved_scopes": ["Mail.Read", "Mail.ReadWrite"]}}
    grants = {"value": [
        {"clientId": "h1", "scope": "Mail.ReadWrite Mail.Read",
         "consentType": "Principal"}]}
    p = _write(tmp_path, "g.json", grants)
    c = _write(tmp_path, "cat.json", cat)
    _, out, _ = _run("--grants", str(p), "--catalog", str(c))
    ob = [f for f in out["findings"]
          if f["check"] == "over-broad-scope"]
    assert len(ob) == 1
    assert "downgrade" in ob[0]["message"]


def test_app_aggregate_critical(tmp_path):
    grants = {"value": [
        {"clientId": "x1", "scope": "Directory.ReadWrite.All "
         "Application.ReadWrite.All Files.ReadWrite.All "
         "Sites.FullControl.All User.ReadWrite.All "
         "Group.ReadWrite.All", "consentType": "AllPrincipals"}]}
    p = _write(tmp_path, "g.json", grants)
    rc, out, _ = _run("--grants", str(p))
    assert rc == 1
    ag = [f for f in out["findings"]
          if f["check"] == "app-aggregate-critical"]
    assert len(ag) == 1
    assert out["apps"][0]["aggregate"] == "CRITICAL"
    assert out["apps"][0]["score"] >= 100


# ------------------------------------------------------- kontrak
def test_stats_and_notes(tmp_path):
    p = _write(tmp_path, "g.json", GRAPH_GRANTS)
    _, out, _ = _run("--grants", str(p))
    st = out["stats"]
    assert st["grants"] == 3 and st["apps"] == 3
    assert st["critical"] >= 2 and st["low"] >= 2
    assert any("STALE" in n for n in out["notes"])
    assert any("tidak diport" in n or "LIVE" in n for n in out["notes"])


def test_schema_sorted(tmp_path):
    p = _write(tmp_path, "g.json", GRAPH_GRANTS)
    _, out, _ = _run("--grants", str(p))
    assert out["schema"] == oga.SCHEMA
    sevs = [oga.SEV_ORDER[f["severity"]] for f in out["findings"]]
    assert sevs == sorted(sevs, reverse=True)
    scores = [a["score"] for a in out["apps"]]
    assert scores == sorted(scores, reverse=True)
    assert all({"check", "severity", "app", "message"}
               <= set(f) for f in out["findings"])


def test_fail_on_high(tmp_path):
    p = _write(tmp_path, "g.json", {"value": [
        {"clientId": "low", "scope": "User.Read openid",
         "consentType": "Principal"}]})
    rc, out, _ = _run("--grants", str(p))
    assert rc == 0  # hanya low, tanpa temuan >= medium
