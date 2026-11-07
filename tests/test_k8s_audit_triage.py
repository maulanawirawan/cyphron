"""test_k8s_audit_triage — triase audit log kube-apiserver (#0205),
nol jaringan.

Fixture = event audit sintetis dari format audit kube-apiserver
(verb, user, objectRef, responseStatus, requestObject) sesuai
dokumentasi resmi Kubernetes.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import k8s_audit_triage as kat  # noqa: E402


def _ev(**kw) -> dict:
    ev = {
        "auditID": kw.pop("auditID", "A-1"),
        "stage": kw.pop("stage", "ResponseComplete"),
        "verb": kw.pop("verb", "get"),
        "user": kw.pop("user", {"username": "admin",
                                "groups": ["system:masters"]}),
        "objectRef": kw.pop("objectRef", {"resource": "pods"}),
        "responseStatus": kw.pop("responseStatus", {"code": 200}),
        "sourceIPs": kw.pop("sourceIPs", ["10.0.0.5"]),
    }
    ev.update(kw)
    return ev


def _run(path: Path, *extra: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "k8s_audit_triage.py"), "--log",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _tmp(tmp_path: Path, name: str, rows: list[dict]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                 encoding="utf-8")
    return p


def test_benign_ops_no_findings(tmp_path):
    rows = [_ev(auditID=f"B{i}", verb="get",
                user={"username": "deploy-bot",
                      "groups": ["system:serviceaccounts:ci"]},
                objectRef={"resource": "pods", "namespace": "ci",
                           "name": f"runner-{i}"})
            for i in range(10)]
    rows += [_ev(auditID="Bcfg", verb="patch",
                 user={"username": "deploy-bot"},
                 objectRef={"resource": "configmaps",
                            "namespace": "ci", "name": "app"},
                 responseStatus={"code": 200})]
    p = _tmp(tmp_path, "benign.jsonl", rows)
    rc, out, _ = _run(p)
    assert rc == 0 and out is not None
    assert out["finding_count"] == 0
    assert out["events"] == 11
    assert out["meta"]["denied_events"] == 0


def test_pod_exec_detection(tmp_path):
    rows = [
        _ev(auditID="E1", verb="create",
            user={"username": "suspicious-sa"},
            objectRef={"resource": "pods", "subresource": "exec",
                       "namespace": "prod", "name": "api-7d9"}),
        _ev(auditID="E2", verb="create",
            user={"username": "suspicious-sa"},
            objectRef={"resource": "pods", "subresource": "attach",
                       "namespace": "prod", "name": "api-7d9"}),
        # gaya ringkas 'pods/exec'
        _ev(auditID="E3", verb="create",
            user={"username": "other-sa"},
            objectRef={"resource": "pods/exec", "namespace": "dev",
                       "name": "worker-1"}),
    ]
    p = _tmp(tmp_path, "exec.jsonl", rows)
    rc, out, _ = _run(p)
    pe = [f for f in out["findings"] if f["type"] == "pod-exec"]
    assert len(pe) == 2
    agg = next(f for f in pe if f["user"] == "suspicious-sa")
    assert agg["severity"] == "high"
    assert agg["evidence"]["events"] == 2
    assert set(agg["evidence"]["subresources"]) == {"exec", "attach"}
    assert agg["evidence"]["samples"][0]["sourceIPs"] == ["10.0.0.5"]


def test_secret_access_get_vs_bulk(tmp_path):
    rows = [
        _ev(auditID="S1", verb="get",
            user={"username": "app-sa"},
            objectRef={"resource": "secrets", "namespace": "prod",
                       "name": "db-cred"}),
        _ev(auditID="S2", verb="list",
            user={"username": "app-sa"},
            objectRef={"resource": "secrets", "namespace": "prod"}),
    ]
    p = _tmp(tmp_path, "sec.jsonl", rows)
    rc, out, _ = _run(p)
    # get (medium) dan list (high) beda kunci agregasi -> dua temuan
    sa = [f for f in out["findings"] if f["type"] == "secret-access"]
    assert len(sa) == 2
    sevs = sorted(f["severity"] for f in sa)
    assert sevs == ["high", "medium"]
    bulk = next(f for f in sa if f["severity"] == "high")
    assert "list/watch" in bulk["detail"]


def test_rbac_escalation_levels(tmp_path):
    rows = [
        _ev(auditID="R1", verb="create",
            user={"username": "attacker-sa"},
            objectRef={"resource": "clusterrolebindings",
                       "name": "pwn-all"}),
        _ev(auditID="R2", verb="update",
            user={"username": "attacker-sa"},
            objectRef={"resource": "roles", "namespace": "prod",
                       "name": "edit"}),
    ]
    p = _tmp(tmp_path, "rbac.jsonl", rows)
    rc, out, _ = _run(p)
    rb = [f for f in out["findings"]
          if f["type"] == "rbac-escalation"]
    assert len(rb) == 2
    crb = next(f for f in rb if "clusterrolebinding" in f["detail"])
    assert crb["severity"] == "critical"
    mut = next(f for f in rb if "RBAC" in f["detail"])
    assert mut["severity"] == "high"


def test_privileged_pod_requestobject(tmp_path):
    ro = {
        "apiVersion": "v1", "kind": "Pod",
        "spec": {
            "hostPID": True,
            "containers": [
                {"name": "main", "image": "nginx",
                 "securityContext": {"privileged": True}},
            ],
            "volumes": [{"name": "root", "hostPath": {"path": "/"}}],
        },
    }
    clean = {
        "apiVersion": "v1", "kind": "Pod",
        "spec": {"containers": [{"name": "web", "image": "nginx"}]},
    }
    rows = [
        _ev(auditID="P1", verb="create",
            user={"username": "dev-sa"},
            objectRef={"resource": "pods", "namespace": "prod",
                       "name": "debugger"}, requestObject=ro),
        _ev(auditID="P2", verb="create",
            user={"username": "dev-sa"},
            objectRef={"resource": "pods", "namespace": "prod",
                       "name": "web-1"}, requestObject=clean),
    ]
    p = _tmp(tmp_path, "priv.jsonl", rows)
    rc, out, _ = _run(p)
    pp = [f for f in out["findings"]
          if f["type"] == "privileged-pod"]
    assert len(pp) == 1
    reasons = pp[0]["evidence"]["pods"]["debugger"]
    assert "hostPID" in reasons
    assert "privileged:main" in reasons
    assert "hostPath:/" in reasons
    assert "web-1" not in pp[0]["evidence"]["pods"]
    assert out["meta"]["requestobject_coverage"] == 2


def test_privileged_pod_without_requestobject_no_finding(tmp_path):
    rows = [_ev(auditID="P9", verb="create",
                user={"username": "dev-sa"},
                objectRef={"resource": "pods", "name": "x"})]
    p = _tmp(tmp_path, "noro.jsonl", rows)
    rc, out, _ = _run(p)
    assert not [f for f in out["findings"]
                if f["type"] == "privileged-pod"]
    assert out["meta"]["requestobject_coverage"] == 0


def test_anonymous_and_impersonation(tmp_path):
    rows = [
        _ev(auditID="A1", verb="list",
            user={"username": "system:anonymous",
                  "groups": ["system:unauthenticated"]},
            objectRef={"resource": "secrets", "namespace": "prod"}),
        _ev(auditID="A2", verb="get",
            user={"username": "ci-bot"},
            objectRef={"resource": "pods", "name": "web"},
            impersonatedUser={"username": "admin"}),
    ]
    p = _tmp(tmp_path, "anon.jsonl", rows)
    rc, out, _ = _run(p)
    types = {f["type"] for f in out["findings"]}
    assert "anonymous-access" in types
    assert "impersonation" in types
    anon = next(f for f in out["findings"]
                if f["type"] == "anonymous-access")
    assert anon["severity"] == "high"


def test_dedupe_stages_same_auditid(tmp_path):
    rows = [
        _ev(auditID="D1", stage="RequestReceived", verb="create",
            user={"username": "suspicious-sa"},
            objectRef={"resource": "pods", "subresource": "exec",
                       "name": "api"}),
        _ev(auditID="D1", stage="ResponseComplete", verb="create",
            user={"username": "suspicious-sa"},
            objectRef={"resource": "pods", "subresource": "exec",
                       "name": "api"},
            responseStatus={"code": 200}),
    ]
    p = _tmp(tmp_path, "dup.jsonl", rows)
    rc, out, _ = _run(p)
    assert out["parsed"] == 2
    assert out["duplicate_audits"] == 1
    assert out["events"] == 1
    pe = [f for f in out["findings"] if f["type"] == "pod-exec"]
    assert len(pe) == 1 and pe[0]["evidence"]["events"] == 1


def test_unparsed_and_fail_closed(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"verb": "get"}\nbukan json\n'
                 '{"user": {"username": "x"}}\n',
                 encoding="utf-8")
    rc, out, _ = _run(p)
    # 1 valid + 2 unparsed (bukan json / tanpa verb)
    assert rc == 0
    assert out["parsed"] == 1 and out["unparsed_count"] == 2
    assert "bukan json" in out["unparsed_sample"][0]

    p2 = tmp_path / "empty.jsonl"
    p2.write_text("", encoding="utf-8")
    rc2, out2, _ = _run(p2)
    assert rc2 == 2 and out2 is None

    p3 = tmp_path / "noise.jsonl"
    p3.write_text("hello\nworld\n", encoding="utf-8")
    rc3, out3, _ = _run(p3)
    assert rc3 == 2 and out3 is None


def test_fail_on_gate(tmp_path):
    rows = [_ev(auditID="F1", verb="create",
                user={"username": "attacker"},
                objectRef={"resource": "clusterrolebindings",
                           "name": "pwn"})]
    p = _tmp(tmp_path, "gate.jsonl", rows)
    rc, out, err = _run(p, "--fail-on", "critical")
    assert rc == 1 and out["fail_on_hit"] == 1
    assert "fail-on" in err

    rows2 = [_ev(auditID="F2", verb="get",
                 user={"username": "app-sa"},
                 objectRef={"resource": "pods", "name": "web"})]
    p2 = _tmp(tmp_path, "gate2.jsonl", rows2)
    rc2, out2, _ = _run(p2, "--fail-on", "critical")
    assert rc2 == 0 and out2["fail_on_hit"] == 0


def test_cli_out_schema(tmp_path):
    rows = [_ev(auditID="C1", verb="get")]
    p = _tmp(tmp_path, "cli.jsonl", rows)
    outp = tmp_path / "out.json"
    rc, _, _ = _run(p, "--out", str(outp))
    assert rc == 0 and outp.is_file()
    data = json.loads(outp.read_text(encoding="utf-8"))
    assert data["schema"] == "cyphron.k8s-audit-triage/1"
    assert data["read_only"] is True
    assert data["note"].startswith("semua temuan = LEAD")


# ---------- unit langsung ----------

def test_normalize_ref():
    assert kat._normalize_ref({"objectRef": {"resource": "pods/exec"}}) \
        == ("pods", "exec")
    assert kat._normalize_ref(
        {"objectRef": {"resource": "pods", "subresource": "log"}}) \
        == ("pods", "log")
    assert kat._normalize_ref({}) == ("", "")


def test_privilege_reasons_unit():
    reasons = kat._pod_privilege_reasons({"spec": {
        "hostNetwork": True,
        "initContainers": [{"name": "i",
                            "securityContext": {"privileged": True}}],
    }})
    assert "hostNetwork" in reasons and "privileged:i" in reasons
    assert kat._pod_privilege_reasons({}) == []
