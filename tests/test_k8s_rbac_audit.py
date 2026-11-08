"""Nol jaringan — test k8s_rbac_audit (audit offline manifest RBAC)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import k8s_rbac_audit as kra  # noqa: E402


ROLE_ADMIN_WILDCARD = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: god-mode
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""

ROLE_SECRETS = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
"""

ROLE_PODS_EXEC = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: executor
  namespace: app
rules:
- apiGroups: [""]
  resources: ["pods", "pods/exec"]
  verbs: ["create", "get", "list"]
"""

ROLE_ESCALATE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: self-grantor
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate", "bind"]
"""

ROLE_IMPERSONATE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: anyone
rules:
- apiGroups: [""]
  resources: ["users", "groups"]
  verbs: ["impersonate"]
"""

BINDING_CLUSTER_ADMIN_SA = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oops-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: ci-runner
  namespace: ci
"""

BINDING_UNAUTH = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: open-to-world
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: Group
  name: system:unauthenticated
  apiGroup: rbac.authorization.k8s.io
"""

BINDING_DEFAULT_SA = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: app
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: executor
subjects:
- kind: ServiceAccount
  name: default
  namespace: app
"""

CLEAN_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: app
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
"""

BUILTIN_SYSTEM_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:node
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
"""


def _write(dirp: str, name: str, text: str) -> Path:
    p = Path(dirp) / name
    p.write_text(text, encoding="utf-8")
    return p


class TestYamlParse(unittest.TestCase):
    """Parser YAML subset untuk bentuk manifest RBAC umum."""

    def test_dokumen_tunggal(self):
        docs = kra.parse_documents(ROLE_PODS_EXEC)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["kind"], "Role")
        self.assertEqual(docs[0]["metadata"]["namespace"], "app")
        rules = docs[0]["rules"]
        self.assertEqual(rules[0]["resources"], ["pods", "pods/exec"])

    def test_multi_dokumen(self):
        text = "---\n" + ROLE_SECRETS + "---\n" + CLEAN_ROLE
        docs = kra.parse_documents(text)
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["metadata"]["name"], "secret-reader")
        self.assertEqual(docs[1]["metadata"]["name"], "pod-reader")

    def test_inline_list_tanpa_kutip(self):
        text = """\
kind: ClusterRole
metadata:
  name: x
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
"""
        docs = kra.parse_documents(text)
        self.assertEqual(docs[0]["rules"][0]["resources"], ["pods"])

    def test_komentar_dilewati(self):
        text = CLEAN_ROLE + "# rules tambahan: TODO hapus\n"
        docs = kra.parse_documents(text)
        self.assertEqual(docs[0]["metadata"]["name"], "pod-reader")

    def test_struktur_rusak_valueerror(self):
        with self.assertRaises(ValueError):
            kra.parse_documents("kind: [unclosed")
        with self.assertRaises(ValueError):
            kra.parse_documents("hanya_teks_tanpa_kolon")


class TestRiskyRules(unittest.TestCase):
    """Klasifikasi aturan berisiko."""

    def test_wildcard_all(self):
        r = kra._risky_rules([{"verbs": ["*"], "resources": ["*"]}])
        self.assertEqual(r[0]["code"], "wildcard-all")
        self.assertEqual(r[0]["severity"], "critical")

    def test_secrets_read(self):
        r = kra._risky_rules([{"verbs": ["get", "list"],
                               "resources": ["secrets"]}])
        self.assertEqual(r[0]["code"], "secrets-read")

    def test_secrets_dengan_resourcenames_tercatat(self):
        r = kra._risky_rules([{"verbs": ["get"],
                               "resources": ["secrets"],
                               "resourceNames": ["app-token"]}])
        self.assertIn("app-token", r[0]["detail"])

    def test_pods_exec(self):
        r = kra._risky_rules([{"verbs": ["create"],
                               "resources": ["pods/exec"]}])
        self.assertEqual(r[0]["code"], "pods-exec")

    def test_get_pods_saja_tidak_berisiko(self):
        r = kra._risky_rules([{"verbs": ["get", "list"],
                               "resources": ["pods"]}])
        self.assertEqual(r, [])

    def test_escalate_bind_impersonate(self):
        r = kra._risky_rules([
            {"verbs": ["escalate"], "resources": ["clusterroles"]},
            {"verbs": ["bind"], "resources": ["roles"]},
            {"verbs": ["impersonate"], "resources": ["users"]},
        ])
        self.assertEqual([x["code"] for x in r],
                         ["escalate-verb", "bind-verb", "impersonate"])

    def test_sa_token_create(self):
        r = kra._risky_rules([{"verbs": ["create"],
                               "resources": ["serviceaccounts/token"]}])
        self.assertEqual(r[0]["code"], "sa-token-create")


class TestAudit(unittest.TestCase):
    """Analisis gabungan role + binding + ringkasan eskalasi."""

    def _audit_yaml(self, *texts: str) -> dict:
        return kra.audit(kra._extract_manifests(
            kra.parse_documents("\n---\n".join(texts))))

    def test_wildcard_role_dan_eskalasi_subject(self):
        text = ROLE_ADMIN_WILDCARD + "---\n" + BINDING_CLUSTER_ADMIN_SA
        r = self._audit_yaml(text)
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("wildcard-all", codes)
        self.assertIn("binding-cluster-admin", codes)
        # tanpa pengulangan kelas berulir utk wildcard penuh
        self.assertNotIn("secrets-read", codes)
        self.assertEqual(r["summary"]["by_severity"].get("critical"), 2)
        esc = r["escalation_subjects"]
        self.assertTrue(any("ServiceAccount:ci-runner@ci" == e["subject"]
                            for e in esc))
        self.assertIn("wildcard-all", esc[0]["escalation"])

    def test_default_sa_terikat_role_exec(self):
        r = self._audit_yaml(ROLE_PODS_EXEC, BINDING_DEFAULT_SA)
        codes = {f["code"] for f in r["findings"]}
        self.assertIn("pods-exec", codes)
        self.assertIn("default-sa-bound", codes)

    def test_binding_unauthenticated(self):
        r = self._audit_yaml(BINDING_UNAUTH)
        codes = [f["code"] for f in r["findings"]]
        self.assertIn("binding-unauth", codes)

    def test_builtin_system_dilewati(self):
        r = self._audit_yaml(BUILTIN_SYSTEM_ROLE)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["builtin_system_skipped"], 1)

    def test_role_bersih_nol_temuan(self):
        r = self._audit_yaml(CLEAN_ROLE)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["summary"]["findings_total"], 0)


class TestInput(unittest.TestCase):
    """Input file/dir + fail-closed + CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dirp = self.tmp.name

    def _path(self, name: str) -> Path:
        return Path(self.dirp) / name

    def test_json_kubectl_style(self):
        p = self._path("rbac.json")
        p.write_text(json.dumps({
            "kind": "List",
            "items": [json.loads(json.dumps(
                kra.parse_documents(ROLE_SECRETS)[0]))],
        }), encoding="utf-8")
        r = kra.audit(kra._load_files(p)[0])
        self.assertEqual(r["roles_audited"], 1)
        self.assertIn("secrets-read",
                      [f["code"] for f in r["findings"]])

    def test_dir_multi_file(self):
        _write(self.dirp, "a.yaml", ROLE_ADMIN_WILDCARD)
        _write(self.dirp, "b.yaml", CLEAN_ROLE)
        r = kra.audit(kra._load_files(Path(self.dirp))[0])
        self.assertEqual(r["roles_audited"], 2)

    def test_dir_tanpa_manifest_exit_2(self):
        _write(self.dirp, "readme.txt", "bukan manifest")
        rc = kra.main(["--source", self.dirp])
        self.assertEqual(rc, 2)

    def test_yaml_rusak_tercatat_unparsed_tetap_lanjut(self):
        _write(self.dirp, "good.yaml", ROLE_SECRETS)
        _write(self.dirp, "bad.yaml", "kind: [rusak")
        r = kra.audit(kra._load_files(Path(self.dirp))[0])
        unparsed = kra._load_files(Path(self.dirp))[1]
        self.assertTrue(any("bad.yaml" in u for u in unparsed))
        self.assertEqual(r["roles_audited"], 1)

    def test_semua_file_rusak_exit_2(self):
        _write(self.dirp, "bad.yaml", "kind: [rusak")
        rc = kra.main(["--source", self.dirp])
        self.assertEqual(rc, 2)

    def test_source_tidak_ada_exit_2(self):
        rc = kra.main(["--source",
                       str(self._path("missing.yaml"))])
        self.assertEqual(rc, 2)

    def test_fail_on_high_exit_1(self):
        p = _write(self.dirp, "risky.yaml", ROLE_SECRETS)
        rc = kra.main(["--source", str(p), "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_bersih_fail_on_tetap_0(self):
        p = _write(self.dirp, "clean.yaml", CLEAN_ROLE)
        rc = kra.main(["--source", str(p), "--fail-on", "high"])
        self.assertEqual(rc, 0)

    def test_out_json_valid(self):
        p = _write(self.dirp, "risky.yaml", ROLE_ADMIN_WILDCARD)
        out = self._path("out.json")
        rc = kra.main(["--source", str(p), "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "secai.k8s-rbac-audit/1")
        self.assertIn("wildcard-all",
                      [f["code"] for f in data["findings"]])


if __name__ == "__main__":
    unittest.main()
