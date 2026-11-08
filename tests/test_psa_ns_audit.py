"""Nol jaringan — test psa_ns_audit (audit offline label PSA Namespace +
AdmissionConfiguration)."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import psa_ns_audit as pna  # noqa: E402


class Helpers(unittest.TestCase):
    """Jalankan tool lewat capture stdout supaya exit code dan isi
    report diuji sekaligus."""

    def _main_capture(self, text: str, *extra: str):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "psa.yaml"
            src.write_text(text, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pna.main(["--source", str(src), *extra])
            return (json.loads(buf.getvalue()) if buf.getvalue().strip()
                    else {}), rc

    @staticmethod
    def _checks(rep: dict) -> "set[str]":
        return {f["check"] for f in rep.get("findings", [])}


class TestNamespaceLabels(Helpers):
    NS_TPL = """\
apiVersion: v1
kind: Namespace
metadata:
  name: {name}
{labels}"""

    def test_restricted_pinned_clean(self):
        text = self.NS_TPL.format(
            name="production",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["summary"]["namespaces_audited"], 1)

    def test_no_psa_labels_high(self):
        text = self.NS_TPL.format(name="team-app",
                                  labels="""  labels:
    team: app
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("psa-no-labels", self._checks(rep))

    def test_audit_warn_only_medium(self):
        text = self.NS_TPL.format(
            name="staging",
            labels="""  labels:
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
""")
        rep, rc = self._main_capture(text)
        checks = self._checks(rep)
        self.assertIn("psa-not-enforced", checks)
        self.assertNotIn("psa-no-labels", checks)
        self.assertNotIn("psa-version-unpinned", checks)

    def test_enforce_privileged_non_system_high(self):
        text = self.NS_TPL.format(
            name="legacy",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: privileged
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("psa-enforce-privileged", self._checks(rep))

    def test_enforce_privileged_system_ns_clean(self):
        text = self.NS_TPL.format(
            name="kube-system",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: privileged
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 0, rep)
        self.assertNotIn("psa-enforce-privileged", self._checks(rep))

    def test_below_minimum_with_flag(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: baseline
""")
        rep, rc = self._main_capture(text, "--min-enforce", "restricted")
        self.assertIn("psa-enforce-below-minimum", self._checks(rep))
        # default min=baseline -> clean
        rep2, rc2 = self._main_capture(text)
        self.assertNotIn("psa-enforce-below-minimum",
                         self._checks(rep2))

    def test_invalid_enforce_value_high(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: Restricted
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("psa-value-invalid", self._checks(rep))

    def test_invalid_audit_value_medium(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: hard
""")
        rep, rc = self._main_capture(text)
        inv = [f for f in rep["findings"]
               if f["check"] == "psa-value-invalid"]
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["severity"], "medium")
        self.assertEqual(inv[0]["field"], "audit")

    def test_typo_suffix_flagged(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enfore: restricted
""")
        rep, rc = self._main_capture(text)
        self.assertIn("psa-label-unknown-suffix", self._checks(rep))

    def test_version_unpinned_low(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: restricted
""")
        rep, rc = self._main_capture(text)
        self.assertIn("psa-version-unpinned", self._checks(rep))

    def test_version_invalid_medium(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28.3
""")
        rep, rc = self._main_capture(text)
        self.assertIn("psa-version-invalid", self._checks(rep))

    def test_warn_weaker_than_enforce_low(self):
        text = self.NS_TPL.format(
            name="app",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: baseline
""")
        rep, rc = self._main_capture(text)
        inc = [f for f in rep["findings"]
               if f["check"] == "psa-mode-inconsistent"]
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["severity"], "low")

    def test_system_ns_extension_flag(self):
        text = self.NS_TPL.format(
            name="monitoring",
            labels="""  labels:
    pod-security.kubernetes.io/enforce: privileged
""")
        rep, rc = self._main_capture(
            text, "--system-namespaces", "monitoring")
        self.assertNotIn("psa-enforce-privileged", self._checks(rep))

    def test_system_ns_default_no_labels_clean(self):
        text = self.NS_TPL.format(name="kube-node-lease", labels="")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 0, rep)


class TestAdmissionConfig(Helpers):
    ADM_TPL = """\
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
metadata:
  name: psa
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: {enforce}
        enforce-version: latest
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces: {ns}
"""

    def test_defaults_baseline_clean(self):
        rep, rc = self._main_capture(
            self.ADM_TPL.format(enforce="baseline",
                                ns="[kube-system, kube-public]"))
        self.assertEqual(rc, 0, rep)

    def test_defaults_missing_medium(self):
        rep, rc = self._main_capture(
            self.ADM_TPL.format(enforce="", ns="[]")
            .replace("      defaults:\n        enforce: \n"
                     "        enforce-version: latest\n", ""))
        self.assertIn("psa-defaults-missing", self._checks(rep))

    def test_defaults_below_minimum(self):
        rep, rc = self._main_capture(
            self.ADM_TPL.format(enforce="privileged", ns="[]"),
            "--min-enforce", "baseline")
        self.assertIn("psa-defaults-below-minimum", self._checks(rep))

    def test_unknown_exempt_namespace_medium(self):
        rep, rc = self._main_capture(
            self.ADM_TPL.format(enforce="baseline", ns="[monitoring]"))
        self.assertIn("psa-exempt-namespace-unknown", self._checks(rep))

    def test_exempt_usernames_low(self):
        text = self.ADM_TPL.format(enforce="baseline", ns="[]") \
            .replace("        usernames: []",
                     "        usernames:\n          - system:serviceaccount:kube-system:deployer")
        rep, rc = self._main_capture(text)
        self.assertIn("psa-exempt-usernames", self._checks(rep))

    def test_plugin_missing_medium(self):
        text = """\
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
metadata:
  name: other
plugins:
  - name: ImagePolicyWebhook
    configuration: {}
"""
        rep, rc = self._main_capture(text)
        self.assertIn("psa-plugin-missing", self._checks(rep))

    def test_malformed_configuration_high(self):
        text = """\
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
metadata:
  name: psa
plugins:
  - name: PodSecurity
"""
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("psa-config-malformed", self._checks(rep))


class TestIoContract(unittest.TestCase):
    def test_mixed_namespace_and_admission(self):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "mix.yaml"
            src.write_text("""\
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      kind: PodSecurityConfiguration
      defaults:
        enforce: baseline
      exemptions:
        namespaces: [gatekeeper-system]
""", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pna.main(["--source", str(src), "--system-namespaces",
                               "gatekeeper-system"])
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["summary"]["namespaces_audited"], 1)
            self.assertEqual(rep["summary"]["admission_configs_audited"],
                             1)
            self.assertNotIn("psa-exempt-namespace-unknown",
                             {f["check"] for f in rep["findings"]})

    def test_json_input(self):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ns.json"
            src.write_text(json.dumps([
                {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": "app1", "labels": {
                     "pod-security.kubernetes.io/enforce": "baseline"}}},
            ]), encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pna.main(["--source", str(src)])
            self.assertEqual(rc, 0)

    def test_fail_closed_no_recognized_kind_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "pod.yaml"
            src.write_text("apiVersion: v1\nkind: Pod\n"
                           "metadata:\n  name: x\n", encoding="utf-8")
            rc = pna.main(["--source", str(src)])
            self.assertEqual(rc, 2)

    def test_missing_source_exit2(self):
        rc = pna.main(["--source", "Z:/no/such-file.yaml"])
        self.assertEqual(rc, 2)

    def test_fail_on_low_catches_low_findings(self):
        text = """\
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: restricted
"""
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ns.yaml"
            src.write_text(text, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pna.main(["--source", str(src), "--fail-on", "low"])
            self.assertEqual(rc, 1)  # psa-version-unpinned = low

    def test_out_writes_file(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ns.yaml"
            src.write_text("""\
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
""", encoding="utf-8")
            out = Path(td) / "out.json"
            rc = pna.main(["--source", str(src), "--out", str(out)])
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rc, 0)
            self.assertEqual(rep["schema"], "cyphron.psa-ns-audit/1")

    def test_list_items_recursed(self):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "list.yaml"
            src.write_text("""\
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: ns-a
      labels:
        pod-security.kubernetes.io/enforce: privileged
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: kube-public
""", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = pna.main(["--source", str(src)])
            rep = json.loads(buf.getvalue())
            self.assertEqual(rc, 1)
            self.assertEqual(rep["summary"]["namespaces_audited"], 2)
            self.assertIn("psa-enforce-privileged",
                          {f["check"] for f in rep["findings"]})


if __name__ == "__main__":
    unittest.main()
