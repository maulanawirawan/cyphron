"""Nol jaringan — test netpol_audit (audit offline manifest NetworkPolicy)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import netpol_audit as npa  # noqa: E402


class Helpers(unittest.TestCase):
    """Jalankan tool lewat capture stdout (bukan --out) supaya exit
    code dan isi report diuji sekaligus."""

    def _main_capture(self, text: str, *extra: str):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "np.yaml"
            src.write_text(text, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = npa.main(["--source", str(src), *extra])
            return (json.loads(buf.getvalue()) if buf.getvalue().strip()
                    else {}), rc


class TestDenyBaseline(Helpers):
    DENY_OK = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""

    def test_correct_deny_all_clean(self):
        rep, rc = self._main_capture(self.DENY_OK)
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["summary"]["policies_audited"], 1)
        self.assertEqual(rep["summary"]["by_severity"]["high"], 0)
        checks = {f["check"] for f in rep["findings"]}
        self.assertNotIn("deny-all-noop", checks)
        # baseline deny ada -> tidak ada temuan missing
        self.assertNotIn("deny-ingress-missing", checks)
        self.assertNotIn("deny-egress-missing", checks)

    def test_deny_without_policytypes_is_noop(self):
        text = self.DENY_OK.replace("  policyTypes: [Ingress, Egress]\n",
                                    "")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        high = [f for f in rep["findings"] if f["severity"] == "high"]
        self.assertEqual({f["check"] for f in high}, {"deny-all-noop"})
        self.assertIn("TIDAK mengenforce", high[0]["message"])

    def test_scoped_policy_only_flags_baseline_missing(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
"""
        rep, rc = self._main_capture(text)
        checks = {f["check"] for f in rep["findings"]}
        self.assertIn("deny-egress-missing", checks)
        self.assertIn("deny-ingress-missing", checks)
        # scoped peer pada policy scoped: bukan allow-all
        self.assertNotIn("allow-all-peer", checks)
        self.assertNotIn("allow-all-pods", checks)


class TestAllowAllDefeat(Helpers):
    BASE = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: t
  namespace: production
spec:
{spec}
"""

    def test_rule_without_from_is_allow_all(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - ports:
        - protocol: TCP
          port: 80
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("allow-all-rule",
                      {f["check"] for f in rep["findings"]})

    def test_empty_from_list_is_allow_all(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from: []
""")
        rep, rc = self._main_capture(text)
        self.assertIn("allow-all-rule",
                      {f["check"] for f in rep["findings"]})

    def test_empty_peer_object_is_allow_all(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - {}
""")
        rep, rc = self._main_capture(text)
        self.assertIn("allow-all-peer",
                      {f["check"] for f in rep["findings"]})

    def test_nsselector_empty_is_allow_all(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {}
""")
        rep, rc = self._main_capture(text)
        self.assertIn("allow-all-peer",
                      {f["check"] for f in rep["findings"]})

    def test_podselector_empty_on_empty_policy_high(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("select-all-on-select-all",
                      {f["check"] for f in rep["findings"]})

    def test_podselector_empty_on_scoped_policy_medium(self):
        text = self.BASE.format(spec="""\
  podSelector:
    matchLabels:
      app: backend
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
""")
        rep, rc = self._main_capture(text)
        med = {f["check"] for f in rep["findings"]
               if f["severity"] == "medium"}
        self.assertIn("allow-all-pods", med)
        self.assertNotIn("select-all-on-select-all",
                         {f["check"] for f in rep["findings"]})

    def test_egress_rule_without_to_is_allow_all(self):
        text = self.BASE.format(spec="""\
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - ports:
        - protocol: TCP
          port: 443
""")
        rep, rc = self._main_capture(text)
        self.assertIn("allow-all-rule",
                      {f["check"] for f in rep["findings"]})

    def test_quoted_empty_map_artifact_recognized(self):
        # artefak parser YAML-subset: podSelector: "{}" (string)
        text = self.BASE.format(spec="""\
  podSelector: "{}"
  policyTypes: [Ingress, Egress]
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 0, rep)


class TestPolicyTypes(Helpers):
    def test_egress_rules_without_egress_type_dead(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dead-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress]
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - protocol: TCP
          port: 5432
"""
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 1)
        self.assertIn("policytypes-mismatch",
                      {f["check"] for f in rep["findings"]})

    def test_policytypes_missing_with_rules_medium(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inferred
  namespace: production
spec:
  podSelector: {}
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
"""
        rep, rc = self._main_capture(text)
        self.assertIn("policytypes-missing",
                      {f["check"] for f in rep["findings"]})
        # inference: Ingress ada -> baseline ingress terpenuhi
        self.assertNotIn("deny-ingress-missing",
                         {f["check"] for f in rep["findings"]})


class TestIpBlock(Helpers):
    BASE = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
{rules}
"""

    def test_wide_open_and_metadata_exposed(self):
        text = self.BASE.replace("{rules}", """\
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
""")
        rep, rc = self._main_capture(text)
        checks = {f["check"] for f in rep["findings"]}
        self.assertIn("wide-open-ipblock", checks)
        self.assertIn("metadata-egress-exposed", checks)

    def test_metadata_excepted_clean_of_metadata(self):
        text = self.BASE.replace("{rules}", """\
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
              - 100.100.100.200/32
      ports:
        - protocol: TCP
          port: 443
""")
        rep, rc = self._main_capture(text)
        checks = {f["check"] for f in rep["findings"]}
        self.assertNotIn("metadata-egress-exposed", checks)
        # ada except -> bukan wide-open penuh
        self.assertNotIn("wide-open-ipblock", checks)

    def test_invalid_cidr_flagged(self):
        text = self.BASE.replace("{rules}", """\
    - to:
        - ipBlock:
            cidr: 10.0.0.0/99
""")
        rep, rc = self._main_capture(text)
        self.assertIn("ipblock-cidr-invalid",
                      {f["check"] for f in rep["findings"]})

    def test_scoped_cidr_no_findings(self):
        text = self.BASE.replace("{rules}", """\
    - to:
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - protocol: TCP
          port: 443
""")
        rep, rc = self._main_capture(text)
        self.assertEqual(rc, 0, rep)


class TestNamespaceAggregate(Helpers):
    def test_dns_blocked_flagged(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-only
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
"""
        rep, rc = self._main_capture(text)
        self.assertIn("dns-egress-missing",
                      {f["check"] for f in rep["findings"]})

    def test_dns_allowed_via_udp53(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
"""
        rep, rc = self._main_capture(text)
        checks = {f["check"] for f in rep["findings"]}
        self.assertNotIn("dns-egress-missing", checks)
        self.assertNotIn("deny-ingress-missing", checks)
        self.assertNotIn("deny-egress-missing", checks)

    def test_dns_allowed_via_all_ports_rule(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress
  namespace: prod
spec:
  podSelector: {}
  policyTypes: [Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 203.0.113.0/24
"""
        rep, rc = self._main_capture(text)
        self.assertNotIn("dns-egress-missing",
                         {f["check"] for f in rep["findings"]})

    def test_expect_ns_without_policy_high(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""
        rep, rc = self._main_capture(text, "--expect-ns", "production,"
                                     "pci-cde")
        self.assertEqual(rc, 1)
        no_pol = [f for f in rep["findings"]
                  if f["check"] == "no-policy-namespace"]
        self.assertEqual(len(no_pol), 1)
        self.assertEqual(no_pol[0]["namespace"], "pci-cde")

    def test_expect_ns_covered_clean(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""
        rep, rc = self._main_capture(text, "--expect-ns", "production")
        self.assertEqual(rc, 0, rep)


class TestIoContract(unittest.TestCase):
    def test_list_items_and_json_input(self):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "np.json"
            src.write_text(json.dumps({"kind": "List", "items": [
                {"apiVersion": "networking.k8s.io/v1",
                 "kind": "NetworkPolicy",
                 "metadata": {"name": "d", "namespace": "ns1"},
                 "spec": {"podSelector": {},
                          "policyTypes": ["Ingress", "Egress"]}}]}),
                encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = npa.main(["--source", str(src)])
            rep = json.loads(buf.getvalue())
            self.assertEqual(rc, 0, rep)
            self.assertEqual(rep["summary"]["policies_audited"], 1)
            self.assertEqual(rep["summary"]["namespaces"], ["ns1"])

    def test_no_networkpolicy_fail_closed_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "other.yaml"
            src.write_text("apiVersion: v1\nkind: Pod\n"
                           "metadata:\n  name: x\n", encoding="utf-8")
            rc = npa.main(["--source", str(src)])
            self.assertEqual(rc, 2)

    def test_missing_source_exit2(self):
        rc = npa.main(["--source", "Z:/does/not/exist-xyz.yaml"])
        self.assertEqual(rc, 2)

    def test_empty_dir_exit2(self):
        with tempfile.TemporaryDirectory() as td:
            rc = npa.main(["--source", td])
            self.assertEqual(rc, 2)

    def test_unparsed_file_recorded(self):
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "bad.yaml").write_text(
                "kind: NetworkPolicy\nspec: {podSelector: {}, "
                "policyTypes: [Ingress, Egress]}\n",
                encoding="utf-8")
            (Path(td) / "broken.yaml").write_text(
                "spec:\n  - tidak [valid\n  :\n", encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = npa.main(["--source", td])
            rep = json.loads(buf.getvalue())
            self.assertTrue(any("broken.yaml" in u
                                for u in rep["summary"]["unparsed"]))
            self.assertIn("fail-closed", " ".join(rep["notes"]).lower())

    def test_fail_on_medium_escalates_exit(self):
        text = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inferred
  namespace: production
spec:
  podSelector: {}
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
"""
        import io
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "np.yaml"
            src.write_text(text, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = npa.main(["--source", str(src),
                               "--fail-on", "medium"])
            self.assertEqual(rc, 1)

    def test_out_writes_file(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "np.yaml"
            src.write_text("""\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: d
  namespace: ns1
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
""", encoding="utf-8")
            out = Path(td) / "out.json"
            rc = npa.main(["--source", str(src), "--out", str(out)])
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rc, 0)
            self.assertEqual(rep["schema"], "secai.netpol-audit/1")


if __name__ == "__main__":
    unittest.main()
