"""Nol jaringan — test k8s_podsec_audit (audit offline spec pod vs PSS)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import k8s_podsec_audit as kpa  # noqa: E402

DEPLOY_PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-privileged
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
"""

DEPLOY_GOOD_RESTRICTED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good-restricted
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: nginx
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsUser: 10001
      volumes:
      - name: scratch
        emptyDir: {}
"""

POD_HOSTPATH_HOSTPID = """\
apiVersion: v1
kind: Pod
metadata:
  name: hosty
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: busybox
    volumeMounts:
    - name: rootdisk
      mountPath: /host
  volumes:
  - name: rootdisk
    hostPath:
      path: /
"""

CRONJOB_UNSET = """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: python
"""

JSON_LIST_MIXED = {
    "kind": "List",
    "items": [
        {"kind": "Pod", "metadata": {"name": "j1"},
         "spec": {"containers": [{"name": "c", "image": "i",
                                  "securityContext": {
                                      "runAsNonRoot": True,
                                      "allowPrivilegeEscalation": False,
                                      "capabilities": {"drop": ["ALL"]},
                                      "seccompProfile":
                                          {"type": "RuntimeDefault"},
                                      "runAsUser": 1000}}]}},
        {"kind": "ConfigMap", "metadata": {"name": "cm"},
         "data": {"a": "b"}},
    ],
}


class K8sPodsecAuditTest(unittest.TestCase):

    def test_privileged_fails_restricted_and_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "d.yaml"
            p.write_text(DEPLOY_PRIVILEGED, encoding="utf-8")
            for profile in ("restricted", "baseline"):
                out = Path(td) / f"o-{profile}.json"
                code = kpa.main(["--source", str(p),
                                 "--profile", profile,
                                 "--out", str(out)])
                self.assertEqual(code, 1, profile)
                rep = json.loads(out.read_text(encoding="utf-8"))
                checks = {f["check"] for f in rep["findings"]}
                self.assertIn("privileged", checks)
                if profile == "restricted":
                    self.assertIn("allow-priv-esc", checks)

    def test_good_restricted_clean(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "g.yaml"
            p.write_text(DEPLOY_GOOD_RESTRICTED, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--out", str(out)])
            self.assertEqual(code, 0)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rep["findings"], [])
            self.assertEqual(rep["summary"]["workloads_audited"], 1)

    def test_pod_hostpath_hostpid(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.yaml"
            p.write_text(POD_HOSTPATH_HOSTPID, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--out", str(out)])
            self.assertEqual(code, 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            checks = {f["check"] for f in rep["findings"]}
            self.assertIn("host-pid/ipc", checks)
            self.assertIn("host-network", checks)
            self.assertIn("host-path-volume", checks)

    def test_cronjob_pod_spec_reached(self):
        # CronJob tanpa securityContext = banyak pelanggaran Restricted
        # (allow-priv-esc tak diset, seccomp tak diset, dst).
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yaml"
            p.write_text(CRONJOB_UNSET, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--out", str(out)])
            self.assertEqual(code, 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rep["summary"]["workloads_audited"], 1)
            checks = {f["check"] for f in rep["findings"]}
            self.assertIn("allow-priv-esc", checks)
            self.assertIn("seccomp-profile", checks)
            self.assertIn("cap-drop-all-missing", checks)

    def test_json_list_skips_non_pod(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "l.json"
            p.write_text(json.dumps(JSON_LIST_MIXED), encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--out", str(out)])
            self.assertEqual(code, 0)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rep["summary"]["workloads_audited"], 1)
            self.assertEqual(rep["findings"], [])

    def test_baseline_profile_satisfied_by_default_caps(self):
        # cap NET_RAW + NET_BIND_SERVICE sah di Baseline, tak sah di
        # Restricted.
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: net-tools
spec:
  containers:
  - name: c
    image: i
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
        add: ["NET_RAW", "NET_BIND_SERVICE"]
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.yaml"
            p.write_text(body, encoding="utf-8")
            out_b = Path(td) / "ob.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--profile", "baseline",
                                       "--out", str(out_b)]), 0)
            out_r = Path(td) / "or.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--profile", "restricted",
                                       "--out", str(out_r)]), 1)
            rep = json.loads(out_r.read_text(encoding="utf-8"))
            self.assertIn("restricted-cap-add",
                          {f["check"] for f in rep["findings"]})

    def test_disallowed_cap_sysadmin_flagged_both_profiles(self):
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: capsys
spec:
  containers:
  - name: c
    image: i
    securityContext:
      capabilities:
        add: ["SYS_ADMIN"]
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "s.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            kpa.main(["--source", str(p), "--profile", "baseline",
                      "--out", str(out)])
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("disallowed-cap-add",
                          {f["check"] for f in rep["findings"]})

    def test_restricted_unset_run_as_non_root_medium(self):
        # Container dgn semua cek eksplisit KECUALI runAsNonRoot ->
        # medium (bukan high) karena pod-level juga tidak menetapkan.
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: partial
spec:
  containers:
  - name: c
    image: i
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "p.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--out", str(out)])
            self.assertEqual(code, 0)  # default --fail-on high
            rep = json.loads(out.read_text(encoding="utf-8"))
            runr = [f for f in rep["findings"]
                    if f["check"] == "run-as-non-root"]
            self.assertEqual(len(runr), 1)
            self.assertEqual(runr[0]["severity"], "medium")

    def test_run_as_user_root_pod_level_inherited(self):
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: uid0
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 0
  containers:
  - name: c
    image: i
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "u.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--out", str(out)]), 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("run-as-user-root",
                          {f["check"] for f in rep["findings"]})

    def test_seccomp_unconfined_high(self):
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: nouser
spec:
  containers:
  - name: c
    image: i
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: Unconfined
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--out", str(out)]), 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            secc = [f for f in rep["findings"]
                    if f["check"] == "seccomp-profile"]
            self.assertEqual(secc[0]["severity"], "high")

    def test_restricted_volume_type_violation(self):
        body = """\
apiVersion: v1
kind: Pod
metadata:
  name: nfs
spec:
  containers:
  - name: c
    image: i
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
  volumes:
  - name: share
    nfs:
      server: 10.0.0.5
      path: /export
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "v.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--fail-on", "medium",
                                       "--out", str(out)]), 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("volume-type",
                          {f["check"] for f in rep["findings"]})

    def test_fail_on_medium_exit_1(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yaml"
            p.write_text(CRONJOB_UNSET, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(p), "--fail-on", "medium",
                             "--out", str(out)])
            self.assertEqual(code, 1)

    def test_no_workloads_fail_closed_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.yaml"
            p.write_text("kind: ConfigMap\n"
                         "metadata:\n  name: cm\n", encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stderr
            sys.stderr = buf
            try:
                code = kpa.main(["--source", str(p)])
            finally:
                sys.stderr = old
            self.assertEqual(code, 2)
            self.assertIn("fail-closed", buf.getvalue())

    def test_missing_source_exit_2(self):
        import io
        buf = io.StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            code = kpa.main(["--source",
                             str(Path("D:/nonexistent-b22/x.yaml"))])
        finally:
            sys.stderr = old
        self.assertEqual(code, 2)

    def test_unparsed_reported_not_clean(self):
        # File dgn YAML rusak di samping workload valid -> tercatat di
        # unparsed + note fail-closed.
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "broken.yaml").write_text(
                "kind: Pod\n  spec: [unclosed\n", encoding="utf-8")
            (Path(td) / "ok.yaml").write_text(
                DEPLOY_GOOD_RESTRICTED, encoding="utf-8")
            out = Path(td) / "o.json"
            code = kpa.main(["--source", str(td), "--out", str(out)])
            self.assertEqual(code, 0)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(rep["summary"]["unparsed"])
            self.assertTrue(any("fail-closed" in n
                                for n in rep["notes"]))

    def test_init_containers_audited(self):
        body = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: initbad
spec:
  template:
    spec:
      containers:
      - name: app
        image: i
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
      initContainers:
      - name: installer
        image: i
        securityContext:
          privileged: true
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "i.yaml"
            p.write_text(body, encoding="utf-8")
            out = Path(td) / "o.json"
            self.assertEqual(kpa.main(["--source", str(p),
                                       "--out", str(out)]), 1)
            rep = json.loads(out.read_text(encoding="utf-8"))
            priv = [f for f in rep["findings"]
                    if f["check"] == "privileged"]
            self.assertEqual(priv[0]["container"], "installer")


if __name__ == "__main__":
    unittest.main()
