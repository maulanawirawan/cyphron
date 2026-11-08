"""Nol jaringan — test etcd_config_audit (audit konfigurasi etcd +
EncryptionConfiguration dari file statis).

Fixture manifest dibangun inline sesuai bentuk kubeadm nyata (YAML
subset). Tidak ada request jaringan.
"""
from __future__ import annotations

import base64
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import etcd_config_audit as eca  # noqa: E402
from findings import validate_finding  # noqa: E402

K32 = base64.b64encode(b"k" * 32).decode()
K8 = base64.b64encode(b"k" * 8).decode()

# static pod etcd ala kubeadm — versi LEMAH (tanpa mTLS peer, http)
ETCD_WEAK = """apiVersion: v1
kind: Pod
metadata:
  name: etcd-master
  namespace: kube-system
spec:
  containers:
    - name: etcd
      image: registry.k8s.io/etcd:3.5.12-0
      command:
        - etcd
        - --advertise-client-urls=https://10.0.0.1:2379
        - --listen-client-urls=http://0.0.0.0:2379
        - --listen-peer-urls=http://10.0.0.1:2380
        - --auto-tls=true
        - --enable-v2=true
        - --data-dir=/var/lib/etcd
"""

# etcd yang benar: mTLS penuh, https
ETCD_STRONG = """apiVersion: v1
kind: Pod
metadata:
  name: etcd-master
spec:
  containers:
    - name: etcd
      command:
        - etcd
        - --listen-client-urls=https://127.0.0.1:2379
        - --listen-peer-urls=https://10.0.0.1:2380
        - --client-cert-auth=true
        - --peer-client-cert-auth=true
        - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
        - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
        - --cert-file=/etc/kubernetes/pki/etcd/server.crt
        - --key-file=/etc/kubernetes/pki/etcd/server.key
        - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
        - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
"""

# kube-apiserver: etcd https tapi tanpa encryption-provider-config
APISERVER_WEAK = """apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --etcd-servers=https://127.0.0.1:2379
        - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
        - --service-account-key-file=/srv/pub.pem
"""

APISERVER_HTTP = """apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --etcd-servers=http://127.0.0.1:2379,https://10.0.0.1:2379
"""

ENC_IDENTITY_FIRST = """apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - aescbc:
          keys:
            - name: key1
              secret: %s
""" % K32

ENC_AESCBC_SHORTKEY = """apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: %s
      - identity: {}
""" % K8

ENC_NO_SECRETS = """apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - configmaps
    providers:
      - secretbox:
          keys:
            - name: k1
              secret: %s
""" % K32


class EtcdConfigAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="etcd_t"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, text: str, name: str) -> Path:
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def _run(self, *pairs: tuple[str, Path], out="f.json") -> tuple[int, dict]:
        argv: list[str] = ["--out", str(self.tmp / out)]
        for flag, p in pairs:
            argv += [f"--{flag.replace('_', '-')}", str(p)]
        rc = eca.main(argv)
        path = self.tmp / out
        return rc, (json.loads(path.read_text(encoding="utf-8"))
                    if path.exists() else {})

    def test_weak_etcd_flags(self) -> None:
        p = self._write(ETCD_WEAK, "etcd-pod.yaml")
        rc, doc = self._run(("etcd_manifest", p))
        self.assertEqual(rc, 1)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("http://", titles)          # listener plaintext
        self.assertIn("client-cert-auth", titles)
        self.assertIn("auto-tls", titles)
        self.assertIn("enable-v2", titles)
        highs = [f for f in doc["findings"] if f["severity"] == "high"]
        self.assertGreaterEqual(len(highs), 3)
        self.assertTrue(doc["data"]["etcd_side"])
        self.assertFalse(doc["data"]["apiserver_side"])

    def test_strong_etcd_clean(self) -> None:
        p = self._write(ETCD_STRONG, "etcd-strong.yaml")
        rc, doc = self._run(("etcd_manifest", p))
        self.assertEqual(rc, 0)
        self.assertEqual(doc["findings"], [])

    def test_raw_args_text_fallback(self) -> None:
        p = self._write("/usr/bin/etcd --client-cert-auth=false "
                        "--listen-client-urls=http://0.0.0.0:2379 "
                        "--data-dir=/var/lib/etcd", "ps.txt")
        rc, doc = self._run(("etcd_manifest", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("client-cert-auth tidak aktif (false)", titles)

    def test_apiserver_missing_encryption(self) -> None:
        p = self._write(APISERVER_WEAK, "ka-pod.yaml")
        rc, doc = self._run(("apiserver_manifest", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("encryption-provider-config", titles)
        self.assertIn("PLAINTEXT", titles)

    def test_apiserver_http_server(self) -> None:
        p = self._write(APISERVER_HTTP, "ka-http.yaml")
        rc, doc = self._run(("apiserver_manifest", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("non-https", titles)
        self.assertIn("http://127.0.0.1:2379", titles)

    def test_identity_first_high(self) -> None:
        p = self._write(ENC_IDENTITY_FIRST, "enc.yaml")
        rc, doc = self._run(("encryption_config", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("provider PERTAMA identity", titles)
        self.assertIn("PLAINTEXT", titles)
        # nilai kunci TIDAK PERNAH muncul di output
        self.assertNotIn(K32, json.dumps(doc))

    def test_aescbc_short_key_and_identity_fallback_ok(self) -> None:
        p = self._write(ENC_AESCBC_SHORTKEY, "enc2.yaml")
        rc, doc = self._run(("encryption_config", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("panjang 8 byte", titles)
        # identity SETELAH aescbc = fallback sah (info, bukan high)
        self.assertFalse(any(
            f["severity"] == "high"
            for f in doc["findings"] if "identity" in f["title"]))

    def test_enc_without_secrets_resource(self) -> None:
        p = self._write(ENC_NO_SECRETS, "enc3.yaml")
        rc, doc = self._run(("encryption_config", p))
        self.assertEqual(rc, 1)
        titles = " || ".join(f["title"] for f in doc["findings"])
        self.assertIn("tidak mencakup resource", titles)
        self.assertIn("secrets", titles)

    def test_fail_closed(self) -> None:
        out = self.tmp / "x.json"
        # tanpa input
        self.assertEqual(eca.main(["--out", str(out)]), 2)
        # file tidak ada
        self.assertEqual(eca.main(["--etcd-manifest",
                                   str(self.tmp / "no.yaml"),
                                   "--out", str(out)]), 2)
        # file tanpa flag dikenali
        p = self._write("hello: world\nfoo:\n  - bar", "noise.yaml")
        self.assertEqual(eca.main(["--etcd-manifest", str(p),
                                   "--out", str(out)]), 2)
        self.assertFalse(out.exists())

    def test_flag_boolean_telanjang_dan_equal(self) -> None:
        f = eca.extract_flags_text(
            "etcd --client-cert-auth --peer-client-cert-auth=true "
            "--listen-client-urls https://a:2379 --enable-v2 false")
        self.assertEqual(f["client-cert-auth"], "true")
        self.assertEqual(f["peer-client-cert-auth"], "true")
        self.assertEqual(f["listen-client-urls"], "https://a:2379")
        self.assertEqual(f["enable-v2"], "false")


if __name__ == "__main__":
    unittest.main()
