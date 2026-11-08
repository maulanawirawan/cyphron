"""Nol jaringan — test aws_config_audit (configuration-item/snapshot AWS
Config). Fixture dibangun inline mengikuti struktur configuration-item
(resourceType/configuration/supplementaryConfiguration); perilaku rule
diuji terhadap konsep managed rule CIS + custom required-tags sumber.
Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("tools",):
    sys.path.insert(0, str(ROOT / sub))

import aws_config_audit as aca  # noqa: E402

TOOL = ROOT / "tools" / "aws_config_audit.py"


def _s3_bad() -> dict:
    return {"resourceType": "AWS::S3::Bucket", "resourceId": "data-lake",
            "configuration": {
                "publicAccessBlockConfiguration": {
                    "blockPublicAcls": True, "ignorePublicAcls": True,
                    "blockPublicPolicy": False,  # lubang
                    "restrictPublicBuckets": True},
                "bucketPolicy": json.dumps({"Statement": [
                    {"Effect": "Allow", "Principal": "*",
                     "Action": "s3:GetObject"}]}),
                "serverSideEncryptionConfiguration": {},
                "tags": [{"key": "Environment", "value": "prod"},
                         {"key": "Owner", "value": "ops"}],
            }}


def _s3_good() -> dict:
    return {"resourceType": "AWS::S3::Bucket", "resourceId": "ok-bucket",
            "configuration": {
                "publicAccessBlockConfiguration": {
                    "blockPublicAcls": True, "ignorePublicAcls": True,
                    "blockPublicPolicy": True, "restrictPublicBuckets": True},
                "bucketPolicy": json.dumps({"Statement": [
                    {"Effect": "Deny", "Principal": "*",
                     "Action": "s3:*",
                     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}),
                "serverSideEncryptionConfiguration": [
                    {"sseAlgorithm": "aws:kms"}],
                "tags": [{"key": "Environment", "value": "prod"},
                         {"key": "Owner", "value": "ops"}],
            }}


def _sg(port: int) -> dict:
    return {"resourceType": "AWS::EC2::SecurityGroup", "resourceId": "sg-x",
            "configuration": {"ipPermissions": [
                {"fromPort": port, "toPort": port,
                 "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}}


def _audit(items: list[dict], require_tags=None):
    findings: list[dict] = []
    notes: list[str] = []
    summary = aca.audit_items(items, require_tags or ["Environment", "Owner"],
                              14, findings, notes)
    return findings, summary, notes


class TestFailClosed(unittest.TestCase):
    def test_bentuk_tak_dikenali_raise(self):
        with self.assertRaises(ValueError):
            aca._load_items({"foo": "bar"})

    def test_bentuk_configurationitem_dan_array(self):
        item = {"resourceType": "AWS::EC2::Volume", "resourceId": "v1"}
        self.assertEqual(aca._load_items({"configurationItem": item}), [item])
        self.assertEqual(aca._load_items([item]), [item])
        self.assertEqual(
            aca._load_items({"configurationItems": [item]}), [item])

    def test_cli_file_hilang_exit_2(self):
        r = subprocess.run([sys.executable, str(TOOL), "--item",
                            "TIDAK-ADA.json"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_cli_bukan_json_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.json"
            p.write_text("{bukan", encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--item", str(p)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)


class TestS3Checks(unittest.TestCase):
    def test_s3_lubang_publik_dan_tanpa_ssl(self):
        findings, _, _ = _audit([_s3_bad()])
        checks = {(f["check"], f["resource_id"]) for f in findings}
        self.assertIn(("s3-public-block", "data-lake"), checks)
        self.assertIn(("s3-no-ssl-deny", "data-lake"), checks)
        self.assertIn(("s3-sse-absent", "data-lake"), checks)
        high = [f for f in findings if f["severity"] == "high"]
        self.assertEqual([f["check"] for f in high], ["s3-public-block"])

    def test_s3_baik_bersih(self):
        findings, _, notes = _audit([_s3_good()])
        s3 = [f for f in findings if f["resource_id"] == "ok-bucket"]
        self.assertEqual(s3, [])

    def test_s3_pab_absent_medium(self):
        item = {"resourceType": "AWS::S3::Bucket", "resourceId": "b2",
                "configuration": {"tags": [{"key": "Environment",
                                            "value": "x"},
                                           {"key": "Owner", "value": "y"}]}}
        findings, _, _ = _audit([item])
        self.assertIn(("s3-pab-absent", "b2"),
                      {(f["check"], f["resource_id"]) for f in findings})


class TestIamChecks(unittest.TestCase):
    def test_root_access_key_high(self):
        item = {"resourceType": "AWS::IAM::User",
                "resourceId": "<root_account>",
                "configuration": {"userName": "<root_account>",
                                  "accessKeys": [{"status": "Active"}]}}
        findings, _, _ = _audit([item])
        root = [f for f in findings if f["check"] == "root-access-key"]
        self.assertEqual(len(root), 1)
        self.assertEqual(root[0]["severity"], "high")

    def test_user_access_key_medium(self):
        item = {"resourceType": "AWS::IAM::User", "resourceId": "svc-x",
                "configuration": {"userName": "svc-x",
                                  "accessKeys": [{"status": "Active"},
                                                 {"status": "Inactive"}]}}
        findings, _, _ = _audit([item])
        med = [f for f in findings if f["check"] == "user-access-keys"]
        self.assertEqual(len(med), 1)
        self.assertIn("svc-x", med[0]["message"])

    def test_password_policy_lemah(self):
        item = {"resourceType": "AWS::Account", "resourceId": "acct",
                "configuration": {"passwordPolicy": {
                    "requireUppercaseCharacters": True,
                    "requireLowercaseCharacters": True,
                    "requireNumbers": False,
                    "requireSymbols": True,
                    "minimumPasswordLength": 8}}}
        findings, _, _ = _audit([item])
        pp = [f for f in findings if f["check"] == "password-policy"]
        self.assertEqual(len(pp), 2)  # numbers + panjang
        self.assertTrue(any("minimumPasswordLength" in f["message"]
                            for f in pp))


class TestNetworkChecks(unittest.TestCase):
    def test_ssh_dan_rdp_terbuka_high(self):
        findings, _, _ = _audit([_sg(22), _sg(3389)])
        open_ports = [f for f in findings if f["check"] == "sg-open-port"]
        self.assertEqual(len(open_ports), 2)
        self.assertTrue(all(f["severity"] == "high" for f in open_ports))

    def test_port_tidak_terbuka_bersih(self):
        findings, _, _ = _audit([_sg(8080)])
        self.assertEqual([f for f in findings
                          if f["check"] == "sg-open-port"], [])


class TestEncryptionAndTags(unittest.TestCase):
    def test_rds_ebs_unencrypted(self):
        items = [
            {"resourceType": "AWS::RDS::DBInstance", "resourceId": "db-1",
             "configuration": {"storageEncrypted": False,
                               "tags": [{"key": "Environment", "value": "p"},
                                        {"key": "Owner", "value": "o"}]}},
            {"resourceType": "AWS::EC2::Volume", "resourceId": "vol-1",
             "configuration": {"encrypted": False}},
        ]
        findings, _, _ = _audit(items)
        checks = {(f["check"], f["resource_id"]) for f in findings}
        self.assertIn(("rds-unencrypted", "db-1"), checks)
        self.assertIn(("ebs-unencrypted", "vol-1"), checks)

    def test_required_tags_missing(self):
        item = {"resourceType": "AWS::EC2::Instance", "resourceId": "i-1",
                "configuration": {"tags": [{"key": "Environment",
                                            "value": "prod"}]}}
        findings, _, _ = _audit([item])
        miss = [f for f in findings if f["check"] == "required-tags-missing"]
        self.assertEqual(len(miss), 1)
        self.assertIn("Owner", miss[0]["message"])

    def test_vpc_tanpa_flowlog(self):
        items = [{"resourceType": "AWS::EC2::VPC", "resourceId": "vpc-7",
                  "configuration": {"state": "available"}},
                 {"resourceType": "AWS::EC2::FlowLog", "resourceId": "fl-1",
                  "configuration": {"resourceId": "vpc-lain"}}]
        findings, _, _ = _audit(items)
        hit = [f for f in findings if f["check"] == "vpc-flow-logs-off"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["resource_id"], "vpc-7")

    def test_vpc_dengan_flowlog_bersih(self):
        items = [{"resourceType": "AWS::EC2::VPC", "resourceId": "vpc-9",
                  "configuration": {"state": "available"}},
                 {"resourceType": "AWS::EC2::FlowLog", "resourceId": "fl-9",
                  "configuration": {"resourceId": "vpc-9"}}]
        findings, _, _ = _audit(items)
        self.assertEqual([f for f in findings
                          if f["check"] == "vpc-flow-logs-off"], [])

    def test_item_tanpa_configuration_dihitung(self):
        item = {"resourceType": "AWS::EC2::Instance", "resourceId": "i-x"}
        findings, summary, _ = _audit([item])
        self.assertEqual(summary["items_without_configuration"], 1)
        self.assertEqual(findings, [])


class TestCli(unittest.TestCase):
    def test_snapshot_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "snapshot.json"
            p.write_text(json.dumps({"configurationItems": [
                _s3_bad(), _sg(22)]}), encoding="utf-8")
            out = Path(td) / "hasil.json"
            r = subprocess.run([sys.executable, str(TOOL), "--item", str(p),
                                "--json", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["kind"], "aws-config-audit")
            self.assertIn("attribution", doc)
            checks = {f["check"] for f in doc["findings"]}
            self.assertIn("s3-public-block", checks)
            self.assertIn("sg-open-port", checks)

    def test_fail_on_high_mengabaikan_medium(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "snapshot.json"
            p.write_text(json.dumps({"configurationItems": [_s3_good()]}),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--item", str(p),
                                "--fail-on", "high"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
