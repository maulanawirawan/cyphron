"""Nol jaringan — test iam_escalation_scan (analisis artefak IAM offline).

Artefak 'get-account-authorization-details' sintetis dibangun di memori
(format struktur mengikuti dokumentasi AWS publik). Tidak ada panggilan
AWS, tidak ada jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import iam_escalation_scan as iam  # noqa: E402

ACC = "111122223333"


def stmt(effect="Allow", actions=("s3:ListBucket",), resource="*",
         **extra):
    s = {"Effect": effect, "Action": list(actions),
         "Resource": resource if isinstance(resource, list) else [resource]}
    s.update(extra)
    return s


def pol(name: str, statements) -> dict:
    return {"PolicyName": name,
            "Arn": f"arn:aws:iam::{ACC}:policy/{name}",
            "PolicyVersionList": [
                {"VersionId": "v1", "IsDefaultVersion": True,
                 "Document": {"Statement": statements}}]}


def attach(name: str) -> dict:
    return {"PolicyName": name,
            "PolicyArn": f"arn:aws:iam::{ACC}:policy/{name}"}


def auth(*, users=(), roles=(), groups=(), policies=()) -> dict:
    return {"UserDetailList": list(users), "RoleDetailList": list(roles),
            "GroupDetailList": list(groups), "Policies": list(policies)}


def checks(fnds):
    return {f["check"] for f in fnds}


class TestEvaluateDocument(unittest.TestCase):
    """Nol jaringan — evaluasi satu policy document."""

    def test_admin_wildcard(self):
        v = iam.evaluate_document({"Statement": [stmt(actions=("*",))]})
        self.assertIn("admin-wildcard", checks(v))
        self.assertEqual(v[0]["severity"], "high")

    def test_deny_bukan_temuan(self):
        v = iam.evaluate_document({"Statement": [
            stmt(effect="Deny", actions=("*",))]})
        self.assertEqual(v, [])

    def test_policy_version_swap(self):
        v = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:CreatePolicyVersion",))]})
        self.assertIn("policy-version-swap", checks(v))
        v2 = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:SetDefaultPolicyVersion",))]})
        self.assertIn("policy-version-swap", checks(v2))

    def test_passrole_combo(self):
        v = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:PassRole", "lambda:CreateFunction"))]})
        self.assertIn("passrole-combo", checks(v))
        v2 = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:PassRole", "ec2:RunInstances"))]})
        self.assertIn("passrole-combo", checks(v2))
        # PassRole sendirian bukan combo
        v3 = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:PassRole",))]})
        self.assertNotIn("passrole-combo", checks(v3))

    def test_credential_dan_assume(self):
        v = iam.evaluate_document({"Statement": [
            stmt(actions=("iam:CreateAccessKey",))]})
        self.assertIn("credential-forgery", checks(v))
        v2 = iam.evaluate_document({"Statement": [
            stmt(actions=("sts:AssumeRole",))]})
        self.assertIn("assume-role-broad", checks(v2))

    def test_wildcard_sensitive_medium(self):
        v = iam.evaluate_document({"Statement": [
            stmt(actions=("secretsmanager:GetSecretValue",),
                 resource="*")]})
        self.assertIn("wildcard-sensitive", checks(v))
        self.assertEqual(v[0]["severity"], "medium")
        # resource spesifik bukan temuan
        v2 = iam.evaluate_document({"Statement": [
            stmt(actions=("secretsmanager:GetSecretValue",),
                 resource=f"arn:aws:secretsmanager:us-east-1:{ACC}:secret/x")]})
        self.assertNotIn("wildcard-sensitive", checks(v2))

    def test_notaction_dicatat_info(self):
        v = iam.evaluate_document({"Statement": [
            {"Effect": "Allow", "NotAction": "iam:DeleteUser",
             "Resource": "*"}]})
        self.assertIn("notaction-unanalyzable", checks(v))
        self.assertEqual(v[0]["severity"], "info")


class TestScan(unittest.TestCase):
    """Nol jaringan — pipeline artefak penuh."""

    def test_artefak_berisiko(self):
        art = auth(
            users=[{"UserName": "admin-asal",
                    "AttachedManagedPolicies": [attach("Administrator")],
                    "UserPolicyList": []}],
            roles=[{"RoleName": "ci-runner",
                    "AttachedManagedPolicies": [attach("Deploy")],
                    "RolePolicyList": [],
                    "AssumeRolePolicyDocument": {"Statement": [
                        {"Effect": "Allow", "Principal": "*",
                         "Action": "sts:AssumeRole"}]}}],
            policies=[
                pol("Administrator", [stmt(actions=("*",))]),
                pol("Deploy", [stmt(actions=("iam:PassRole",
                                             "lambda:CreateFunction"))]),
            ])
        r = iam.scan(art)
        self.assertEqual(r["principals_total"], 2)
        self.assertEqual(r["verdict"], "ESCALATION_VECTORS_FOUND")
        self.assertIn("admin-wildcard", checks(r["findings"]))
        self.assertIn("passrole-combo", checks(r["findings"]))
        self.assertIn("trust-wildcard", checks(r["findings"]))

    def test_role_tanpa_trust_baik(self):
        art = auth(
            roles=[{"RoleName": "rapi",
                    "AttachedManagedPolicies": [],
                    "RolePolicyList": [],
                    "AssumeRolePolicyDocument": {"Statement": [
                        {"Effect": "Allow",
                         "Principal": {"AWS": f"arn:aws:iam::{ACC}:root"},
                         "Action": "sts:AssumeRole"}]}}],
            policies=[pol("ReadOnlyS3", [stmt(
                actions=("s3:GetObject",),
                resource=f"arn:aws:s3:::bucket-internal/*")])])
        r = iam.scan(art)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["verdict"], "CLEAN_NO_KNOWN_VECTOR")

    def test_policy_doc_missing_tidak_diam(self):
        art = auth(users=[{"UserName": "u",
                           "AttachedManagedPolicies": [
                               {"PolicyName": "Ghost",
                                "PolicyArn": "arn:aws:iam::aws:policy/x"}],
                           "UserPolicyList": []}],
                   policies=[])
        r = iam.scan(art)
        self.assertIn("policy-doc-missing", checks(r["findings"]))

    def test_inline_policy_user_dievaluasi(self):
        art = auth(users=[{"UserName": "u2",
                           "AttachedManagedPolicies": [],
                           "UserPolicyList": [
                               {"PolicyName": "inline-buruk",
                                "PolicyDocument": {"Statement": [
                                    stmt(actions=("sts:AssumeRole",))]}}]}])
        r = iam.scan(art)
        self.assertIn("assume-role-broad", checks(r["findings"]))
        f = next(f for f in r["findings"]
                 if f["check"] == "assume-role-broad")
        self.assertEqual(f["principal"], "user/u2")
        self.assertEqual(f["policy"], "inline-buruk")


class TestCLI(unittest.TestCase):
    """Nol jaringan — CLI exit code + fail-closed."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / "iam_escalation_scan.py"),
             *extra], capture_output=True, text=True, timeout=60)

    def test_exit_1_0_2(self):
        with tempfile.TemporaryDirectory() as td:
            buruk = Path(td) / "buruk.json"
            art_bad = auth(
                users=[{"UserName": "admin-asal",
                        "AttachedManagedPolicies": [attach("Admin")],
                        "UserPolicyList": []}],
                policies=[pol("Admin", [stmt(actions=("*",))])])
            buruk.write_text(json.dumps(art_bad), encoding="utf-8")
            r1 = self._run("--auth", str(buruk), "--json")
            self.assertEqual(r1.returncode, 1)
            out = json.loads(r1.stdout)
            self.assertEqual(out["schema"], "cyphron.iam-escalation-scan/1")
            self.assertIn("admin-wildcard", checks(out["findings"]))

            bersih = Path(td) / "bersih.json"
            art_ok = auth(users=[{"UserName": "u",
                                  "AttachedManagedPolicies": [],
                                  "UserPolicyList": []}])
            bersih.write_text(json.dumps(art_ok), encoding="utf-8")
            r0 = self._run("--auth", str(bersih))
            self.assertEqual(r0.returncode, 0)
            self.assertIn("CLEAN_NO_KNOWN_VECTOR", r0.stdout)

            r2a = self._run("--auth", str(Path(td) / "tak-ada.json"))
            self.assertEqual(r2a.returncode, 2)

            rusak = Path(td) / "rusak.json"
            rusak.write_text("{json rusak", encoding="utf-8")
            r2b = self._run("--auth", str(rusak))
            self.assertEqual(r2b.returncode, 2)

            kosong = Path(td) / "kosong.json"
            kosong.write_text(json.dumps({"UserDetailList": [],
                                          "RoleDetailList": [],
                                          "GroupDetailList": []}),
                              encoding="utf-8")
            r2c = self._run("--auth", str(kosong))
            self.assertEqual(r2c.returncode, 2)

    def test_fail_on_medium(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "med.json"
            art = auth(
                users=[{"UserName": "u",
                        "AttachedManagedPolicies": [attach("Sens")],
                        "UserPolicyList": []}],
                policies=[pol("Sens", [stmt(
                    actions=("secretsmanager:GetSecretValue",))])])
            f.write_text(json.dumps(art), encoding="utf-8")
            rm = self._run("--auth", str(f), "--fail-on", "medium")
            self.assertEqual(rm.returncode, 1)
            rh = self._run("--auth", str(f))
            self.assertEqual(rh.returncode, 0)


if __name__ == "__main__":
    unittest.main()
