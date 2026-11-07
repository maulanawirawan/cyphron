"""Nol jaringan — test terraform_audit (audit statis .tf, fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import terraform_audit as tfa  # noqa: E402


SG_OPEN_22 = """\
resource "aws_security_group" "ssh_open" {
  name = "ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

SG_OPEN_80 = """\
resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

SG_STANDALONE_RULE_RDP = """\
resource "aws_vpc_security_group_ingress_rule" "rdp" {
  from_port   = 3389
  to_port     = 3389
  cidr_ipv4   = "::/0"
}
"""

SG_CLEAN = """\
resource "aws_security_group" "internal" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""

S3_PUBLIC = """\
resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  acl    = "public-read"
}
"""

S3_ENCRYPTED = """\
resource "aws_s3_bucket" "data" {
  bucket = "acme-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
"""

DB_INSECURE = """\
resource "aws_db_instance" "main" {
  identifier           = "main"
  storage_encrypted    = false
  publicly_accessible  = true
}
"""

EBS_PLAIN = """\
resource "aws_ebs_volume" "extra" {
  availability_zone = "us-east-1a"
  size              = 100
}
"""

EBS_OK = """\
resource "aws_ebs_volume" "safe" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}
"""

HARDCODED = """\
resource "aws_db_instance" "legacy" {
  identifier = "legacy"
  password   = "SuperSecret123"
}
"""

VAR_REF_OK = """\
variable "db_password" {
  type = string
}

resource "aws_db_instance" "v2" {
  identifier = "v2"
  password   = var.db_password
}
"""

AWS_KEY = """\
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/b7X"
}
"""

COMMENTED_OUT = """\
# resource "aws_security_group" "old" {
#   ingress {
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

resource "aws_security_group" "current" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["10.0.0.0/8"]  # internal saja
  }
}
"""


class TestIngress(unittest.TestCase):
    """Ingress terbuka: admin port critical, port lain high."""

    def _run(self, text: str) -> list:
        f, err = tfa.audit_file(text, "main.tf")
        self.assertIsNone(err)
        return f

    def test_ssh_open_critical(self):
        f = self._run(SG_OPEN_22)
        self.assertEqual(f[0]["code"], "open-ingress-admin")
        self.assertEqual(f[0]["severity"], "critical")

    def test_http_open_high(self):
        f = self._run(SG_OPEN_80)
        self.assertEqual(f[0]["code"], "open-ingress")
        self.assertEqual(f[0]["severity"], "high")

    def test_ipv6_rdp_critical(self):
        f = self._run(SG_STANDALONE_RULE_RDP)
        self.assertEqual(f[0]["code"], "open-ingress-admin")

    def test_internal_cidr_bersih(self):
        self.assertEqual(self._run(SG_CLEAN), [])

    def test_komentar_tidak_diflag(self):
        self.assertEqual(self._run(COMMENTED_OUT), [])


class TestS3(unittest.TestCase):
    """S3: ACL publik, public access block, enkripsi silang."""

    def _run(self, text: str) -> list:
        f, err = tfa.audit_file(text, "main.tf")
        self.assertIsNone(err)
        return f

    def test_public_acl(self):
        f = self._run(S3_PUBLIC)
        codes = {x["code"] for x in f}
        self.assertIn("s3-public-acl", codes)
        self.assertIn("s3-no-encryption", codes)

    def test_encrypted_bucket_tidak_diflag(self):
        f = self._run(S3_ENCRYPTED)
        self.assertNotIn("s3-no-encryption", [x["code"] for x in f])


class TestDbEbs(unittest.TestCase):
    def _run(self, text: str) -> list:
        f, err = tfa.audit_file(text, "main.tf")
        self.assertIsNone(err)
        return f

    def test_db_insecure(self):
        codes = {x["code"] for x in self._run(DB_INSECURE)}
        self.assertIn("storage-encrypted-off", codes)
        self.assertIn("publicly-accessible", codes)

    def test_ebs_tanpa_encrypted(self):
        self.assertIn("ebs-unencrypted",
                      [x["code"] for x in self._run(EBS_PLAIN)])

    def test_ebs_encrypted_bersih(self):
        self.assertEqual(self._run(EBS_OK), [])


class TestSecrets(unittest.TestCase):
    def _run(self, text: str) -> list:
        f, err = tfa.audit_file(text, "main.tf")
        self.assertIsNone(err)
        return f

    def test_password_literal(self):
        codes = {x["code"] for x in self._run(HARDCODED)}
        self.assertIn("hardcoded-secret", codes)

    def test_var_reference_tidak_diflag(self):
        self.assertEqual(self._run(VAR_REF_OK), [])

    def test_aws_access_key_critical(self):
        f = self._run(AWS_KEY)
        self.assertIn("aws-access-key-id",
                      [x["code"] for x in f])
        self.assertEqual(f[0]["severity"], "critical")


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dirp = self.tmp.name

    def _path(self, name: str) -> Path:
        return Path(self.dirp) / name

    def test_tanpa_tf_exit_2(self):
        p = self._path("readme.md")
        p.write_text("bukan tf", encoding="utf-8")
        self.assertEqual(tfa.main(["--source", str(p)]), 2)

    def test_source_tidak_ada_exit_2(self):
        self.assertEqual(tfa.main(["--source",
                                   str(self._path("missing"))]), 2)

    def test_kurung_tidak_seimbang_unparsed(self):
        p = self._path("bad.tf")
        p.write_text('resource "aws_s3_bucket" "x" {\n  acl = "private"\n',
                     encoding="utf-8")
        findings, err = tfa.audit_file(p.read_text(encoding="utf-8"),
                                       "bad.tf")
        self.assertEqual(findings, [])
        self.assertIn("tidak seimbang", err)

    def test_dir_campuran(self):
        (self._path("good.tf")).write_text(SG_OPEN_22, encoding="utf-8")
        (self._path("also.tf")).write_text(S3_ENCRYPTED,
                                           encoding="utf-8")
        result, unparsed = tfa.audit(Path(self.dirp))
        self.assertEqual(result["files_scanned"], 2)
        self.assertIn("open-ingress-admin",
                      [x["code"] for x in result["findings"]])

    def test_out_json_dan_fail_on(self):
        p = self._path("main.tf")
        p.write_text(SG_OPEN_22, encoding="utf-8")
        out = self._path("out.json")
        rc = tfa.main(["--source", str(p), "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "cyphron.terraform-audit/1")
        rc = tfa.main(["--source", str(p), "--fail-on", "critical"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
