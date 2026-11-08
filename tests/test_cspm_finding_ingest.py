"""Nol jaringan — test cspm_finding_ingest (ingest temuan CSPM eksternal).

Fixture dibangun inline mengikuti format Prowler flat JSON / Prowler OCSF
JSONL / struktur laporan ScoutSuite; perilaku normalize-dedup-sort diuji
terhadap kernel konsep sumber (id = sha256(resource|check), FAIL saja,
urut severity). Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import cspm_finding_ingest as cfi  # noqa: E402
from findings import validate_finding  # noqa: E402


def _flat(**kw) -> dict:
    base = {"CheckId": "s3_public", "CheckTitle": "S3 public access",
            "Severity": "high", "Status": "FAIL", "Provider": "aws",
            "AccountId": "111", "Region": "us-east-1",
            "ResourceType": "AwsS3Bucket", "ResourceId": "bucket-x",
            "StatusExtended": "terbuka"}
    base.update(kw)
    return base


def _tmpfile(content: str, suffix: str = ".json") -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                     encoding="utf-8") as fh:
        fh.write(content)
        return Path(fh.name)


class TestNormalizeStatus(unittest.TestCase):
    def test_status_map(self):
        for s in ("FAIL", "failing", "ALARM", "non_compliant"):
            self.assertEqual(cfi._norm_status(s), "FAIL")
        for s in ("PASS", "ok", "compliant", "resolved"):
            self.assertEqual(cfi._norm_status(s), "PASS")
        self.assertEqual(cfi._norm_status("entah"), "UNKNOWN")
        self.assertEqual(cfi._norm_status(None), "UNKNOWN")


class TestFlatIngest(unittest.TestCase):
    def test_dedup_id_stabil(self):
        f1 = _tmpfile(json.dumps([_flat(), _flat()]))
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["parsed"], 2)
            self.assertEqual(meta["dedup_dropped"], 1)
            self.assertEqual(meta["emitted"], 1)
            self.assertTrue(findings[0]["cspm_fingerprint"].startswith("hash:"))
        finally:
            f1.unlink()

    def test_hanya_fail_yang_masuk(self):
        f1 = _tmpfile(json.dumps([_flat(), _flat(Status="PASS",
                                                 ResourceId="bucket-ok")]))
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["pass_count"], 1)
            self.assertEqual(meta["emitted"], 1)
            self.assertEqual(findings[0]["severity"], "high")
        finally:
            f1.unlink()

    def test_severity_tak_dikenali_ditolak(self):
        f1 = _tmpfile(json.dumps([_flat(Severity="TIDAK_ADA")]))
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["rejected_severity"], 1)
            self.assertEqual(meta["emitted"], 0)
        finally:
            f1.unlink()

    def test_urutan_severity(self):
        items = [_flat(Severity="low", CheckId="c-low"),
                 _flat(Severity="critical", CheckId="c-crit"),
                 _flat(Severity="medium", CheckId="c-med")]
        f1 = _tmpfile(json.dumps(items))
        try:
            findings, _ = cfi.ingest([f1])
            self.assertEqual([f["severity"] for f in findings],
                             ["critical", "medium", "low"])
        finally:
            f1.unlink()

    def test_informational_map_ke_info(self):
        f1 = _tmpfile(json.dumps([_flat(Severity="informational")]))
        try:
            findings, _ = cfi.ingest([f1])
            self.assertEqual(findings[0]["severity"], "info")
        finally:
            f1.unlink()


class TestOcsfIngest(unittest.TestCase):
    def test_jsonl_ocsf(self):
        line = json.dumps({
            "metadata": {"product": {"name": "Prowler"}},
            "finding_info": {"title": "rds_no_encryption"},
            "severity_id": 5, "status_id": 1,
            "resource": {"uid": "db-1", "type": "DBInstance"},
            "cloud": {"provider": "aws"},
        })
        f1 = _tmpfile(line + "\n" + line + "\n", suffix=".jsonl")
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["emitted"], 1)  # dedup by uid+check
            self.assertEqual(findings[0]["severity"], "critical")
            self.assertEqual(findings[0]["resource_id"], "db-1")
        finally:
            f1.unlink()

    def test_ocsf_resolved_dihitung_pass(self):
        line = json.dumps({"finding_info": {"title": "x"},
                           "severity_id": 3, "status_id": 4,
                           "resource": {"uid": "r1"}})
        f1 = _tmpfile(line, suffix=".jsonl")
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["pass_count"], 1)
            self.assertEqual(meta["emitted"], 0)
        finally:
            f1.unlink()

    def test_baris_rusak_dicatat_tidak_dipendam(self):
        line = json.dumps({"finding_info": {"title": "x"},
                           "severity_id": 3, "status_id": 1,
                           "resource": {"uid": "r1"}})
        f1 = _tmpfile(line + "\nbukan json\n", suffix=".jsonl")
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["emitted"], 1)
            self.assertTrue(any("bukan JSON" in e for e in meta["file_errors"]))
        finally:
            f1.unlink()


class TestScoutSuite(unittest.TestCase):
    def test_node_danger_warning_dikumpulkan(self):
        report = {"aws": {"s3": {"findings": {
            "bucket_policy_grants_full_access": {
                "level": "danger", "items": ["bucket-a", "bucket-b"],
                "description": "Bucket policy grants full access",
                "rationale": "why"},
            "logging_enabled": {
                "level": "warning", "items": ["bucket-c"],
                "description": "Logging not enabled"},
            "bukan_finding": {"level": "danger", "items": None},
        }}}}
        f1 = _tmpfile(json.dumps(report))
        try:
            findings, meta = cfi.ingest([f1])
            self.assertEqual(meta["emitted"], 2)
            sevs = {f["severity"] for f in findings}
            self.assertEqual(sevs, {"high", "medium"})
            self.assertTrue(all(f["tool"].startswith("cspm:scoutsuite")
                                for f in findings))
        finally:
            f1.unlink()


class TestFailClosed(unittest.TestCase):
    def test_semua_file_gagal_exit_path(self):
        f1 = _tmpfile("bukan json {{{")
        try:
            with self.assertRaises(ValueError):
                cfi.ingest([f1])
        finally:
            f1.unlink()

    def test_min_severity_tidak_sah(self):
        with self.assertRaises(ValueError):
            cfi.ingest([], min_severity="bukan")

    def test_min_severity_filter(self):
        f1 = _tmpfile(json.dumps([_flat(Severity="low")]))
        try:
            findings, meta = cfi.ingest([f1], min_severity="medium")
            self.assertEqual(meta["emitted"], 0)
        finally:
            f1.unlink()


class TestKontrakFindings(unittest.TestCase):
    def test_finding_lulus_validate_finding(self):
        f1 = _tmpfile(json.dumps([_flat()]))
        try:
            findings, _ = cfi.ingest([f1])
            self.assertEqual(findings[0]["verdict"], 0)  # L0 OBSERVED
            self.assertEqual(findings[0]["status"], "unconfirmed")
            self.assertEqual(validate_finding(findings[0]), [])
        finally:
            f1.unlink()


if __name__ == "__main__":
    unittest.main()
