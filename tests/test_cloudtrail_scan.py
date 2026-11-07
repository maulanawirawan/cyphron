"""Nol jaringan — test cloudtrail_scan (triase log CloudTrail offline).

Event CloudTrail sintetis (struktur userIdentity/eventName/request
Parameters mengikuti format log CloudTrail publik) dibangun di memori.
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

import cloudtrail_scan as ct  # noqa: E402

ALICE = "arn:aws:iam::111122223333:user/alice"
ROLE = "arn:aws:iam::111122223333:role/app"


def ev(name: str, *, ident=ALICE, typ="IAMUser", acct="111122223333",
       ts="2026-11-08T10:00:00Z", **extra) -> dict:
    e = {
        "eventTime": ts,
        "eventName": name,
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {"type": typ, "arn": ident, "accountId": acct},
    }
    e.update(extra)
    return e


def checks(fnds):
    return {f["check"] for f in fnds}


class TestCheckEvent(unittest.TestCase):
    """Nol jaringan — cek deterministik per event."""

    def test_root_activity(self):
        f = ct.check_event(ev("ConsoleLogin", typ="Root",
                              ident="arn:aws:iam::111122223333:root",
                              additionalEventData={"MFAUsed": "Yes"}))
        self.assertIn("root-activity", checks(f))
        self.assertNotIn("console-login-no-mfa", checks(f))

    def test_console_no_mfa(self):
        f = ct.check_event(ev("ConsoleLogin",
                              additionalEventData={"MFAUsed": "No"}))
        self.assertIn("console-login-no-mfa", checks(f))
        self.assertEqual(f[0]["severity"], "high")

    def test_logging_impaired(self):
        for name in ("StopLogging", "DeleteTrail", "DeleteFlowLogs"):
            f = ct.check_event(ev(name))
            self.assertIn("logging-impaired", checks(f), msg=name)
            self.assertEqual(f[0]["severity"], "high", msg=name)

    def test_iam_persistence_dan_secret(self):
        self.assertIn("iam-persistence", checks(
            ct.check_event(ev("CreateAccessKey",
                              requestParameters={"userName": "ghost"}))))
        self.assertIn("iam-persistence", checks(
            ct.check_event(ev("PutRolePolicy",
                              requestParameters={"policyName": "p"}))))
        self.assertIn("secret-access", checks(
            ct.check_event(ev("GetSecretValue",
                              requestParameters={"secretId": "prod/db"}))))

    def test_sg_open_world(self):
        f = ct.check_event(ev(
            "AuthorizeSecurityGroupIngress",
            requestParameters={
                "ipPermissions": {"items": [{"cidrIp": "0.0.0.0/0",
                                             "fromPort": 22}]}}))
        self.assertIn("sg-open-world", checks(f))
        self.assertEqual(f[0]["severity"], "high")

    def test_sg_tertutup_tidak_temuan(self):
        f = ct.check_event(ev(
            "AuthorizeSecurityGroupIngress",
            requestParameters={
                "ipPermissions": {"items": [{"cidrIp": "10.0.0.0/8"}]}}))
        self.assertEqual(f, [])

    def test_snapshot_publik_dan_nonpublik(self):
        pub = ct.check_event(ev(
            "ModifySnapshotAttribute",
            requestParameters={"attribute": "createVolumePermission",
                               "operationType": "add",
                               "group": "all"}))
        self.assertIn("snapshot-shared-public", checks(pub))
        pribadi = ct.check_event(ev(
            "ModifySnapshotAttribute",
            requestParameters={"attribute": "createVolumePermission",
                               "operationType": "remove",
                               "userId": {"items": ["12345"]}}))
        self.assertNotIn("snapshot-shared-public", checks(pribadi))

    def test_cross_account_assume(self):
        f = ct.check_event(ev(
            "AssumeRole", ident=ROLE, typ="AssumedRole",
            requestParameters={"roleArn":
                               "arn:aws:iam::999900001111:role/cross"}))
        self.assertIn("cross-account-assume", checks(f))
        sama = ct.check_event(ev(
            "AssumeRole", ident=ROLE, typ="AssumedRole",
            requestParameters={"roleArn":
                               "arn:aws:iam::111122223333:role/app"}))
        self.assertNotIn("cross-account-assume", checks(sama))

    def test_bucket_dan_key_medium(self):
        self.assertIn("bucket-policy-change", checks(
            ct.check_event(ev("PutBucketPolicy"))))
        self.assertIn("key-impact", checks(
            ct.check_event(ev("ScheduleKeyDeletion"))))


class TestScan(unittest.TestCase):
    """Nol jaringan — agregat burst + loader."""

    def test_denied_burst(self):
        events = [ev("GetObject", ts=f"2026-11-08T10:00:{i:02d}Z",
                     errorCode="AccessDenied") for i in range(12)]
        r = ct.scan(events, deny_burst=10)
        self.assertIn("denied-burst", checks(r["findings"]))
        f = next(f for f in r["findings"] if f["check"] == "denied-burst")
        self.assertEqual(f["identity"], ALICE)
        r2 = ct.scan(events, deny_burst=20)
        self.assertNotIn("denied-burst", checks(r2["findings"]))

    def test_loader_json_records_dan_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "trail.json"
            p1.write_text(json.dumps({"Records": [ev("StopLogging")]}),
                          encoding="utf-8")
            evs, bad = ct._load_events(p1)
            self.assertEqual(len(evs), 1)
            self.assertEqual(bad, [])

            p2 = Path(td) / "trail.jsonl"
            p2.write_text(json.dumps(ev("DisableKey")) + "\n" +
                          json.dumps(ev("PutBucketPolicy")) + "\n",
                          encoding="utf-8")
            evs2, bad2 = ct._load_events(p2)
            self.assertEqual(len(evs2), 2)

            p3 = Path(td) / "rusak.jsonl"
            p3.write_text("{bukan json}\n", encoding="utf-8")
            evs3, bad3 = ct._load_events(p3)
            self.assertEqual(evs3, [])
            self.assertEqual(len(bad3), 1)

    def test_verdict_bersih(self):
        events = [ev("DescribeInstances"), ev("ListBuckets"),
                  ev("GetUser")]
        r = ct.scan(events)
        self.assertEqual(r["verdict"], "CLEAN_NO_HIGH_RISK_EVENT")
        self.assertEqual(r["findings"], [])


class TestCLI(unittest.TestCase):
    """Nol jaringan — CLI exit code + JSON."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / "cloudtrail_scan.py"),
             *extra], capture_output=True, text=True, timeout=60)

    def test_exit_1_0_2(self):
        with tempfile.TemporaryDirectory() as td:
            bad_f = Path(td) / "buruk.json"
            bad_f.write_text(json.dumps({"Records": [
                ev("ConsoleLogin", typ="Root",
                   additionalEventData={"MFAUsed": "No"}),
                ev("StopLogging"),
            ]}), encoding="utf-8")
            r1 = self._run("--log", str(bad_f), "--json")
            self.assertEqual(r1.returncode, 1)
            out = json.loads(r1.stdout)
            self.assertEqual(out["schema"], "cyphron.cloudtrail-scan/1")
            self.assertIn("root-activity", checks(out["findings"]))
            self.assertIn("logging-impaired", checks(out["findings"]))

            ok_f = Path(td) / "tenang.jsonl"
            ok_f.write_text(json.dumps(ev("DescribeInstances")) + "\n",
                            encoding="utf-8")
            r0 = self._run("--log", str(ok_f))
            self.assertEqual(r0.returncode, 0)
            self.assertIn("CLEAN_NO_HIGH_RISK_EVENT", r0.stdout)

            r2 = self._run("--log", str(Path(td) / "tak-ada.json"))
            self.assertEqual(r2.returncode, 2)

            kosong = Path(td) / "kosong.jsonl"
            kosong.write_text("{rusak}\n", encoding="utf-8")
            r3 = self._run("--log", str(kosong))
            self.assertEqual(r3.returncode, 2)

    def test_fail_on_medium(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "med.json"
            f.write_text(json.dumps({"Records": [ev("PutBucketPolicy")]}),
                         encoding="utf-8")
            rm = self._run("--log", str(f), "--fail-on", "medium")
            self.assertEqual(rm.returncode, 1)
            rh = self._run("--log", str(f))
            self.assertEqual(rh.returncode, 0)

    def test_dir_mode(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.json").write_text(
                json.dumps({"Records": [ev("CreateUser")]}),
                encoding="utf-8")
            (Path(td) / "b.jsonl").write_text(
                json.dumps(ev("DeleteTrail")) + "\n", encoding="utf-8")
            r = self._run("--dir", td, "--json")
            self.assertEqual(r.returncode, 1)
            out = json.loads(r.stdout)
            self.assertEqual(out["files_scanned"], 2)
            self.assertIn("logging-impaired", checks(out["findings"]))


if __name__ == "__main__":
    unittest.main()
