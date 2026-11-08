"""Nol jaringan — test kubebench_ingest (ingest output kube-bench
teks & JSON). Fixture dibangun inline sesuai bentuk output nyata.
Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import kubebench_ingest as kbi  # noqa: E402
from findings import validate_finding  # noqa: E402

TEXT_REPORT = """[INFO] 1 Control Plane Security Configuration
[INFO] 1.2 API Server
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.2 Ensure that the --authorization-mode argument includes RBAC
[WARN] 1.2.3 Ensure that the --audit-log-path argument is set
[INFO] 2 Etcd Node Configuration
[FAIL] 2.1.1 Ensure that the --client-cert-auth argument is set to true
== Summary ==
45 checks PASS
2 checks FAIL
1 checks WARN
"""

JSON_REPORT = [
    {
        "id": "1",
        "version": "1.29",
        "text": "Control Plane Security Configuration",
        "node_type": "master",
        "tests": [
            {
                "section": "1.2",
                "desc": "API Server",
                "results": [
                    {"test_number": "1.2.1",
                     "test_desc": "Ensure that the --anonymous-auth "
                                  "argument is set to false",
                     "status": "FAIL",
                     "remediation": "Edit the apiserver manifest and set "
                                    "--anonymous-auth=false",
                     "expected_result": "'false' is present",
                     "actual_value": "'true' is present"},
                    {"test_number": "1.2.2",
                     "test_desc": "Ensure that the --token-auth-file "
                                  "argument is not set",
                     "status": "PASS",
                     "remediation": "", "expected_result": "",
                     "actual_value": ""},
                ],
            }
        ],
    }
]


class KubebenchIngestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="kbi_t"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, content: str, name: str) -> Path:
        p = self.tmp / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_text_format_fail_triage(self) -> None:
        p = self._write(TEXT_REPORT, "kb.txt")
        out = self.tmp / "f.json"
        rc = kbi.main(["--report", str(p), "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["format"], "text")
        self.assertEqual(doc["data"]["summary"]["FAIL"], 2)
        self.assertEqual(doc["data"]["summary"]["WARN"], 1)
        highs = [f for f in doc["findings"] if f["severity"] == "high"]
        # 1.2.2 (rbac) & 2.1.1 (client-cert-auth) = kontrol kritis
        self.assertEqual(len(highs), 2)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])

    def test_json_format(self) -> None:
        p = self._write(json.dumps(JSON_REPORT), "kb.json")
        out = self.tmp / "fj.json"
        rc = kbi.main(["--report", str(p), "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["format"], "json")
        fails = [f for f in doc["findings"] if f["severity"] == "high"]
        self.assertEqual(len(fails), 1)
        self.assertIn("anonymous-auth", fails[0]["title"])
        self.assertIn("anonymous-auth=false",
                      fails[0]["recommendation"].lower())

    def test_managed_downgrade_but_counted(self) -> None:
        p = self._write(TEXT_REPORT, "kb2.txt")
        out = self.tmp / "fm.json"
        rc = kbi.main(["--report", str(p), "--out", str(out), "--managed"])
        self.assertEqual(rc, 1)  # FAIL tetap menggerakkan exit
        doc = json.loads(out.read_text(encoding="utf-8"))
        managed = [f for f in doc["findings"]
                   if f.get("label") == "managed-cluster-exception"]
        self.assertGreaterEqual(len(managed), 2)
        for f in managed:
            self.assertEqual(f["severity"], "medium")
            self.assertIn("pengecualian", f["description"].lower())

    def test_warn_manual_verification(self) -> None:
        results, _ = kbi.parse_text("[WARN] 1.2.3 Ensure audit log set")
        findings, _ = kbi.triage(results, False)
        self.assertEqual(findings[0]["severity"], "info")

    def test_no_fail_exit_0(self) -> None:
        p = self._write("[INFO] 1 X\n[PASS] 1.1.1 all good\n", "ok.txt")
        out = self.tmp / "f0.json"
        rc = kbi.main(["--report", str(p), "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["summary"]["FAIL"], 0)
        self.assertEqual(doc["findings"], [])

    def test_fail_closed(self) -> None:
        out = self.tmp / "x.json"
        self.assertEqual(kbi.main(["--report", str(self.tmp / "no.txt"),
                                   "--out", str(out)]), 2)
        empty = self._write("", "empty.txt")
        self.assertEqual(kbi.main(["--report", str(empty),
                                   "--out", str(out)]), 2)
        noise = self._write("baris acak tanpa format sama sekali\n"
                            "dan lagi\n", "noise.txt")
        self.assertEqual(kbi.main(["--report", str(noise),
                                   "--out", str(out)]), 2)
        badjson = self._write("{rusak", "bad.json")
        self.assertEqual(kbi.main(["--report", str(badjson),
                                   "--out", str(out)]), 2)
        self.assertFalse(out.exists())

    def test_duplicates_counted(self) -> None:
        p = self._write("[FAIL] 1.2.2 dup a\n[FAIL] 1.2.2 dup b\n", "d.txt")
        out = self.tmp / "fd.json"
        rc = kbi.main(["--report", str(p), "--out", str(out)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["data"]["duplicates"].get("1.2.2"), 2)


if __name__ == "__main__":
    unittest.main()
