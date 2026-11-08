"""Nol jaringan — test diff_risk_scan (#0026, pindai diff perubahan risiko)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import diff_risk_scan as drs  # noqa: E402


DIFF_SAMPLE = """diff --git a/app/api.py b/app/api.py
--- a/app/api.py
+++ b/app/api.py
@@ -10,6 +10,9 @@ def client():
 def fetch():
-    return requests.get(url)
+    # komentar: konteks
+    return requests.get(url, verify=False)
+    print("debug baru")
 
 def call():
     pass
diff --git a/app/auth.py b/app/auth.py
--- a/app/auth.py
+++ b/app/auth.py
@@ -20,3 +20,4 @@ def login(user):
 def login(user):
     token = issue(user)
+    jwt_key = "hardcoded-secret-value-123"
     return token
diff --git a/tests/test_api.py b/tests/test_api.py
--- a/tests/test_api.py
+++ b/tests/test_api.py
@@ -1,3 +1,4 @@
+API_KEY = """ + '"' + ("AKIA" + "IOSFODNN7EXAMPLE") + '"' + """
"""


class TestParse(unittest.TestCase):
    def test_parse_files_and_lines(self):
        files = drs.parse_unified_diff(DIFF_SAMPLE)
        self.assertEqual(len(files), 3)
        self.assertEqual(files[0]["file"], "app/api.py")
        # +verify=False di line 13-ish; komentar juga termasuk added
        self.assertTrue(any("verify=False" in t for _, t in files[0]["added"]))


class TestScan(unittest.TestCase):
    def test_protection_disabled_dan_debug(self):
        files = drs.parse_unified_diff(DIFF_SAMPLE)
        res = drs.scan_diff_files(files)
        cats = {}
        for f in res:
            cats[f["category"]] = cats.get(f["category"], 0) + 1
        self.assertIn("protection-disabled", cats)
        self.assertIn("debug-statement", cats)
        self.assertIn("secret-strong", cats)  # dari file tests/ tapi AKIA kuat

    def test_secret_di_test_file_diturunkan_low(self):
        files = drs.parse_unified_diff(DIFF_SAMPLE)
        res = drs.scan_diff_files(files)
        akia = [f for f in res if f["category"] == "secret-strong"]
        self.assertTrue(akia)
        self.assertTrue(all(f["severity"] == "low" and f["in_test_file"]
                            for f in akia))

    def test_auth_area_changed(self):
        diff = ("diff --git a/app/auth.py b/app/auth.py\n"
                "--- a/app/auth.py\n+++ b/app/auth.py\n"
                "@@ -1,2 +1,3 @@\n old\n+new helper line for login flow\n")
        res = drs.scan_diff_files(drs.parse_unified_diff(diff))
        self.assertIn("auth-area-changed",
                      {f["category"] for f in res})

    def test_komentar_tak_dinilai(self):
        diff = ("diff --git a/app/api.py b/app/api.py\n"
                "--- a/app/api.py\n+++ b/app/api.py\n"
                "@@ -1,2 +1,3 @@\n"
                "+    # verify=False hanya catatan\n"
                "+    return requests.get(url)\n")
        res = drs.scan_diff_files(drs.parse_unified_diff(diff))
        self.assertNotIn("protection-disabled", {f["category"] for f in res})

    def test_tanpa_temuan(self):
        diff = ("diff --git a/readme.md b/readme.md\n"
                "--- a/readme.md\n+++ b/readme.md\n"
                "@@ -1,2 +1,3 @@\n+doc line\n")
        res = drs.scan_diff_files(drs.parse_unified_diff(diff))
        self.assertEqual(res, [])

    def test_dedup_identik(self):
        diff = ("diff --git a/app/api.py b/app/api.py\n"
                "--- a/app/api.py\n+++ b/app/api.py\n"
                "@@ -1,2 +1,4 @@\n"
                "+ssl_verify = False\n"
                "+ssl_verify = False\n")
        res = drs.scan_diff_files(drs.parse_unified_diff(diff))
        self.assertEqual(len([f for f in res
                              if f["category"] == "protection-disabled"]), 2)


class TestGitRange(unittest.TestCase):
    """Repo git lokal sementara — subprocess git lokal saja, nol jaringan."""

    def test_git_range_jalan(self):
        tmp = Path(tempfile.mkdtemp())
        def git(*a):
            subprocess.run(["git", *a], cwd=tmp, capture_output=True,
                           check=True)
        git("init", "-q")
        git("config", "user.email", "t@t")
        git("config", "user.name", "t")
        (tmp / "a.txt").write_text("hello\n", encoding="utf-8")
        git("add", "."); git("commit", "-q", "-m", "one")
        (tmp / "a.txt").write_text(
            "hello\napi_key = \"supersecretvalue\"\n", encoding="utf-8")
        git("add", "."); git("commit", "-q", "-m", "two")
        res = drs.scan_source(None, "HEAD~1..HEAD", repo=str(tmp))
        self.assertEqual(res["files_in_diff"], 1)
        self.assertIn("secret-assignment", res["by_category"])

    def test_bukan_repo_exit2(self):
        tmp = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            drs.scan_source(None, "HEAD~1..HEAD", repo=str(tmp))


class TestCli(unittest.TestCase):
    def test_cli_file_exit1(self):
        fd = Path(tempfile.mkdtemp()) / "d.diff"
        fd.write_text(DIFF_SAMPLE, encoding="utf-8")
        rc = drs.main(["--file", str(fd)])
        self.assertEqual(rc, 1)

    def test_cli_bersih_exit0(self):
        fd = Path(tempfile.mkdtemp()) / "d.diff"
        fd.write_text("diff --git a/r.md b/r.md\n--- a/r.md\n+++ b/r.md\n"
                      "@@ -1 +1,2 @@\n+doc\n", encoding="utf-8")
        rc = drs.main(["--file", str(fd)])
        self.assertEqual(rc, 0)

    def test_out_json_valid(self):
        fd = Path(tempfile.mkdtemp()) / "d.diff"
        out = fd.parent / "r.json"
        fd.write_text(DIFF_SAMPLE, encoding="utf-8")
        drs.main(["--file", str(fd), "--out", str(out)])
        d = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(d["schema"], "secai.diff-risk/1")


if __name__ == "__main__":
    unittest.main()
