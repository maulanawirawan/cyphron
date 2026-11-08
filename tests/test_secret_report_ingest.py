"""Nol jaringan — test secret_report_ingest (ingest gitleaks/trufflehog
+ diff baseline).

Fixture dibangun inline mengikuti format JSON natif gitleaks (array
dgn RuleID/File/StartLine/Secret/Fingerprint) dan trufflehog (JSONL
dgn SourceMetadata/DetectorName/Raw/Verified). Dua fokus: (1) nilai
rahasia TIDAK PERNAH muncul penuh di output (redaksi + param non-
rahasia), (2) baseline diff hanya menembuskan temuan BARU. Tidak ada
request jaringan.
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

import secret_report_ingest as sri  # noqa: E402
from findings import validate_finding  # noqa: E402

SECRET = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"


def _gitleaks_entry(**kw) -> dict:
    e = {"RuleID": "aws-access-key-id", "Description": "AWS key",
         "File": "src/config/aws.py", "StartLine": 23,
         "Secret": SECRET, "Fingerprint": "a1b2c3d4:src/config/aws.py:"
         "aws-access-key-id:23"}
    e.update(kw)
    return e


def _trufflehog_entry(**kw) -> dict:
    e = {"SourceMetadata": {"Data": {"FilesystemPath":
                                     "scripts/deploy.sh"}},
         "SourceID": 3, "SourceType": 15, "SourceName": "fs",
         "DetectorName": "GitHub", "DetectorType": 5,
         "Verified": True, "Raw": "ghp_" + SECRET[:20]}
    e.update(kw)
    return e


def _tmpfile(content: str, suffix: str = ".json") -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                     encoding="utf-8") as fh:
        fh.write(content)
        return Path(fh.name)


class TestFormatDetect(unittest.TestCase):
    def test_gitleaks_recognized(self):
        self.assertTrue(sri.is_gitleaks_entry(_gitleaks_entry()))
        self.assertFalse(sri.is_trufflehog_entry(_gitleaks_entry()))

    def test_trufflehog_recognized(self):
        self.assertTrue(sri.is_trufflehog_entry(_trufflehog_entry()))
        self.assertFalse(sri.is_gitleaks_entry(_trufflehog_entry()))

    def test_unknown_rejected(self):
        f = _tmpfile(json.dumps([{"foo": "bar"}]), ".json")
        with self.assertRaises(SystemExit):
            sri.load_reports([str(f)])


class TestNormalize(unittest.TestCase):
    def test_gitleaks_fields(self):
        n = sri.norm_gitleaks(_gitleaks_entry(), "rep.json")
        self.assertEqual(n["scanner"], "gitleaks")
        self.assertEqual(n["severity"], "high")
        self.assertEqual(n["file_path"], "src/config/aws.py")
        self.assertEqual(n["line_start"], 23)
        self.assertEqual(n["param"], _gitleaks_entry()["Fingerprint"])
        # nilai rahasia tidak penuh di mana pun
        blob = json.dumps(n)
        self.assertNotIn(SECRET, blob)
        self.assertIn("***", n["poc"])

    def test_trufflehog_verified_critical(self):
        n = sri.norm_trufflehog(_trufflehog_entry(), "rep.jsonl")
        self.assertEqual(n["severity"], "critical")
        self.assertEqual(n["title"], "trufflehog:GitHub (verified)")
        self.assertEqual(n["param"], "3")
        # nilai rahasia penuh tidak ada; prefix skema (ghp_) = bagian
        # redaksi by-design (prefix+panjang)
        blob = json.dumps(n)
        self.assertNotIn(SECRET[:20], blob)
        self.assertNotIn(SECRET, blob)

    def test_trufflehog_unverified_high(self):
        n = sri.norm_trufflehog(_trufflehog_entry(Verified=False),
                                "rep.jsonl")
        self.assertEqual(n["severity"], "high")

    def test_trufflehog_git_source_path(self):
        e = _trufflehog_entry(
            SourceName="git",
            SourceMetadata={"Data": {"repo": "org/repo.git"}})
        n = sri.norm_trufflehog(e, "rep.jsonl")
        self.assertEqual(n["file_path"], "git:org/repo.git")

    def test_trufflehog_nopath_fallback_ctx(self):
        e = _trufflehog_entry(
            SourceMetadata={"Data": {}},
            SourceID=99, Raw="tokvalsupersecret1234567890")
        n = sri.norm_trufflehog(e, "rep.jsonl")
        self.assertEqual(n["file_path"], "rep.jsonl")
        blob = json.dumps(n)
        self.assertNotIn("tokvalsupersecret", blob)
        self.assertIn("99", n["param"])


class TestBaselineDiff(unittest.TestCase):
    def _entries(self) -> list[dict]:
        return [sri.norm_gitleaks(_gitleaks_entry(), "r.json"),
                sri.norm_trufflehog(_trufflehog_entry(), "r.jsonl")]

    def test_first_run_all_new(self):
        findings, meta = sri.build_findings(self._entries(), set())
        self.assertEqual(len(findings), 2)
        self.assertEqual(meta["new"], 2)
        for f in findings:
            self.assertEqual(validate_finding(f), [])

    def test_baseline_known_suppressed(self):
        first, _ = sri.build_findings(self._entries(), set())
        ids = {f["id"] for f in first}
        second, meta = sri.build_findings(self._entries(), ids)
        self.assertEqual(second, [])
        self.assertEqual(meta["baseline_known"], 2)

    def test_mixed_new_and_known(self):
        e1 = sri.norm_gitleaks(_gitleaks_entry(), "r.json")
        e2 = sri.norm_gitleaks(_gitleaks_entry(File="other.py"),
                               "r.json")
        first, _ = sri.build_findings([e1], set())
        ids = {f["id"] for f in first}
        second, meta = sri.build_findings([e1, e2], ids)
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0]["file_path"], "other.py")
        self.assertEqual(meta["baseline_known"], 1)

    def test_dedup_same_fingerprint(self):
        e = sri.norm_gitleaks(_gitleaks_entry(), "r.json")
        findings, meta = sri.build_findings([e, dict(e)], set())
        self.assertEqual(len(findings), 1)
        self.assertEqual(meta["dedup"], 1)


class TestMain(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, Path]:
        out = Path(tempfile.mkdtemp()) / "findings.json"
        rc = sri.main(argv + ["--out", str(out)])
        return rc, out

    def test_new_findings_exit1(self):
        f1 = _tmpfile(json.dumps([_gitleaks_entry()]), ".json")
        f2 = _tmpfile("\n".join(
            json.dumps(e) for e in [_trufflehog_entry()]), ".jsonl")
        rc, out = self._run(["--report", f"{f1},{f2}"])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["findings"]), 2)
        self.assertEqual(doc["data"]["by_scanner"],
                         {"gitleaks": 1, "trufflehog": 1})

    def test_baseline_gate_passes(self):
        f1 = _tmpfile(json.dumps([_gitleaks_entry()]), ".json")
        rc1, out1 = self._run(["--report", str(f1)])
        self.assertEqual(rc1, 1)
        rc2, _ = self._run(["--report", str(f1), "--baseline",
                            str(out1)])
        self.assertEqual(rc2, 0)

    def test_wrapped_findings_key(self):
        f1 = _tmpfile(json.dumps({"findings": [_gitleaks_entry()]}),
                      ".json")
        rc, out = self._run(["--report", str(f1)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["findings"]), 1)

    def test_garbage_exit2(self):
        f1 = _tmpfile("bukan json sama sekali", ".json")
        rc, _ = self._run(["--report", str(f1)])
        self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc, _ = self._run(["--report", "tidak-ada.json"])
        self.assertEqual(rc, 2)

    def test_bad_baseline_exit2(self):
        f1 = _tmpfile(json.dumps([_gitleaks_entry()]), ".json")
        b = _tmpfile('{"tidak": "valid"}', ".json")
        rc, _ = self._run(["--report", str(f1), "--baseline", str(b)])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
