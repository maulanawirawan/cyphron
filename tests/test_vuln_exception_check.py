"""Nol jaringan — test vuln_exception_check (register pengecualian,
fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vuln_exception_check as vec  # noqa: E402

AS_OF = "2026-11-08"
AS_OF_D = vec._parse_date(AS_OF, "--as-of", "test")


def _ok_rec(**over) -> dict:
    rec = {
        "id": "EXC-1",
        "cve_id": "CVE-2026-1234",
        "finding_id": "F-77",
        "category": "remediation_delay",
        "justification": "upgrade DB dulu sebelum patch",
        "compensating_controls": ["WAF rule blok pola eksploit"],
        "status": "approved",
        "requested_by": "owner@lab.local",
        "approved_by": "sec-lead@lab.local",
        "approved_at": "2026-11-01",
        "expires_at": "2026-11-25",  # durasi 24 hari <= 30
    }
    rec.update(over)
    return rec


class VulnExceptionCheckUnit(unittest.TestCase):
    def test_valid_record(self) -> None:
        row, issues = vec.check_record(_ok_rec(), AS_OF_D, 14)
        self.assertEqual(issues, [])
        self.assertEqual(row["state"], "valid")
        self.assertEqual(row["duration_days"], 24)
        self.assertEqual(row["days_left"], 17)

    def test_expired(self) -> None:
        row, _ = vec.check_record(_ok_rec(expires_at="2026-11-01"),
                                  AS_OF_D, 14)
        self.assertEqual(row["state"], "expired")

    def test_expiring_soon_boundary(self) -> None:
        # sisa tepat 14 hari -> expiring_soon; 15 hari -> valid
        row, _ = vec.check_record(_ok_rec(expires_at="2026-11-22"),
                                  AS_OF_D, 14)
        self.assertEqual(row["state"], "expiring_soon")
        row, _ = vec.check_record(_ok_rec(expires_at="2026-11-23"),
                                  AS_OF_D, 14)
        self.assertEqual(row["state"], "valid")

    def test_over_max_duration(self) -> None:
        row, issues = vec.check_record(_ok_rec(expires_at="2026-12-15"),
                                       AS_OF_D, 14)
        self.assertEqual(row["duration_days"], 44)
        self.assertTrue(any("melebihi maks" in i for i in issues))
        self.assertEqual(row["state"], "invalid")

    def test_max_duration_per_category(self) -> None:
        # no_fix 90 hari
        row, _ = vec.check_record(_ok_rec(
            category="no-fix",  # varian ejaan dinormalkan
            approved_at="2026-08-01", expires_at="2026-10-30"), AS_OF_D, 14)
        self.assertEqual(row["category"], "no_fix")
        self.assertEqual(row["duration_days"], 90)
        # compensating_control 180 hari
        row, _ = vec.check_record(_ok_rec(
            category="compensating_control",
            approved_at="2026-05-15", expires_at="2026-11-10"), AS_OF_D, 14)
        self.assertEqual(row["duration_days"], 179)
        # false_positive: tanpa kontrol kompensasi tetap sah
        rec = _ok_rec(category="false_positive")
        rec.pop("compensating_controls")
        row, issues = vec.check_record(rec, AS_OF_D, 14)
        self.assertEqual(issues, [])

    def test_missing_compensating_control(self) -> None:
        rec = _ok_rec()
        rec.pop("compensating_controls")
        row, issues = vec.check_record(rec, AS_OF_D, 14)
        self.assertTrue(any("compensating_controls" in i for i in issues))
        self.assertEqual(row["state"], "invalid")

    def test_pending_without_approval(self) -> None:
        rec = _ok_rec(status="pending")
        rec.pop("approved_by")
        rec.pop("approved_at")
        row, issues = vec.check_record(rec, AS_OF_D, 14)
        self.assertEqual(issues, [])
        self.assertEqual(row["state"], "pending_approval")
        self.assertIsNone(row["duration_days"])

    def test_approved_needs_approver(self) -> None:
        rec = _ok_rec()
        rec.pop("approved_by")
        row, issues = vec.check_record(rec, AS_OF_D, 14)
        self.assertTrue(any("approved_by" in i for i in issues))
        self.assertEqual(row["state"], "invalid")

    def test_bad_fields_never_valid(self) -> None:
        row, issues = vec.check_record(
            {"id": "X1", "category": "mustahil",
             "justification": "", "expires_at": "31/12/2026"},
            AS_OF_D, 14)
        self.assertEqual(row["state"], "invalid")
        joined = " | ".join(issues)
        for frag in ("kategori tak dikenal", "justification",
                     "requested_by", "bukan tanggal ISO"):
            self.assertIn(frag, joined)

    def test_expires_before_approved(self) -> None:
        row, issues = vec.check_record(_ok_rec(approved_at="2026-11-05",
                                               expires_at="2026-11-01"),
                                       AS_OF_D, 14)
        self.assertTrue(any("sebelum" in i for i in issues))
        self.assertIsNone(row["duration_days"])
        self.assertEqual(row["state"], "invalid")


class VulnExceptionCheckCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _src(self, records: list) -> Path:
        p = self.dir / "exc.json"
        p.write_text(json.dumps(records), encoding="utf-8")
        return p

    def _run(self, argv: list[str], out: str | None = None):
        import io
        import contextlib
        argv = list(argv)
        if out:
            argv += ["--out", out]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = vec.main(argv)
        data = None
        if out and Path(out).exists():
            data = json.loads(Path(out).read_text(encoding="utf-8"))
        return code, data, buf.getvalue()

    def test_mixed_register(self) -> None:
        out = str(self.dir / "out.json")
        code, data, _ = self._run(
            ["--source", str(self._src([
                _ok_rec(),
                _ok_rec(id="EXC-2", expires_at="2026-11-01"),      # expired
                _ok_rec(id="EXC-3", status="pending"),             # pending
                {"id": "EXC-4", "category": "apa-aja"},            # invalid
            ])), "--as-of", AS_OF], out)
        self.assertEqual(code, 0)
        self.assertEqual(data["schema"],
                         "cyphron.vuln-exception-check/1")
        c = data["summary"]["counts"]
        self.assertEqual(c, {"valid": 1, "expiring_soon": 0, "expired": 1,
                             "pending_approval": 1, "invalid": 1})
        self.assertEqual(data["summary"]["over_max_duration"], 0)

    def test_fail_on_flags(self) -> None:
        src = str(self._src([_ok_rec(expires_at="2026-11-01")]))
        code, _, _ = self._run(["--source", src, "--as-of", AS_OF,
                                "--fail-on", "expired"])
        self.assertEqual(code, 1)
        src2 = str(self._src([_ok_rec(status="pending")]))
        code, _, _ = self._run(["--source", src2, "--as-of", AS_OF,
                                "--fail-on", "pending"])
        self.assertEqual(code, 1)
        src3 = str(self._src([_ok_rec(expires_at="2026-12-15")]))
        code, _, _ = self._run(["--source", src3, "--as-of", AS_OF,
                                "--fail-on", "over-max"])
        self.assertEqual(code, 1)
        src4 = str(self._src([_ok_rec()]))
        code, _, _ = self._run(["--source", src4, "--as-of", AS_OF,
                                "--fail-on", "any"])
        self.assertEqual(code, 0)

    def test_input_errors_exit2(self) -> None:
        code, _, _ = self._run(["--source",
                                str(self.dir / "tak-ada.json")])
        self.assertEqual(code, 2)
        bad = self.dir / "bad.json"
        bad.write_text("[{pecah", encoding="utf-8")
        code, _, _ = self._run(["--source", str(bad)])
        self.assertEqual(code, 2)
        notlist = self.dir / "nl.json"
        notlist.write_text("{\"exceptions\": 5}", encoding="utf-8")
        code, _, _ = self._run(["--source", str(notlist)])
        self.assertEqual(code, 2)
        code, _, _ = self._run(["--source", str(bad),
                                "--as-of", "08-11-2026"])
        self.assertEqual(code, 2)

    def test_nonobject_record_counted_invalid(self) -> None:
        out = str(self.dir / "out.json")
        code, data, _ = self._run(
            ["--source", str(self._src(["bukan-objek"])),
             "--as-of", AS_OF], out)
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["counts"]["invalid"], 1)
        self.assertEqual(data["summary"]["errors"], 1)


if __name__ == "__main__":
    unittest.main()
