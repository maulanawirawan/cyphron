"""F2 — fixture kontrak lintas bahasa: payload yang sama dengan
core-rs/tests/contract_fixtures_test.rs (Rust). Satu sumber kebenaran."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import validate_finding  # noqa: E402

FIXTURE = json.loads((ROOT / "core-rs" / "tests" / "contract_fixtures.json")
                     .read_text(encoding="utf-8"))


def _resolve_auto_id(finding: dict) -> dict:
    """id=AUTO_ID dihitung dari basis kontrak (tool|title|target|file|param)
    supaya fixture tidak menanam hash yang bisa basi."""
    if finding.get("id") != "AUTO_ID":
        return finding
    basis = "|".join([
        str(finding.get("tool", "")), str(finding.get("title", "")),
        str(finding.get("target_url") or ""), str(finding.get("file_path") or ""),
        str(finding.get("param") or "")])
    out = dict(finding)
    out["id"] = hashlib.sha256(basis.encode()).hexdigest()[:16]
    return out


class ContractFixtureTest(unittest.TestCase):
    def test_valid_fixtures_lolos_validasi_python(self):
        self.assertTrue(FIXTURE["valid"])
        for f in FIXTURE["valid"]:
            errs = validate_finding(_resolve_auto_id(f["finding"]))
            self.assertEqual(
                [], errs, f"{f['name']} harus valid di Python: {errs}")

    def test_invalid_fixtures_ditolak_python(self):
        self.assertTrue(FIXTURE["invalid"])
        for f in FIXTURE["invalid"]:
            errs = validate_finding(_resolve_auto_id(f["finding"]))
            self.assertTrue(
                errs, f"{f['name']} harus DITOLAK Python ({f['reject_because']})")

    def test_invalid_fixture_ditolak_karena_alasan_yang_diklaim(self):
        # alasan penolakan di fixture harus terpantul di pesan error python
        hints = {
            "gerbang status-verdict": "unconfirmed",
            "gerbang bukti": "without evidence",
            "whitespace bukan bukti": "without evidence",
            "false-positive wajib -1": "false-positive",
            "confidence wajib angka": "confidence",
            "reportable mismatch": "reportable mismatch",
        }
        for f in FIXTURE["invalid"]:
            errs = " ".join(validate_finding(_resolve_auto_id(f["finding"])))
            for key, hint in hints.items():
                if key in f["reject_because"]:
                    self.assertIn(hint, errs,
                                  f"{f['name']}: pesan tidak menyebut '{hint}': {errs}")


if __name__ == "__main__":
    unittest.main()
