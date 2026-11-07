"""Nol jaringan — test risk_matrix_80030 (matriks risiko 5x5,
fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import risk_matrix_80030 as r80  # noqa: E402


class NormalizeLevel(unittest.TestCase):
    def test_canonical_and_aliases(self) -> None:
        self.assertEqual(r80.normalize_level("very_low"), "very_low")
        self.assertEqual(r80.normalize_level("VERY-HIGH"), "very_high")
        self.assertEqual(r80.normalize_level("vl"), "very_low")
        self.assertEqual(r80.normalize_level("vh"), "very_high")
        self.assertEqual(r80.normalize_level("medium"), "moderate")
        self.assertEqual(r80.normalize_level("M"), "moderate")
        self.assertEqual(r80.normalize_level(3), "moderate")
        self.assertEqual(r80.normalize_level("5"), "very_high")
        self.assertEqual(r80.normalize_level(1.0), "very_low")

    def test_rejects_out_of_scale(self) -> None:
        for bad in (0, 6, "10", "none", "", None, True, 2.5, "kata"):
            with self.assertRaises(ValueError):
                r80.normalize_level(bad)


class Matrix(unittest.TestCase):
    def test_corners_monotonic(self) -> None:
        self.assertEqual(r80.risk_level("very_low", "very_low"),
                         "very_low")
        self.assertEqual(r80.risk_level("very_high", "very_high"),
                         "very_high")
        # monotonic: naik impact pada likelihood tetap tak pernah turun
        order = {n: i for i, n in enumerate(r80.LEVELS)}
        for i, lik in enumerate(r80.LEVELS):
            row = [order[r80.risk_level(lik, imp)]
                   for imp in r80.LEVELS]
            self.assertEqual(row, sorted(row), f"baris {lik} tak monoton")
        for j, imp in enumerate(r80.LEVELS):
            col = [order[r80.risk_level(lik, imp)]
                   for lik in r80.LEVELS]
            self.assertEqual(col, sorted(col), f"kolom {imp} tak monoton")

    def test_known_cells(self) -> None:
        self.assertEqual(r80.risk_level("very_low", "very_high"),
                         "moderate")
        self.assertEqual(r80.risk_level("moderate", "moderate"),
                         "moderate")
        self.assertEqual(r80.risk_level("high", "low"), "moderate")
        self.assertEqual(r80.risk_level("low", "high"), "moderate")


class Assess(unittest.TestCase):
    def test_rank_order_and_summary(self) -> None:
        recs = [
            {"id": "R-1", "likelihood": "high", "impact": "very_high"},
            {"id": "R-2", "likelihood": "very_low", "impact": "very_low"},
            {"id": "R-3", "likelihood": "moderate", "impact": "moderate"},
            {"id": "R-4", "likelihood": 5, "impact": "h"},
        ]
        res = r80.assess(recs)
        self.assertEqual(res["errors"], [])
        levels = [r["risk_level"] for r in res["ranked"]]
        # very_high dulu, lalu high, moderate, very_low
        self.assertEqual(levels, ["very_high", "very_high", "moderate",
                                  "very_low"])
        self.assertEqual(res["ranked"][0]["id"], "R-1")
        self.assertEqual(res["ranked"][1]["id"], "R-4")
        self.assertEqual(res["summary"]["by_level"]["very_high"], 2)
        self.assertEqual(res["summary"]["by_level"]["very_low"], 1)

    def test_residual_direction(self) -> None:
        recs = [{
            "id": "R-1", "likelihood": "high", "impact": "very_high",
            "residual_likelihood": "low", "residual_impact": "low",
        }, {
            "id": "R-2", "likelihood": "low", "impact": "low",
            "residual_likelihood": "high", "residual_impact": "high",
        }, {
            "id": "R-3", "likelihood": "moderate", "impact": "moderate",
            "residual_likelihood": "moderate", "residual_impact": "moderate",
        }]
        res = r80.assess(recs)
        by_id = {r["id"]: r for r in res["ranked"]}
        self.assertEqual(by_id["R-1"]["residual_risk_level"], "very_low")
        self.assertEqual(by_id["R-1"]["residual_direction"], "lowered")
        self.assertEqual(by_id["R-2"]["residual_direction"], "raised")
        self.assertEqual(by_id["R-3"]["residual_direction"], "unchanged")
        self.assertEqual(res["summary"]["lowered"], 1)
        self.assertEqual(res["summary"]["raised"], 1)

    def test_error_items_never_ranked(self) -> None:
        recs = [
            {"id": "OK-1", "likelihood": "low", "impact": "low"},
            {"id": "E-1", "likelihood": "tidak-ada", "impact": "low"},
            {"id": "E-2", "likelihood": 9, "impact": "low"},
            {"likelihood": "low", "impact": "low"},          # tanpa id
            "bukan-objek",
        ]
        res = r80.assess(recs)
        self.assertEqual(len(res["errors"]), 4)
        self.assertEqual([r["id"] for r in res["ranked"]], ["OK-1"])
        self.assertEqual(res["summary"]["errors"], 4)
        self.assertNotIn("E-1", [r["id"] for r in res["ranked"]])

    def test_treatment_carried_and_validated(self) -> None:
        recs = [
            {"id": "A", "likelihood": "low", "impact": "low",
             "treatment": "mitigate"},
            {"id": "B", "likelihood": "low", "impact": "low",
             "treatment": "sell"},
        ]
        res = r80.assess(recs)
        by_id = {r["id"]: r for r in res["ranked"]}
        self.assertEqual(by_id["A"]["treatment"], "mitigate")
        self.assertEqual(by_id["B"]["treatment_valid"], False)
        self.assertEqual(len(res["errors"]), 1)


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _src(self, obj) -> Path:
        p = self.dir / "reg.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def _run(self, argv: list[str]):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = r80.main(argv)
        out = None
        if "--out" in argv:
            dest = Path(argv[argv.index("--out") + 1])
            if dest.exists():
                out = json.loads(dest.read_text(encoding="utf-8"))
        return code, out, buf.getvalue()

    def test_roundtrip(self) -> None:
        out_path = str(self.dir / "o.json")
        code, data, _ = self._run(
            ["--source", str(self._src({"risks": [
                {"id": "R-1", "threat_event": "exfil via phishing",
                 "asset": "crm", "likelihood": "high",
                 "impact": "very_high", "treatment": "mitigate",
                 "residual_likelihood": "low",
                 "residual_impact": "moderate"}]})),
             "--out", out_path])
        self.assertEqual(code, 0)
        self.assertEqual(data["schema"], "cyphron.risk-matrix-80030/1")
        self.assertEqual(data["matrix"][4][4], "very_high")
        row = data["register"][0]
        self.assertEqual(row["risk_level"], "very_high")
        self.assertEqual(row["residual_risk_level"], "low")
        self.assertEqual(data["summary"]["total"], 1)

    def test_fail_on_levels(self) -> None:
        src = str(self._src([
            {"id": "R-1", "likelihood": "moderate", "impact": "moderate"}]))
        code, _, _ = self._run(["--source", src, "--fail-on", "very_high"])
        self.assertEqual(code, 0)
        code, _, _ = self._run(["--source", src, "--fail-on", "moderate"])
        self.assertEqual(code, 1)
        code, _, _ = self._run(["--source", src, "--fail-on", "any"])
        self.assertEqual(code, 0)
        src2 = str(self._src([
            {"id": "R-9", "likelihood": "high", "impact": "high"}]))
        code, _, _ = self._run(["--source", src2, "--fail-on", "any"])
        self.assertEqual(code, 1)

    def test_input_errors_exit2(self) -> None:
        code, _, _ = self._run(
            ["--source", str(self.dir / "tak-ada.json")])
        self.assertEqual(code, 2)
        bad = self.dir / "bad.json"
        bad.write_text("{pecah", encoding="utf-8")
        code, _, _ = self._run(["--source", str(bad)])
        self.assertEqual(code, 2)
        notlist = self.dir / "nl.json"
        notlist.write_text('{"risks": "satu"}', encoding="utf-8")
        code, _, _ = self._run(["--source", str(notlist)])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
