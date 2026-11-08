"""Nol jaringan — test owasp_risk_rating (OWASP Risk Rating
Methodology: 16 faktor -> L x I -> matriks band; fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import owasp_risk_rating as orr  # noqa: E402


class BandMatrix(unittest.TestCase):
    def test_band_thresholds(self) -> None:
        self.assertEqual(orr.band(0.0), "low")
        self.assertEqual(orr.band(2.99), "low")
        self.assertEqual(orr.band(3.0), "medium")
        self.assertEqual(orr.band(6.0), "medium")
        self.assertEqual(orr.band(6.01), "high")
        self.assertEqual(orr.band(9.0), "high")

    def test_matrix_corners(self) -> None:
        self.assertEqual(orr.risk_level("high", "high"), "critical")
        self.assertEqual(orr.risk_level("low", "low"), "note")
        self.assertEqual(orr.risk_level("medium", "medium"), "medium")

    def test_matrix_monotonic(self) -> None:
        order = {"note": 0, "low": 1, "medium": 2, "high": 3,
                 "critical": 4}
        # baris = band L DARI high ke low (urutan deklarasi): naik
        # impact di likelihood tetap tak pernah turun level
        for row in orr.RISK_MATRIX:
            vals = [order[v] for v in row]
            self.assertEqual(vals, sorted(vals), f"baris {row}")
        # kolom: likelihood NAIK (low->high = indeks 2->0) pada impact
        # tetap tak pernah turun level
        for j in range(3):
            col = [order[orr.RISK_MATRIX[i][j]] for i in (2, 1, 0)]
            self.assertEqual(col, sorted(col), f"kolom {j}")


class ParseCwe(unittest.TestCase):
    def test_accepted(self) -> None:
        self.assertEqual(orr.parse_cwe("CWE-79"), 79)
        self.assertEqual(orr.parse_cwe("cwe-89"), 89)
        self.assertEqual(orr.parse_cwe(79), 79)
        self.assertEqual(orr.parse_cwe("918"), 918)

    def test_rejected_no_guess(self) -> None:
        for bad in ("CWE-abc", "", None, 0, -5, True, "SQLI", "CWE-"):
            self.assertIsNone(orr.parse_cwe(bad))


class Derivation(unittest.TestCase):
    def test_all_defaults_no_flags(self) -> None:
        d = orr.derive_defaults({}, {}, None)
        self.assertEqual(d["skill_level"], 4)
        self.assertEqual(d["motive"], 7)
        self.assertEqual(d["opportunity"], 7)
        self.assertEqual(d["size"], 4)
        self.assertEqual(d["intrusion_detection"], 8)
        self.assertEqual(d["accountability"], 7)
        self.assertEqual(d["privacy"], 2)
        for v in d.values():
            self.assertGreaterEqual(v, 0)
            self.assertLessEqual(v, 9)

    def test_flags_move_defaults(self) -> None:
        finding = {"authenticated": True, "scanner_detected": True,
                   "exploit_available": True, "data_exposure": True,
                   "dos": True}
        ctx = {"internet_facing": True, "waf_enabled": True,
               "logging_enabled": True, "processes_payments": True,
               "customer_facing": True, "pci_scope": True,
               "handles_pii": True}
        d = orr.derive_defaults(finding, ctx, 89)
        self.assertEqual(d["opportunity"], 4)
        self.assertEqual(d["size"], 9)
        self.assertEqual(d["ease_of_discovery"], 8)
        self.assertEqual(d["ease_of_exploit"], 7)
        self.assertEqual(d["intrusion_detection"], 3)
        self.assertEqual(d["accountability"], 3)
        self.assertEqual(d["financial"], 7)
        self.assertEqual(d["non_compliance"], 8)
        self.assertEqual(d["privacy"], 9)
        self.assertEqual(d["skill_level"], 6)
        self.assertEqual(d["integrity"], 9)
        self.assertEqual(d["confidentiality"], 9)
        self.assertEqual(d["availability"], 7)

    def test_unknown_cwe_no_injection_default(self) -> None:
        d = orr.derive_defaults({}, {}, 1234)
        self.assertEqual(d["skill_level"], 4)
        self.assertEqual(d["integrity"], 4)


class Rate(unittest.TestCase):
    def test_explicit_factor_overrides_and_derived_list(self) -> None:
        row = orr.rate({"id": "f1", "factors": {"motive": 3}}, {})
        self.assertEqual(row["factors"]["motive"], 3.0)
        self.assertNotIn("motive", row["factors_derived"])
        self.assertEqual(len(row["factors_derived"]), 15)

    def test_severe_sqli_is_high(self) -> None:
        finding = {"id": "sqli", "cwe": "CWE-89", "scanner_detected":
                   True, "exploit_available": True, "data_exposure": True}
        row = orr.rate(finding, {})
        # L=(6+7+7+4+8+7+6+8)/8=6.625 high; I=(9+9+2+7+3+2+3+2)/8=4.625 med
        self.assertEqual(row["likelihood"]["band"], "high")
        self.assertEqual(row["impact"]["band"], "medium")
        self.assertEqual(row["risk_level"], "high")
        self.assertAlmostEqual(row["likelihood"]["score"], 6.62, places=2)
        self.assertAlmostEqual(row["impact"]["score"], 4.62, places=2)

    def test_internet_facing_context_raises_size(self) -> None:
        row = orr.rate({"id": "s", "cwe": 89, "scanner_detected": True,
                        "exploit_available": True, "data_exposure": True},
                       {"internet_facing": True})
        # L=(6+7+7+9+8+7+6+8)/8=7.25
        self.assertAlmostEqual(row["likelihood"]["score"], 7.25, places=2)

    def test_context_business_critical(self) -> None:
        finding = {"id": "idor", "cwe": 22, "scanner_detected": True,
                   "exploit_available": True, "data_exposure": True}
        ctx = {"internet_facing": True, "processes_payments": True,
               "customer_facing": True, "pci_scope": True,
               "handles_pii": True}
        row = orr.rate(finding, ctx)
        # L=(4+7+7+9+8+7+6+8)/8=7.0 high; I=(9+4+2+7+7+6+8+9)/8=6.5 high
        self.assertEqual(row["risk_level"], "critical")
        self.assertEqual(row["owasp_top10"], "A01")

    def test_note_level_when_everything_low(self) -> None:
        factors = {name: 2 for name in orr.ALL_FACTORS}
        row = orr.rate({"id": "n1", "factors": factors}, {})
        self.assertEqual(row["risk_level"], "note")
        self.assertEqual(row["likelihood"]["band"], "low")
        self.assertEqual(row["impact"]["band"], "low")

    def test_cwe_top10_mapping_and_unknown(self) -> None:
        self.assertEqual(orr.rate({"id": "a", "cwe": 918}, {})
                         ["owasp_top10"], "A10")
        self.assertEqual(orr.rate({"id": "b", "cwe": 611}, {})
                         ["owasp_top10"], "A05")
        self.assertIsNone(orr.rate({"id": "c", "cwe": 1234}, {})
                          ["owasp_top10"])

    def test_passthrough_fields(self) -> None:
        row = orr.rate({"id": "p", "title": "XSS refleksi",
                        "url": "/q", "source": "zap"}, {})
        self.assertEqual(row["title"], "XSS refleksi")
        self.assertEqual(row["url"], "/q")
        self.assertEqual(row["source"], "zap")

    def test_error_cases(self) -> None:
        for finding in (
            {"id": ""},                                   # tanpa id
            {"id": "x", "factors": {"motive": 10}},       # di luar skala
            {"id": "x", "factors": {"motive": -1}},       # negatif
            {"id": "x", "factors": {"motive": "abc"}},    # bukan angka
            {"id": "x", "factors": {"motive": True}},     # bool
            {"id": "x", "factors": {"motiv": 3}},         # nama salah
            {"id": "x", "factors": [1, 2]},               # bukan objek
            {"id": "x", "authenticated": "ya"},           # flag non-bool
        ):
            with self.assertRaises(ValueError, msg=str(finding)):
                orr.rate(finding, {})

    def test_context_unknown_flag_rejected_in_main_path(self) -> None:
        with self.assertRaises(ValueError):
            ctx = {"waf": True}
            unknown = set(ctx) - set(orr.CONTEXT_FLAGS)
            if unknown:
                raise ValueError("flag konteks tak dikenal")


class Assess(unittest.TestCase):
    def test_rank_and_errors_isolated(self) -> None:
        good1 = {"id": "a", "cwe": 89, "scanner_detected": True,
                 "exploit_available": True, "data_exposure": True}
        good2 = {"id": "b", "cwe": 79, "scanner_detected": True}
        bad = {"id": "bad", "factors": {"motive": 12}}
        result = orr.assess([bad, good2, good1], {})
        self.assertEqual(len(result["ranked"]), 2)
        self.assertEqual(result["ranked"][0]["id"], "a")
        self.assertEqual(result["ranked"][1]["id"], "b")
        self.assertEqual(result["summary"]["errors"], 1)
        self.assertIn("bad", result["errors"][0])

    def test_summary_top10_coverage(self) -> None:
        result = orr.assess([{"id": "a", "cwe": 918},
                             {"id": "b", "cwe": 89}], {})
        cov = result["summary"]["owasp_top10_coverage"]
        self.assertEqual(cov.get("A10"), 1)
        self.assertEqual(cov.get("A03"), 1)


class MainExitCodes(unittest.TestCase):
    def _write(self, obj: object, name: str) -> str:
        p = Path(tempfile.gettempdir()) / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def tearDown(self) -> None:
        for name in ("f.json", "ctx.json", "out.json", "rusak.json"):
            (Path(tempfile.gettempdir()) / name).unlink(missing_ok=True)

    def test_exit0_and_json_out(self) -> None:
        src = self._write([{"id": "a", "cwe": 79}], "f.json")
        out = Path(tempfile.gettempdir()) / "out.json"
        rc = orr.main(["--source", src, "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "cyphron.owasp-risk-rating/1")
        self.assertEqual(doc["summary"]["total"], 1)
        self.assertEqual(doc["findings"][0]["owasp_top10"], "A03")
        self.assertIn("matrix", doc)

    def test_exit1_fail_on_critical(self) -> None:
        src = self._write([{"id": "a", "cwe": 22, "scanner_detected":
                            True, "exploit_available": True,
                            "data_exposure": True}],
                          "f.json")
        ctx = self._write({"internet_facing": True,
                           "processes_payments": True,
                           "handles_pii": True, "pci_scope": True,
                           "customer_facing": True}, "ctx.json")
        self.assertEqual(orr.main(["--source", src, "--context", ctx,
                                   "--fail-on", "critical"]), 1)

    def test_exit0_no_critical(self) -> None:
        src = self._write([{"id": "a", "cwe": 79}], "f.json")
        self.assertEqual(orr.main(["--source", src,
                                   "--fail-on", "critical"]), 0)

    def test_exit2_broken_json(self) -> None:
        p = Path(tempfile.gettempdir()) / "rusak.json"
        p.write_text("{bukan json", encoding="utf-8")
        self.assertEqual(orr.main(["--source", str(p)]), 2)

    def test_exit2_unknown_context_flag(self) -> None:
        src = self._write([{"id": "a"}], "f.json")
        ctx = self._write({"waf_only_flag": True}, "ctx.json")
        self.assertEqual(orr.main(["--source", src, "--context", ctx]),
                         2)

    def test_exit2_missing_source(self) -> None:
        self.assertEqual(orr.main(["--source", "zombie.json"]), 2)

    def test_errors_do_not_crash_exit(self) -> None:
        src = self._write([{"id": "a", "factors": {"motive": 99}},
                           {"id": "b", "cwe": 79}], "f.json")
        rc = orr.main(["--source", src])
        self.assertEqual(rc, 0)  # error item dilaporkan, exit tetap 0


if __name__ == "__main__":
    unittest.main()
