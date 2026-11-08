"""Nol jaringan — test asset_criticality_score (model kritikalitas aset,
tier 1-5, modifier SLA; fail-closed)."""
from __future__ import annotations

import io
import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import asset_criticality_score as acs  # noqa: E402


def _run_cli(argv: list[str]) -> tuple[int, dict | None, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = acs.main(argv)
    out = None
    if "--out" in argv:
        dest = Path(argv[argv.index("--out") + 1])
        if dest.exists():
            out = json.loads(dest.read_text(encoding="utf-8"))
    else:
        try:
            out = json.loads(buf.getvalue())
        except json.JSONDecodeError:
            out = None
    return code, out, buf.getvalue()


class TierTable(unittest.TestCase):
    def test_tier_boundaries(self) -> None:
        self.assertEqual(acs.tier_for(5.0)[1], 1)
        self.assertEqual(acs.tier_for(4.5)[1], 1)
        self.assertEqual(acs.tier_for(4.49)[1], 2)
        self.assertEqual(acs.tier_for(3.5)[1], 2)
        self.assertEqual(acs.tier_for(2.5)[1], 3)
        self.assertEqual(acs.tier_for(1.5)[1], 4)
        self.assertEqual(acs.tier_for(1.0)[1], 5)

    def test_weights_sum_to_one(self) -> None:
        self.assertAlmostEqual(sum(acs.FACTORS.values()), 1.0, places=9)


class ScoreAsset(unittest.TestCase):
    def test_all_five_is_crown_jewels(self) -> None:
        row = acs.score_asset("a", {f: 5 for f in acs.FACTORS},
                              dict(acs.FACTORS))
        self.assertEqual(row["score"], 5.0)
        self.assertEqual(row["tier"], 1)
        self.assertEqual(row["sla_modifier"], -0.5)
        self.assertEqual(row["defaulted"], [])

    def test_all_one_is_minimal(self) -> None:
        row = acs.score_asset("a", {f: 1 for f in acs.FACTORS},
                              dict(acs.FACTORS))
        self.assertEqual(row["score"], 1.0)
        self.assertEqual(row["tier"], 5)
        self.assertEqual(row["sla_modifier"], 0.5)

    def test_mixed_mixed_value(self) -> None:
        factors = {"business_function": 4, "data_sensitivity": 4,
                   "regulatory_scope": 4, "network_exposure": 3,
                   "recoverability": 3, "user_population": 3}
        row = acs.score_asset("a", factors, dict(acs.FACTORS))
        self.assertEqual(row["score"], 3.65)
        self.assertEqual(row["tier"], 2)
        self.assertEqual(row["label"], "High Value")

    def test_absent_factors_default_flagged(self) -> None:
        row = acs.score_asset("a", {}, dict(acs.FACTORS))
        self.assertEqual(row["score"], 3.0)
        self.assertEqual(row["tier"], 3)
        self.assertEqual(sorted(row["defaulted"]), sorted(acs.FACTORS))

    def test_out_of_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            acs.score_asset("a", {"data_sensitivity": 6},
                            dict(acs.FACTORS))
        with self.assertRaises(ValueError):
            acs.score_asset("a", {"data_sensitivity": "tinggi"},
                            dict(acs.FACTORS))
        with self.assertRaises(ValueError):
            acs.score_asset("a", {"data_sensitivity": True},
                            dict(acs.FACTORS))

    def test_string_factor_accepted(self) -> None:
        row = acs.score_asset("a", {"data_sensitivity": "4"},
                              dict(acs.FACTORS))
        self.assertEqual(row["factors"]["data_sensitivity"], 4.0)


class AdjustedSla(unittest.TestCase):
    def _join(self, tier: int, severity: str) -> int | None:
        entry = next(t for t in acs.TIERS if t[1] == tier)
        recs = [{"asset_id": "a", "severity": severity}]
        assets = [{f: entry[0] for f in acs.FACTORS}]  # skor persis ambang
        assets[0]["asset_id"] = "a"
        out = acs.assess(assets, recs, dict(acs.FACTORS))
        return out["vulns"][0]["adjusted_sla_days"]

    def test_critical_crown_jewels_halved(self) -> None:
        self.assertEqual(self._join(1, "critical"), 7)

    def test_high_high_value_quarter_off(self) -> None:
        self.assertEqual(self._join(2, "high"), 23)  # ceil(22.5)

    def test_medium_standard_unchanged(self) -> None:
        self.assertEqual(self._join(3, "medium"), 60)

    def test_low_impact_extended(self) -> None:
        self.assertEqual(self._join(4, "low"), 113)  # ceil(112.5)

    def test_minimal_extended_half(self) -> None:
        self.assertEqual(self._join(5, "low"), 135)

    def test_info_has_no_sla(self) -> None:
        self.assertIsNone(self._join(1, "info"))


class LoadWeights(unittest.TestCase):
    def _wfile(self, obj: object) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(obj, tmp)
        tmp.close()
        return Path(tmp.name)

    def test_valid_override(self) -> None:
        p = self._wfile({f: 1 / 6 for f in acs.FACTORS})
        w = acs.load_weights(p)
        self.assertAlmostEqual(sum(w.values()), 1.0, places=9)

    def test_wrong_factor_set_rejected(self) -> None:
        with self.assertRaises(acs.InputError):
            acs.load_weights(self._wfile({"business_function": 1.0}))

    def test_bad_sum_rejected(self) -> None:
        obj = {f: 0.1 for f in acs.FACTORS}
        with self.assertRaises(acs.InputError):
            acs.load_weights(self._wfile(obj))

    def test_negative_rejected(self) -> None:
        obj = dict(acs.FACTORS)
        obj["recoverability"] = -0.1
        obj["business_function"] = 0.35
        with self.assertRaises(acs.InputError):
            acs.load_weights(self._wfile(obj))

    def test_non_object_rejected(self) -> None:
        with self.assertRaises(acs.InputError):
            acs.load_weights(self._wfile([0.5, 0.5]))


class CliAssess(unittest.TestCase):
    def _files(self, tmp: Path, assets: list[dict], vulns: list[dict] | None,
               ext: str = "json") -> tuple[str, str | None]:
        ap = tmp / f"assets.{ext}"
        vp = tmp / f"vulns.{ext}" if vulns is not None else None
        if ext == "json":
            ap.write_text(json.dumps(assets), encoding="utf-8")
            if vp:
                vp.write_text(json.dumps(vulns), encoding="utf-8")
        else:
            cols = ["asset_id", *acs.FACTORS]
            lines = [",".join(cols)]
            for a in assets:
                lines.append(",".join(str(a.get(c, "")) for c in cols))
            ap.write_text("\n".join(lines), encoding="utf-8")
            if vp:
                vcols = ["asset_id", "severity"]
                vlines = [",".join(vcols)]
                for v in vulns or []:
                    vlines.append(",".join(str(v.get(c, "")) for c in vcols))
                vp.write_text("\n".join(vlines), encoding="utf-8")
        return str(ap), (str(vp) if vp else None)

    def test_full_join_with_unmapped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            assets = [
                {"asset_id": "dc01", **{f: 5 for f in acs.FACTORS}},
                {"asset_id": "paydb01", **{f: 5 for f in acs.FACTORS}},
                {"asset_id": "wiki", **{f: 2 for f in acs.FACTORS}},
                {"asset_id": "test-vm", **{f: 1 for f in acs.FACTORS}},
                {"asset_id": "fileserver", **{f: 1 for f in acs.FACTORS}},
            ]
            vulns = [
                {"asset_id": "dc01", "severity": "critical"},
                {"asset_id": "ghost-host", "severity": "high"},
                {"asset_id": "wiki", "severity": "info"},
                {"asset_id": "wiki", "severity": "wuahaha"},
            ]
            apath, vpath = self._files(tmp, assets, vulns)
            code, out, _ = _run_cli(
                ["--assets", apath, "--vulns", vpath])
            self.assertEqual(code, 0)
            assert out is not None
            ids = {r["asset_id"] for r in out["assets"]}
            self.assertEqual(ids, {"dc01", "paydb01", "wiki", "test-vm",
                                   "fileserver"})
            by_sev = {(v["asset_id"], v["severity"]): v
                      for v in out["vulns"]}
            # dc01 = 5.0 tier1 -> critical 14*0.5 = 7
            self.assertEqual(by_sev[("dc01", "critical")]
                             ["adjusted_sla_days"], 7)
            # ghost-host = unmapped -> baseline tier 3 -> high = 30
            g = by_sev[("ghost-host", "high")]
            self.assertEqual(g["tier"], 3)
            self.assertEqual(g["adjusted_sla_days"], 30)
            # info = tanpa SLA
            self.assertIsNone(by_sev[("wiki", "info")]
                              ["adjusted_sla_days"])
            checks = {f["check"] for f in out["findings"]}
            self.assertIn("vuln-asset-unmapped", checks)
            self.assertIn("vuln-severity-unknown", checks)
            # 3/5 aset tier 1-2 = 60% -> tidak ada catatan saturasi
            self.assertNotIn("tiering-saturation", checks)

    def test_csv_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            assets = [{"asset_id": "app01",
                       "business_function": 4, "data_sensitivity": 4,
                       "regulatory_scope": 4, "network_exposure": 3,
                       "recoverability": 3, "user_population": 3}]
            vulns = [{"asset_id": "app01", "severity": "high"}]
            apath, vpath = self._files(tmp, assets, vulns, ext="csv")
            code, out, _ = _run_cli(
                ["--assets", apath, "--vulns", vpath])
            self.assertEqual(code, 0)
            assert out is not None
            self.assertEqual(out["assets"][0]["score"], 3.65)
            self.assertEqual(out["assets"][0]["tier"], 2)
            # high tier2 = ceil(30*0.75) = 23
            self.assertEqual(out["vulns"][0]["adjusted_sla_days"], 23)

    def test_duplicate_and_invalid_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            assets = [
                {"asset_id": "a1", "data_sensitivity": 2},
                {"asset_id": "a1", "data_sensitivity": 5},  # duplikat
                {"asset_id": "", "data_sensitivity": 3},    # tanpa id
                {"asset_id": "a2", "data_sensitivity": 9},  # tak valid
            ]
            apath, _ = self._files(tmp, assets, None)
            code, out, _ = _run_cli(["--assets", apath])
            self.assertEqual(code, 0)
            assert out is not None
            self.assertEqual(len(out["assets"]), 1)
            self.assertEqual(out["assets"][0]["asset_id"], "a1")
            # data_sensitivity=2, sisanya default 3:
            # 3*.25 + 2*.25 + 3*.15 + 3*.15 + 3*.10 + 3*.10 = 2.75
            self.assertEqual(out["assets"][0]["score"], 2.75)
            checks = {f["check"] for f in out["findings"]}
            self.assertIn("asset-duplicate", checks)
            self.assertIn("asset-no-id", checks)
            self.assertIn("asset-factor-invalid", checks)
            self.assertIn("asset-factor-defaulted", checks)
            self.assertEqual(out["summary"]["assets_excluded"], 3)

    def test_saturation_note(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            assets = [
                {"asset_id": "t1", **{f: 5 for f in acs.FACTORS}},
                {"asset_id": "t2", **{f: 5 for f in acs.FACTORS}},
                {"asset_id": "t3", **{f: 4.6 for f in acs.FACTORS}},
                {"asset_id": "t4", **{f: 4.5 for f in acs.FACTORS}},
                {"asset_id": "rendah", **{f: 1 for f in acs.FACTORS}},
            ]
            apath, _ = self._files(tmp, assets, None)
            code, out, _ = _run_cli(["--assets", apath])
            self.assertEqual(code, 0)
            assert out is not None
            checks = {f["check"] for f in out["findings"]}
            self.assertIn("tiering-saturation", checks)

    def test_weights_override_changes_score(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            wp = tmp / "w.json"
            wp.write_text(json.dumps({
                "business_function": 0.5, "data_sensitivity": 0.1,
                "regulatory_scope": 0.1, "network_exposure": 0.1,
                "recoverability": 0.1, "user_population": 0.1}),
                encoding="utf-8")
            apath, _ = self._files(
                tmp, [{"asset_id": "a", "business_function": 5}], None)
            code, out, _ = _run_cli(
                ["--assets", apath, "--weights", str(wp)])
            self.assertEqual(code, 0)
            assert out is not None
            # 5*.5 + 3*(0.1*5) = 2.5 + 1.5 = 4.0 -> tier 2
            self.assertEqual(out["assets"][0]["score"], 4.0)
            self.assertEqual(out["assets"][0]["tier"], 2)

    def test_input_errors_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            code, _, err = _run_cli(["--assets", str(tmp / "missing.json")])
            self.assertEqual(code, 2)
            bad = tmp / "bad.json"
            bad.write_text("{bukan json", encoding="utf-8")
            code, _, _ = _run_cli(["--assets", str(bad)])
            self.assertEqual(code, 2)
            # weights tidak valid (jumlah 0.6) -> exit 2
            wbad = tmp / "wb.json"
            wbad.write_text(json.dumps({f: 0.1 for f in acs.FACTORS}),
                            encoding="utf-8")
            good = tmp / "g.json"
            good.write_text(json.dumps([{"asset_id": "a"}]),
                            encoding="utf-8")
            code, _, _ = _run_cli(
                ["--assets", str(good), "--weights", str(wbad)])
            self.assertEqual(code, 2)

    def test_deterministic_and_vulns_optional(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            apath, _ = self._files(
                tmp, [{"asset_id": "a", "network_exposure": 5}], None)
            code1, out1, _ = _run_cli(["--assets", apath])
            code2, out2, _ = _run_cli(["--assets", apath])
            self.assertEqual(code1, code2)
            self.assertEqual(out1, out2)
            self.assertEqual(out1["vulns"], [])


if __name__ == "__main__":
    unittest.main()
