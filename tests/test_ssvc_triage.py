"""Nol jaringan — test ssvc_triage (tabel deployer SSVC v2.0 resmi +
sub-tabel human impact + derivasi titik keputusan; fail-closed).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ssvc_triage as st  # noqa: E402

DEFAULTS = {"exposure": "open", "safety": "marginal",
            "mission": "mef-failure", "automatable": "no"}
CLI_DEFAULTS = ["--default-exposure", "open",
                "--default-safety", "marginal",
                "--default-mission", "mef-failure",
                "--default-automatable", "no"]


class Tables(unittest.TestCase):
    def test_deployer_complete(self) -> None:
        # 3 exploitation x 3 exposure x 2 automatable x 4 human = 72
        self.assertEqual(len(st.DEPLOYER_TABLE), 72)
        combos = {(e, x, a, h) for e in st.EXPLOITATION
                  for x in st.EXPOSURE for a in st.AUTOMATABLE
                  for h in st.HUMAN}
        self.assertEqual(set(st.DEPLOYER_TABLE), combos)

    def test_deployer_outcomes_valid(self) -> None:
        for outcome in st.DEPLOYER_TABLE.values():
            self.assertIn(outcome, ("defer", "scheduled",
                                    "out-of-cycle", "immediate"))
            dec, label, sla = st.cisa_decision(outcome)
            self.assertIn(dec, st.CISA_ORDER)
            self.assertTrue(label)
            self.assertTrue(sla)

    def test_deployer_monotonic(self) -> None:
        # menaikkan SATU titik keputusan tak pernah menurunkan prioritas
        order = {"defer": 0, "scheduled": 1, "out-of-cycle": 2,
                 "immediate": 3}
        axes = {"exploitation": st.EXPLOITATION, "exposure": st.EXPOSURE,
                "automatable": st.AUTOMATABLE, "human": st.HUMAN}
        base_combo = {"exploitation": "none", "exposure": "small",
                      "automatable": "no", "human": "low"}
        for name, values in axes.items():
            for i, up in enumerate(values):
                for lower in values[:i]:
                    for e in st.EXPLOITATION:
                        for x in st.EXPOSURE:
                            for a in st.AUTOMATABLE:
                                for h in st.HUMAN:
                                    combo = {"exploitation": e,
                                             "exposure": x,
                                             "automatable": a,
                                             "human": h}
                                    combo[name] = lower
                                    low_val = order[st.ssvc_outcome(
                                        combo["exploitation"],
                                        combo["exposure"],
                                        combo["automatable"],
                                        combo["human"])]
                                    combo[name] = up
                                    high_val = order[st.ssvc_outcome(
                                        combo["exploitation"],
                                        combo["exposure"],
                                        combo["automatable"],
                                        combo["human"])]
                                    self.assertLessEqual(
                                        low_val, high_val,
                                        f"{name} {lower}->{up} di "
                                        f"{(e, x, a, h)}")

    def test_human_table_complete_and_resmi(self) -> None:
        self.assertEqual(len(st.HUMAN_TABLE), 16)
        # sampel baris resmi (human_impact_1_0_0.csv, CMU SEI)
        self.assertEqual(st.human_impact("negligible", "degraded"),
                         "low")
        self.assertEqual(st.human_impact("critical",
                                         "mef-support-crippled"), "high")
        self.assertEqual(st.human_impact("catastrophic", "degraded"),
                         "very high")
        self.assertEqual(st.human_impact("negligible",
                                         "mission-failure"),
                         "very high")
        self.assertEqual(st.human_impact("marginal", "mef-failure"),
                         "medium")


class KnownRows(unittest.TestCase):
    def test_resmi_baris_kunci(self) -> None:
        # nilai resmi dari CSV deployer (CMU SEI) — dipakai apa adanya
        self.assertEqual(st.ssvc_outcome("active", "open", "yes",
                                         "very high"), "immediate")
        self.assertEqual(st.ssvc_outcome("none", "small", "no", "low"),
                         "defer")
        self.assertEqual(st.ssvc_outcome("poc", "controlled", "yes",
                                         "very high"), "out-of-cycle")
        self.assertEqual(st.ssvc_outcome("none", "open", "yes",
                                         "very high"), "out-of-cycle")
        self.assertEqual(st.ssvc_outcome("active", "open", "no", "low"),
                         "scheduled")
        self.assertEqual(st.ssvc_outcome("none", "open", "yes", "medium"),
                         "scheduled")

    def test_cisa_mapping_sla(self) -> None:
        self.assertEqual(st.cisa_decision("immediate")[0], "act")
        self.assertEqual(st.cisa_decision("out-of-cycle")[0], "attend")
        self.assertEqual(st.cisa_decision("scheduled")[0], "track*")
        self.assertEqual(st.cisa_decision("defer")[0], "track")
        self.assertEqual(st.cisa_decision("immediate")[2], "48 jam")
        self.assertEqual(st.cisa_decision("defer")[2], "90 hari")


class CvssDerivation(unittest.TestCase):
    def test_derivation(self) -> None:
        self.assertTrue(st.parse_cvss_automatable(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(st.parse_cvss_automatable(
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(st.parse_cvss_automatable(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(st.parse_cvss_automatable(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L"))

    def test_malformed_rejected(self) -> None:
        for bad in ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",  # metrik v4.0
                    "AV:N/AC:L/UI:N",                     # tanpa prefix
                    "CVSS:3.1/AV:N/AC:L",                 # tanpa UI
                    "CVSS:3.1/AV:N/AC:L/UI:N/XX:H",       # metrik asing
                    "CVSS:3.1/AV:N/AV:N/UI:N",            # duplikat
                    "CVSS:3.1/gibberish",                 # tanpa colon
                    ""):
            with self.assertRaises(ValueError, msg=bad):
                st.parse_cvss_automatable(bad)


class ResolvePoints(unittest.TestCase):
    def test_full_explicit(self) -> None:
        row = st.resolve_points({
            "id": "V-1", "cve": "CVE-2024-3400",
            "exploitation": "active", "exposure": "open",
            "automatable": "yes", "safety": "critical",
            "mission": "mef-failure", "title": "pan-os",
        }, {}, None, None, 0.5)
        self.assertEqual(row["decision"], "act")
        self.assertEqual(row["ssvc_outcome"], "immediate")
        # (critical, mef-failure) = high di tabel resmi
        self.assertEqual(row["human_impact"], "high")
        dp = row["decision_points"]
        self.assertEqual(dp["exploitation"]["source"], "explicit")
        self.assertEqual(dp["system_exposure"]["source"], "explicit")
        self.assertEqual(dp["safety_impact"]["value"], "critical")

    def test_kev_aktivasi(self) -> None:
        row = st.resolve_points({"id": "V-2",
                                 "cve": "CVE-2024-3400"},
                                DEFAULTS, {"CVE-2024-3400"}, None, 0.5)
        dp = row["decision_points"]
        self.assertEqual(dp["exploitation"]["value"], "active")
        self.assertEqual(dp["exploitation"]["source"], "derived:kev")

    def test_epss_threshold(self) -> None:
        # epss 0.94 > 0.5 -> poc (heuristik internal)
        row = st.resolve_points({"id": "V-3", "cve": "CVE-X",
                                 "epss": 0.94}, DEFAULTS, set(),
                                {"CVE-X": 0.94}, 0.5)
        dp = row["decision_points"]
        self.assertEqual(dp["exploitation"]["value"], "poc")
        self.assertTrue(dp["exploitation"]["source"].startswith(
            "derived:epss"))
        # epss 0.2 <= 0.5 -> none dgn sumber tercatat
        row = st.resolve_points({"id": "V-4", "cve": "CVE-Y"},
                                DEFAULTS, set(), {"CVE-Y": 0.2}, 0.5)
        self.assertEqual(row["decision_points"]["exploitation"]["value"],
                         "none")

    def test_none_tanpa_cve_ditolak(self) -> None:
        # fail-closed: tanpa cve & tanpa flag = tidak boleh dinilai
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-5", "epss": 0.1}, DEFAULTS,
                              None, None, 0.5)

    def test_automatable_dari_cvss(self) -> None:
        row = st.resolve_points({"id": "V-6", "cve": "CVE-A6",
                                 "cvss_vector": "CVSS:3.1/AV:N/AC:L/"
                                                "PR:N/UI:N/S:U/C:H/I:H/"
                                                "A:H"},
                                DEFAULTS, set(), None, 0.5)
        dp = row["decision_points"]
        self.assertEqual(dp["automatable"]["value"], "yes")
        self.assertEqual(dp["automatable"]["source"], "derived:cvss")

    def test_automatable_string_alias(self) -> None:
        row = st.resolve_points({"id": "V-7", "cve": "CVE-A7",
                                 "automatable": "no"},
                                DEFAULTS, set(), None, 0.5)
        self.assertEqual(row["decision_points"]["automatable"]["value"],
                         "no")

    def test_defaults_tercatat(self) -> None:
        row = st.resolve_points({"id": "V-8", "cve": "CVE-Z"}, DEFAULTS,
                                set(), None, 0.5)
        dp = row["decision_points"]
        self.assertEqual(dp["system_exposure"]["source"], "default")
        self.assertEqual(dp["safety_impact"]["source"], "default")
        self.assertEqual(dp["mission_impact"]["source"], "default")
        self.assertEqual(dp["automatable"]["source"], "default")

    def test_tanpa_default_ditolak(self) -> None:
        for field in ("exposure", "safety", "mission", "automatable"):
            with self.assertRaises(ValueError, msg=field):
                st.resolve_points({"id": "V-9", "cve": "CVE-Z"}, {},
                                  set(), None, 0.5)

    def test_kosakata_salah_ditolak(self) -> None:
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-10", "exploitation": "wild"},
                              DEFAULTS, None, None, 0.5)
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-11", "exposure": "internet"},
                              DEFAULTS, None, None, 0.5)
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-12", "safety": "apokaliptik"},
                              DEFAULTS, None, None, 0.5)
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-13", "mission": "rusak"},
                              DEFAULTS, None, None, 0.5)
        with self.assertRaises(ValueError):
            st.resolve_points({"id": "V-14", "automatable": "mungkin"},
                              DEFAULTS, None, None, 0.5)

    def test_tanpa_id_ditolak(self) -> None:
        with self.assertRaises(ValueError):
            st.resolve_points({"cve": "CVE-Z"}, DEFAULTS, set(), None,
                              0.5)


class Assess(unittest.TestCase):
    def test_ranking_errors_summary(self) -> None:
        entries = [
            {"id": "B", "cve": "CVE-B", "exploitation": "active",
             "exposure": "open", "automatable": "yes",
             "safety": "critical", "mission": "mission-failure"},
            {"id": "A", "cve": "CVE-A"},  # default semua -> rendah
            {"id": "", "cve": "CVE-X"},   # tanpa id -> error
            # eksplisit exploitation sah tanpa cve -> attend
            {"id": "C", "exploitation": "active"},
            "bukan-dict",
        ]
        res = st.assess(entries, set(), None, 0.5, DEFAULTS)
        ranked = res["ranked"]
        self.assertEqual([r["id"] for r in ranked], ["B", "C", "A"])
        self.assertEqual(ranked[0]["decision"], "act")
        self.assertEqual(ranked[1]["decision"], "attend")
        # A: none+open+no+human(marginal,mef-failure)=medium -> track*
        self.assertEqual(ranked[2]["decision"], "track*")
        self.assertEqual(len(res["errors"]), 2)
        self.assertEqual(res["summary"]["by_decision"],
                         {"track": 0, "track*": 1, "attend": 1,
                          "act": 1})
        self.assertEqual(res["summary"]["errors"], 2)

    def test_sort_same_decision_by_id(self) -> None:
        entries = [{"id": "z", "cve": "CVE-1", "exploitation": "none",
                    "exposure": "small", "automatable": "no",
                    "safety": "negligible", "mission": "degraded"},
                   {"id": "a", "cve": "CVE-2", "exploitation": "none",
                    "exposure": "small", "automatable": "no",
                    "safety": "negligible", "mission": "degraded"}]
        res = st.assess(entries, set(), None, 0.5, {})
        self.assertEqual([r["id"] for r in res["ranked"]], ["a", "z"])


class Loaders(unittest.TestCase):
    def test_kev_valid(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "kev.json"
            p.write_text(json.dumps({
                "vulnerabilities": [
                    {"cveID": "CVE-2024-3400"},
                    {"cveID": "CVE-2023-4863"}]},
                ensure_ascii=False), encoding="utf-8")
            self.assertEqual(st.load_kev_set(p),
                             {"CVE-2024-3400", "CVE-2023-4863"})

    def test_kev_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "kev.json"
            p.write_text('{"broken": true}', encoding="utf-8")
            with self.assertRaises(ValueError):
                st.load_kev_set(p)
            p.write_text('{"vulnerabilities": [{}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                st.load_kev_set(p)
            p.write_text('bukan json', encoding="utf-8")
            with self.assertRaises(ValueError):
                st.load_kev_set(p)

    def test_epss_valid_dgn_skip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "epss.json"
            p.write_text(json.dumps({"data": [
                {"cve": "CVE-1", "epss": "0.94"},
                {"cve": "CVE-2", "epss": 0.3},
                {"cve": "", "epss": 0.5},          # dilewati
                {"cve": "CVE-3", "epss": "bukan"},  # dilewati
                {"cve": "CVE-4", "epss": 1.5},      # dilewati (luar 0-1)
                "bukan-dict",
            ]}), encoding="utf-8")
            scores = st.load_epss_map(p)
            self.assertEqual(scores, {"CVE-1": 0.94, "CVE-2": 0.3})

    def test_epss_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "epss.json"
            p.write_text('{"data": []}', encoding="utf-8")
            with self.assertRaises(ValueError):
                st.load_epss_map(p)
            p.write_text('{"salah": 1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                st.load_epss_map(p)


class Cli(unittest.TestCase):
    def _write(self, path: Path, obj: object) -> None:
        path.write_text(json.dumps(obj), encoding="utf-8")

    def test_end_to_end_kev(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            kev = Path(d) / "kev.json"
            out = Path(d) / "out.json"
            self._write(src, [{"id": "KEV-HIT", "cve": "CVE-2024-3400",
                               "exposure": "open", "safety": "critical",
                               "mission": "mission-failure",
                               "automatable": "yes"}])
            self._write(kev, {"vulnerabilities": [
                {"cveID": "CVE-2024-3400"}]})
            rc = st.main(["--source", str(src), "--kev-json", str(kev)]
                         + CLI_DEFAULTS + ["--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "secai.ssvc-triage/1")
            row = data["vulnerabilities"][0]
            self.assertEqual(row["decision"], "act")
            self.assertEqual(row["ssvc_outcome"], "immediate")

    def test_fail_on_act(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            self._write(src, [{"id": "X", "cve": "CVE-1",
                               "exposure": "open",
                               "safety": "catastrophic",
                               "mission": "mission-failure",
                               "automatable": "yes",
                               "exploitation": "active"}])
            rc = st.main(["--source", str(src), "--fail-on", "act"]
                         + CLI_DEFAULTS)
            self.assertEqual(rc, 1)

    def test_track_tidak_memicu_fail_on_act(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            self._write(src, [{"id": "Y", "cve": "CVE-1",
                               "exposure": "small",
                               "safety": "negligible",
                               "mission": "degraded",
                               "automatable": "no",
                               "exploitation": "none"}])
            rc = st.main(["--source", str(src), "--fail-on", "act"]
                         + CLI_DEFAULTS)
            self.assertEqual(rc, 0)

    def test_tanpa_default_exposure_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            self._write(src, [{"id": "Z", "cve": "CVE-1",
                               "exploitation": "active",
                               "automatable": "yes"}])
            rc = st.main(["--source", str(src)])
            self.assertEqual(rc, 2)

    def test_source_rusak_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            src.write_text("{{{bukan", encoding="utf-8")
            rc = st.main(["--source", str(src),
                          "--default-exposure", "open",
                          "--default-safety", "marginal",
                          "--default-mission", "degraded"])
            self.assertEqual(rc, 2)  # --default-automatable kurang

    def test_ambang_epss_luar_skala_exit2(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "v.json"
            self._write(src, [])
            rc = st.main(["--source", str(src), "--epss-poc-threshold",
                          "1.5"] + CLI_DEFAULTS)
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
