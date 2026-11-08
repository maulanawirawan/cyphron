"""Nol jaringan — test attack_coverage (matriks cakupan ATT&CK)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import attack_coverage as ac  # noqa: E402

RULES_MIXED = [
    {"name": "kerberoast-tgs", "techniques": ["T1558.003"],
     "status": "active", "data_ready": True},
    {"name": "dcsync-repl", "techniques": ["T1003.006"],
     "status": "active", "data_ready": False},
    {"name": "dns-tunnel", "techniques": ["T1071.004"],
     "status": "disabled", "data_ready": True},
    {"name": "no-mapping", "techniques": [], "status": "active",
     "data_ready": True},
]

UNIVERSE = {
    "T1558.003": {"name": "Kerberoasting", "tactic":
                  "credential-access"},
    "T1003.006": {"name": "DCSync", "tactic": "credential-access"},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic":
              "impact"},
}


def _w(td: Path, name: str, text: str) -> Path:
    p = td / name
    p.write_text(text, encoding="utf-8")
    return p


class AttackCoverageTest(unittest.TestCase):

    def test_states_covered_partial_gap(self):
        res = ac.compute_coverage([dict(r) for r in RULES_MIXED],
                                  dict(UNIVERSE))
        states = {t["id"]: t["state"] for t in res["techniques"]}
        self.assertEqual(states["T1558.003"], "covered")
        self.assertEqual(states["T1003.006"], "partial")  # data off
        self.assertEqual(states["T1071.004"], "partial")  # disabled
        self.assertEqual(states["T1059.001"], "gap")
        self.assertEqual(states["T1486"], "gap")
        self.assertEqual(res["summary"]["gap"], 2)
        self.assertEqual(res["summary"]["covered"], 1)

    def test_no_data_ready_field_is_partial(self):
        rules = [{"name": "r1", "techniques": ["T1110"],
                  "status": "active"}]  # tanpa field data_ready
        uni = {"T1110": {"name": "Brute Force", "tactic":
                         "credential-access"}}
        res = ac.compute_coverage(rules, uni)
        self.assertEqual(res["techniques"][0]["state"], "partial")
        self.assertEqual(
            res["summary"]["rules_data_ready_field_missing"], 1)

    def test_universe_defaults_to_union(self):
        res = ac.compute_coverage([dict(r) for r in RULES_MIXED], None)
        # tanpa universe: tak ada gap — semua teknik terlihat
        self.assertEqual(res["summary"]["gap"], 0)
        self.assertEqual(res["summary"]["universe_size"],
                         res["summary"]["techniques_unique"])
        self.assertFalse(any(t.get("outside_universe")
                             for t in res["techniques"]))

    def test_non_functional_count(self):
        res = ac.compute_coverage([dict(r) for r in RULES_MIXED],
                                  dict(UNIVERSE))
        # disabled 1 (dns-tunnel) + data_ready False 1 (dcsync);
        # no-mapping aktif dgn data_ready=true = functional
        self.assertEqual(res["summary"]["non_functional_rules"], 2)

    def test_unmapped_rules_counted(self):
        res = ac.compute_coverage([dict(r) for r in RULES_MIXED],
                                  dict(UNIVERSE))
        self.assertEqual(res["summary"]["rules_unmapped"], 1)

    def test_by_tactic_breakdown(self):
        res = ac.compute_coverage([dict(r) for r in RULES_MIXED],
                                  dict(UNIVERSE))
        cred = res["by_tactic"]["credential-access"]
        self.assertEqual(cred["total"], 2)
        self.assertEqual(cred["covered"], 1)
        self.assertEqual(cred["partial"], 1)

    def test_json_and_csv_parse_same(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            j = _w(tdp, "r.json", json.dumps(RULES_MIXED))
            csv_lines = ["name,techniques,status,data_ready",
                         "kerberoast-tgs,T1558.003,active,true",
                         "dcsync-repl,T1003.006,active,false",
                         "dns-tunnel,T1071.004,disabled,true",
                         "no-mapping,,active,true"]
            c = _w(tdp, "r.csv", "\n".join(csv_lines))
            rj, _ = ac.parse_rules_file(j)
            rc, _ = ac.parse_rules_file(c)
            self.assertEqual([r["techniques"] for r in rj],
                             [r["techniques"] for r in rc])

    def test_regex_extraction_from_prose(self):
        rules = [{"name": "prose-rule",
                  "techniques": "covers T1078 and sub-teknik T1078.004",
                  "status": "active", "data_ready": True}]
        res = ac.compute_coverage(rules, {"T1078": {"tactic": None},
                                          "T1078.004": {"tactic": None}})
        self.assertEqual(res["summary"]["techniques_unique"], 2)

    def test_alias_keys_enabled_bool(self):
        rules = [{"title": "legacy-export", "mitre_attack":
                  ["T1021.002"], "enabled": False}]
        with tempfile.TemporaryDirectory() as td:
            p = _w(Path(td), "r.json", json.dumps(rules))
            parsed, _ = ac.parse_rules_file(p)
        self.assertEqual(parsed[0]["status"], "disabled")
        self.assertEqual(parsed[0]["techniques"], ["T1021.002"])
        self.assertEqual(parsed[0]["unmapped"], False)

    def test_universe_text_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = _w(Path(td), "u.txt",
                   "# priority list\ncarberasting invalid\n"
                   "T1486 data encrypted\nT1059.001 powershell\n")
            uni = ac.load_universe(p)
            self.assertIn("T1486", uni)
            self.assertIn("T1059.001", uni)
            self.assertNotIn("CARBERASTING", uni)

    def test_main_exit_gap_and_clean(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            rj = _w(tdp, "r.json", json.dumps(RULES_MIXED))
            uj = _w(tdp, "u.json", json.dumps(UNIVERSE))
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = ac.main(["--rules", str(rj), "--universe",
                                str(uj)])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)  # ada gap

            full = [{"name": "ok1", "techniques": ["T1486"],
                     "status": "active", "data_ready": True},
                    {"name": "ok2", "techniques": ["T1558.003",
                                                   "T1003.006",
                                                   "T1071.004",
                                                   "T1059.001"],
                     "status": "active", "data_ready": True}]
            rj2 = _w(tdp, "full.json", json.dumps(full))
            out2 = tdp / "o2.json"
            code = ac.main(["--rules", str(rj2), "--universe", str(uj),
                            "--out", str(out2)])
            self.assertEqual(code, 0)
            rep = json.loads(out2.read_text(encoding="utf-8"))
            self.assertEqual(rep["summary"]["gap"], 0)
            self.assertEqual(rep["summary"]["covered"], 5)

    def test_fail_on_partial(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            rj = _w(tdp, "r.json", json.dumps(RULES_MIXED))
            uj = _w(tdp, "u.json", json.dumps(UNIVERSE))
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = ac.main(["--rules", str(rj), "--universe",
                                str(uj), "--fail-on", "partial"])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)

    def test_fail_on_none_informative(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            rj = _w(tdp, "r.json", json.dumps(RULES_MIXED))
            uj = _w(tdp, "u.json", json.dumps(UNIVERSE))
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                code = ac.main(["--rules", str(rj), "--universe",
                                str(uj), "--fail-on", "none"])
            finally:
                sys.stdout = old
            self.assertEqual(code, 0)

    def test_no_rules_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = _w(Path(td), "empty.json", "[]")
            import io
            buf = io.StringIO()
            old = sys.stderr
            sys.stderr = buf
            try:
                code = ac.main(["--rules", str(p)])
            finally:
                sys.stderr = old
            self.assertEqual(code, 2)

    def test_missing_rules_file_fail_closed(self):
        import io
        buf = io.StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            code = ac.main(["--rules", "D:/nonexistent-b22/r.json"])
        finally:
            sys.stderr = old
        self.assertEqual(code, 2)

    def test_unnamed_rule_recorded_not_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            rules = [{"techniques": ["T1003"], "status": "active",
                      "data_ready": True}]
            p = _w(Path(td), "r.json", json.dumps(rules))
            parsed, notes = ac.parse_rules_file(p)
            self.assertEqual(len(parsed), 1)
            self.assertTrue(any("tanpa nama" in n for n in notes))
            self.assertTrue(parsed[0]["name"].startswith("(unnamed"))


if __name__ == "__main__":
    unittest.main()
