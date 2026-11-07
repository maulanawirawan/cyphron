"""Nol jaringan — test vuln_sla_aging (mesin SLA/aging, fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vuln_sla_aging as vsa  # noqa: E402

AS_OF = "2026-11-08"
AS_OF_D = vsa._parse_date(AS_OF, "--as-of", "test")

BASE_POLICY = dict(vsa.DEFAULT_SLA_DAYS)


def _run_cli(argv: list[str]) -> tuple[int, dict | None, str]:
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = vsa.main(argv)
    out = None
    dest = None
    for a in argv:
        if a == "--out":
            dest = argv[argv.index("--out") + 1]
    if dest and Path(dest).exists():
        out = json.loads(Path(dest).read_text(encoding="utf-8"))
    return code, out, buf.getvalue()


class VulnSlaAgingUnit(unittest.TestCase):
    def test_effective_sla_defaults_and_modifiers(self) -> None:
        self.assertEqual(vsa.effective_sla("critical", BASE_POLICY,
                                           False, False, 0.5, 2), 14)
        self.assertEqual(vsa.effective_sla("low", BASE_POLICY,
                                           False, False, 0.5, 2), 90)
        # internet-facing memotong 50% (ceil, min 1)
        self.assertEqual(vsa.effective_sla("high", BASE_POLICY,
                                           True, False, 0.5, 2), 15)
        self.assertEqual(vsa.effective_sla("low", BASE_POLICY,
                                           True, False, 0.5, 2), 45)
        # KEV override menang atas facing
        self.assertEqual(vsa.effective_sla("medium", BASE_POLICY,
                                           True, True, 0.5, 2), 2)
        # info = tanpa SLA
        self.assertIsNone(vsa.effective_sla("info", BASE_POLICY,
                                            False, False, 0.5, 2))

    def test_escalation_ladder(self) -> None:
        self.assertEqual(vsa._escalation(10.0), "none")
        self.assertEqual(vsa._escalation(50.0), "reminder")
        self.assertEqual(vsa._escalation(75.0), "manager")
        self.assertEqual(vsa._escalation(99.9), "manager")
        self.assertEqual(vsa._escalation(100.0), "ciso")

    def test_bucket_boundaries(self) -> None:
        self.assertEqual(vsa._bucket(0), "0-14d")
        self.assertEqual(vsa._bucket(14), "0-14d")
        self.assertEqual(vsa._bucket(15), "15-30d")
        self.assertEqual(vsa._bucket(31), "31-60d")
        self.assertEqual(vsa._bucket(61), "60d+")

    def test_open_overdue_and_pct(self) -> None:
        rows = [{
            "id": "V-1", "severity": "high", "discovered": "2026-09-01",
            # 2026-09-01 -> 2026-11-08 = 68 hari > 30 -> overdue
        }]
        res = vsa.assess(rows, AS_OF_D, BASE_POLICY, 0.5, 2)
        row = res["rows"][0]
        self.assertEqual(row["state"], "overdue")
        self.assertEqual(row["sla_days"], 30)
        self.assertEqual(row["days_overdue"], 38)
        self.assertEqual(row["escalation"], "ciso")
        self.assertEqual(res["summary"]["overdue"], 1)
        self.assertEqual(res["summary"]["overdue_by_severity"], {"high": 1})

    def test_closed_compliant_and_mttr(self) -> None:
        rows = [
            {"id": "V-1", "severity": "critical",
             "discovered": "2026-11-01", "resolved": "2026-11-08"},
            {"id": "V-2", "severity": "high",
             "discovered": "2026-08-01", "resolved": "2026-11-08"},
        ]
        res = vsa.assess(rows, AS_OF_D, BASE_POLICY, 0.5, 2)
        by_id = {r["id"]: r for r in res["rows"]}
        self.assertEqual(by_id["V-1"]["state"], "compliant")
        self.assertEqual(by_id["V-2"]["state"], "breached")
        s = res["summary"]
        self.assertEqual(s["closed"], 2)
        self.assertEqual(s["sla_compliance_rate"], 50.0)
        self.assertEqual(s["mttr_days"], 53.0)

    def test_kev_and_facing_from_record(self) -> None:
        rows = [{
            "id": "V-KEV", "severity": "medium", "kev": "true",
            "discovered": "2026-11-01",
        }, {
            "id": "V-FACE", "severity": "high", "internet_facing": "yes",
            "discovered": "2026-11-01",
        }]
        res = vsa.assess(rows, AS_OF_D, BASE_POLICY, 0.5, 2)
        by_id = {r["id"]: r for r in res["rows"]}
        self.assertEqual(by_id["V-KEV"]["sla_days"], 2)
        self.assertEqual(by_id["V-FACE"]["sla_days"], 15)

    def test_error_paths_never_clean(self) -> None:
        rows = [
            {"id": "E1", "severity": "catastrophic",
             "discovered": "2026-11-01"},
            {"id": "E2", "severity": "high", "discovered": "bukan-tanggal"},
            {"id": "E3", "severity": "high",
             "discovered": "2026-11-08", "resolved": "2026-11-01"},
            {"id": "E4", "severity": "high"},
        ]
        res = vsa.assess(rows, AS_OF_D, BASE_POLICY, 0.5, 2)
        self.assertEqual(len(res["errors"]), 4)
        self.assertTrue(all(r["state"] == "error" for r in res["rows"]))
        self.assertEqual(res["summary"]["errors"], 4)
        self.assertNotIn("overdue", res["summary"]["overdue_by_severity"])

    def test_info_no_sla(self) -> None:
        rows = [{"id": "I-1", "severity": "Info",
                 "discovered": "2026-01-01"}]
        res = vsa.assess(rows, AS_OF_D, BASE_POLICY, 0.5, 2)
        row = res["rows"][0]
        self.assertEqual(row["state"], "no-sla")
        self.assertIsNone(row["sla_days"])
        self.assertEqual(res["summary"]["no_sla"], 1)


class VulnSlaAgingCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, text: str) -> Path:
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_json_roundtrip(self) -> None:
        src = self._write("f.json", json.dumps([
            {"id": "V-1", "severity": "critical",
             "discovered": "2026-10-01", "asset": "edge-01",
             "internet_facing": True},
            {"id": "V-2", "severity": "low", "discovered": "2026-11-01"},
        ]))
        out = self.dir / "out.json"
        code, data, _ = _run_cli(["--source", str(src), "--as-of", AS_OF,
                                  "--out", str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(data["schema"], "cyphron.vuln-sla-aging/1")
        self.assertEqual(data["summary"]["total"], 2)
        # critical internet-facing: SLA ceil(14*0.5)=7, umur 38 -> overdue
        v1 = next(f for f in data["findings"] if f["id"] == "V-1")
        self.assertEqual(v1["state"], "overdue")
        self.assertEqual(v1["sla_days"], 7)

    def test_dict_wrapper_and_csv(self) -> None:
        wrapped = self._write("w.json", json.dumps(
            {"findings": [{"id": "W-1", "severity": "high",
                           "discovered": "2026-11-01"}]}))
        out1 = self.dir / "o1.json"
        code, data, _ = _run_cli(["--source", str(wrapped),
                                  "--as-of", AS_OF, "--out", str(out1)])
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["total"], 1)
        csvsrc = self._write(
            "f.csv",
            "id,severity,discovered,resolved\n"
            "C-1,high,2026-11-01,\n"
            "C-2,critical,2026-11-01,2026-11-08\n")
        out2 = self.dir / "o2.json"
        code, data, _ = _run_cli(["--source", str(csvsrc), "--as-of", AS_OF,
                                  "--out", str(out2)])
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["closed"], 1)
        self.assertEqual(data["summary"]["open"], 1)

    def test_fail_on_overdue(self) -> None:
        src = self._write("f.json", json.dumps([
            {"id": "V-1", "severity": "critical",
             "discovered": "2026-06-01"},
        ]))
        code, _, _ = _run_cli(["--source", str(src), "--as-of", AS_OF,
                               "--fail-on", "overdue"])
        self.assertEqual(code, 1)

    def test_input_errors_exit2(self) -> None:
        code, _, _ = _run_cli(["--source",
                               str(self.dir / "tak-ada.json")])
        self.assertEqual(code, 2)
        bad = self._write("bad.json", "{bukan json")
        code, _, _ = _run_cli(["--source", str(bad)])
        self.assertEqual(code, 2)
        notlist = self._write("nl.json", json.dumps({"a": 1}))
        code, _, _ = _run_cli(["--source", str(notlist)])
        self.assertEqual(code, 2)
        code, _, _ = _run_cli(["--source", str(self.dir / "x.json"),
                               "--as-of", "31-12-2026"])
        self.assertEqual(code, 2)
        code, _, _ = _run_cli(["--source", str(self.dir / "x.json"),
                               "--sla", "mustahil=7"])
        self.assertEqual(code, 2)

    def test_sla_override(self) -> None:
        src = self._write("f.json", json.dumps([
            {"id": "V-1", "severity": "critical", "discovered": "2026-11-01"},
        ]))
        out3 = self.dir / "o3.json"
        code, data, _ = _run_cli(["--source", str(src), "--as-of", AS_OF,
                                  "--sla", "critical=3", "--out", str(out3)])
        self.assertEqual(code, 0)
        self.assertEqual(data["findings"][0]["sla_days"], 3)
        self.assertEqual(data["findings"][0]["state"], "overdue")


if __name__ == "__main__":
    unittest.main()
