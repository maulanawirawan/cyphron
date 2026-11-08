"""Nol jaringan — test campaign_correlate (skor korelasi kampanye berbobot).

Bobot & ambang mengikuti konsep skill sumber (#0360): infra 40 / kapabilitas
35 / temporal 15 / viktimologi 10; HIGH>=70, MEDIUM>=45; penjaga FP privat
IP & CDN. Semua kasus deterministik, tanpa jaringan.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import campaign_correlate as cc  # noqa: E402


def ev(eid, t, **kw):
    d = {"id": eid, "time": t, "ips": [], "domains": [], "hashes": [],
         "ttps": [], "sector": "", "geography": ""}
    d.update(kw)
    return d


def evs(*raw):
    """Bangun event berbentuk loaded (t0/dst) via load_events, dari JSON."""
    import tempfile
    f = Path(tempfile.mkdtemp()) / "ev.json"
    f.write_text(json.dumps(list(raw)), encoding="utf-8")
    events, leads = cc.load_events(f)
    assert not leads, leads
    return events


def corr(*raw):
    return cc.correlate(evs(*raw), cc._load_cdn(None))


class TestScoring(unittest.TestCase):
    """Nol jaringan — mesin skor & ambang."""

    def test_high_semua_pivot(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", ips=["185.220.1.5"],
               hashes=["deadbeef"], ttps=["T1566.001", "T1059"],
               sector="finansial"),
            ev("B", "2026-09-02T08:00:00Z", ips=["185.220.1.5"],
               hashes=["deadbeef"], ttps=["T1566.001", "T1059"],
               sector="finansial"),
        ]
        pairs = cc.correlate(evs(*events_raw), cc._load_cdn(None))
        self.assertEqual(len(pairs), 1)
        p = pairs[0]
        # infra 40 (IP unik di kedua sisi, bukan privat/CDN) + cap 35 +
        # temporal 15 + victim 10 = 100
        self.assertEqual(p["score"], 100.0)
        self.assertEqual(p["verdict"], "HIGH")

    def test_medium_infra_temporal(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", ips=["198.51.100.7"]),
            ev("B", "2026-09-02T09:00:00Z", ips=["198.51.100.7"]),
        ]
        p = corr(*events_raw)[0]
        self.assertEqual(p["score"], 55.0)  # infra 40 + temporal 15
        self.assertEqual(p["verdict"], "MEDIUM")

    def test_low_hanya_temporal(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z"),
            ev("B", "2026-09-02T09:00:00Z"),
        ]
        p = corr(*events_raw)[0]
        self.assertLess(p["score"], cc.MEDIUM)
        self.assertEqual(p["verdict"], "LOW")

    def test_ttp_sama_tanpa_guard_daur_ulang(self):
        # overlap kapabilitas -> bukan temporal-murni, guard tidak menyala
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", ttps=["T1105"]),
            ev("B", "2026-09-02T09:00:00Z", ttps=["T1105"]),
        ]
        p = corr(*events_raw)[0]
        self.assertFalse(any("daur ulang" in r for r in p["reasons"]))
        self.assertEqual(p["pivots"]["capability"], cc.W_CAP)

    def test_temporal_murni_guard_daur_ulang(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z"),
            ev("B", "2026-09-02T09:00:00Z"),
        ]
        p = corr(*events_raw)[0]
        self.assertEqual(p["pivots"]["temporal"], cc.W_TEMP * cc.GUARD_TEMPORAL_ONLY)
        self.assertTrue(any("daur ulang" in r for r in p["reasons"]))

    def test_temporal_window_overlap(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", window_hours=48, ips=["198.51.100.9"]),
            ev("B", "2026-09-02T18:00:00Z", ips=["198.51.100.9"]),
        ]
        p = corr(*events_raw)[0]
        # gap 33 jam - window 48 -> efektif 0 -> temporal penuh
        self.assertEqual(p["pivots"]["temporal"], cc.W_TEMP)


class TestGuards(unittest.TestCase):
    """Nol jaringan — penjaga false-positive."""

    def test_ip_privat_dipangkas(self):
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", ips=["10.0.5.8"]),
            ev("B", "2026-09-02T09:00:00Z", ips=["10.0.5.8"]),
        ]
        p = corr(*events_raw)[0]
        self.assertAlmostEqual(p["pivots"]["infra"], cc.W_INFRA * cc.GUARD_SHARED)
        self.assertTrue(any("privat" in r for r in p["reasons"]))

    def test_ip_cdn_dipangkas(self):
        # 104.16.132.229 = alamat Cloudflare nyata, dalam rentang default
        events_raw = [
            ev("A", "2026-09-01T09:00:00Z", ips=["104.16.132.229"]),
            ev("B", "2026-09-02T09:00:00Z", ips=["104.16.132.229"]),
        ]
        p = corr(*events_raw)[0]
        self.assertAlmostEqual(p["pivots"]["infra"], cc.W_INFRA * cc.GUARD_SHARED)
        self.assertTrue(any("CDN" in r for r in p["reasons"]))

    def test_cdn_file_custom(self):
        nets = cc._load_cdn(None)
        self.assertTrue(nets)
        # CIDR custom via tmp file
        import tempfile
        f = Path(tempfile.mkdtemp()) / "cdn.txt"
        f.write_text("# komentar\n198.51.100.0/24\n", encoding="utf-8")
        nets2 = cc._load_cdn(f)
        self.assertTrue(any(str(n) == "198.51.100.0/24" for n in nets2))

    def test_cdn_file_cidr_rusak(self):
        import tempfile
        f = Path(tempfile.mkdtemp()) / "cdn.txt"
        f.write_text("bukan-cidr\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            cc._load_cdn(f)

    def test_ip_tidak_valid(self):
        self.assertEqual(cc._ip_flags("bukan-ip", cc._load_cdn(None)), (False, False))


class TestFailClosed(unittest.TestCase):
    """Nol jaringan — event tak valid tidak pernah dihitung bersih."""

    def test_event_tanpa_id(self):
        events, leads = cc.load_events(Path(self._write([{"ips": ["1.2.3.4"]}])) )
        self.assertEqual(len(events), 0)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["check"], "event-unparsed")
        self.assertEqual(leads[0]["severity"], "high")

    def test_time_rusak(self):
        events, leads = cc.load_events(
            Path(self._write([{"id": "E1", "time": "bukan-waktu"}])))
        self.assertEqual(len(events), 0)
        self.assertEqual(leads[0]["message"].startswith("event E1"), True)

    def test_root_bukan_list(self):
        import tempfile
        f = Path(tempfile.mkdtemp()) / "x.json"
        f.write_text('{"bukan": "list"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            cc.load_events(f)

    def test_list_field_aman(self):
        # field non-string/non-list tidak meledak: difilter ketat
        events, _ = cc.load_events(Path(self._write(
            [{"id": "E1", "time": "2026-09-01T09:00:00Z",
              "ips": ["1.2.3.4", 42, "", None], "ttps": "T1566"}])))
        self.assertEqual(events[0]["ips"], ["1.2.3.4"])
        self.assertEqual(events[0]["ttps"], [])  # non-list -> kosong (fail-safe)

    def _write(self, data) -> str:
        import tempfile
        f = Path(tempfile.mkdtemp()) / "ev.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        return str(f)


class TestCLI(unittest.TestCase):
    """Nol jaringan — exit codes + output."""

    def _run(self, argv):
        return cc.main(argv)

    def _tmp(self, data) -> Path:
        import tempfile
        f = Path(tempfile.mkdtemp()) / "ev.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        return f

    def test_exit_bersih(self):
        f = self._tmp([ev("A", "2026-09-01T09:00:00Z", ips=["198.51.100.1"]),
                       ev("B", "2026-09-10T09:00:00Z", ips=["203.0.113.5"])])
        self.assertEqual(self._run(["--source", str(f)]), 0)

    def test_exit_lead_unparsed(self):
        f = self._tmp([{"id": "E1", "time": "rusak"}])
        self.assertEqual(self._run(["--source", str(f)]), 1)

    def test_exit_input_error(self):
        self.assertEqual(self._run(["--source", "T:/tidak/ada.json"]), 2)
        f = self._tmp({"x": 1})
        self.assertEqual(self._run(["--source", str(f)]), 2)

    def test_min_score_filter_dan_json_out(self):
        import tempfile
        events = [ev("A", "2026-09-01T09:00:00Z", ips=["198.51.100.1"]),
                  ev("B", "2026-09-01T09:30:00Z", ips=["198.51.100.1"]),
                  ev("C", "2026-09-09T09:00:00Z", ips=["203.0.113.9"])]
        f = self._tmp(events)
        jf = Path(tempfile.mkdtemp()) / "out.json"
        self.assertEqual(self._run(["--source", str(f), "--json", str(jf),
                                    "--min-score", "45"]), 0)
        data = json.loads(jf.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "secai.campaign-correlate/1")
        self.assertEqual(data["summary"]["pairs"], 1)  # hanya A-B MEDIUM
        self.assertEqual(data["pairs"][0]["verdict"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
