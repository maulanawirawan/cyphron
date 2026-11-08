"""Nol jaringan — test zeek_beacon_scan (kandidat beacon dari conn.log).

Log Zeek sintetis dibangun di memori: TSV dengan header #fields dan
JSON lines. Tidak ada file capture nyata, tidak ada jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import zeek_beacon_scan as zb  # noqa: E402

BEACONER = "10.0.0.66"
C2 = "198.51.100.7"  # TEST-NET-2 — lab, tidak dirutekan
VICTIM = "10.0.0.20"
SQUID = "10.0.0.30"


def tsv_log(rows: "list[tuple[float, str, str, int]]") -> str:
    out = ("#separator \\x09\n"
           "#set_separator\t,\n"
           "#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto"
           "\tservice\tduration\torig_bytes\tresp_bytes\n")
    for i, (ts, o, r, p) in enumerate(rows):
        out += (f"{ts:.6f}\tC{i}\t{o}\t{r}\t{p}\ttcp\t-\t0.1\t"
                f"128\t1024\n")
    return out


def json_log(rows: "list[tuple[float, str, str, int]]") -> str:
    return "\n".join(json.dumps({
        "ts": ts, "uid": f"C{i}", "id": {"orig_h": o, "resp_h": r,
                                          "resp_p": p},
        "proto": "tcp"}) for i, (ts, o, r, p) in enumerate(rows)) + "\n"


def _scan(txt, **kw):
    conns, _bad = zb.parse_conn_log(txt)
    return zb.scan(conns, **kw)


def beacon_rows(n: int = 20, period: float = 60.0, jitter: float = 0.0,
                orig=BEACONER, resp=C2, port=443,
                start: float = 1_700_000_000.0):
    return [(start + i * period + (jitter if i % 2 else -jitter),
             orig, resp, port) for i in range(n)]


class TestScan(unittest.TestCase):
    """Nol jaringan — agregat interval + ambang."""

    def test_beacon_reguler_terdeteksi(self):
        conns, bad = zb.parse_conn_log(tsv_log(beacon_rows()))
        self.assertEqual(bad, [])
        r = zb.scan(conns)
        self.assertEqual(r["verdict"], "BEACON_PATTERN_DETECTED")
        self.assertEqual(len(r["candidates"]), 1)
        c = r["candidates"][0]
        self.assertEqual(c["orig"], BEACONER)
        self.assertEqual(c["resp"], C2)
        self.assertEqual(c["conns"], 20)
        self.assertLessEqual(c["cv"], 0.25)
        self.assertAlmostEqual(c["mean_interval_s"], 60.0, delta=1.0)

    def test_trafik_acak_tidak_terdeteksi(self):
        # interval berosilasi lebar -> CV besar
        rows = [(1_700_000_000.0 + i * (5 if i % 3 else 120),
                 BEACONER, C2, 443) for i in range(30)]
        r = _scan(tsv_log(rows))
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["verdict"], "CLEAN_NO_REGULAR_PAIR")

    def test_burst_konkuren_dibuang_min_interval(self):
        rows = [(1_700_000_000.0 + i * 0.01, BEACONER, C2, 443)
                for i in range(30)]
        r = _scan(tsv_log(rows))
        self.assertEqual(r["candidates"], [])

    def test_min_conns_gate(self):
        rows = beacon_rows(n=8)  # 7 interval < min_conns-1 (default 10)
        r = _scan(tsv_log(rows))
        self.assertEqual(r["candidates"], [])
        r2 = _scan(tsv_log(rows), min_conns=5)
        self.assertEqual(len(r2["candidates"]), 1)

    def test_severity_high_untuk_banyak_koneksi(self):
        r = _scan(tsv_log(beacon_rows(n=55)))
        self.assertEqual(r["candidates"][0]["severity"], "high")
        r2 = _scan(tsv_log(beacon_rows(n=12)))
        self.assertEqual(r2["candidates"][0]["severity"], "medium")

    def test_pasangan_lain_tidak_menular(self):
        # beacon ke C2 + traffic tak beraturan host lain -> 1 kandidat
        rows = beacon_rows() + [(1_700_000_000.0 + i * (3 if i % 2 else 11),
                                 SQUID, VICTIM, 8080) for i in range(15)]
        r = _scan(tsv_log(rows))
        self.assertEqual(len(r["candidates"]), 1)
        self.assertEqual(r["candidates"][0]["resp"], C2)

    def test_format_json_lines(self):
        conns, bad = zb.parse_conn_log(json_log(beacon_rows()))
        self.assertEqual(bad, [])
        self.assertEqual(len(conns), 20)
        r = zb.scan(conns)
        self.assertEqual(len(r["candidates"]), 1)

    def test_baris_rusak_tercatat(self):
        txt = tsv_log(beacon_rows(n=12)) + "baris-sampah\n"
        conns, bad = zb.parse_conn_log(txt)
        self.assertEqual(len(conns), 12)
        self.assertEqual(len(bad), 1)

    def test_header_tanpa_kolom_wajib(self):
        conns, bad = zb.parse_conn_log("#fields\tts\tuid\n1.0\tC1\n")
        self.assertEqual(conns, [])
        self.assertTrue(bad)


class TestCLI(unittest.TestCase):
    """Nol jaringan — CLI exit code + JSON."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools" / "zeek_beacon_scan.py"),
             *extra], capture_output=True, text=True, timeout=60)

    def test_exit_1_beacon_0_bersih_2_error(self):
        with tempfile.TemporaryDirectory() as td:
            beacon = Path(td) / "beacon.log"
            beacon.write_text(tsv_log(beacon_rows()), encoding="utf-8")
            r1 = self._run("--log", str(beacon), "--json")
            self.assertEqual(r1.returncode, 1)
            out = json.loads(r1.stdout)
            self.assertEqual(out["schema"], "secai.zeek-beacon-scan/1")
            self.assertEqual(out["candidates"][0]["port"], 443)

            noise = Path(td) / "noise.log"
            rows = [(1_700_000_000.0 + i * (5 if i % 3 else 120),
                     BEACONER, C2, 443) for i in range(30)]
            noise.write_text(tsv_log(rows), encoding="utf-8")
            r0 = self._run("--log", str(noise), "--min-conns", "10")
            self.assertEqual(r0.returncode, 0)
            self.assertIn("CLEAN_NO_REGULAR_PAIR", r0.stdout)

            r2 = self._run("--log", str(Path(td) / "tak-ada.log"))
            self.assertEqual(r2.returncode, 2)

            kosong = Path(td) / "kosong.log"
            kosong.write_text("hanya-baris-rusak\n", encoding="utf-8")
            r3 = self._run("--log", str(kosong))
            self.assertEqual(r3.returncode, 2)

    def test_fail_on_high_medium_tidak_gagal(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "beacon12.log"
            f.write_text(tsv_log(beacon_rows(n=12)), encoding="utf-8")
            r_med = self._run("--log", str(f))
            self.assertEqual(r_med.returncode, 1)
            r_high = self._run("--log", str(f), "--fail-on", "high")
            self.assertEqual(r_high.returncode, 0)


if __name__ == "__main__":
    unittest.main()
