"""Nol jaringan — test web_log_intrusion (analisis access log, fail-closed)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import web_log_intrusion as wli  # noqa: E402


def _write_log(lines: list[str]) -> Path:
    fd = tempfile.NamedTemporaryFile(
        "w", suffix=".log", delete=False, encoding="utf-8")
    fd.write("\n".join(lines) + "\n")
    fd.close()
    return Path(fd.name)


class TestParse(unittest.TestCase):
    """Parser Combined/Common Log Format."""

    def test_combined_line(self):
        p = wli.parse_line(
            '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] '
            '"GET /products?id=1 HTTP/1.1" 200 4532 '
            '"https://x.example/" "Mozilla/5.0"')
        self.assertIsNotNone(p)
        self.assertEqual(p["ip"], "192.168.1.100")
        self.assertEqual(p["method"], "GET")
        self.assertEqual(p["status"], 200)
        self.assertEqual(p["ua"], "Mozilla/5.0")
        self.assertEqual(p["ts"].isoformat(), "2024-01-15T10:30:45")

    def test_common_line_tanpa_referer_ua(self):
        p = wli.parse_line(
            '10.0.0.5 - alice [02/Feb/2024:08:00:01 +0700] '
            '"POST /login HTTP/1.1" 401 128')
        self.assertIsNotNone(p)
        self.assertEqual(p["method"], "POST")
        self.assertEqual(p["user"], "alice")
        self.assertEqual(p["ua"], "")

    def test_timezone_dinormalisasi_ke_utc(self):
        p = wli.parse_line(
            '10.0.0.5 - - [02/Feb/2024:08:00:01 +0700] "GET / HTTP/1.1" '
            '200 10')
        self.assertEqual(p["ts"].isoformat(), "2024-02-02T01:00:01")

    def test_baris_sampah_none(self):
        self.assertIsNone(wli.parse_line("bukan log sama sekali"))
        self.assertIsNone(wli.parse_line(""))

    def test_timestamp_tak_dikenal_tetap_parse(self):
        p = wli.parse_line(
            '1.2.3.4 - - [bukan-timestamp] "GET / HTTP/1.1" 200 10')
        self.assertIsNotNone(p)
        self.assertIsNone(p["ts"])


class TestSignature(unittest.TestCase):
    """Aturan signature: SQLi/LFI/traversal/XSS/UA scanner."""

    def _analyze_lines(self, lines: list[str]) -> dict:
        return wli.analyze(_write_log(lines))

    def test_sqli_union_select(self):
        r = self._analyze_lines([
            '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] '
            '"GET /products?id=1%27%20UNION%20SELECT%20username,password'
            '%20FROM%20users-- HTTP/1.1" 200 4532',
        ])
        cats = [f["category"] for f in r["findings"]]
        self.assertIn("sqli", cats)
        f = r["findings"][cats.index("sqli")]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["matched_form"], "uri-decoded")
        self.assertIn("UNION", f["evidence"])

    def test_sqli_or_1eq1(self):
        r = self._analyze_lines([
            '1.1.1.1 - - [15/Jan/2024:10:30:45 +0000] '
            '"GET /item?id=1 OR 1=1 HTTP/1.1" 200 10',
        ])
        self.assertIn("sqli", [f["category"] for f in r["findings"]])

    def test_traversal_encoded_dan_mentah(self):
        r = self._analyze_lines([
            '2.2.2.2 - - [15/Jan/2024:10:31:00 +0000] '
            '"GET /download?file=../../etc/passwd HTTP/1.1" 200 100',
            '2.2.2.3 - - [15/Jan/2024:10:31:05 +0000] '
            '"GET /download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" '
            '200 100',
        ])
        trav = [f for f in r["findings"] if f["category"] == "lfi-traversal"]
        self.assertEqual(len(trav), 2)
        forms = {f["matched_form"] for f in trav}
        self.assertEqual(forms, {"uri-raw", "uri-decoded"})

    def test_php_filter(self):
        r = self._analyze_lines([
            '2.2.2.4 - - [15/Jan/2024:10:31:10 +0000] '
            '"GET /index?page=php://filter/convert.base64-encode'
            '/resource=index.php HTTP/1.1" 200 100',
        ])
        self.assertIn("lfi-traversal", [f["category"] for f in r["findings"]])

    def test_xss_onerror(self):
        r = self._analyze_lines([
            '3.3.3.3 - - [15/Jan/2024:10:32:00 +0000] '
            '"GET /search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E '
            'HTTP/1.1" 200 200',
        ])
        xss = [f for f in r["findings"] if f["category"] == "xss"]
        self.assertEqual(len(xss), 1)
        self.assertEqual(xss[0]["severity"], "medium")

    def test_scanner_ua(self):
        r = self._analyze_lines([
            '4.4.4.4 - - [15/Jan/2024:10:33:00 +0000] '
            '"GET /admin HTTP/1.1" 404 0 "-" '
            '"sqlmap/1.7.11#stable (http://sqlmap.org)"',
            '4.4.4.5 - - [15/Jan/2024:10:33:01 +0000] '
            '"GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0 (normal)"',
        ])
        ua = [f for f in r["findings"] if f["category"] == "scanner-ua"]
        self.assertEqual(len(ua), 1)
        self.assertEqual(ua[0]["ip"], "4.4.4.4")

    def test_line_normal_bukan_temuan(self):
        r = self._analyze_lines([
            '5.5.5.5 - - [15/Jan/2024:10:34:00 +0000] '
            '"GET /about/team HTTP/1.1" 200 500 "-" "Mozilla/5.0"',
        ])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["summary"]["findings_total"], 0)


class TestBruteForce(unittest.TestCase):
    """Hitungan brute force deterministik dari timestamp."""

    def test_50_post_login_dalam_5_menit(self):
        base = "2024-01-15T10:30:00Z"
        lines = []
        from datetime import datetime, timedelta
        t0 = datetime(2024, 1, 15, 10, 30, 0)
        for i in range(50):
            t = t0 + timedelta(seconds=i)
            lines.append(
                f'9.9.9.9 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"POST /login HTTP/1.1" 401 100 "-" "Mozilla/5.0"')
        self.assertEqual(lines[0].split("[")[1][:20], "15/Jan/2024:10:30:00")
        r = wli.analyze(_write_log(lines))
        bf = [f for f in r["findings"] if f["category"] == "brute-force"]
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0]["ip"], "9.9.9.9")
        self.assertEqual(r["brute_force"]["groups"][0]["count"], 50)

    def test_sebar_lebar_tidak_memicu(self):
        from datetime import datetime, timedelta
        t0 = datetime(2024, 1, 15, 10, 30, 0)
        lines = []
        for i in range(60):
            t = t0 + timedelta(minutes=i)  # 1 request/menit, 60 menit
            lines.append(
                f'8.8.8.8 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"POST /login HTTP/1.1" 401 100 "-" "Mozilla/5.0"')
        r = wli.analyze(_write_log(lines), window_s=300, threshold=50)
        bf = [f for f in r["findings"] if f["category"] == "brute-force"]
        self.assertEqual(bf, [])

    def test_bukan_post_tidak_dihitung(self):
        from datetime import datetime, timedelta
        t0 = datetime(2024, 1, 15, 10, 30, 0)
        lines = []
        for i in range(60):
            t = t0 + timedelta(seconds=i)
            lines.append(
                f'7.7.7.7 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"GET /login HTTP/1.1" 200 100 "-" "Mozilla/5.0"')
        r = wli.analyze(_write_log(lines))
        bf = [f for f in r["findings"] if f["category"] == "brute-force"]
        self.assertEqual(bf, [])

    def test_bukan_endpoint_login_tidak_dihitung(self):
        from datetime import datetime, timedelta
        t0 = datetime(2024, 1, 15, 10, 30, 0)
        lines = []
        for i in range(55):
            t = t0 + timedelta(seconds=i)
            lines.append(
                f'6.6.6.6 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
                f'"POST /api/normal HTTP/1.1" 200 100 "-" "Mozilla/5.0"')
        r = wli.analyze(_write_log(lines))
        bf = [f for f in r["findings"] if f["category"] == "brute-force"]
        self.assertEqual(bf, [])


class TestFailClosed(unittest.TestCase):
    """Fail-closed: file kosong / format tak dikenal / baris unparsed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name: str) -> Path:
        return Path(self.tmp.name) / name

    def test_file_tidak_ada_exit_2(self):
        rc = wli.main(["--log", str(self._path("missing.log"))])
        self.assertEqual(rc, 2)

    def test_file_kosong_error(self):
        p = self._path("empty.log")
        p.write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            wli.analyze(p)

    def test_format_tak_dikenal_error(self):
        p = self._path("junk.log")
        p.write_text("satu\ndua\ntiga\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            wli.analyze(p)

    def test_baris_unparsed_tercatat_bukan_dibuang(self):
        p = _write_log([
            '1.2.3.4 - - [15/Jan/2024:10:30:00 +0000] "GET / HTTP/1.1" '
            '200 10',
            "BARIS RUSAK TANPA FORMAT",
        ])
        r = wli.analyze(p)
        self.assertEqual(r["lines_total"], 2)
        self.assertEqual(r["lines_parsed"], 1)
        self.assertEqual(r["unparsed"]["count"], 1)
        self.assertIn(2, r["unparsed"]["sample_lines"])

    def test_out_json_valid(self):
        p = _write_log([
            '1.2.3.4 - - [15/Jan/2024:10:30:00 +0000] '
            '"GET /a?id=1%20OR%201=1 HTTP/1.1" 200 10',
        ])
        out = self._path("result.json")
        rc = wli.main(["--log", str(p), "--out", str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "cyphron.web-log-intrusion/1")
        self.assertIn("sqli",
                      [f["category"] for f in data["findings"]])

    def test_window_threshold_invalid_exit_2(self):
        p = _write_log([
            '1.2.3.4 - - [15/Jan/2024:10:30:00 +0000] "GET / HTTP/1.1" '
            '200 10',
        ])
        rc = wli.main(["--log", str(p), "--threshold", "0"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
