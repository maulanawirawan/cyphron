"""Test browser_history_triage (#0516) — nol jaringan, fixture SQLite dibuat
sendiri (skema Chromium/Firefox minimal), tanpa menyentuh profil asli."""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import browser_history_triage as bht

WEBKIT_OFFSET = 11644473600


def _wk(unix):
    """unix detik -> epoch WebKit (us sejak 1601)."""
    return int((unix + WEBKIT_OFFSET) * 1_000_000)


def _make_chromium(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                           visit_count INTEGER, typed_count INTEGER,
                           last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER,
                             visit_time INTEGER, from_visit INTEGER,
                             transition INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT,
                                target_path TEXT, tab_url TEXT,
                                total_bytes INTEGER, mime_type TEXT,
                                start_time INTEGER, end_time INTEGER,
                                state INTEGER, danger_type INTEGER);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER,
                                           url_id INTEGER, term TEXT,
                                           normalized_term TEXT);
        """)
    # unix acuan: 1.700.000.000 = 2023-11-14T22:13:20Z
    base = 1_700_000_000
    urls = [
        (1, "https://example.com/docs/page?q=kue", "Contoh", 3, 1,
         _wk(base), 0),
        (2, "http://203.0.113.7:8081/payload.bin", "dl", 1, 0,
         _wk(base + 60), 0),
        (3, "https://user:secret@corp.example.net/admin", "admin", 2, 0,
         _wk(base + 120), 0),
        (4, "file:///C:/Users/u/Downloads/invoice.htm", "invoice", 1, 0,
         _wk(base + 180), 0),
        (5, "https://ok.example.org/", "ok", 1, 0, 0, 0),  # tanpa waktu
    ]
    db.executemany("INSERT INTO urls VALUES (?,?,?,?,?,?,?)", urls)
    visits = [
        (1, 1, _wk(base - 3600), 0, 805306368),
        (2, 1, _wk(base), 1, 805306368),
        (3, 2, _wk(base + 60), 0, 805306368),
        (4, 3, _wk(base + 120), 0, 805306368),
        (5, 4, _wk(base + 180), 0, 805306368),
        (6, 1, _wk(2_100_000_000), 1, 805306368),  # tahun 2036 -> anomaly
    ]
    db.executemany("INSERT INTO visits VALUES (?,?,?,?,?)", visits)
    db.execute(
        "INSERT INTO downloads VALUES (1,'g','C:/dl/report.pdf',"
        "'https://203.0.113.7:8081/r',1048576,'application/pdf',"
        "?,?,?,?)",
        (_wk(base + 60), _wk(base + 90), 1, 3))  # complete + dangerous-content
    db.executemany("INSERT INTO keyword_search_terms VALUES (?,?,?,?)",
                   [(1, 1, "kue kering", "kue kering"),
                    (2, 1, "resep", "resep")])
    db.commit()
    db.close()


def _make_firefox(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT,
                                 title TEXT, rev_host TEXT,
                                 visit_count INTEGER, hidden INTEGER,
                                 last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY,
                                        from_visit INTEGER,
                                        place_id INTEGER,
                                        visit_date INTEGER,
                                        visit_type INTEGER);
        """)
    base = 1_700_000_000
    db.executemany("INSERT INTO moz_places VALUES (?,?,?,?,?,?,?)", [
        (1, "https://mozilla.example.org/x", "X", "gro.elpmaxe", 2, 0,
         (base + 30) * 1_000_000),
        (2, "http://198.51.100.9:9000/a", "A", "9.001.158.891", 1, 0,
         (base + 90) * 1_000_000),
    ])
    db.executemany("INSERT INTO moz_historyvisits VALUES (?,?,?,?,?)", [
        (1, 0, 1, (base + 30) * 1_000_000, 1),
        (2, 1, 2, (base + 90) * 1_000_000, 1),
    ])
    db.commit()
    db.close()


class TestChromium(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hist = Path(self.tmp.name) / "History"
        _make_chromium(self.hist)
        self.out = Path(self.tmp.name) / "r.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, extra=None):
        rc = bht.main(["--source", str(self.hist), "--out", str(self.out)]
                      + (extra or []))
        return rc, json.loads(self.out.read_text(encoding="utf-8"))

    def test_family_and_summary(self):
        rc, rep = self._run()
        self.assertEqual(rc, 1)  # ada temuan medium
        self.assertEqual(rep["sources"][0]["family"], "chromium")
        self.assertEqual(rep["sources"][0]["urls"], 5)
        self.assertEqual(rep["sources"][0]["visits"], 6)
        self.assertEqual(rep["sources"][0]["first"],
                         "2023-11-14T21:13:20Z")
        # last mencakup kunjungan anomali 2036 (span penuh, jujur)
        self.assertEqual(rep["sources"][0]["last"], "2036-07-18T13:20:00Z")
        self.assertEqual(rep["sources"][0]["search_terms"],
                         ["kue kering", "resep"])

    def test_findings_fire(self):
        rc, rep = self._run()
        checks = {f["check"] for f in rep["findings"]}
        self.assertIn("visit-direct-ip", checks)
        self.assertIn("visit-embedded-credentials", checks)
        self.assertIn("visit-file-scheme", checks)
        self.assertIn("visit-epoch-anomaly", checks)
        self.assertIn("visit-nonstandard-port", checks)
        self.assertIn("download-danger-flagged", checks)

    def test_download_details(self):
        rc, rep = self._run()
        dl = rep["sources"][0]["downloads"]
        self.assertEqual(len(dl), 1)
        self.assertEqual(dl[0]["state"], "complete")
        self.assertEqual(dl[0]["danger"], "dangerous-content")
        self.assertIn("report.pdf", dl[0]["path"])

    def test_masking_default_and_show_query(self):
        rc, rep = self._run()
        cred = next(f for f in rep["findings"]
                    if f["check"] == "visit-embedded-credentials")
        # netloc userinfo + query sama-sama dibersihkan saat masking
        self.assertNotIn("secret", cred["url"])
        self.assertNotIn("user:", cred["url"])
        anom = next(f for f in rep["findings"]
                    if f["check"] == "visit-epoch-anomaly")
        self.assertIn("<masked:", anom["url"])
        rc, rep = self._run(["--show-query"])
        cred = next(f for f in rep["findings"]
                    if f["check"] == "visit-embedded-credentials")
        self.assertIn("user:secret@", cred["url"])

    def test_top_domains_order(self):
        rc, rep = self._run(["--top", "2"])
        top = rep["sources"][0]["top_domains"]
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0]["domain"], "example.com")
        self.assertEqual(top[0]["visits"], 3)

    def test_clean_profile_exit0_with_fail_on_medium(self):
        # profil bersih: hanya urls normal tanpa temuan
        hist2 = Path(self.tmp.name) / "Clean"
        db = sqlite3.connect(hist2)
        db.executescript(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT,"
            " title TEXT, visit_count INTEGER, typed_count INTEGER,"
            " last_visit_time INTEGER, hidden INTEGER);"
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER,"
            " visit_time INTEGER, from_visit INTEGER, transition INTEGER);")
        db.execute("INSERT INTO urls VALUES (1,'https://fine.example/',"
                   "'f',1,1,?,0)", (_wk(1_700_000_000),))
        db.execute("INSERT INTO visits VALUES (1,1,?,0,805306368)",
                   (_wk(1_700_000_000),))
        db.commit(); db.close()
        out = Path(self.tmp.name) / "c.json"
        rc = bht.main(["--source", str(hist2), "--out", str(out)])
        self.assertEqual(rc, 0)

    def test_wal_note(self):
        Path(str(self.hist) + "-wal").write_bytes(b"")
        rc, rep = self._run()
        self.assertIn("source-wal-present",
                      {f["check"] for f in rep["findings"]})

    def test_allow_check(self):
        rc, rep = self._run(["--allow-check", "visit-direct-ip"])
        self.assertNotIn("visit-direct-ip",
                         {f["check"] for f in rep["findings"]})


class TestFirefox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.places = Path(self.tmp.name) / "places.sqlite"
        _make_firefox(self.places)
        self.out = Path(self.tmp.name) / "r.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_family_and_direct_ip(self):
        rc = bht.main(["--source", str(self.places), "--out", str(self.out)])
        rep = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 1)
        self.assertEqual(rep["sources"][0]["family"], "firefox")
        self.assertIn("visit-direct-ip",
                      {f["check"] for f in rep["findings"]})
        self.assertEqual(rep["sources"][0]["visits"], 2)


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "r.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_schema_exit2(self):
        p = Path(self.tmp.name) / "bukan.sqlite"
        db = sqlite3.connect(p)
        db.execute("CREATE TABLE lain (a INTEGER)")
        db.commit(); db.close()
        rc = bht.main(["--source", str(p), "--out", str(self.out)])
        self.assertEqual(rc, 2)

    def test_missing_file_exit2(self):
        rc = bht.main(["--source", str(Path(self.tmp.name) / "nope")])
        self.assertEqual(rc, 2)

    def test_mixed_known_and_unknown(self):
        hist = Path(self.tmp.name) / "History"
        _make_chromium(hist)
        bad = Path(self.tmp.name) / "lain.db"
        db = sqlite3.connect(bad)
        db.execute("CREATE TABLE x (a)")
        db.commit(); db.close()
        rc = bht.main(["--source", str(hist), str(bad),
                       "--out", str(self.out)])
        rep = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 1)
        self.assertEqual(len(rep["sources"]), 1)  # hanya yang dikenali
        self.assertIn("input-schema-unknown",
                      {f["check"] for f in rep["findings"]})


if __name__ == "__main__":
    unittest.main()
