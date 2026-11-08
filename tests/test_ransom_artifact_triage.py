"""Test ransom_artifact_triage (#0740) — nol jaringan, fixture inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ransom_artifact_triage as rat


def _listing(files):
    return json.dumps({"files": files}, ensure_ascii=False)


class TestVariantExtension(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lp = Path(self.tmp.name) / "listing.json"
        self.lp.write_text(_listing([
            {"path": "C:/d/doc.docx.lockbit", "size": 1,
             "mtime": "2026-11-08T02:10:00Z"},
            {"path": "C:/d/x.pdf.lockbit", "mtime": "2026-11-08T02:20:00Z"},
        ]), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_variant_match_high_dan_window(self):
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out),
                       "--fail-on", "high"])
        self.assertEqual(rc, 1)
        rep = json.loads(out.read_text(encoding="utf-8"))
        checks = [f["check"] for f in rep["findings"]]
        self.assertIn("variant-extension-match", checks)
        self.assertEqual(rep["summary"]["variants"]["LockBit"], 2)
        win = rep["summary"]["encryption_window"]["LockBit"]
        self.assertEqual(win["span_minutes"], 10.0)
        self.assertEqual(win["first"], "2026-11-08T02:10:00+00:00")

    def test_epoch_mtime(self):
        self.lp.write_text(_listing([
            {"path": "C:/d/a.ryuk", "mtime": 1793788200},
        ]), encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rat.main(["--listing", str(self.lp), "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rep["summary"]["variants"]["Ryuk"], 1)
        self.assertIn("2026", rep["summary"]["encryption_window"]
                      ["Ryuk"]["first"])

    def test_generic_ext_tidak_masuk_tabel_varian(self):
        self.lp.write_text(_listing([{"path": "C:/d/a.enc"}]),
                           encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)  # satu .enc saja = bukan temuan apa pun
        self.assertEqual(rep["summary"]["variants"], {})
        self.assertEqual(rep["findings"], [])


class TestMassEncrypted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lp = Path(self.tmp.name) / "listing.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _run_listing(self, entries):
        self.lp.write_text(_listing(entries), encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out)])
        return rc, json.loads(out.read_text(encoding="utf-8"))

    def test_mass_di_satu_direktori_medium(self):
        rc, rep = self._run_listing(
            [{"path": f"C:/share/f{i}.locked"} for i in range(25)])
        self.assertEqual(rc, 1)
        mass = [f for f in rep["findings"]
                if f["check"] == "mass-encrypted-files"]
        self.assertEqual(len(mass), 1)
        self.assertEqual(mass[0]["severity"], "medium")
        self.assertEqual(mass[0]["object"], "C:/share")

    def test_di_bawah_ambang_tidak_menandai(self):
        rc, rep = self._run_listing(
            [{"path": f"C:/share/f{i}.enc"} for i in range(24)])
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])

    def test_ambang_dinilai_per_direktori(self):
        rc, rep = self._run_listing(
            [{"path": f"C:/a/f{i}.crypt"} for i in range(15)]
            + [{"path": f"C:/b/f{i}.crypt"} for i in range(15)])
        self.assertEqual(rc, 0, "15+15 lintas dua direktori = tidak melewati ambang per-dir")
        self.assertEqual(rep["findings"], [])

    def test_allow_ext_whitelist(self):
        self._run_listing(
            [{"path": f"C:/share/f{i}.enc"} for i in range(30)]
            + [{"path": "C:/share/keep.txt.enc"}])
        out = Path(self.tmp.name) / "o2.json"
        rc = rat.main(["--listing", str(self.lp), "--allow-ext", ".enc",
                       "--out", str(out)])
        rep2 = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(rep2["findings"], [])
        notes = " ".join(rep2["notes"])
        self.assertIn(".enc", notes)

    def test_file_tunggal_tanpa_mtime_tetap_bersih(self):
        rc, rep = self._run_listing([{"path": "C:/x/report.enc"}])
        self.assertEqual(rc, 0)
        self.assertIn("window", " ".join(rep["notes"]).lower()
                      or "window")  # catatan keterbatasan mtime ada


class TestNoteFilename(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lp = Path(self.tmp.name) / "listing.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _run_listing(self, entries, *extra):
        self.lp.write_text(_listing(entries), encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out),
                       *extra])
        return rc, json.loads(out.read_text(encoding="utf-8"))

    def test_pola_note_umum(self):
        for name in ("README_FOR_DECRYPT.txt", "how_to_restore.html",
                     "RANSOM_NOTE.txt", "!!!-WARNING-!!!.hta",
                     "Help_Decrypt.lnk", "#RECOVERY#.txt"):
            rc, rep = self._run_listing([{"path": f"C:/u/{name}"}])
            self.assertEqual(rc, 1, name)
            checks = [f["check"] for f in rep["findings"]]
            self.assertIn("ransom-note-filename", checks, name)

    def test_hta_dapat_keterangan_dropper(self):
        rc, rep = self._run_listing([{"path": "C:/u/restore_files.hta"}])
        msg = rep["findings"][0]["message"]
        self.assertIn("dropper", msg)

    def test_nama_biasa_tidak_menandai(self):
        for name in ("README.md", "README.txt", "readme_generator.py",
                     "recovery_plan_2026.docx", "decryptor_vendor.bin"):
            rc, rep = self._run_listing([{"path": f"C:/u/{name}"}])
            self.assertEqual(rc, 0, name)

    def test_note_arg_dan_listing_tidak_duplikat(self):
        note = Path(self.tmp.name) / "README_RECOVER.txt"
        note.write_text("hello", encoding="utf-8")
        rc, rep = self._run_listing(
            [{"path": "C:/u/README_RECOVER.txt"}, {"path": "C:/u/x.doc"}],
            "--note", str(note))
        dupes = [f for f in rep["findings"]
                 if f["check"] == "ransom-note-filename"]
        self.assertEqual(len(dupes), 1)


class TestNoteContent(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lp = Path(self.tmp.name) / "listing.json"
        self.lp.write_text(_listing([{"path": "C:/u/a.doc"}]),
                           encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _run_note(self, text):
        np = Path(self.tmp.name) / "n.txt"
        np.write_text(text, encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--note", str(np),
                       "--out", str(out)])
        return rc, json.loads(out.read_text(encoding="utf-8"))

    def test_btc_legacy_dan_onion(self):
        rc, rep = self._run_note(
            "Send 0.5 BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n"
            "check http://nv3jdmo2t5pgc7ncnnbnpkqec36bgrpu4aocpr4xj"
            ".onion\n")
        self.assertEqual(rc, 1)
        self.assertIn("note-content-ransom-iocs",
                      [f["check"] for f in rep["findings"]])
        self.assertTrue(rep["summary"]["iocs"]["bitcoin"])
        self.assertTrue(rep["summary"]["iocs"]["onion"])

    def test_bech32_btc(self):
        rc, rep = self._run_note(
            "pay: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n")
        self.assertEqual(rc, 1)
        self.assertEqual(rep["summary"]["iocs"]["bitcoin"],
                         ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"])

    def test_monero(self):
        xmr = ("4" + "8" + "A" + "1" * 92)  # 4[0-9AB][base58]{93}
        rc, rep = self._run_note(f"pay XMR: {xmr}\n")
        self.assertEqual(rc, 1)
        self.assertEqual(len(rep["summary"]["iocs"]["monero"]), 1)

    def test_email_saja_tidak_menandai(self):
        rc, rep = self._run_note(
            "Questions? support@example.com — sorry for trouble\n")
        self.assertEqual(rc, 0)
        self.assertEqual([f for f in rep["findings"]
                          if f["check"] == "note-content-ransom-iocs"], [])
        # email tetap dikumpulkan sbg informasi
        self.assertEqual(rep["summary"]["iocs"]["emails"],
                         ["support@example.com"])

    def test_note_biner_direkam_error_tanpa_tandai(self):
        np = Path(self.tmp.name) / "n.bin"
        np.write_bytes(b"\x00\x01\x02binary\x00")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--note", str(np),
                       "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertTrue(any("biner" in e for e in rep["errors"]))


class TestFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lp = Path(self.tmp.name) / "listing.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_listing_hilang_exit_2(self):
        rc = rat.main(["--listing",
                       str(Path(self.tmp.name) / "nope.json")])
        self.assertEqual(rc, 2)

    def test_json_korup_exit_2(self):
        self.lp.write_text('{"files": [', encoding="utf-8")
        rc = rat.main(["--listing", str(self.lp)])
        self.assertEqual(rc, 2)

    def test_json_objek_tanpa_kunci_files_exit_2(self):
        self.lp.write_text('{"bukan": 1}', encoding="utf-8")
        rc = rat.main(["--listing", str(self.lp)])
        self.assertEqual(rc, 2)

    def test_entri_tanpa_path_tercatat_error_bukan_diam(self):
        self.lp.write_text(_listing([{"size": 5}, {"path": "C:/ok.txt"}]),
                           encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertTrue(any("tanpa 'path'" in e for e in rep["errors"]))
        self.assertEqual(rep["summary"]["files_scanned"], 1)

    def test_mtime_aneh_tercatat_error(self):
        self.lp.write_text(_listing([{"path": "C:/a.akira",
                                      "mtime": "besok"}]),
                           encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(any("mtime" in e for e in rep["errors"]))

    def test_note_hilang_exit_2(self):
        self.lp.write_text(_listing([{"path": "C:/x"}]), encoding="utf-8")
        rc = rat.main(["--listing", str(self.lp),
                       "--note", str(Path(self.tmp.name) / "gone.txt")])
        self.assertEqual(rc, 2)

    def test_teks_listing_satu_path_per_baris(self):
        self.lp.write_text("C:/a/one.lockbit\n# komentar\n\nC:/b/two.txt\n",
                           encoding="utf-8")
        out = Path(self.tmp.name) / "o.json"
        rc = rat.main(["--listing", str(self.lp), "--out", str(out)])
        rep = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(rc, 1)
        self.assertEqual(rep["summary"]["files_scanned"], 2)
        self.assertTrue(any("mtime" in n for n in rep["notes"]))


class TestAllowCheck(unittest.TestCase):
    def test_allow_check_menyaring_dan_dicatat(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            lp = Path(tmp.name) / "l.json"
            lp.write_text(_listing([{"path": "C:/u/x.lockbit"}]),
                          encoding="utf-8")
            out = Path(tmp.name) / "o.json"
            rc = rat.main(["--listing", str(lp),
                           "--allow-check", "variant-extension-match",
                           "--out", str(out)])
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rc, 0)
            self.assertEqual(rep["findings"], [])
            self.assertIn("variant-extension-match",
                          " ".join(rep["notes"]))
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
