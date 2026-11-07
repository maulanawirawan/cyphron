"""Nol jaringan — test ioc_defang (ekstraksi/defang/refang IOC)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ioc_defang as iocd  # noqa: E402

SAMPLE = """
Incident report 42: malware C2 hxxp://185.234.218.50[:]/gate.php and
mirror https://evil-c2.example.com/push. Submit to soc[@]corp[.]example.
Hashes: d41d8cd98f00b204e9800998ecf8427e (md5),
da39a3ee5e6b4b0d3255bfef95601890afd80709 (sha1),
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (sha256).
Sender was ADMIN@phish-demo.net; also seen 10.0.0.7 and evil-c2.example.com.
Bogus hash too long: zzze3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855zzz.
"""


class TestRefang(unittest.TestCase):
    def test_protocols(self):
        self.assertEqual(iocd.refang_text("hxxp://a.b"), "http://a.b")
        self.assertEqual(iocd.refang_text("hXXps://a.b"), "https://a.b")
        self.assertEqual(iocd.refang_text("Hxxps://A.B"), "https://A.B")

    def test_prose_words_untouched(self):
        # 'hp'/'php' tidak boleh berubah jadi http
        self.assertEqual(iocd.refang_text("php is fun, hp printers"),
                         "php is fun, hp printers")

    def test_dots_colons_ats(self):
        self.assertEqual(iocd.refang_text("evil[.]com"), "evil.com")
        self.assertEqual(iocd.refang_text("evil(dot)com"), "evil.com")
        self.assertEqual(iocd.refang_text("1.2.3.4[:]8080"), "1.2.3.4:8080")
        self.assertEqual(iocd.refang_text("admin[@]evil.com"),
                         "admin@evil.com")
        self.assertEqual(iocd.refang_text("admin[at]evil.com"),
                         "admin@evil.com")

    def test_roundtrip(self):
        raw = "goto hxxp://bad[.]host/p and mail a[@]b[.]c-d.org"
        once = iocd.defang_text(raw)
        twice = iocd.defang_text(once)
        self.assertEqual(once, twice)  # idempoten


class TestExtract(unittest.TestCase):
    def test_all_types(self):
        r = iocd.extract_iocs(SAMPLE)
        self.assertEqual(r["ipv4"], ["10.0.0.7", "185.234.218.50"])
        self.assertEqual(r["url"], ["http://185.234.218.50/gate.php",
                                    "https://evil-c2.example.com/push"])
        self.assertEqual(r["email"],
                         ["admin@phish-demo.net", "soc@corp.example"])
        self.assertIn("evil-c2.example.com",
                      {iocd._host_of(u) for u in r["url"]})
        # path URL tidak boleh jadi 'domain' (anti-FP); domain email
        # dan host URL juga tidak diulang di bucket domain
        self.assertEqual(r["domain"], [])
        self.assertEqual(r["md5"], ["d41d8cd98f00b204e9800998ecf8427e"])
        self.assertEqual(r["sha1"],
                         ["da39a3ee5e6b4b0d3255bfef95601890afd80709"])
        self.assertEqual(r["sha256"],
                         ["e3b0c44298fc1c149afbf4c8996fb924"
                          "27ae41e4649b934ca495991b7852b855"])

    def test_url_host_not_in_domain_bucket(self):
        r = iocd.extract_iocs("visit http://stash.example.net/x now")
        self.assertEqual(r["url"], ["http://stash.example.net/x"])
        self.assertNotIn("stash.example.net", r["domain"])

    def test_uppercase_domain_and_trailing_dot(self):
        r = iocd.extract_iocs("host: EVIL-C2.Example.COM. regards")
        self.assertEqual(r["domain"], ["evil-c2.example.com"])

    def test_allowlist_suffix(self):
        r = iocd.extract_iocs(
            "a.telemetry.example.com and evil.example.com",
            allowlist={"example.com"})
        self.assertNotIn("a.telemetry.example.com", r["domain"])
        self.assertNotIn("evil.example.com", r["domain"])
        # tipe lain tidak tersentuh allowlist
        r2 = iocd.extract_iocs("http://ok.example.com/x",
                               allowlist={"example.com"})
        self.assertEqual(r2["url"], ["http://ok.example.com/x"])

    def test_hash_lengths_strict(self):
        r = iocd.extract_iocs("A" * 64 + " B" * 16)
        self.assertEqual(r["sha256"], ["a" * 64])
        self.assertEqual(r["md5"], [])
        self.assertEqual(r["sha1"], [])


class TestDefang(unittest.TestCase):
    def test_value_rendering(self):
        self.assertEqual(
            iocd.defang_value("url", "https://a.b/c?d=1"), "hxxps://a[.]b/c?d=1")
        self.assertEqual(iocd.defang_value("ipv4", "1.2.3.4"), "1[.]2[.]3[.]4")
        self.assertEqual(iocd.defang_value("domain", "a.b.com"),
                         "a[.]b[.]com")
        self.assertEqual(iocd.defang_value("email", "x@y.z"), "x[@]y[.]z")
        self.assertEqual(iocd.defang_value("sha256", "ab" * 32), "ab" * 32)

    def test_text_no_active_scheme_left(self):
        out = iocd.defang_text(SAMPLE)
        self.assertNotIn("http://", out)
        self.assertNotIn("https://", out)
        self.assertNotIn("hxxp://185[.]234[.]218[.]50", out.replace(
            "hxxp://185[.]234[.]218[.]50", ""))
        self.assertIn("hxxp://185[.]234[.]218[.]50", out)
        self.assertIn("soc[@]corp[.]example", out)

    def test_word_boundary_and_longest_first(self):
        out = iocd.defang_text("we monitor evil.com and evil.community")
        self.assertIn("evil[.]com", out)          # host pendek
        self.assertIn("evil[.]community", out)    # host panjang utuh
        self.assertNotIn("evil[.]communityx", out)

    def test_ip_boundary(self):
        out = iocd.defang_text("hits from 1.2.3.4 and 11.2.3.44")
        self.assertIn("1[.]2[.]3[.]4", out)
        self.assertIn("11[.]2[.]3[.]44", out)


class TestStix(unittest.TestCase):
    def test_patterns(self):
        self.assertEqual(iocd.stix_pattern("ipv4", "1.2.3.4"),
                         "[ipv4-addr:value = '1.2.3.4']")
        self.assertEqual(iocd.stix_pattern("domain", "a.com"),
                         "[domain-name:value = 'a.com']")
        self.assertEqual(iocd.stix_pattern("sha256", "ab" * 32),
                         "[file:hashes.'SHA-256' = '" + "ab" * 32 + "']")

    def test_quote_escaped(self):
        p = iocd.stix_pattern("url", "http://a.b/x'y")
        self.assertIn("\\'", p)
        self.assertNotIn("x'y'", p.replace("\\'", ""))

    def test_cli_stix_sorted_deterministic(self):
        r1 = iocd.extract_iocs(SAMPLE)
        r2 = iocd.extract_iocs(SAMPLE[::-1][:0] + SAMPLE)
        self.assertEqual(r1, r2)


class TestCli(unittest.TestCase):
    def test_no_input_is_exit_2(self):
        with self.assertRaises(SystemExit) as cm:
            iocd.main([])
        self.assertEqual(cm.exception.code, 2)

    def test_missing_file_exit_2(self):
        rc = iocd.main(["--file", "tidak-ada-xyz.txt"])
        self.assertEqual(rc, 2)

    def test_text_flow_and_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "iocs.json"
            rc = iocd.main(["--text", "mail a[@]b[.]c-d.org see hxxp://e.f/g",
                            "--stix", "--emit-defanged", "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], iocd.SCHEMA)
            self.assertEqual(data["iocs"]["email"], ["a@b.c-d.org"])
            self.assertIn("stix_patterns", data)
            self.assertIn("defanged_text", data)
            self.assertNotIn("http://", data["defanged_text"])

    def test_binary_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin.txt"
            f.write_bytes(b"http://a.b/c\x00tail")
            rc = iocd.main(["--file", str(f)])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
