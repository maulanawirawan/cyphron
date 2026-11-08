"""Nol jaringan — test brand_lookalike_scan (klasifikasi domain lookalike
merek OFFLINE; fail-closed; metadata risiko hanya bila ada di input)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import brand_lookalike_scan as bls  # noqa: E402


def _write(tmp: str, name: str, content: str) -> Path:
    p = Path(tmp) / name
    p.write_text(content, encoding="utf-8")
    return p


BRANDS_JSON = json.dumps({"brands": [{
    "name": "acme",
    "domains": ["acme.com", "acme.co.id"],
    "keywords": ["acmeshop"],
}]})


class UnitTests(unittest.TestCase):
    def test_damerau_osa_basic(self):
        self.assertEqual(bls.damerau_osa("acme", "acme"), 0)
        self.assertEqual(bls.damerau_osa("acme", "acem"), 1)   # transposisi
        self.assertEqual(bls.damerau_osa("acme", "acm"), 1)    # omission
        self.assertEqual(bls.damerau_osa("acmes", "acme"), 1)  # insertion
        self.assertEqual(bls.damerau_osa("xcrme", "acme"), 2)
        self.assertEqual(bls.damerau_osa("acme", "amce"), 1)

    def test_distance_ops_classes(self):
        self.assertEqual(bls.distance_ops("acme", "acem"), "transposition")
        self.assertEqual(bls.distance_ops("acme", "acm"), "omission")
        self.assertEqual(bls.distance_ops("acme", "acmes"), "insertion")
        self.assertEqual(bls.distance_ops("acmee", "acme"), "repetition")
        self.assertEqual(bls.distance_ops("acne", "acme"), "substitution")
        self.assertIsNone(bls.distance_ops("acme", "acme"))
        self.assertIsNone(bls.distance_ops("xcrme", "acme"))

    def test_skeleton_confusable(self):
        self.assertEqual(bls.skeleton("аcme"), "acme")      # Cyrillic а
        self.assertEqual(bls.skeleton("g00gle"), "google")  # digit swap
        self.assertEqual(bls.skeleton("gооgle"), "google")  # Cyrillic о
        self.assertEqual(bls.skeleton("acrn"), "acm")       # rn -> m
        # identitas utk ASCII murni
        self.assertEqual(bls.skeleton("acme.com"), "acme.com")

    def test_registrable_multilabel_suffix(self):
        self.assertEqual(bls.registrable("mail.acme.com"), "acme.com")
        self.assertEqual(bls.registrable("x.acme.co.id"), "acme.co.id")
        self.assertEqual(bls.registrable("acme.com.evil.io"), "evil.io")

    def test_label_core(self):
        self.assertEqual(bls.label_core("mail.acme.com"), "acme")
        self.assertEqual(bls.label_core("sub.acme.co.id"), "acme")

    def test_decode_punycode_and_cleanup(self):
        cyr = "аррӏе"
        puny = "xn--" + cyr.encode("punycode").decode("ascii")
        dom, ok, had_puny = bls.decode_domain(puny + ".com")
        self.assertTrue(ok)
        self.assertTrue(had_puny)
        self.assertEqual(dom, cyr + ".com")
        dom, ok, _ = bls.decode_domain("*.Acme.COM.")
        self.assertEqual(dom, "acme.com")
        dom, ok, _ = bls.decode_domain("xn--!!!.com")
        self.assertFalse(ok)  # punycode rusak = idn-unparseable


class CliTests(unittest.TestCase):
    def _run(self, tmp, observed, extra=None, brands=BRANDS_JSON):
        obs = _write(tmp, "obs.txt", observed)
        argv = ["--observed", str(obs)]
        if brands is not None:
            bp = _write(tmp, "brands.json", brands)
            argv += ["--brands", str(bp)]
        out = Path(tmp) / "out.json"
        argv += ["--out", str(out)]
        if extra:
            argv += extra
        rc = bls.main(argv)
        data = json.loads(out.read_text(encoding="utf-8"))
        return rc, data

    def test_exact_other_tld(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "acme.org\nacme.net\n")
            self.assertEqual(rc, 1)
            techs = [f["param"] for f in data["findings"]]
            self.assertEqual(techs, ["exact-other-tld", "exact-other-tld"])
            for f in data["findings"]:
                self.assertEqual(f["severity"], "medium")
                self.assertEqual(f["verdict"], 2)
                self.assertEqual(f["status"], "confirmed")
            # tanpa metadata = tanpa uplift, dicatat None
            self.assertIsNone(data["findings"][0]["age_days"])

    def test_homoglyph_cyrillic(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "аcme.com\n")  # Cyrillic а
            self.assertEqual(rc, 1)
            self.assertEqual(data["findings"][0]["param"], "homoglyph")
            self.assertEqual(data["findings"][0]["severity"], "high")

    def test_homoglyph_punycode(self):
        # klasik: label punycode menyembunyikan homoglyph (kasus аpple)
        cyr = "аcmе"  # а dan е Cyrillic
        puny = "xn--" + cyr.encode("punycode").decode("ascii")
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, puny + ".com\n")
            self.assertEqual(rc, 1)
            f = data["findings"][0]
            self.assertEqual(f["param"], "homoglyph")
            self.assertEqual(f["technique"], "homoglyph")
            self.assertIn("confusable", f["description"])
            self.assertEqual(data["data"]["idn_unparseable"], 0)

    def test_typo_distance1_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "acm.com\nacem.com\nacmes.com\n")
            self.assertEqual(rc, 1)
            techs = sorted(f["param"] for f in data["findings"])
            self.assertEqual(techs, ["typo-distance-1"] * 3)
            ops = sorted(json.dumps(f) for f in data["findings"])
            # kelas operasi tercatat di poc/detail
            joined = " ".join(f["description"] for f in data["findings"])
            self.assertIn("omission", joined)
            self.assertIn("transposition", joined)
            self.assertIn("insertion", joined)
            self.assertEqual(len(ops), 3)

    def test_typo_distance2_low_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "xcrme.com\n",
                                 extra=["--fail-on", "high"])
            # low < fail-on high -> exit 0, temuan tetap tercatat
            self.assertEqual(rc, 0)
            self.assertEqual(data["findings"][0]["param"],
                             "typo-distance-2")
            self.assertEqual(data["findings"][0]["severity"], "low")

    def test_brand_plus_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(
                tmp, "acme-login.com\nsecureacme.net\nacmezzz.com\n")
            self.assertEqual(rc, 1)
            by_dom = {f["target_url"]: f for f in data["findings"]}
            self.assertEqual(by_dom["acme-login.com"]["severity"], "high")
            self.assertEqual(by_dom["secureacme.net"]["severity"], "high")
            self.assertEqual(by_dom["acmezzz.com"]["severity"], "medium")
            for f in data["findings"]:
                self.assertEqual(f["param"], "brand-plus-token")

    def test_keyword_embed(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "acmeshop-login.com\n")
            self.assertEqual(rc, 1)
            self.assertEqual(data["findings"][0]["param"],
                             "brand-plus-token")
            self.assertEqual(data["findings"][0]["severity"], "high")

    def test_subdomain_embed(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, "acme.com.evil.io\n")
            self.assertEqual(rc, 1)
            f = data["findings"][0]
            self.assertEqual(f["param"], "subdomain-embed")
            self.assertEqual(f["severity"], "medium")

    def test_legit_and_subdomain_of_brand_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(
                tmp, "acme.com\nmail.acme.com\nacme.co.id\nacme.org\n",
                extra=["--legit", "acme.org"])
            self.assertEqual(rc, 0)
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["data"]["observed_unique"], 4)

    def test_metadata_uplift_recent_mx(self):
        # JSON dnstwist-ish: created 10 hari lalu + mx -> medium naik high
        recent = (datetime.now(timezone.utc) - timedelta(days=10)
                  ).date().isoformat()
        obs = json.dumps([
            {"domain": "acme.org", "created": recent, "mx": True},
        ])
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, obs)
            self.assertEqual(rc, 1)
            f = data["findings"][0]
            self.assertEqual(f["severity"], "high")
            self.assertIn("uplift", f["description"])
            self.assertIsNotNone(f["age_days"])
            self.assertTrue(f["mx"])

    def test_metadata_old_no_uplift(self):
        old = (datetime.now(timezone.utc) - timedelta(days=400)
               ).date().isoformat()
        obs = json.dumps([{"domain": "acme.org", "created": old}])
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, obs)
            self.assertEqual(rc, 1)
            self.assertEqual(data["findings"][0]["severity"], "medium")

    def test_dedup_and_junk_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(
                tmp, "acme.org\nacme.org\ntotal tidak jelas ::\n")
            self.assertEqual(rc, 1)
            self.assertEqual(data["data"]["duplicates"], 1)
            self.assertEqual(len(data["findings"]), 1)
            self.assertTrue(data["data"]["junk_samples"])

    def test_idn_unparseable_counted(self):
        bad = "xn--abc!!!.com"  # punycode tak sah (karakter non-basic)
        with tempfile.TemporaryDirectory() as tmp:
            rc, data = self._run(tmp, bad + "\n")
            self.assertEqual(data["data"]["idn_unparseable"], 1)

    def test_fail_closed_no_brands(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs = _write(tmp, "obs.txt", "acme.org\n")
            rc = bls.main(["--observed", str(obs),
                           "--out", str(Path(tmp) / "o.json")])
            self.assertEqual(rc, 2)

    def test_fail_closed_empty_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs = _write(tmp, "obs.txt", "# komentar saja\n\n")
            bp = _write(tmp, "brands.json", BRANDS_JSON)
            rc = bls.main(["--observed", str(obs), "--brands", str(bp),
                           "--out", str(Path(tmp) / "o.json")])
            self.assertEqual(rc, 2)

    def test_fail_closed_missing_file(self):
        rc = bls.main(["--observed", "TIDAK-ADA-file.txt",
                       "--brand", "acme.com",
                       "--out", "o-tmp-bls.json"])
        self.assertEqual(rc, 2)

    def test_brand_quickpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs = _write(tmp, "obs.txt", "acme-login.com\nacme.org\n")
            out = Path(tmp) / "o.json"
            rc = bls.main(["--observed", str(obs), "--brand", "acme.com",
                           "--out", str(out)])
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rc, 1)
            self.assertEqual(len(data["findings"]), 2)
            self.assertEqual(data["data"]["brands"]["brands_unique"], 1)


if __name__ == "__main__":
    unittest.main()
