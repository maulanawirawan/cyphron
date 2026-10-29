"""Test F26 batch 3b — perluasan + 2 skill baru (jalur DETEKSI).

Port/ekspansi dari katalog legacy, lewat pipeline wajib (mock NOL
jaringan, zero-FP, (rows, meta), verdict ladder):
  - hsts-preload-checker +max-age pendek (<30 hari) -> lead ekstra;
  - cookie-flags-aggregate +prefix __Host-/__Secure- dilanggar -> lead;
  - file-exposure-checker (baru, bounded-requests) — verifikasi
    SIGNATURE isi; halaman generik/halaman error = bukan temuan;
  - internal-info-leak-checker (baru, 1-request) — IP privat RFC1918
    HANYA di konteks non-HTML (anti-FP), bukti dipotong.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import cookie_flags_aggregate as ckf        # noqa: E402
import hsts_preload_checker as hsts         # noqa: E402
import file_exposure_checker as fexp        # noqa: E402
import internal_info_leak_checker as iil    # noqa: E402

URL = "https://lab.local/"
REG = json.loads((ROOT / "skills" / "registry.json").read_text("utf-8"))


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class HstsShortMaxAgeTest(unittest.TestCase):
    def test_short_max_age_adds_extra_lead(self):
        rows, _ = hsts.audit(URL, {"Strict-Transport-Security":
                                   "max-age=86400"})
        self.assertIsNotNone(one(rows, "HSTS preload not ready"))
        f = one(rows, "max-age pendek")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertFalse(f["reportable"])
        self.assertEqual(f["max_age"], 86400)

    def test_ready_and_absent_have_no_short_row(self):
        rows, _ = hsts.audit(URL, {"Strict-Transport-Security":
                                   "max-age=31536000; includeSubDomains; "
                                   "preload"})
        self.assertIsNone(one(rows, "max-age pendek"))
        rows, _ = hsts.audit(URL, {})
        self.assertIsNone(one(rows, "max-age pendek"))
        # max-age panjang tapi belum preload-ready -> tidak ada row pendek
        rows, _ = hsts.audit(URL, {"Strict-Transport-Security":
                                   "max-age=31536000"})
        self.assertIsNone(one(rows, "max-age pendek"))


class CookiePrefixTest(unittest.TestCase):
    def test_host_prefix_without_secure_is_lead(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie": "__Host-sid=abc; Path=/"})
        f = one(rows, "dilanggar")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertIn("Secure hilang", "; ".join(f["violations"]))

    def test_host_prefix_correct_is_not_flagged(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie":
                                  "__Host-sid=abc; Secure; Path=/"})
        self.assertIsNone(one(rows, "dilanggar"))

    def test_host_prefix_with_domain_is_lead(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie":
                                  "__Host-sid=abc; Secure; "
                                  "Domain=example.com; Path=/"})
        f = one(rows, "dilanggar")
        self.assertIsNotNone(f)
        self.assertIn("Domain", "; ".join(f["violations"]))

    def test_secure_prefix_without_secure_is_lead(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie": "__Secure-t=1; Path=/"})
        f = one(rows, "dilanggar")
        self.assertIsNotNone(f)
        self.assertEqual(f["cwe"], "CWE-614")

    def test_plain_cookie_has_no_prefix_row(self):
        rows, _ = ckf.audit(URL, {"Set-Cookie": "sid=abc; Path=/"})
        self.assertIsNone(one(rows, "dilanggar"))
        self.assertIsNotNone(one(rows, "Cookie flags missing"))


class FileExposureTest(unittest.TestCase):
    def test_git_config_signature_is_lead(self):
        res = {"/.git/config": {"status": 200,
                                "body": "[core]\n\tbare = false\n"}}
        rows, meta = fexp.audit(URL, res)
        f = one(rows, "git-config")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(meta["exposed"], ["/.git/config"])
        self.assertEqual(meta["requests"], 1)

    def test_generic_page_200_is_not_flagged(self):
        res = {"/.git/config": {"status": 200,
                                "body": "<!DOCTYPE html><html>404 page"},
               "/.env": {"status": 404, "body": ""}}
        rows, meta = fexp.audit(URL, res)
        self.assertIsNone(one(rows, "exposed on"))
        self.assertEqual(meta["exposed"], [])
        self.assertEqual(one(rows, "posture")["verdict"], 0)

    def test_env_and_binaries_signature(self):
        res = {"/.env": {"status": 200, "body": "DB_PASS=hunter2\nAPP_ENV=prod"},
               "/backup.zip": {"status": 200, "body": "PK\x03\x04...."},
               "/.svn/wc.db": {"status": 200,
                               "body": "SQLite format 3\x00..."}}
        rows, meta = fexp.audit(URL, res)
        self.assertEqual(len(meta["exposed"]), 3)
        self.assertEqual(len([r for r in rows if r["verdict"] == 1]), 4)


class InternalInfoLeakTest(unittest.TestCase):
    def test_private_ip_in_json_is_lead_redacted(self):
        res = {"status": 200, "content_type": "application/json",
               "body": '{"db_host": "192.168.10.25", "cache": "10.0.0.3"}'}
        rows, meta = fexp_ok(iil, res)
        f = one(rows, "Internal IP leak")
        self.assertIsNotNone(f)
        self.assertEqual(f["verdict"], 1)
        self.assertEqual(f["cwe"], "CWE-200")
        self.assertEqual(meta["hits"], 2)
        # bukti dipotong: dua oktet terakhir tidak ditulis utuh
        self.assertNotIn("192.168.10.25", f["response"])
        self.assertIn("192.168.x.x", f["response"])

    def test_html_context_is_skipped_anti_fp(self):
        res = {"status": 200, "content_type": "text/html; charset=utf-8",
               "body": "<p>Server 192.168.1.1 adalah contoh</p>"}
        rows, meta = fexp_ok(iil, res)
        self.assertEqual(meta["hits"], 0)
        self.assertTrue(meta["html_skip"])
        self.assertEqual(one(rows, "No internal IP leak")["verdict"], 0)

    def test_invalid_octets_do_not_match(self):
        res = {"status": 200, "content_type": "application/json",
               "body": '{"bad": "192.168.999.5", "ok": "172.16.31.200"}'}
        rows, meta = fexp_ok(iil, res)
        self.assertEqual(meta["hits"], 1)

    def test_transport_error_is_fail_closed(self):
        rows, _ = iil.audit(URL, {"status": None, "error": "URLError",
                                  "content_type": "", "body": ""})
        self.assertEqual(rows[0]["title"], f"Fetch failed on {URL}")


def fexp_ok(mod, res):
    """audit helper dengan return shape (rows, meta)."""
    return mod.audit(URL, res)


class RegistryBatch3bTest(unittest.TestCase):
    def test_two_new_entries_valid(self):
        self.assertGreaterEqual(len(REG["skills"]), 86)
        by_name = {s["name"]: s for s in REG["skills"]}
        for name, cls in (("file-exposure-checker", "bounded-requests"),
                          ("internal-info-leak-checker", "1-request")):
            s = by_name[name]
            self.assertEqual(s["safety_class"], cls)
            self.assertEqual(s["needs"], "target")
            cmd = s["cmd"]
            self.assertTrue((ROOT / cmd[1]).exists(), cmd[1])


if __name__ == "__main__":
    unittest.main()
