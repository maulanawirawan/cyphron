"""Test F75f — wordpress-rest-surface verify L3 + js-secret-scanner
refetch L2 (masking bukti).

wordpress-rest-surface:
  - URL wp-json dari evidence (absolut) terbaca;
  - signature eksklusif: "routes" dict + "namespaces" berisi "wp/v2"
    = L3 (kontrak verdict_tag + reportable sinkron);
  - bukan shape WP / 401 / 403 / gagal jaringan = tetap L1 + catatan;
  - zero-retention: daftar PATH route tidak disimpan (hanya jumlah +
    namespaces).

js-secret-scanner-v2:
  - HIGIENE: nilai kredensial di-mask di bukti (capture-1 DAN
    capture-2) — format+panjang tetap terbaca;
  - refetch pola sama = L2 REPRODUCED (kontrak sinkron);
  - refetch tanpa pola / gagal = tetap L1;
  - tanpa lead JS (hanya komentar HTML) = verify tidak jalan.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import wordpress_rest_surface as wrs   # noqa: E402
import js_secret_scanner_v2 as jss     # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://site.example"
WPJSON = ('{"name":"S","description":"","url":"https://site.example",'
          '"namespaces":["wp/v2","wp-site-health/v1"],'
          '"routes":{"/":{"namespace":[],"methods":["GET"],'
          '"endpoints":[]},"/wp/v2/posts":{}}}')
SECRET = 'var cfg = { api_key: "AKIA1234567890abcdef1234" };'


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class RestSurfaceTest(unittest.TestCase):
    def test_url_dari_evidence(self):
        html = ('<html><link rel="alternate" type="application/json" '
                'href="https://site.example/wp-json/" /></html>')
        self.assertEqual(wrs.wpjson_url_from_evidence(html),
                         "https://site.example/wp-json/")
        self.assertIsNone(wrs.wpjson_url_from_evidence("<html>x</html>"))

    def test_strict_wpjson_signature(self):
        info = wrs.strict_wpjson(WPJSON)
        self.assertEqual(info["n_routes"], 2)
        self.assertTrue(info["wp_v2_open"])
        # wp/v2 DIFILTER tetap index WP sah (kasus nyata: plugin
        # keamanan menyaring namespace) — wp_v2_open=False
        filtered = wrs.strict_wpjson(
            '{"routes": {"/oembed/1.0/embed": {}},'
            ' "namespaces": ["oembed/1.0", "jetpack/v4"]}')
        self.assertIsNotNone(filtered)
        self.assertFalse(filtered["wp_v2_open"])
        # bukan WP: tanpa routes
        self.assertIsNone(wrs.strict_wpjson('{"namespaces": ["wp/v2"]}'))
        # bukan WP: kunci route tidak berawalan "/"
        self.assertIsNone(wrs.strict_wpjson(
            '{"routes": {"posts": {}}, "namespaces": ["x/v1"]}'))
        self.assertIsNone(wrs.strict_wpjson("<html>soft404</html>"))

    def test_verify_wp_v2_difilter_tetap_l3_dengan_catatan(self):
        rows, meta = wrs.audit(URL, "<html>wp-json ada</html>")
        body = ('{"routes": {"/oembed/1.0/embed": {}, "/jetpack/v4": {}},'
                ' "namespaces": ["oembed/1.0", "jetpack/v4"]}')
        rows, meta = wrs.apply_verify(
            rows, meta, URL + "/wp-json/",
            {"status": 200, "body": body})
        lead = rows[0]
        self.assertEqual(lead["verdict"], 3)
        self.assertIn("TIDAK terdaftar", lead["description"])
        self.assertIn("wp_v2_open", lead["response"])
        self.assertFalse(meta["verify"]["wp_v2_open"])
        self.assertEqual(validate_finding(lead), [])

    def test_verify_naik_l3_kontrak_lengkap(self):
        rows, meta = wrs.audit(URL, "<html>wp-json ada</html>")
        self.assertEqual(rows[0]["verdict"], 1)
        rows, meta = wrs.apply_verify(
            rows, meta, URL + "/wp-json/",
            {"status": 200, "body": WPJSON})
        self.assertEqual(meta["verify"]["outcome"], "wp-rest-index")
        lead = rows[0]
        self.assertEqual(lead["verdict"], 3)
        self.assertTrue(lead["reportable"])
        self.assertEqual(validate_finding(lead), [])
        # zero-retention: path route tidak disimpan
        self.assertNotIn("/wp/v2/posts", lead["response"])
        self.assertIn("n_routes", lead["response"])

    def test_verify_terlindungi_tetap_l1(self):
        rows, meta = wrs.audit(URL, "<html>wp-json ada</html>")
        rows, meta = wrs.apply_verify(rows, meta, URL + "/wp-json/",
                                      {"status": 401, "body": "denied"})
        self.assertEqual(meta["verify"]["outcome"], "protected")
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("terlindungi", rows[0]["description"])

    def test_verify_bukan_wp_dan_gagal_tetap_l1(self):
        rows, meta = wrs.audit(URL, "<html>wp-json ada</html>")
        rows, meta = wrs.apply_verify(rows, meta, URL + "/wp-json/",
                                      {"status": 200,
                                       "body": "<html>spa</html>"})
        self.assertEqual(meta["verify"]["outcome"], "not-reproduced")
        self.assertEqual(rows[0]["verdict"], 1)
        rows2, meta2 = wrs.audit(URL, "<html>wp-json ada</html>")
        rows2, meta2 = wrs.apply_verify(
            rows2, meta2, URL + "/wp-json/",
            {"status": None, "body": "", "error": "URLError"})
        self.assertEqual(meta2["verify"]["outcome"], "error")
        self.assertEqual(rows2[0]["verdict"], 1)

    def test_verify_tanpa_lead_noop(self):
        rows, meta = wrs.audit(URL, "<html>bersih</html>")
        rows, meta = wrs.apply_verify(rows, meta, URL + "/wp-json/",
                                      {"status": 200, "body": WPJSON})
        self.assertEqual(meta["verify"]["outcome"], "no-lead")
        self.assertEqual(rows[0]["verdict"], 0)


class SecretScannerTest(unittest.TestCase):
    def test_masking_nilai_kredensial(self):
        rows, meta = jss.audit(URL, SECRET)
        lead = one(rows, "JS secret-like")
        self.assertEqual(lead["verdict"], 1)
        # nilai TIDAK boleh ikut ke bukti
        self.assertNotIn("AKIA1234567890abcdef1234",
                         json.dumps(lead))
        self.assertIn("<masked:", lead["response"])
        self.assertEqual(lead["n_matches"], 1)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_mask_format_panjang_tetap(self):
        s = jss.mask_sample('api_key: "ABCDEFGHIJKLMNOP"')
        self.assertIn("<masked:16-char>", s)

    def test_verify_refetch_naik_l2(self):
        rows, meta = jss.audit(URL, SECRET)
        rows, meta = jss.apply_verify(
            rows, meta, URL, {"status": 200, "body": SECRET + " x"})
        self.assertEqual(meta["verify"]["outcome"], "reproduced")
        lead = rows[0]
        self.assertEqual(lead["verdict"], 2)
        self.assertIn("capture2_n", lead["response"])
        # nilai tetap ter-mask di capture-2
        self.assertNotIn("AKIA1234567890abcdef1234",
                         json.dumps(lead))
        self.assertEqual(validate_finding(lead), [])

    def test_verify_refetch_tanpa_pola_tetap_l1(self):
        rows, meta = jss.audit(URL, SECRET)
        rows, meta = jss.apply_verify(
            rows, meta, URL, {"status": 200,
                              "body": "<html>konto berubah</html>"})
        self.assertEqual(meta["verify"]["outcome"], "not-reproduced")
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("konten berubah", rows[0]["description"])

    def test_verify_gagal_jaringan_tetap_l1(self):
        rows, meta = jss.audit(URL, SECRET)
        rows, meta = jss.apply_verify(
            rows, meta, URL,
            {"status": None, "body": "", "error": "TimeoutError"})
        self.assertEqual(meta["verify"]["outcome"], "error")
        self.assertEqual(rows[0]["verdict"], 1)

    def test_tanpa_lead_js_verify_noop(self):
        # hanya komentar HTML -> verify tidak berlaku (bukan jalur refetch)
        rows, meta = jss.audit(URL, "<!-- TODO: password lama -->")
        lead = one(rows, "HTML comment")
        self.assertIsNotNone(lead)
        rows, meta = jss.apply_verify(rows, meta, URL,
                                      {"status": 200, "body": SECRET})
        self.assertEqual(meta["verify"]["outcome"], "no-js-lead")
        self.assertEqual(lead["verdict"], 1)


if __name__ == "__main__":
    unittest.main()
