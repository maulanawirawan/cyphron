"""Test F75b — api-docs-surface signature ketat + verify reproduced.

NOL jaringan (res verify di-mock). Yang dikunci:
  - openapi JSON / swagger JSON / swagger-ui DOM+bundle = strict;
  - teks "/openapi.json" biasa TANPA dokumen nyata = TIDAK strict;
  - DOM #swagger-ui tanpa bundle = belum strict (anti-FP);
  - verify reproduced -> L3 dgn bukti capture-1/capture-2 tersimpan;
  - verify gagal jaringan / tidak cocok / tanpa lead = tetap L1/L0
    (fail-closed);
  - kontrak validate_finding lolos di semua baris.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import api_docs_surface as ads  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://app.example"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


OPENAPI_JSON = ('{"openapi": "3.0.1", "info": {"title": "API", '
                '"version": "1.0"}, "paths": {"/v1/x": {}}}')
SWAGGER_JSON = '{"swagger": "2.0", "info": {"title": "API"}}'
SWAGGER_UI = ('<html><head><title>Swagger UI</title></head><body>'
              '<div id="swagger-ui"></div>'
              '<script src="swagger-ui-bundle.js"></script>'
              '<script>SwaggerUIBundle({url: "/openapi.json"})</script>'
              '</body></html>')


class StrictDocsTest(unittest.TestCase):
    def test_openapi_json_strict(self):
        self.assertEqual(ads.strict_docs(OPENAPI_JSON), "openapi-json")

    def test_swagger_json_strict(self):
        self.assertEqual(ads.strict_docs(SWAGGER_JSON), "swagger-json")

    def test_swagger_ui_dom_plus_bundle_strict(self):
        self.assertEqual(ads.strict_docs(SWAGGER_UI), "swagger-ui-dom")

    def test_dom_tanpa_bundle_tidak_strict(self):
        html = '<html><body><div id="swagger-ui"></div></body></html>'
        self.assertIsNone(ads.strict_docs(html))

    def test_teks_biasa_tidak_strict(self):
        html = ('<html><body><p>Lihat spec di '
                '<a href="/openapi.json">/openapi.json</a></p></body>'
                '</html>')
        self.assertIsNone(ads.strict_docs(html))
        rows, meta = ads.audit(URL, html)
        self.assertEqual(meta["matched"], True)   # tetap lead L1
        self.assertIsNone(meta["strict"])
        self.assertEqual(rows[0]["verdict"], 1)

    def test_kosong_aman(self):
        rows, meta = ads.audit(URL, "")
        self.assertEqual(one(rows, "No API docs surface")["verdict"], 0)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))


class VerifyTest(unittest.TestCase):
    def test_reproduced_naik_l3(self):
        rows, meta = ads.audit(URL, OPENAPI_JSON)
        self.assertEqual(rows[0]["verdict"], 1)
        rows, meta = ads.apply_verify(rows, meta, URL + "/openapi.json",
                                      {"status": 200, "body": OPENAPI_JSON})
        self.assertEqual(meta["verify"]["outcome"], "reproduced")
        lead = rows[0]
        self.assertEqual(lead["verdict"], 3)
        self.assertEqual(lead["finding_class"], "weakness")
        self.assertIn("GET " + URL + "/openapi.json", lead["request"])
        self.assertIn("capture-1", lead["response"])
        self.assertIn("capture-2", lead["response"])
        self.assertTrue(lead["extra"]["verify"]["reproduced"])
        self.assertEqual(validate_finding(lead), [])

    def test_tidak_cocok_tetap_l1(self):
        rows, meta = ads.audit(URL, OPENAPI_JSON)
        rows, meta = ads.apply_verify(rows, meta, URL + "/openapi.json",
                                      {"status": 404, "body": "gone"})
        self.assertEqual(meta["verify"]["outcome"], "not-reproduced")
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("TIDAK menampilkan", rows[0]["description"])

    def test_error_jaringan_tetap_l1(self):
        rows, meta = ads.audit(URL, SWAGGER_UI)
        rows, meta = ads.apply_verify(rows, meta, URL + "/swagger",
                                      {"status": None, "body": "",
                                       "error": "TimeoutError"})
        self.assertEqual(meta["verify"]["outcome"], "error")
        self.assertEqual(rows[0]["verdict"], 1)

    def test_tanpa_lead_noop(self):
        rows, meta = ads.audit(URL, "<html>halaman biasa</html>")
        rows, meta = ads.apply_verify(rows, meta, URL,
                                      {"status": 200,
                                       "body": OPENAPI_JSON})
        self.assertEqual(meta["verify"]["outcome"], "no-lead")
        self.assertEqual(rows[0]["verdict"], 0)


if __name__ == "__main__":
    unittest.main()
