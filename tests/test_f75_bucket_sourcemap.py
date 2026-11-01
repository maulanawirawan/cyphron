"""Test F75e — cloud-bucket verify reproduced + sourcemap verify L2/L3.

cloud-bucket-exposure (strategi D, atribusi = caveat):
  - listable + re-GET signature sama -> L2 REPRODUCED dgn bukti
    capture-1/capture-2; ownership_verified TETAP False; L3 tidak
    diberikan (atribusi tak terverifikasi);
  - listable tanpa verify (backward compat) -> tetap L1;
  - re-GET tidak cocok -> tetap L1 + catatan jujur;
  - tidak ada listable -> verify_listable() = {} (NOL request tambahan).

sourcemap-exposure-checker (strategi D, map = file di host target):
  - map valid "version"+"sources" ter-fetch -> L2;
  - map + sourcesContent tidak kosong -> L3 CWE-540 (source asli
    terbaca; isi TIDAK disimpan — hanya jumlah + path pertama);
  - fetch gagal / bukan map -> tetap L1 (fail-closed);
  - sinkron kontrak verdict_tag + reportable;
  - map_url dari evidence: sourceMappingURL diutamakan; urljoin
    relative -> absolut.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import cloud_bucket_exposure as cbe   # noqa: E402
import sourcemap_exposure_checker as smap  # noqa: E402
from findings import validate_finding  # noqa: E402

URL = "https://app.example"
LISTING = "<ListBucketResult><Key>a</Key></ListBucketResult>"


def one(rows, needle):
    hits = [r for r in rows if needle in r["title"]]
    return hits[0] if hits else None


class CloudBucketVerifyTest(unittest.TestCase):
    def base_result(self):
        return {"results": {
            "https://lab-com.s3.amazonaws.com/": {"status": 200,
                                                  "body": LISTING},
            "x": {"status": 404, "body": ""}}}

    def test_verify_reproduced_naik_l2(self):
        res = self.base_result()
        res["verify"] = {"url": "https://lab-com.s3.amazonaws.com/",
                         "status": 200, "signature_match": True}
        rows, meta = cbe.audit("lab.example", res)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        f = one(rows, "Publicly listable")
        self.assertEqual(f["verdict"], 2)
        self.assertIn("capture-2", f["response"])
        self.assertIn("TEREPRODUKSI", f["description"])
        # make_finding me-flatten extra ke top-level (pelajaran F45)
        self.assertFalse(f["ownership_verified"],
                         "atribusi tetap caveat — tidak pernah L3")
        self.assertTrue(meta["verify"])

    def test_verify_tidak_cocok_tetap_l1(self):
        res = self.base_result()
        res["verify"] = {"url": "https://lab-com.s3.amazonaws.com/",
                         "status": 403, "signature_match": False}
        rows, meta = cbe.audit("lab.example", res)
        f = one(rows, "Publicly listable")
        self.assertEqual(f["verdict"], 1)
        self.assertIn("TIDAK cocok", f["description"])

    def test_tanpa_verify_backward_compat_l1(self):
        rows, meta = cbe.audit("lab.example", self.base_result())
        f = one(rows, "Publicly listable")
        self.assertEqual(f["verdict"], 1)
        self.assertIn("(probe)", f["request"])

    def test_verify_listable_nol_request_tanpa_listable(self):
        res = {"results": {"https://lab-com.s3.amazonaws.com/":
                           {"status": 403, "body": ""}}}
        self.assertEqual(cbe.verify_listable(res), {})

    def test_meta_requests_menghitung_verify(self):
        res = self.base_result()
        res["verify"] = {"url": "u", "status": 200,
                         "signature_match": True}
        _rows, meta = cbe.audit("lab.example", res)
        self.assertEqual(meta["requests"], 3)  # 2 probe + 1 verify


class SourcemapVerifyTest(unittest.TestCase):
    def test_strict_map_parser(self):
        body = ('{"version": 3, "sources": ["webpack:///src/a.ts"],'
                ' "sourcesContent": ["const x = 1;"], "names": []}')
        info = smap.strict_map(body)
        self.assertEqual(info["n_sources"], 1)
        self.assertEqual(info["n_sources_content"], 1)
        self.assertIn("a.ts", info["first_source"])
        self.assertIsNone(smap.strict_map("<html>bukan map</html>"))
        self.assertIsNone(smap.strict_map('{"version": 3}'))  # tanpa sources

    def test_map_url_dari_evidence(self):
        html = '//# sourceMappingURL=app.min.js.map"'
        self.assertEqual(smap.map_url_from_evidence(html),
                         "app.min.js.map")
        html2 = '<script src="/static/bundle.js.map"></script>'
        self.assertEqual(smap.map_url_from_evidence(html2),
                         "/static/bundle.js.map")
        self.assertIsNone(smap.map_url_from_evidence("<html>bersih</html>"))

    def test_verify_sources_content_naik_l3(self):
        rows, meta = smap.audit(URL, '//# sourceMappingURL=app.min.js.map"')
        self.assertEqual(rows[0]["verdict"], 1)
        body = ('{"version": 3, "sources": ["webpack:///src/a.ts",'
                ' "webpack:///src/b.ts"], "sourcesContent":'
                ' ["const x=1;", "const y=2;"]}')
        rows, meta = smap.apply_verify(
            rows, meta, URL + "/app.min.js.map",
            {"status": 200, "body": body})
        self.assertEqual(meta["verify"]["outcome"], "sources-content")
        lead = rows[0]
        self.assertEqual(lead["verdict"], 3)
        self.assertEqual(lead["cwe"], "CWE-540")
        self.assertTrue(lead["reportable"])
        self.assertIn("2/2", lead["description"])
        # zero-retention: isi source tidak disimpan di bukti
        self.assertNotIn("const x=1;", lead["response"])
        self.assertIn("n_sources_content", lead["response"])
        self.assertEqual(validate_finding(lead), [])

    def test_verify_map_tanpa_sources_content_l2(self):
        rows, meta = smap.audit(URL, '//# sourceMappingURL=app.min.js.map"')
        body = '{"version": 3, "sources": ["a.ts"], "names": []}'
        rows, meta = smap.apply_verify(
            rows, meta, URL + "/app.min.js.map",
            {"status": 200, "body": body})
        lead = rows[0]
        self.assertEqual(lead["verdict"], 2)
        self.assertFalse(lead.get("reportable", False))
        self.assertEqual(validate_finding(lead), [])

    def test_verify_gagal_tetap_l1(self):
        rows, meta = smap.audit(URL, '//# sourceMappingURL=app.min.js.map"')
        rows, meta = smap.apply_verify(
            rows, meta, URL + "/app.min.js.map",
            {"status": 404, "body": "gone"})
        self.assertEqual(meta["verify"]["outcome"], "not-a-map")
        self.assertEqual(rows[0]["verdict"], 1)
        rows2, meta2 = smap.apply_verify(
            *smap.audit(URL, '//# sourceMappingURL=a.map"'),
            URL + "/a.map",
            {"status": None, "body": "", "error": "TimeoutError"})
        self.assertEqual(meta2["verify"]["outcome"], "error")
        self.assertEqual(rows2[0]["verdict"], 1)

    def test_verify_tanpa_lead_noop(self):
        rows, meta = smap.audit(URL, "<html>bersih</html>")
        rows, meta = smap.apply_verify(rows, meta, URL + "/a.map",
                                       {"status": 200, "body": "{}"})
        self.assertEqual(meta["verify"]["outcome"], "no-lead")
        self.assertEqual(rows[0]["verdict"], 0)


if __name__ == "__main__":
    unittest.main()
