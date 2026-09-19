"""U7: PDF god-tier (cover penuh, verdict ladder LEAD vs VERIFIED, tabel
CVSS, path graph vektor) + graph.to_svg (artifact SVG)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import pdfout
from cyphron.findings import Finding
from cyphron.graph import build_with_findings, to_svg
from cyphron.reporting import _build_doc
from cyphron.orchestrator import ScanOptions, ScanSummary
from cyphron.world.model import WorldModel

_REPO = Path(__file__).resolve().parents[1]


def _finding(**kw) -> Finding:
    base = dict(tool="sqli_probe", title="SQL injection (error-based)",
                severity="critical", description="marker terlihat",
                target_url="https://t.test/item", param="id",
                confidence=0.95, status="confirmed", cwe="CWE-89",
                request="GET /item?id=1'='1", response="<td>Row A</td>")
    base.update(kw)
    f = Finding(**base)
    f.attach_evidence("probe-pair", {"url": "x"})
    return f


class TestPdfGodTier(unittest.TestCase):
    def _doc(self, full_cover=True):
        f = _finding()
        return {
            "ref": "CYPHRON-TEST", "brand": "CYPHRON",
            "brand_sub": "SECURITY ASSESSMENT", "doc_title": "https://t.test",
            "title": "Laporan Uji Keamanan", "subtitle": "Target: https://t.test",
            "chip": {"text": "RISIKO KRITIKAL", "kind": "red"},
            "full_cover": full_cover,
            "meta": [("Tanggal", "18 September 2026"),
                     ("Mode", "offensive")],
            "sections": [
                {"no": "01b", "title": "VERDICT LADDER", "kind": "ladder"},
                {"no": "02b", "title": "RINGKASAN CVSS", "kind": "table",
                 "head": ["Severity", "Jumlah", "Band"],
                 "widths": [2, 1, 2], "rows": [["KRITIKAL", "1", "9.0-10.0"]]},
                {"no": "04c", "title": "PATH GRAPH", "kind": "graph",
                 "paths": [[{"kind": "TARGET", "key": "https://t.test"},
                            {"kind": "ENDPOINT", "key": "/item"},
                            {"kind": "VULNERABILITY", "key": f.id}]]},
                {"no": "04", "title": "DETAIL TEMUAN", "kind": "findings",
                 "items": [{"sev": f.severity, "title": f.title,
                            "verdict": "ADA - TERKONFIRMASI",
                            "ladder": 3, "meta": "CWE-89",
                            "desc": f.description, "req": f.request,
                            "resp": f.response, "poc": "curl ...",
                            "rec": "parameterized query"}]},
            ],
        }

    def test_render_report_full_cover_ladder_graph(self):
        data = pdfout.render_report(self._doc())
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        # cover penuh + konten -> minimal 2 halaman
        self.assertGreaterEqual(data.count(b"/Type /Page "), 2)
        self.assertIn(b"VERDICT LADDER", data)
        self.assertIn(b"PATH-1", data)
        self.assertIn(b"VULNERABILITY", data)
        self.assertIn(b"L3 DETERMINISTIC VERIFIED", data)
        self.assertIn(b"LEAD", data)

    def test_cover_menyebut_aturan_ladder(self):
        data = pdfout.render_report(self._doc(full_cover=True))
        self.assertIn(b"level >= 3", data)
        self.assertIn(b"dilabel LEAD", data)

    def test_doc_from_reporting_memiliki_semua_bagian(self):
        w = WorldModel()
        w.target = "https://t.test"
        w.observe_endpoint("https://t.test/item", ["id"], "GET").status = 200
        f = _finding()
        s = ScanSummary(target="https://t.test", mode="offensive",
                        steps_executed=10, confirmed=[f])
        opts = ScanOptions(target="https://t.test")

        class _A:
            entries = []

        doc = _build_doc(opts, s, w, _A(), [])
        nos = [sec["no"] for sec in doc["sections"]]
        self.assertIn("01b", nos, "verdict ladder section wajib ada")
        self.assertIn("02b", nos, "ringkasan CVSS wajib ada")
        self.assertIn("04c", nos, "path graph section wajib ada")
        self.assertTrue(doc.get("full_cover"))
        items = next(sec for sec in doc["sections"]
                     if sec["no"] == "04")["items"]
        self.assertEqual(items[0]["ladder"], 3,
                         "temuan confirmed berbukti = L3")
        # graph path dari TARGET ke VULNERABILITY terbentuk
        self.assertTrue(doc["sections"][0])  # struktur valid
        path_sec = next(sec for sec in doc["sections"] if sec["no"] == "04c")
        self.assertTrue(path_sec["paths"], "path graph harus ada")
        self.assertEqual(path_sec["paths"][0][0]["kind"], "TARGET")


class TestGraphSvg(unittest.TestCase):
    def test_svg_dari_graph_temuan(self):
        w = WorldModel()
        w.target = "https://t.test"
        w.observe_endpoint("https://t.test/item", ["id"], "GET").status = 200
        f = _finding()
        g = build_with_findings(w, [f])
        svg = to_svg(g)
        self.assertTrue(svg.startswith('<svg xmlns'))
        self.assertIn("VULNERABILITY", svg)
        self.assertIn("TARGET", svg)
        self.assertIn("ENDPOINT", svg)
        self.assertIn("</svg>", svg)
        # path SVG punya arah (marker polygon) dan kurva
        self.assertIn("polygon", svg)

    def test_svg_deterministik(self):
        w = WorldModel()
        w.target = "https://t.test"
        f = _finding()
        g = build_with_findings(w, [f])
        self.assertEqual(to_svg(g), to_svg(g))

    def test_svg_graph_kosong(self):
        from cyphron.graph import KnowledgeGraph
        svg = to_svg(KnowledgeGraph())
        self.assertIn("graph kosong", svg)


if __name__ == "__main__":
    unittest.main()
