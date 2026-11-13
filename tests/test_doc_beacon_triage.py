"""Test doc_beacon_triage — NOL jaringan, dokumen di-mock in-memory.

Kontrak yang dikunci:
  - OOXML external rel callback dinilai kualitasnya (ip/punycode/
    shortener/lure/protocol-handler), bukan sekadar keberadaan;
  - RTF \\objdata + token protokol = critical (kelas Follina);
  - dokumen web normal (1 rel https brand) = clean, zero-FP;
  - fail-closed: bukan OOXML/RTF -> error (exit 2 via main).
"""
from __future__ import annotations

import io
import json
import zipfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import doc_beacon_triage as db  # noqa: E402


def _docx(rels_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/_rels/document.xml.rels", rels_xml)
    return buf.getvalue()


NORMAL_RELS = """<?xml version="1.0"?>
<Relationships>
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://contoh.co.id/artikel" TargetMode="External"/>
</Relationships>
"""

BEACON_RELS = """<?xml version="1.0"?>
<Relationships>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://203.0.113.66/c2/login?token=1" TargetMode="External"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://bit.ly/x1" TargetMode="External"/>
</Relationships>
"""

FOLLINA_RELS = """<?xml version="1.0"?>
<Relationships>
<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="ms-msdt:FollinaPayload" TargetMode="External"/>
</Relationships>
"""

RTF_CLEAN = (b"{\\rtf1\\ansi hello document tanpa object}")
RTF_FOLLINA = (b"{\\rtf1\\ansi {\\object\\objclass Word.Document.12}"
               b"{\\objdata ms-msdt:PCWPLOGBEACON}}")


def _write(tmp: Path, data: bytes, name: str) -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


class OoxmlTest(unittest.TestCase):
    def test_normal_https_rel_is_clean(self):
        res = db.triage_file(_write(Path("/tmp"), _docx(NORMAL_RELS), "n.docx"))
        self.assertEqual(res["doc_type"], "ooxml")
        self.assertEqual(res["external_urls"], 1)
        self.assertTrue(res["clean"])
        self.assertEqual(res["finding_count"], 0)

    def test_ip_and_lure_and_shortener_flagged(self):
        res = db.triage_file(_write(Path("/tmp"), _docx(BEACON_RELS), "b.docx"))
        self.assertEqual(res["finding_count"], 3)  # 2 beacon-url + density
        kinds = [f["type"] for f in res["findings"]]
        self.assertIn("beacon-url", kinds)
        self.assertIn("beacon-density", kinds)
        top = [f for f in res["findings"] if "203.0.113.66" in f["detail"]][0]
        self.assertEqual(top["severity"], "high")
        self.assertIn("ip-literal", top["evidence"])
        self.assertIn("lure-path", top["evidence"])

    def test_protocol_handler_is_critical(self):
        res = db.triage_file(_write(Path("/tmp"), _docx(FOLLINA_RELS), "f.docx"))
        self.assertEqual(res["findings"][0]["severity"], "critical")
        self.assertIn("protocol-handler", res["signal_histogram"])


class RtfTest(unittest.TestCase):
    def test_rtf_clean_is_clean(self):
        res = db.triage_file(_write(Path("/tmp"), RTF_CLEAN, "c.rtf"))
        self.assertEqual(res["doc_type"], "rtf")
        self.assertTrue(res["clean"])

    def test_rtf_follina_is_critical(self):
        res = db.triage_file(_write(Path("/tmp"), RTF_FOLLINA, "f.rtf"))
        self.assertEqual(res["finding_count"], 1)
        self.assertEqual(res["findings"][0]["severity"], "critical")
        self.assertEqual(res["findings"][0]["type"], "rtf-objdata-protocol")


class FailClosedTest(unittest.TestCase):
    def test_not_a_document_raises(self):
        with self.assertRaises(ValueError):
            db.triage_file(_write(Path("/tmp"), b"<html>hello</html>", "x.docx"))

    def test_main_exit_2_on_unknown_format(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), b"plain text", "x.docx")
            rc = db.main(["--file", str(p)])
            self.assertEqual(rc, 2)

    def test_main_exit_2_on_missing_file(self):
        rc = db.main(["--file", str(ROOT / ".tmp" / "nope.docx")])
        self.assertEqual(rc, 2)

    def test_main_writes_single_json_line(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), RTF_CLEAN, "c.rtf")
            out = Path(td) / "o.json"
            rc = db.main(["--file", str(p), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "secai.doc-beacon-triage/1")
            self.assertTrue(doc["read_only"])


if __name__ == "__main__":
    unittest.main()
