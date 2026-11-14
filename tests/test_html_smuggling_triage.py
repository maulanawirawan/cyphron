"""Test html_smuggling_triage — NOL jaringan, dokumen di-mock.

Kontrak yang dikunci:
  - pola smuggling lengkap (msSaveOrOpenBlob/createObjectURL/event-arm/
    js-anchor-download/hidden-iframe/embedded-base64) terskor high;
  - zero-FP: halaman normal (link unduh biasa, script eksternal) -> 0
    sinyal, clean;
  - fail-closed: teks tanpa markup HTML -> exit 2 via main;
  - CLI: --file wajib, --out menulis file, exit 0 sukses.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import html_smuggling_triage as hs  # noqa: E402

SMUGGLE = """<html><body>
<script>
var b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjAAAA";
document.addEventListener("mousemove", function(e){
  var blob = new Blob([atob(b64)], {type:"application/octet-stream"});
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url; a.download = "invoice.pdf.scr"; a.click();
});
</script>
<iframe style="display:none" srcdoc="<b>loading</b>"></iframe>
</body></html>
"""

# varian legacy: msSaveOrOpenBlob langsung, payload dipecah per-literal
LEGACY = """<html><body><script>
var payload = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA" +
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
var blob = new Blob([decodeURIComponent(escape(atob(payload)))],
                    {type:"application/octet-stream"});
navigator.msSaveOrOpenBlob(blob, "quarterly-report.xls");
</script></body></html>
"""

# anchor literal data: href
ANCHOR = """<html><body>
<a href="data:application/octet-stream;base64,TVqQAAMAAAAEAAAA" download="setup.exe">Installer</a>
</body></html>
"""

BENIGN = """<html><head><title>Laporan</title>
<script src="app.js"></script></head>
<body><h1>Laporan Penjualan</h1><p>Tabel di bawah.</p>
<a href="/files/laporan.pdf" download>Unduh laporan PDF</a>
<a href="https://example.com/beranda">Beranda</a>
<script>console.log("page ready");</script>
</body></html>
"""


class HtmlSmugglingTriageTest(unittest.TestCase):
    def _run(self, tmp: Path, text: str) -> dict:
        src = tmp / "in.html"
        src.write_text(text, encoding="utf-8")
        out = tmp / "o.json"
        rc = hs.main(["--file", str(src), "--out", str(out)])
        self.assertEqual(rc, 0)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_full_smuggle_high(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), SMUGGLE)
            self.assertEqual(d["severity"], "high")
            self.assertGreaterEqual(d["score"], 3)
            for sig in ("create-object-url", "event-armed",
                        "js-anchor-download", "hidden-iframe-data"):
                self.assertIn(sig, d["signals"])
            self.assertEqual(d["finding_count"], 1)
            self.assertTrue(d["read_only"])

    def test_legacy_ms_save_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), LEGACY)
            self.assertIn("ms-save-blob", d["signals"])
            self.assertIn("embedded-base64", d["signals"])
            self.assertGreaterEqual(d["score"], 2)

    def test_anchor_data_href_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), ANCHOR)
            self.assertIn("anchor-download-data", d["signals"])
            self.assertEqual(d["score"], 1)
            self.assertEqual(d["severity"], "low")

    def test_zero_fp_benign_page(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._run(Path(td), BENIGN)
            self.assertEqual(d["score"], 0)
            self.assertEqual(d["severity"], "info")
            self.assertEqual(d["signals"], [])
            self.assertEqual(d["finding_count"], 0)

    def test_fail_closed_non_html(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "plain.txt"
            src.write_text("ini teks biasa tanpa markup\n", encoding="utf-8")
            rc = hs.main(["--file", str(src)])
            self.assertEqual(rc, 2)

    def test_fail_closed_missing_file(self):
        rc = hs.main(["--file", str(Path("tidak/ada/x.html"))])
        self.assertEqual(rc, 2)

    def test_stdout_json_valid(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.html"
            src.write_text(SMUGGLE, encoding="utf-8")
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                rc = hs.main(["--file", str(src)])
            finally:
                sys.stdout = old
            self.assertEqual(rc, 0)
            d = json.loads(buf.getvalue())
            self.assertEqual(d["schema"], hs.SCHEMA)


if __name__ == "__main__":
    unittest.main(verbosity=1)
