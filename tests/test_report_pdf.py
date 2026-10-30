"""Test suite F3 — generator laporan PDF via Typst.

Meliputi: metrik presisi per tool, retest delta (by id deterministik),
pemetaan compliance, render PDF end-to-end dari fixture findings.json,
ketahanan terhadap karakter spesial (injection-safe via data.json),
dan determinisme render.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import report_pdf as rp  # noqa: E402

# render end-to-end butuh typst (env CYPHRON_TYPST / vendored / PATH)
TYPST_OK = bool(os.environ.get("CYPHRON_TYPST")
                or (ROOT / "tools/bin/typst-x86_64-pc-windows-msvc/typst.exe"
                    ).exists()
                or shutil.which("typst"))


class PrecisionTest(unittest.TestCase):
    def test_counts_per_tool(self):
        rows = [
            {"tool": "a", "verdict": 3},
            {"tool": "a", "verdict": 1},
            {"tool": "a", "verdict": -1},
            {"tool": "b", "verdict": 0},
        ]
        out = rp.precision_per_tool(rows)
        m = {t["tool"]: t for t in out}
        self.assertEqual(m["a"]["total"], 3)
        self.assertEqual(m["a"]["reportable"], 1)
        self.assertEqual(m["a"]["leads"], 1)
        self.assertEqual(m["a"]["rejected"], 1)
        # ratio dihitung dari total - rejected
        self.assertEqual(m["a"]["ratio"], "50%")
        self.assertEqual(m["b"]["leads"], 1)
        self.assertEqual(m["b"]["reportable"], 0)


class DeltaTest(unittest.TestCase):
    def _mk(self, ids_titles):
        return {i: {"id": i, "title": t} for i, t in ids_titles.items()}

    def test_fixed_new_persist(self):
        old = self._mk({"1": "lama ada", "2": "diperbaiki"})
        new = self._mk({"1": "lama ada", "3": "baru muncul"})
        d = rp.retest_delta(old, new)
        self.assertEqual(d["persist"], 1)
        self.assertEqual(d["fixed"], 1)
        self.assertEqual(d["new"], 1)
        self.assertEqual(d["fixed_items"], ["diperbaiki"])
        self.assertEqual(d["new_items"], ["baru muncul"])

    def test_empty(self):
        d = rp.retest_delta({}, {})
        self.assertEqual((d["persist"], d["fixed"], d["new"]), (0, 0, 0))


class BuildDataTest(unittest.TestCase):
    def test_from_fixture(self):
        doc = rp.load_doc(ROOT / "tests/fixtures/report-fixture.json")
        data = rp.build_data([doc], None, "Judul Uji", "Sub")
        # 17 = 16 baris lama + 1 baris L3 reportable (F42: bucket TERBUKTI)
        self.assertEqual(data["total_findings"], 17)
        self.assertEqual(data["reportable_count"], 1)
        self.assertEqual(data["by_severity"], [0, 1, 0, 6, 10])
        # kategori (dari baris confirmed): AMAN, MISC, SURFACE ada
        names = {c["name"] for c in data["categories"]}
        self.assertTrue({"AMAN", "MISC", "SURFACE"} <= names)
        # baris unconfirmed keluar dari kategori -> section tersendiri
        self.assertEqual(len(data["unconfirmed"]), 2)
        self.assertTrue(all(u["title"] not in
                            {f["title"] for c in data["categories"]
                             for f in c["findings"]}
                            for u in data["unconfirmed"]))
        tools = {t["tool"] for t in data["precision"]}
        self.assertEqual(tools, {"banner-posture", "ct-inventory",
                                 "email-sender-surface", "idor-orders"})
        self.assertIsNone(data["delta"])

    def test_doc_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text(json.dumps({"ok": True, "findings": [
                {"tool": "t"}]}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                rp.load_doc(bad)


class DensityTest(unittest.TestCase):
    """F18 — metrik kepadatan run (temuan/detik/request)."""

    def test_density_computed(self):
        rows = [{"verdict": 3}, {"verdict": 1}, {"verdict": 0}]
        d = rp.density_metrics(rows, requests=6, elapsed_s=2.0)
        self.assertEqual(d["total_findings"], 3)
        self.assertEqual(d["findings_per_request"], 0.5)
        self.assertEqual(d["findings_per_second"], 1.5)
        self.assertEqual(d["reportable_per_request"], 0.167)
        self.assertEqual(d["elapsed_s_display"], "2.0")
        self.assertEqual(d["fpr_display"], "0.50")

    def test_density_none_when_zero_cost(self):
        d = rp.density_metrics([], requests=0, elapsed_s=0.0)
        self.assertIsNone(d["findings_per_request"])
        self.assertIsNone(d["findings_per_second"])
        self.assertEqual(d["fpr_display"], "—")
        self.assertEqual(d["fps_display"], "—")
        self.assertEqual(d["rpr_display"], "—")

    def test_precision_includes_tool_requests(self):
        rows = [{"tool": "t", "verdict": 1}, {"tool": "t", "verdict": 3}]
        out = rp.precision_per_tool(rows, {"t": 2})
        self.assertEqual(out[0]["requests"], 2)
        self.assertEqual(out[0]["findings_per_request"], "1.00")
        # tanpa data request -> em-dash, tidak crash
        out2 = rp.precision_per_tool(rows, {})
        self.assertEqual(out2[0]["requests"], "—")

    def test_build_data_carries_density_from_sources(self):
        doc = {"ok": True,
               "data": {"run": "x", "elapsed_s": 1.5,
                        "sources": [{"skill": "banner-posture",
                                     "requests": 3}]},
               "requests": 3,
               "findings": [{"tool": "banner-posture", "title": "t",
                             "severity": "low", "verdict": 1,
                             "verdict_tag": "L1 SUSPECTED - LEAD",
                             "id": "x"}]}
        data = rp.build_data([doc], None, "Judul", "Sub")
        self.assertEqual(data["density"]["requests"], 3)
        self.assertEqual(data["density"]["elapsed_s"], 1.5)
        self.assertAlmostEqual(data["density"]["findings_per_request"], 0.33)
        prec = {t["tool"]: t for t in data["precision"]}
        self.assertEqual(prec["banner-posture"]["requests"], 3)

    def test_exec_summary_mentions_family_quorum(self):
        doc = {"ok": True, "data": {"run": "x"}, "requests": 0,
               "findings": [{"tool": "t", "title": "hsts absent",
                             "severity": "low", "verdict": 1,
                             "verdict_tag": "L1 SUSPECTED - LEAD",
                             "id": "fq", "family_quorum": 3}]}
        data = rp.build_data([doc], None, "Judul", "Sub")
        self.assertIn("FAO family quorum", data["executive_summary"])
        self.assertIn("1 temuan terkonfirmasi lintas 3 tool",
                      data["executive_summary"])
        # tanpa family quorum -> kalimat tidak muncul
        doc2 = {"ok": True, "data": {"run": "x"}, "requests": 0,
                "findings": [{"tool": "t", "title": "x", "severity": "low",
                              "verdict": 0, "verdict_tag": "L0 OBSERVED - LEAD",
                              "id": "y"}]}
        data2 = rp.build_data([doc2], None, "Judul", "Sub")
        self.assertNotIn("family quorum", data2["executive_summary"])


class PlainLanguageTest(unittest.TestCase):
    """F42 — lapisan bahasa awam: bucket DIPETAKAN deterministik dari
    ladder/status (tanpa penilaian di luar bukti). Pembaca awam langsung
    tahu mana yang valid, mana yang masih petunjuk, mana yang gagal dinilai."""

    def test_mapping_by_verdict_and_status(self):
        self.assertEqual(rp.plain_status({"verdict": 4, "status": "confirmed"}), "proven")
        self.assertEqual(rp.plain_status({"verdict": 3, "status": "confirmed"}), "proven")
        self.assertEqual(rp.plain_status({"verdict": 2, "status": "confirmed"}), "check")
        self.assertEqual(rp.plain_status({"verdict": 1, "status": "confirmed"}), "check")
        self.assertEqual(rp.plain_status({"verdict": 0, "status": "confirmed"}), "clean")
        self.assertEqual(rp.plain_status({"verdict": 0, "status": "unconfirmed"}), "unassessed")
        self.assertEqual(rp.plain_status({"verdict": -1, "status": "false-positive"}), "filtered")
        # L-x menang di atas status apa pun
        self.assertEqual(rp.plain_status({"verdict": -1, "status": "confirmed"}), "filtered")

    def test_build_data_counts_sum_and_fields(self):
        doc = {"ok": True, "data": {"run": "x"}, "requests": 0, "findings": [
            {"tool": "t", "title": "a", "severity": "high", "verdict": 4,
             "verdict_tag": "L4", "id": "1", "status": "confirmed"},
            {"tool": "t", "title": "b", "severity": "low", "verdict": 1,
             "verdict_tag": "L1", "id": "2", "status": "confirmed"},
            {"tool": "t", "title": "c", "severity": "info", "verdict": 0,
             "verdict_tag": "L0", "id": "3", "status": "confirmed"},
            {"tool": "t", "title": "d", "severity": "info", "verdict": 0,
             "verdict_tag": "L0", "id": "4", "status": "unconfirmed"},
        ]}
        data = rp.build_data([doc], None, "J", "S")
        pc = data["plain_counts"]
        self.assertEqual(sum(pc.values()), 4)
        self.assertEqual((pc["proven"], pc["check"], pc["clean"],
                          pc["unassessed"]), (1, 1, 1, 1))
        self.assertIn("1 TERBUKTI", data["bottom_line"])
        self.assertIn("Hanya status TERBUKTI", data["bottom_line"])
        # panduan membawa angka + makna; urutan stabil
        self.assertEqual([g["key"] for g in data["plain_guide"]],
                         ["proven", "check", "clean", "unassessed", "filtered"])
        self.assertTrue(all("meaning" in g and "label" in g
                            for g in data["plain_guide"]))
        # tiap temuan kategori membawa label + kalimat artinya
        f0 = data["categories"][0]["findings"][0]
        self.assertEqual(f0["plain_label"], "TERBUKTI")
        self.assertIn("bisa diulang", f0["plain_why"])

    def test_bottom_line_omits_zero_buckets(self):
        counts = {"proven": 0, "check": 2, "clean": 3, "unassessed": 0,
                  "filtered": 0}
        s = rp.plain_bottom_line(counts)
        self.assertNotIn("TIDAK BISA DINILAI", s)
        self.assertNotIn("TERSARING", s)
        self.assertIn("2 masih PERLU DICEK", s)


@unittest.skipUnless(
    TYPST_OK, "typst tidak tersedia (CYPHRON_TYPST / tools/bin / PATH)")
class RenderTest(unittest.TestCase):
    """Render end-to-end via typst — butuh fixture findings.json."""

    def _render(self, docs, compare=None, title="Judul Uji #1 $x [y]"):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.pdf"
            args = ["--findings", str(docs[0]), "--out", str(out),
                    "--title", title]
            if compare:
                args += ["--compare", str(compare)]
            # panggil main() via subprocess-free path: pakai sys.argv trick
            old_argv = sys.argv
            sys.argv = ["report_pdf.py"] + args
            try:
                rc = rp.main()
            finally:
                sys.argv = old_argv
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            self.assertTrue(out.read_bytes()[:5] == b"%PDF-")
            return out.read_bytes()

    def test_render_fixture(self):
        f = ROOT / "tests/fixtures/report-fixture.json"
        pdf = self._render([f])
        self.assertGreater(len(pdf), 10_000)

    def test_render_plain_language_layer(self):
        """F42: kotak 'Cara membaca' + status awam + kalimat artinya
        benar-benar muncul di PDF."""
        import fitz
        f = ROOT / "tests/fixtures/report-fixture.json"
        pdf = self._render([f], title="Lapisan Awam Uji")
        d = fitz.open(stream=pdf, filetype="pdf")
        txt = chr(10).join(d[i].get_text() for i in range(d.page_count))
        d.close()
        self.assertIn("Cara membaca laporan ini", txt)
        for label in ("TERBUKTI", "PERLU DICEK", "BERSIH",
                      "TIDAK BISA DINILAI", "TERSARING"):
            self.assertIn(label, txt)
        self.assertIn("Baris bawah:", txt)
        self.assertIn("Artinya:", txt)

    def test_render_includes_density_section(self):
        import fitz
        f = ROOT / "tests/fixtures/report-fixture.json"
        pdf = self._render([f], title="Kepadatan Uji")
        d = fitz.open(stream=pdf, filetype="pdf")
        txt = "\n".join(d[i].get_text() for i in range(d.page_count))
        d.close()
        self.assertIn("Metrik Kepadatan Run", txt)
        self.assertIn("Temuan / request", txt)
        self.assertIn("Temuan / detik", txt)

    def test_render_with_nasty_strings(self):
        # karakter markup typst di judul/deskripsi tidak boleh merusak render
        nasty = "#*$[]<>\\~\"'"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.json"
            p.write_text(json.dumps({"ok": True, "data": {"run": "x"},
                                     "requests": 0, "findings": [
                {"tool": "t", "title": f"A #B {nasty}", "severity": "low",
                 "description": f"desc {nasty}", "verdict": 1,
                 "verdict_tag": "L1 SUSPECTED - LEAD", "id": "abcd1234",
                 "reportable": False, "target_url": "http://x/",
                 "evidence_kind": "dns", "finding_class": "posture",
                 "confidence": 1.0, "status": "confirmed",
                 "category": "MISC", "safety_class": "read-only",
                 "family_quorum": 3,
                 "family_sources": ["a", "b", "c"]},
            ]}), encoding="utf-8")
            self._render([p], title=f"Uji {nasty}")

    def test_render_family_quorum_badge(self):
        import fitz
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "fq.json"
            p.write_text(json.dumps({"ok": True, "data": {"run": "x"},
                                     "requests": 0, "findings": [
                {"tool": "t", "title": "HSTS absent", "severity": "low",
                 "description": "d", "verdict": 1,
                 "verdict_tag": "L1 SUSPECTED - LEAD", "id": "fq0001",
                 "reportable": False, "target_url": "http://x/",
                 "evidence_kind": "header", "finding_class": "posture",
                 "confidence": 1.0, "status": "confirmed",
                 "category": "MISC", "safety_class": "read-only",
                 "family_quorum": 3,
                 "family_sources": ["banner-posture",
                                    "csp-analyzer",
                                    "http-security-headers"]},
            ]}), encoding="utf-8")
            pdf = self._render([p], title="Family Quorum Uji")
            d = fitz.open(stream=pdf, filetype="pdf")
            txt = "\n".join(d[i].get_text() for i in range(d.page_count))
            d.close()
            self.assertIn("FQ ×3", txt)
            self.assertIn("Family quorum: ×3", txt)
            self.assertIn("banner-posture", txt)

    def test_threat_model_render(self):
        """F74: --threat-model opsional — konteks pemilik muncul di PDF;
        tanpa flag → tidak ada blok (dan file hilang = peringatan, bukan
        error)."""
        import fitz
        with tempfile.TemporaryDirectory() as td:
            tmf = Path(td) / "threat_model.md"
            tmf.write_text(
                "# Threat model: Lab Uji\n\n"
                "## Where untrusted input enters\nHTTP API.\n\n"
                "## How you rate severity\nDoS medium.\n",
                encoding="utf-8")
            f = ROOT / "tests/fixtures/report-fixture.json"

            old_argv = sys.argv
            try:
                out = Path(td) / "r.pdf"
                sys.argv = ["report_pdf.py", "--findings", str(f),
                            "--out", str(out), "--title", "TM Uji",
                            "--threat-model", str(tmf)]
                self.assertEqual(rp.main(), 0)
                doc = fitz.open(str(out))
                full = " ".join("".join(pg.get_text() for pg in doc).split())
                doc.close()
                # teks PDF dibungkus typst — bandingkan setelah normalisasi
                self.assertIn("Threat model program", full)
                self.assertIn("Threat model: Lab Uji", full)
                self.assertIn("How you rate severity", full)
                self.assertIn("tidak mengubah klasifikasi", full)

                # tanpa flag → blok tidak dirender
                out2 = Path(td) / "r2.pdf"
                sys.argv = ["report_pdf.py", "--findings", str(f),
                            "--out", str(out2), "--title", "TM Tanpa"]
                self.assertEqual(rp.main(), 0)
                doc2 = fitz.open(str(out2))
                full2 = " ".join("".join(pg.get_text() for pg in doc2).split())
                doc2.close()
                self.assertNotIn("Threat model program", full2)
            finally:
                sys.argv = old_argv

    def test_delta_render(self):
        with tempfile.TemporaryDirectory() as td:
            def mkdoc(name, ids):
                p = Path(td) / name
                p.write_text(json.dumps({"ok": True, "data": {"run": name},
                                         "requests": 0, "findings": [
                    {"tool": "t", "title": t, "severity": "info",
                     "description": "d", "verdict": 0,
                     "verdict_tag": "L0 OBSERVED - LEAD", "id": i,
                     "reportable": False, "target_url": "http://x/",
                     "evidence_kind": "dns", "finding_class": "posture",
                     "confidence": 1.0, "status": "confirmed",
                     "category": "MISC", "safety_class": "read-only"}
                    for i, t in ids]}), encoding="utf-8")
                return p
            old = mkdoc("old.json", [("a", "lama1"), ("b", "lama2")])
            new = mkdoc("new.json", [("a", "lama1"), ("c", "baru3")])
            pdf = self._render([new], compare=old, title="Delta Uji")
            import fitz
            d = fitz.open(stream=pdf, filetype="pdf")
            txt = "\n".join(d[i].get_text() for i in range(d.page_count))
            d.close()
            self.assertIn("Retest Delta", txt)
            self.assertIn("Terbukti diperbaiki", txt)
            self.assertIn("Baru muncul", txt)

    def test_determinism_same_page_count_and_hash(self):
        f = ROOT / "tests/fixtures/report-fixture.json"
        pdf1 = self._render([f])
        pdf2 = self._render([f])
        import fitz
        d1, d2 = fitz.open(stream=pdf1, filetype="pdf"), fitz.open(stream=pdf2, filetype="pdf")
        n1, n2 = d1.page_count, d2.page_count
        d1.close(); d2.close()
        self.assertEqual(n1, n2)


@unittest.skipUnless(
    TYPST_OK, "typst tidak tersedia (CYPHRON_TYPST / tools/bin / PATH)")
class ExposureRenderTest(RenderTest):
    """F54 — temuan bundle-exposure ter-render jadi PDF client dgn
    lapisan bahasa awam (alur docs/EXPOSURE-AUDIT.md)."""

    def test_render_exposure_findings(self):
        import fitz
        f = ROOT / "scratch" / "exposure-client-demo.json"
        if not f.exists():
            self.skipTest("fixture exposure demo tidak ada")
        pdf = self._render([f], title="Exposure Uji Render")
        d = fitz.open(stream=pdf, filetype="pdf")
        txt = chr(10).join(d[i].get_text() for i in range(d.page_count))
        d.close()
        self.assertIn("Baris bawah", txt)
        self.assertIn("Cara membaca laporan ini", txt)
        self.assertIn("bundle-exposure", txt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
