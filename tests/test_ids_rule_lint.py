"""Nol jaringan — test ids_rule_lint (linter aturan Snort/Suricata).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ids_rule_lint as il  # noqa: E402

CLEAN = r'''
# komentar header diabaikan

alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"LOCAL Reverse Shell Port 4444"; flow:established,to_server; content:"|2f 62 69 6e 2f|"; sid:9000001; rev:1; classtype:trojan-activity; priority:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Large HTTP POST Upload"; flow:to_server,established; http.method; content:"POST"; sid:9000002; rev:2;)
'''


def checks(fs):
    return {f["check"] for f in fs}


def rule(**over) -> str:
    base = ('alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"LOCAL test rule"; content:"Eternal"; sid:9000010; rev:1;)')
    return base.replace('content:"Eternal"', f'content:{over.get("content", chr(34) + "Eternal" + chr(34))}')


class TestParse(unittest.TestCase):
    """Nol jaringan — parser continuation, komentar, fail-closed."""

    def test_bersih_tanpa_temuan(self):
        fs, meta = il.lint_source(CLEAN, "local.rules")
        self.assertEqual(fs, [], msg=str(fs))
        self.assertEqual(meta["rules"], 2)

    def test_continuation_gabung(self):
        text = ('alert tcp $HOME_NET any -> $EXTERNAL_NET 80 \\\n'
                '  (msg:"LOCAL multi"; \\\n'
                '  content:"abc"; sid:9000003; rev:1;)\n')
        fs, meta = il.lint_source(text, "m.rules")
        self.assertEqual(fs, [], msg=str(fs))
        self.assertEqual(meta["rules"], 1)

    def test_kurung_tak_tutup_eof(self):
        fs, meta = il.lint_source(
            'alert tcp a any -> b 80 (msg:"LOCAL x"; sid:9000004; rev:1;', "x.rules")
        self.assertIn("rule-unparsed", checks(fs))
        self.assertEqual(meta["unparsed_rules"], 1)

    def test_kurung_tak_tutup_eof_blok(self):
        # continuation tanpa '(' sama sekali -> file-unparsed
        fs, meta = il.lint_source("alert tcp a any -> b 80 \
", "x.rules")
        self.assertIn("file-unparsed", checks(fs))
        self.assertEqual(meta["unparsed_rules"], 1)

    def test_quote_tak_tutup(self):
        fs, meta = il.lint_source(
            'alert tcp a any -> b 80 (msg:"LOCAL unclosed; sid:9000005; rev:1;)', "x.rules")
        self.assertIn("rule-unparsed", checks(fs))

    def test_header_kurang_kolom(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b (msg:"LOCAL x"; sid:9000006; rev:1;)', "x.rules")
        self.assertIn("rule-unparsed", checks(fs))

    def test_arah_salah(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 80 => (msg:"LOCAL x"; sid:9000007; rev:1;)', "x.rules")
        self.assertIn("rule-unparsed", checks(fs))


class TestChecks(unittest.TestCase):
    """Nol jaringan — cek per rule."""

    def test_sid_hilang(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 80 (msg:"LOCAL x"; rev:1;)', "x.rules")
        self.assertIn("sid-hilang", checks(fs))
        self.assertTrue(all(f["severity"] == "high" for f in fs if f["check"] == "sid-hilang"))

    def test_sid_bukan_angka(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 80 (msg:"LOCAL x"; sid:abc; rev:1;)', "x.rules")
        self.assertIn("sid-hilang", checks(fs))

    def test_sid_duplikat(self):
        text = (rule() + "\n" + rule())
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("sid-duplikat", checks(fs))

    def test_sid_reserved_info(self):
        text = rule().replace("sid:9000010", "sid:42")
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("sid-reserved", checks(fs))
        # sid >= 100 tidak di-flag
        fs2, _ = il.lint_source(rule(), "x.rules")
        self.assertNotIn("sid-reserved", checks(fs2))

    def test_header_dua_kolom_snort3(self):
        # header protokol layanan Snort 3: alert http ( ... )
        fs, meta = il.lint_source(
            'alert http ( msg:"LOCAL UA"; flow:to_server,established; '
            'http_header:field user-agent; content:"HttpBrowser"; '
            'sid:9000030; rev:1;)', "x.rules")
        # info nocase boleh ada (content campuran tanpa nocase)
        self.assertFalse([f for f in fs if f["severity"] in ("high", "medium")],
                         msg=str(fs))
        self.assertEqual(meta["rules"], 1)
        # buffer http. pada proto http sah
        fs2, _ = il.lint_source(
            'alert dns ( msg:"LOCAL DNS tunnel"; dns.query; content:"."; '
            'sid:9000031; rev:1;)', "x.rules")
        self.assertEqual(fs2, [], msg=str(fs2))

    def test_msg_hilang_dan_kosong(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 80 (content:"x"; sid:9000011; rev:1;)', "x.rules")
        self.assertIn("msg-hilang", checks(fs))
        fs2, _ = il.lint_source(
            'alert tcp a any -> b 80 (msg:""; content:"x"; sid:9000012; rev:1;)',
            "x.rules")
        self.assertIn("msg-kosong", checks(fs2))

    def test_rev_hilang(self):
        text = rule().replace(" rev:1;", "")
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("rev-hilang", checks(fs))

    def test_action_tak_kenal(self):
        text = rule().replace("alert tcp", "alarm tcp")
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("action-tak-kenal", checks(fs))

    def test_tanpa_match(self):
        text = rule().replace('content:"Eternal"; ', "")
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("tanpa-match", checks(fs))
        # ja3.hash (Suricata) dianggap konten sah
        fs2, _ = il.lint_source(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"LOCAL JA3"; ja3.hash; content:"72a589da"; sid:9000013; rev:1;)',
            "x.rules")
        self.assertNotIn("tanpa-match", checks(fs2))

    def test_buffer_proto_mismatch(self):
        # dns.* pada proto icmp -> salah
        fs, _ = il.lint_source(
            'alert icmp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"LOCAL DNSwrong"; dns.query; content:"."; sid:9000014; rev:1;)',
            "x.rules")
        self.assertIn("buffer-proto-mismatch", checks(fs))
        # dns.* pada udp sah
        fs2, _ = il.lint_source(
            'alert udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"LOCAL DNSok"; dns.query; content:"."; sid:9000015; rev:1;)',
            "x.rules")
        self.assertNotIn("buffer-proto-mismatch", checks(fs2))
        # http.* pada udp -> salah
        fs3, _ = il.lint_source(
            'alert udp a any -> b 80 (msg:"LOCAL HTTPwrong"; http.uri; '
            'content:"/x"; sid:9000016; rev:1;)', "x.rules")
        self.assertIn("buffer-proto-mismatch", checks(fs3))

    def test_priority_janggal(self):
        text = rule().replace("rev:1;", "rev:1; priority:9;")
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("priority-janggal", checks(fs))

    def test_threshold_tanpa_count(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 22 (msg:"LOCAL brf"; flow:to_server; '
            'threshold:type both, track by_src, seconds 60; sid:9000017; rev:1;)',
            "x.rules")
        self.assertIn("threshold-rusak", checks(fs))
        self.assertTrue(any(f["severity"] == "high" for f in fs
                            if f["check"] == "threshold-rusak"))

    def test_threshold_type_both_tanpa_seconds(self):
        fs, _ = il.lint_source(
            'alert tcp a any -> b 22 (msg:"LOCAL brf"; threshold:type both, '
            'track by_src, count 10; sid:9000018; rev:1;)', "x.rules")
        self.assertIn("threshold-rusak", checks(fs))
        # threshold lengkap tidak di-flag
        fs2, _ = il.lint_source(
            'alert tcp a any -> b 22 (msg:"LOCAL brf"; threshold:type both, '
            'track by_src, count 10, seconds 60; sid:9000019; rev:1;)', "x.rules")
        self.assertNotIn("threshold-rusak", checks(fs2))

    def test_any_any_terbuka_info(self):
        fs, _ = il.lint_source(
            'alert ip any any -> any any (msg:"LOCAL broad"; content:"x"; '
            'sid:9000020; rev:1;)', "x.rules")
        self.assertIn("any-any-terbuka", checks(fs))

    def test_content_tanpa_nocase(self):
        text = rule()  # "ETERNAL" = campuran besar-kecil, tanpa nocase
        fs, _ = il.lint_source(text, "x.rules")
        self.assertIn("content-tanpa-nocase", checks(fs))
        # dengan nocase tidak di-flag
        fs2, _ = il.lint_source(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"LOCAL ok"; content:"Eternal"; nocase; sid:9000021; rev:1;)',
            "x.rules")
        self.assertNotIn("content-tanpa-nocase", checks(fs2))
        # content huruf kecil semua -> tidak di-flag
        fs3, _ = il.lint_source(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"LOCAL ok"; content:"eternal"; sid:9000022; rev:1;)', "x.rules")
        self.assertNotIn("content-tanpa-nocase", checks(fs3))


class TestCLI(unittest.TestCase):
    """Nol jaringan — exit codes + direktori + JSON."""

    def _tmp(self, text: str, name: str = "local.rules") -> Path:
        import tempfile
        f = Path(tempfile.mkdtemp()) / name
        f.write_text(text, encoding="utf-8")
        return f

    def test_exit_bersih_dan_temuan(self):
        clean = self._tmp(CLEAN)
        self.assertEqual(il.main(["--source", str(clean)]), 0)
        dirty = self._tmp(
            'alert tcp a any -> b 80 (msg:"LOCAL x"; sid:9000023; rev:1;)\n')
        self.assertEqual(il.main(["--source", str(dirty)]), 1)

    def test_exit_input_error(self):
        self.assertEqual(il.main(["--source", "T:/tidak-ada.rules"]), 2)

    def test_json_out(self):
        import tempfile
        jf = Path(tempfile.mkdtemp()) / "out.json"
        dirty = self._tmp(CLEAN + '\nalert tcp a any -> b 80 (msg:"LOCAL x"; rev:1;)\n')
        self.assertEqual(il.main(["--source", str(dirty), "--json", str(jf)]), 1)
        import json
        data = json.loads(jf.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "secai.ids-rule-lint/1")
        self.assertEqual(data["summary"]["rules"], 3)
        self.assertGreater(data["summary"]["high"], 0)


if __name__ == "__main__":
    unittest.main()
