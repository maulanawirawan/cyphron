"""Nol jaringan — test scope_gate (gerbang cek scope aset sebelum request).

Fixture kebijakan inline (ditulis ke tempfile saat test) — tidak ada
request, tidak ada socket, tidak ada file eksternal repo.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_tools = str(ROOT / "tools")
if sys_tools not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_tools)

import scope_gate as sg  # noqa: E402

# Kebijakan demo lengkap: eksak + wildcard + CIDR + port + path + OOS.
POLICY = {
    "program": "demo-target",
    "in_scope": [
        "target.com",
        {"asset": "*.target.com", "type": "wildcard"},
        {"asset": "10.0.0.0/24", "type": "cidr"},
        {"asset": "2001:db8:aa::/48", "type": "cidr"},
        {"asset": "api.target.com:8443", "type": "url"},
        {"asset": "target.com/api/", "type": "url"},
    ],
    "out_of_scope": [
        {"asset": "staging.target.com", "type": "domain"},
        {"asset": "blog.target.com", "type": "domain"},
        {"asset": "*.internal.target.com", "type": "wildcard"},
        {"asset": "10.0.0.200", "type": "ip"},
    ],
}


def write_policy(tmp: tempfile.TemporaryDirectory, data, name="policy.json"):
    p = Path(tmp.name) / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def run_main(argv):
    """Jalankan main() dgn stdout tertangkap; kembalikan (exit, output)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sg.main(argv)
    return code, buf.getvalue()


class ParseAssetTest(unittest.TestCase):
    """Parser kanonik aset — fondasi semua keputusan."""

    def test_domain_dan_url(self):
        r = sg._parse_asset("DEV.Target.COM")
        self.assertEqual(r["kind"], "domain")
        self.assertEqual(r["host"], "dev.target.com")
        r = sg._parse_asset("https://api.target.com:8443/v2/users")
        self.assertEqual((r["host"], r["port"], r["path"], r["scheme"]),
                         ("api.target.com", 8443, "/v2/users", "https"))

    def test_trailing_fqdn_dot(self):
        self.assertEqual(sg._parse_asset("target.com.")["host"],
                         "target.com")
        self.assertEqual(
            sg._parse_asset("https://target.com./x")["host"], "target.com")

    def test_ip_v4_v6_dan_url_berip(self):
        self.assertEqual(sg._parse_asset("10.0.0.5")["kind"], "ip")
        self.assertEqual(sg._parse_asset("2001:db8::1")["kind"], "ip")
        r = sg._parse_asset("https://[2001:db8::1]:8080/x")
        self.assertEqual(r["kind"], "ip")
        self.assertEqual(str(r["ip"]), "2001:db8::1")
        self.assertEqual(r["port"], 8080)

    def test_invalid_forms_fail_closed(self):
        invalid = [
            "", "   ", None, 123,
            "https://target.com\\@evil.com/",  # backslash trick
            "ftp://target.com/",               # skema non-http(s)
            "javascript:alert(1)",
            "10.0.0.999",                      # hampir-IP
            "134744072",                       # IP desimal ambigu
            "0x7f.0.0.1",                      # IP heks
            "10.0.0.0/24",                     # CIDR bukan aset konkret
            "*.target.com",                    # wildcard bukan aset konkret
            "tar get.com",                     # spasi
            "targét.com",                      # unicode homoglyph
            "tar..get.com",                    # label kosong
            ".target.com",                     # leading dot
            "target.com:99999",                # port liar
            "target.com:0",                    # port 0
            "https://target.com:0/",           # port 0 via URL
            "target..com/x",
        ]
        for asset in invalid:
            with self.subTest(asset=asset):
                self.assertIsNone(sg._parse_asset(asset), asset)


class MatchingTest(unittest.TestCase):
    """Semantik pencocokan: anchored wildcard, deny-first, CIDR, port, path."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.policy = sg.parse_policy_file(write_policy(cls.tmp, POLICY))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def verdict(self, asset):
        return sg.evaluate(self.policy, asset)

    def test_wildcard_anchored_subdomain_saja(self):
        self.assertEqual(self.verdict("dev.target.com")["verdict"],
                         "IN_SCOPE")
        self.assertEqual(
            self.verdict("dev.target.com")["matched_rule"], "*.target.com")
        self.assertEqual(self.verdict("a.b.dev.target.com")["verdict"],
                         "IN_SCOPE")

    def test_wildcard_bukan_apex_bukan_lookalike(self):
        # Ini kasus wajib handoff: "*.target.com" vs "dev.target.com" in;
        # apex dan "evil-target.com" TIDAK.
        self.assertNotEqual(self.verdict("target.com")["matched_rule"],
                            "*.target.com")
        self.assertEqual(self.verdict("evil-target.com")["verdict"],
                         "NOT_IN_SCOPE")
        self.assertEqual(self.verdict("eviltarget.com")["verdict"],
                         "NOT_IN_SCOPE")
        self.assertEqual(self.verdict("target.com.evil.io")["verdict"],
                         "NOT_IN_SCOPE")

    def test_exact_host_saja(self):
        r = self.verdict("target.com")
        self.assertEqual((r["verdict"], r["matched_rule"]),
                         ("IN_SCOPE", "target.com"))
        # subdomain dicover wildcard, bukan rule eksak
        self.assertEqual(self.verdict("sub.target.com")["matched_rule"],
                         "*.target.com")

    def test_deny_first_out_of_scope_menang(self):
        r = self.verdict("staging.target.com")
        self.assertEqual((r["verdict"], r["severity"]),
                         ("OUT_OF_SCOPE", "high"))
        self.assertEqual(r["matched_rule"], "staging.target.com")
        self.assertEqual(r["finding"]["kind"], "out_of_scope")

    def test_oos_eksak_menutup_subdomain(self):
        # melarang itu melarang cabangnya: cdn.blog ikut terblokir walau
        # wildcard *.target.com menyala
        r = self.verdict("cdn.blog.target.com")
        self.assertEqual(r["verdict"], "OUT_OF_SCOPE")
        self.assertEqual(r["matched_rule"], "blog.target.com")

    def test_oos_wildcard_terjangkar(self):
        self.assertEqual(self.verdict("x.internal.target.com")["verdict"],
                         "OUT_OF_SCOPE")
        # apex tidak tertutup wildcard OOS -> kembali ke wildcard in-scope
        r = self.verdict("internal.target.com")
        self.assertEqual((r["verdict"], r["matched_rule"]),
                         ("IN_SCOPE", "*.target.com"))

    def test_cidr_v4_membership_dan_carveout(self):
        self.assertEqual((self.verdict("10.0.0.77")["verdict"],
                          self.verdict("10.0.0.77")["matched_rule"]),
                         ("IN_SCOPE", "10.0.0.0/24"))
        r = self.verdict("10.0.0.200")
        self.assertEqual((r["verdict"], r["matched_rule"]),
                         ("OUT_OF_SCOPE", "10.0.0.200"))
        self.assertEqual(self.verdict("10.0.1.5")["verdict"], "NOT_IN_SCOPE")
        self.assertEqual(self.verdict("10.0.1.5")["severity"], "medium")

    def test_cidr_v6(self):
        r = self.verdict("2001:db8:aa::77")
        self.assertEqual(r["verdict"], "IN_SCOPE")
        self.assertEqual(r["matched_rule"], "2001:db8:aa::/48")
        self.assertEqual(self.verdict("2001:db8:bb::1")["verdict"],
                         "NOT_IN_SCOPE")

    def test_port_narrowing(self):
        self.assertEqual(
            self.verdict("https://api.target.com:8443/v2/users")["verdict"],
            "IN_SCOPE")
        # port efektif https default 443 != 8443 -> rule port tidak kena;
        # wildcard tanpa batas port tetap mencover
        r = self.verdict("https://api.target.com/v2/users")
        self.assertEqual(r["matched_rule"], "*.target.com")

    def test_port_narrowing_terisolasi(self):
        # kebijakan yang HANYA mengizinkan port 8443: aset port lain
        # tidak terbukti in-scope (fail-closed), bukan otomatis boleh
        tmp = tempfile.TemporaryDirectory()
        try:
            pol = sg.parse_policy_file(write_policy(tmp, {
                "in_scope": ["api.target.com:8443"]}))
            self.assertEqual(sg.evaluate(
                pol, "https://api.target.com:8443/x")["verdict"], "IN_SCOPE")
            self.assertEqual(sg.evaluate(
                pol, "https://api.target.com/x")["verdict"], "NOT_IN_SCOPE")
            self.assertEqual(sg.evaluate(
                pol, "http://api.target.com:8443/x")["verdict"], "IN_SCOPE")
            self.assertEqual(sg.evaluate(
                pol, "https://api.target.com:9443/x")["verdict"],
                "NOT_IN_SCOPE")
        finally:
            tmp.cleanup()

    def test_path_narrowing_dan_batas_segmen(self):
        # kebijakan terisolasi (tanpa rule eksak tanpa-path) agar batasan
        # path benar-benar yang diuji
        tmp = tempfile.TemporaryDirectory()
        try:
            pol = sg.parse_policy_file(write_policy(tmp, {
                "in_scope": [{"asset": "target.com/api/"}],
                "out_of_scope": [{"asset": "target.com/api/admin/"}]}))
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/api/v2")["verdict"], "IN_SCOPE")
            # cocok /api persis (trailing slash opsional)
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/api")["verdict"], "IN_SCOPE")
            # batas segmen: /apixyz bukan /api/*
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/apixyz")["verdict"], "NOT_IN_SCOPE")
            # aset tanpa path tidak bisa membuktikan /api/* -> fail-closed
            self.assertEqual(sg.evaluate(
                pol, "target.com")["verdict"], "NOT_IN_SCOPE")
            # eksklusi path lebih dalam menang (deny-first)
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/api/admin/users")["verdict"],
                "OUT_OF_SCOPE")
        finally:
            tmp.cleanup()

    def test_path_gaya_platform_help_wildcard(self):
        # "target.com/help/*" gaya ekspor platform = prefix /help/
        tmp = tempfile.TemporaryDirectory()
        try:
            pol = sg.parse_policy_file(write_policy(tmp, {
                "in_scope": ["target.com"],
                "out_of_scope": [{"asset": "target.com/help/*"}]}))
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/help/faq")["verdict"],
                "OUT_OF_SCOPE")
            self.assertEqual(sg.evaluate(
                pol, "https://target.com/pricing")["verdict"], "IN_SCOPE")
        finally:
            tmp.cleanup()

    def test_invalid_asset_adalah_temuan_high(self):
        r = self.verdict("https://target.com\\@evil.com/")
        self.assertEqual((r["verdict"], r["severity"]),
                         ("INVALID", "high"))
        self.assertEqual(r["finding"]["kind"], "invalid_asset")


class PolicyErrorTest(unittest.TestCase):
    """Bentuk kebijakan tak dikenal = PolicyError -> exit 2 fail-closed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def expect_policy_error(self, data):
        path = write_policy(self.tmp, data)
        with self.assertRaises(sg.PolicyError):
            sg.parse_policy_file(path)

    def test_bentuk_tak_dikenal(self):
        self.expect_policy_error(["target.com"])            # JSON list
        self.expect_policy_error("target.com")              # JSON string
        self.expect_policy_error({"in_scope": "target.com"})
        self.expect_policy_error({"in_scope": ["ok.io"],
                                  "out_of_scope": "x.io"})
        self.expect_policy_error({"in_scope": [123]})       # entri bukan str/dict
        self.expect_policy_error({"in_scope": [{"nope": "x.io"}]})  # tanpa field aset
        self.expect_policy_error({"in_scope": [{"asset": "x.io",
                                                "type": "gizmo"}]})  # tipe asing

    def test_in_scope_absen_atau_kosong_valid_di_parser(self):
        # parser menerima bentuk OOS-only (klaim larangan tetap berarti
        # untuk aggregate); kecukupan isi adalah keputusan tiap tool
        pol = sg.parse_policy_file(
            write_policy(self.tmp, {"out_of_scope": ["x.io"]}))
        self.assertEqual(pol.in_rules, [])
        self.assertEqual(len(pol.out_rules), 1)
        pol = sg.parse_policy_file(write_policy(self.tmp, {"in_scope": []}))
        self.assertEqual(pol.in_rules, [])

    def test_gate_menolak_kebijakan_tanpa_aturan_in_scope(self):
        # gerbang tidak bisa mengizinkan apa pun -> exit 2 fail-closed
        for data in ({"out_of_scope": ["x.io"]}, {"in_scope": []}):
            path = write_policy(self.tmp, data, "empty.json")
            code, _ = run_main(["--policy", path, "--check", "x.io"])
            self.assertEqual(code, 2, data)

    def test_pola_berbahaya_ditolak_keras(self):
        # pola overbroad = DangerousPatternError SELALU naik, apa pun tipe
        for raw in ("*.com", "*.co.uk", "*.io", "*.localhost",
                    "foo.*.com", "*.target.*"):
            with self.subTest(raw=raw):
                self.expect_policy_error({"in_scope": [raw]})
                self.expect_policy_error(
                    {"in_scope": [{"asset": raw, "type": "OTHER"}]})

    def test_entri_tak_terparse_tak_bertipe_dilewati(self):
        # junk tanpa tipe (salah ketik, prosa) tidak mematikan seluruh
        # kebijakan — dilewati tercatat (lihat test temuan policy-level);
        # arah gagalnya tetap fail-closed: rule in-scope hilang = lebih
        # sempit diizinkan, bukan lebih luas
        path = write_policy(self.tmp, {
            "in_scope": ["ok.io", "ta rget.com", "", "*.tar get.com",
                         "10.0.0.5:8080", "10.0.0.0/24/api", "10.0.0.0/99",
                         "target.com:abc", "https://u@target.com"]})
        pol = sg.parse_policy_file(path)
        self.assertEqual([r["base"] for r in pol.in_rules], ["ok.io"])
        self.assertEqual(len(pol.skipped), 8)

    def test_file_tak_ada_dan_json_rusak(self):
        with self.assertRaises(sg.PolicyError):
            sg.parse_policy_file(str(Path(self.tmp.name) / "tidak-ada.json"))
        p = Path(self.tmp.name) / "rusak.json"
        p.write_text("{in_scope:", encoding="utf-8")
        with self.assertRaises(sg.PolicyError):
            sg.parse_policy_file(str(p))

    def test_entri_alias_field_platform(self):
        # ekspor gaya platform pakai asset_identifier/asset_type
        path = write_policy(self.tmp, {
            "in_scope": [{"asset_identifier": "x.io",
                          "asset_type": "URL"}],
            "out_of_scope": [{"endpoint": "stg.x.io", "category": "domain"}],
        })
        pol = sg.parse_policy_file(path)
        self.assertEqual(pol.in_rules[0]["base"], "x.io")
        self.assertEqual(pol.out_rules[0]["base"], "stg.x.io")
        self.assertEqual(pol.program, Path(path).stem)  # fallback nama file

    def test_tipe_non_jaringan_dilewati_tercatat(self):
        # pelajaran live-verify data H1 nyata: id aplikasi toko mirip
        # domain ("com.wolt.android") tapi BUKAN host — tidak boleh
        # dijadikan rule; dilewati TERCATAT, bukan senyap
        path = write_policy(self.tmp, {
            "program": "wolt-like",
            "in_scope": [
                {"asset": "*.wolt.com", "type": "WILDCARD"},
                {"asset": "com.wolt.android", "type": "GOOGLE_PLAY_APP_ID"},
                {"asset": "1477299281", "type": "APPLE_STORE_APP_ID"},
            ],
            "out_of_scope": [
                {"asset": "blog.wolt.com", "type": "URL"},
                {"asset": "All other assets", "type": "OTHER"},
                {"asset": "SGR1", "type": "SMART_CONTRACT"},
            ],
        })
        pol = sg.parse_policy_file(path)
        # hanya aset jaringan yang jadi rule
        self.assertEqual([r["base"] for r in pol.in_rules], ["wolt.com"])
        self.assertEqual([r["base"] for r in pol.out_rules], ["blog.wolt.com"])
        reasons = {(s["side"], s["reason"]) for s in pol.skipped}
        self.assertEqual(reasons, {("in_scope", "non_network"),
                                   ("out_of_scope", "non_network"),
                                   ("out_of_scope", "unparseable")})
        # tidak ada rule liar dari string mirip-domain non-jaringan
        self.assertFalse(
            any(r["kind"] == "domain" and "wolt.android" in r["base"]
                for r in pol.in_rules + pol.out_rules))
        # wildcard in-scope tetap bekerja
        self.assertEqual(sg.evaluate(pol, "dev.wolt.com")["verdict"],
                         "IN_SCOPE")

    def test_tipe_jaringan_tak_terparse_adalah_anomali(self):
        # ekspor mengklaim aset jaringan (URL) yang tak bisa dinilai
        # -> PolicyError, manusia harus menilai (bukan dilewati senyap)
        path = write_policy(self.tmp, {
            "in_scope": [{"asset": "bukan host!!", "type": "URL"}]})
        with self.assertRaises(sg.PolicyError):
            sg.parse_policy_file(path)

    def test_gate_evidence_membawa_skipped(self):
        path = write_policy(self.tmp, {
            "in_scope": [{"asset": "x.io"},
                         {"asset": "com.x.app", "type": "GOOGLE_PLAY_APP_ID"}]})
        out_path = str(Path(self.tmp.name) / "gate.json")
        code, _ = run_main(["--policy", path, "--check", "x.io",
                            "--out", out_path])
        self.assertEqual(code, 0)
        ev = json.loads(Path(out_path).read_text(encoding="utf-8"))
        self.assertEqual(ev["skipped_count"], 1)
        self.assertEqual(ev["skipped"][0]["reason"], "non_network")

    def test_entri_junk_tak_bertipe_dilewati_tapi_jadi_temuan_policy(self):
        # entri tak bertipe yang tidak berbentuk jaringan (junk/prosa)
        # dilewati tercatat; gate mengangkatnya jadi temuan medium
        # policy-level agar wajib direview (tidak hilang senyap)
        path = write_policy(self.tmp, {
            "in_scope": ["x.io", "10.0.0.5:8080", "target.com:99999"],
            "out_of_scope": ["All other assets"],
        })
        pol = sg.parse_policy_file(path)
        self.assertEqual(len(pol.in_rules), 1)
        self.assertEqual(len(pol.skipped), 3)
        out_path = str(Path(self.tmp.name) / "gate.json")
        code, _ = run_main(["--policy", path, "--check", "x.io",
                            "--out", out_path])
        self.assertEqual(code, 1)  # policy_skipped_unparseable = medium
        ev = json.loads(Path(out_path).read_text(encoding="utf-8"))
        kinds = [f["kind"] for f in ev["findings"]]
        self.assertIn("policy_skipped_unparseable", kinds)

    def test_entri_junk_bertipe_jaringan_adalah_anomali(self):
        # ekspor mengklaim tipe jaringan tapi stringnya tak bisa dinilai
        for entry in ({"asset": "10.0.0.5:8080", "type": "IP_ADDRESS"},
                      {"asset": "10.0.0.0/99", "type": "CIDR"},
                      {"asset": "target.com:99999", "type": "URL"},
                      {"asset": "ftp://target.com", "type": "URL"},
                      {"asset": "https://u@target.com", "type": "URL"}):
            path = write_policy(self.tmp, {"in_scope": [entry]})
            with self.subTest(entry=entry):
                with self.assertRaises(sg.PolicyError):
                    sg.parse_policy_file(path)


class MainExitCodesTest(unittest.TestCase):
    """Exit codes: 0 bersih, 1 temuan (sesuai --fail-on), 2 error."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.policy = write_policy(self.tmp, POLICY)

    def tearDown(self):
        self.tmp.cleanup()

    def test_semua_in_scope_exit_0(self):
        code, out = run_main(["--policy", self.policy, "--check",
                              "dev.target.com", "10.0.0.7"])
        self.assertEqual(code, 0)
        self.assertIn("IN-SCOPE: dev.target.com", out)

    def test_temuan_exit_1(self):
        code, out = run_main(["--policy", self.policy, "--check",
                              "staging.target.com", "dev.target.com"])
        self.assertEqual(code, 1)
        self.assertIn("OUT-OF-SCOPE (HIGH): staging.target.com", out)

    def test_fail_on_high_mengabaikan_medium(self):
        # hanya temuan medium (not_in_scope) -> dgn --fail-on high exit 0
        code, _ = run_main(["--policy", self.policy, "--fail-on", "high",
                            "--check", "unrelated.example"])
        self.assertEqual(code, 0)
        code, _ = run_main(["--policy", self.policy, "--fail-on", "any",
                            "--check", "unrelated.example"])
        self.assertEqual(code, 1)

    def test_explain_menunjukkan_aturan(self):
        code, out = run_main(["--policy", self.policy, "--explain",
                              "dev.target.com", "staging.target.com"])
        self.assertEqual(code, 1)
        self.assertIn("[rule: *.target.com]", out)
        self.assertIn("[rule: staging.target.com]", out)
        self.assertIn("JANGAN DIUJI", out)

    def test_check_file_dan_out_bukti_json(self):
        assets = Path(self.tmp.name) / "assets.txt"
        assets.write_text("dev.target.com\n\nstaging.target.com\n",
                          encoding="utf-8")
        out_path = str(Path(self.tmp.name) / "gate.json")
        code, out = run_main(["--policy", self.policy, "--check-file",
                              str(assets), "--out", out_path])
        self.assertEqual(code, 1)
        ev = json.loads(Path(out_path).read_text(encoding="utf-8"))
        self.assertEqual(ev["schema"], sg.SCHEMA)
        self.assertEqual(ev["tool"], "scope_gate")
        self.assertEqual(ev["program"], "demo-target")
        self.assertEqual(ev["checked"], 2)
        self.assertEqual(ev["in_scope_count"], 1)
        self.assertEqual(ev["finding_count"], 1)
        self.assertEqual(ev["findings"][0]["severity"], "high")
        self.assertEqual(ev["results"][0]["matched_rule"], "*.target.com")
        # baris kosong di file dilewati, bukan temuan
        self.assertNotIn("INVALID", out)

    def test_json_stdout(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sg.main(["--policy", self.policy, "--json", "--check",
                            "dev.target.com"])
        self.assertEqual(code, 0)
        ev = json.loads(buf.getvalue())
        self.assertEqual(ev["results"][0]["verdict"], "IN_SCOPE")

    def test_error_exit_2(self):
        code, _ = run_main(["--policy", str(Path(self.tmp.name) / "nope.json"),
                            "--check", "x.io"])
        self.assertEqual(code, 2)
        bad = write_policy(self.tmp, {"in_scope": ["*.com"]}, "bad.json")
        code, _ = run_main(["--policy", bad, "--check", "x.com"])
        self.assertEqual(code, 2)
        missing = str(Path(self.tmp.name) / "missing.txt")
        code, _ = run_main(["--policy", self.policy, "--check-file", missing])
        self.assertEqual(code, 2)

    def test_argparse_error_systemexit_2(self):
        # penyalahgunaan flag = parser.error -> SystemExit(2)
        with self.assertRaises(SystemExit) as ctx:
            run_main(["--policy", self.policy])  # tanpa aset
        self.assertEqual(ctx.exception.code, 2)
        with self.assertRaises(SystemExit) as ctx:
            run_main(["--policy", self.policy, "--check", "a.io",
                      "--explain", "b.io"])  # saling eksklusif
        self.assertEqual(ctx.exception.code, 2)
        with self.assertRaises(SystemExit) as ctx:
            run_main(["--check", "a.io"])  # tanpa --policy
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
