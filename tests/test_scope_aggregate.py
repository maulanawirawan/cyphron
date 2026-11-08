"""Nol jaringan — test scope_aggregate (konsolidasi kebijakan multi-program).

Fixture kebijakan inline (tempfile) — tidak ada request, tidak ada socket.
Semantik yang dijaga: carve-out satu program BUKAN konflik; tabrakan eksak
satu program = intra; tumpang-tindih lintas program = cross; CIDR beririsan
lintas program = cross.
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
import scope_aggregate as sa  # noqa: E402


def write_policy(tmp: tempfile.TemporaryDirectory, data, name="policy.json"):
    p = Path(tmp.name) / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def load_policies(tmp, *specs):
    """specs: list[(nama, dict)] -> list[(ParsedPolicy, program)]"""
    out = []
    for i, (name, data) in enumerate(specs):
        path = write_policy(tmp, data, name)
        parsed = sg.parse_policy_file(path)
        out.append((parsed, parsed.program))
    return out


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = sa.main(argv)
    return code, buf.getvalue()


class RuleKeyTest(unittest.TestCase):
    """Kunci kanonik dari komponen rule — bukan string mentah."""

    def parse(self, raw):
        return sg._parse_rule(raw, "in_scope", None)

    def test_case_insensitive(self):
        self.assertEqual(sa._rule_key(self.parse("TARGET.com")),
                         sa._rule_key(self.parse("target.com")))

    def test_port_dan_path_membedakan(self):
        self.assertNotEqual(sa._rule_key(self.parse("target.com")),
                            sa._rule_key(self.parse("target.com:8443")))
        self.assertNotEqual(sa._rule_key(self.parse("target.com")),
                            sa._rule_key(self.parse("target.com/api/")))

    def test_wildcard_dan_ip(self):
        self.assertEqual(sa._rule_key(self.parse("*.dev.io")), "*.dev.io")
        self.assertEqual(sa._rule_key(self.parse("10.0.0.5")), "10.0.0.5/32")
        self.assertEqual(sa._rule_key(self.parse("10.0.0.0/24")),
                         "10.0.0.0/24")


class ConflictTest(unittest.TestCase):
    """Deteksi konflik intra/cross pada level semantik."""

    def test_cross_eksak(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["dev.target.com"]}),
                ("b.json", {"program": "beta",
                            "in_scope": ["other.io"],
                            "out_of_scope": ["dev.target.com"]}))
            res = sa.consolidate(pols)
            self.assertEqual(len(res["conflicts"]), 1)
            c = res["conflicts"][0]
            self.assertEqual((c["conflict"], c["severity"], c["asset"]),
                             ("cross", "medium", "dev.target.com"))
            self.assertEqual((c["in_program"], c["out_program"]),
                             ("alpha", "beta"))
        finally:
            tmp.cleanup()

    def test_cross_semantik_wildcard_vs_eksak(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha", "in_scope": ["*.target.com"]}),
                ("b.json", {"program": "beta", "out_of_scope":
                            ["dev.target.com"]}))
            res = sa.consolidate(pols)
            kinds = [(c["conflict"], c["asset"]) for c in res["conflicts"]]
            self.assertIn(("cross", "dev.target.com"), kinds)
        finally:
            tmp.cleanup()

    def test_cross_semantik_eksak_vs_wildcard(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["api.staging.target.com"]}),
                ("b.json", {"program": "beta", "out_of_scope":
                            ["*.staging.target.com"]}))
            res = sa.consolidate(pols)
            kinds = [(c["conflict"], c["asset"]) for c in res["conflicts"]]
            # aset konkret (eksak) yang dilaporkan, bukan wildcard penutupnya
            self.assertIn(("cross", "api.staging.target.com"), kinds)
        finally:
            tmp.cleanup()

    def test_intra_eksak_kontradiktif(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("g.json", {"program": "gamma",
                            "in_scope": ["shop.example"],
                            "out_of_scope": ["shop.example"]}))
            res = sa.consolidate(pols)
            self.assertEqual(len(res["conflicts"]), 1)
            self.assertEqual(res["conflicts"][0]["conflict"], "intra")
        finally:
            tmp.cleanup()

    def test_carve_out_satu_program_bukan_konflik(self):
        # struktur kebijakan yang wajar: wildcard in-scope + eksklusi
        # subdomain sendiri = bukan kontradiksi (deny-dinilai-dulu)
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["*.target.com", "10.0.0.0/24"],
                            "out_of_scope": ["staging.target.com",
                                             "10.0.0.200"]}))
            res = sa.consolidate(pols)
            self.assertEqual(res["conflicts"], [])
            recs = {a["asset"]: a for a in res["assets"]}
            self.assertFalse(recs["*.target.com"]["conflict"])
            self.assertFalse(recs["staging.target.com"]["conflict"])
            # kunci kanonik IP tunggal = /32
            self.assertFalse(recs["10.0.0.200/32"]["conflict"])
        finally:
            tmp.cleanup()

    def test_oos_eksak_apex_vs_wildcard_program_lain_adalah_konflik(self):
        # OOS eksak "target.com" di B melarang host DAN subdomennya
        # (semantik eksklusi) -> bertentangan dgn "*.target.com" in-scope
        # di A yang mengizinkan semua subdomain -> konflik nyata
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha", "in_scope": ["*.target.com"]}),
                ("b.json", {"program": "beta", "out_of_scope": ["target.com"]}))
            res = sa.consolidate(pols)
            kinds = [(c["conflict"], c["asset"]) for c in res["conflicts"]]
            self.assertIn(("cross", "target.com"), kinds)
        finally:
            tmp.cleanup()

    def test_tidak_ada_konflik_di_luar_cakupan(self):
        # OOS wildcard "*.staging.target.com" di B vs in eksak
        # "target.com" di A: apex tak tertutup wildcard OOS -> bukan konflik
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha", "in_scope": ["target.com"]}),
                ("b.json", {"program": "beta",
                            "out_of_scope": ["*.staging.target.com"]}))
            res = sa.consolidate(pols)
            self.assertEqual(res["conflicts"], [])
        finally:
            tmp.cleanup()

    def test_carve_out_sama_antar_program_bukan_konflik(self):
        # pelajaran live-verify robinhood: kedua program SAMA-SAMA
        # meng-exclude affiliates.robinhood.com — kebijakan in-side sudah
        # menolak aset yang disengketakan -> tidak ada pertentangan.
        # Subdomain yang hanya di-exclude SATU program tetap konflik.
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "robinhood",
                            "in_scope": ["*.robinhood.com"],
                            "out_of_scope": ["affiliates.robinhood.com"]}),
                ("b.json", {"program": "robinhood_markets",
                            "in_scope": ["*.robinhood.com"],
                            "out_of_scope": ["affiliates.robinhood.com",
                                             "partners.robinhood.com"]}))
            res = sa.consolidate(pols)
            kinds = [(c["conflict"], c["asset"]) for c in res["conflicts"]]
            self.assertEqual(kinds, [("cross", "partners.robinhood.com")])
        finally:
            tmp.cleanup()

    def test_cross_cidr_beririsan_dan_bersih(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha", "in_scope": ["10.0.0.0/24"]}),
                ("b.json", {"program": "beta",
                            "in_scope": ["10.0.2.0/24"],
                            "out_of_scope": ["10.0.0.55", "10.0.3.0/24"]}))
            res = sa.consolidate(pols)
            kinds = [(c["conflict"], c["asset"], c["kind"])
                     for c in res["conflicts"]]
            self.assertEqual(kinds, [("cross", "10.0.0.55/32", "ip")])
        finally:
            tmp.cleanup()

    def test_ipv4_vs_ipv6_tidak_pernah_konflik(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["2001:db8::/32"]}),
                ("b.json", {"program": "beta",
                            "out_of_scope": ["10.0.0.0/24"]}))
            res = sa.consolidate(pols)
            self.assertEqual(res["conflicts"], [])
        finally:
            tmp.cleanup()

    def test_port_berbeda_tetap_konflik_luas(self):
        # in "target.com:8443" (alpha) vs OOS "target.com" (beta):
        # OOS beta melarang semua port termasuk 8443 -> konflik
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["target.com:8443"]}),
                ("b.json", {"program": "beta",
                            "out_of_scope": ["target.com"]}))
            res = sa.consolidate(pols)
            self.assertEqual(len(res["conflicts"]), 1)
            self.assertEqual(res["conflicts"][0]["conflict"], "cross")
        finally:
            tmp.cleanup()

    def test_dedup_case_insensitive(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha", "in_scope": ["Target.com"]}),
                ("b.json", {"program": "beta", "in_scope": ["target.com"]}))
            res = sa.consolidate(pols)
            self.assertEqual(res["summary"]["unique_assets"], 1)
            self.assertEqual(res["summary"]["multi_program_in_scope"], 1)
            rec = res["assets"][0]
            self.assertEqual(sorted(rec["in_programs"]), ["alpha", "beta"])
            self.assertIn("di-klaim in-scope oleh >= 2 program", rec["note"])
            self.assertFalse(rec["conflict"])  # klaim ganda = info, bukan temuan
        finally:
            tmp.cleanup()


class ConsolidateSummaryTest(unittest.TestCase):
    def test_ringkasan_per_program(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            pols = load_policies(tmp,
                ("a.json", {"program": "alpha",
                            "in_scope": ["*.target.com", "10.0.0.0/24"],
                            "out_of_scope": ["staging.target.com"]}),
                ("b.json", {"program": "beta", "in_scope": ["dev.target.com"]}))
            res = sa.consolidate(pols)
            self.assertEqual(res["summary"]["programs"], 2)
            self.assertEqual(res["summary"]["unique_assets"], 4)
            self.assertEqual(res["summary"]["conflicts"], 0)
            # staging.target.com out-only (tanpa klaim in) tidak dihitung
            self.assertEqual(res["summary"]["clean_in_scope"], 3)
        finally:
            tmp.cleanup()


class MainExitCodesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data, name):
        return write_policy(self.tmp, data, name)

    def test_bersih_exit_0(self):
        a = self.write({"program": "alpha", "in_scope": ["x.io"],
                        "out_of_scope": ["stg.x.io"]}, "a.json")
        b = self.write({"program": "beta", "in_scope": ["y.io"]}, "b.json")
        out_path = str(Path(self.tmp.name) / "agg.json")
        list_path = str(Path(self.tmp.name) / "clean.txt")
        code, out = run_main(["--policy", a, "--policy", b, "--out", out_path,
                              "--list", list_path])
        self.assertEqual(code, 0)
        ev = json.loads(Path(out_path).read_text(encoding="utf-8"))
        self.assertEqual(ev["schema"], sa.SCHEMA)
        self.assertEqual(ev["tool"], "scope_aggregate")
        self.assertEqual([p["program"] for p in ev["policies"]],
                         ["alpha", "beta"])
        lines = Path(list_path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(lines), ["x.io", "y.io"])
        # aset out-of-scope-only tidak masuk daftar bersih
        self.assertNotIn("stg.x.io", lines)

    def test_konflik_exit_1_dan_fail_on_none(self):
        a = self.write({"program": "alpha", "in_scope": ["dev.target.com"]},
                       "a.json")
        b = self.write({"program": "beta",
                        "out_of_scope": ["dev.target.com"]}, "b.json")
        code, out = run_main(["--policy", a, "--policy", b])
        self.assertEqual(code, 1)
        self.assertIn("KONFLIK-CROSS (medium): dev.target.com", out)
        code, _ = run_main(["--policy", a, "--policy", b, "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_konflik_dibuang_dari_list(self):
        # dev.target.com in-scope di beta TAPI tertentang wildcard alpha
        # -> aset disengketakan keluar dari daftar bersih walau ada klaim in
        a = self.write({"program": "alpha", "in_scope": ["*.target.com"]},
                       "a.json")
        b = self.write({"program": "beta", "in_scope": ["dev.target.com",
                                                        "other.io"],
                        "out_of_scope": ["dev.target.com",
                                         "*.staging.beta.io"]}, "b.json")
        list_path = str(Path(self.tmp.name) / "clean.txt")
        code, _ = run_main(["--policy", a, "--policy", b, "--list", list_path])
        self.assertEqual(code, 1)
        lines = Path(list_path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(lines), ["*.target.com", "other.io"])
        self.assertNotIn("dev.target.com", lines)

    def test_satu_kebijakan_gagal_semua_gagal_exit_2(self):
        a = self.write({"program": "alpha", "in_scope": ["x.io"]}, "a.json")
        bad = self.write({"program": "bad", "in_scope": ["*.com"]}, "bad.json")
        code, _ = run_main(["--policy", a, "--policy", bad])
        self.assertEqual(code, 2)
        # kebijakan tak ada juga exit 2
        code, _ = run_main(["--policy", a,
                            "--policy", str(Path(self.tmp.name) / "nope.json")])
        self.assertEqual(code, 2)

    def test_program_fallback_nama_file(self):
        a = self.write({"in_scope": ["x.io"]}, "tanpa-program.json")
        code, out = run_main(["--policy", a])
        self.assertEqual(code, 0)
        self.assertIn("[tanpa-program]", out)


if __name__ == "__main__":
    unittest.main()
