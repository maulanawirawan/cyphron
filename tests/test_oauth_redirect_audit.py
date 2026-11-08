"""Test oauth_redirect_audit (#0983) — NOL jaringan.

Yang dikunci:
  - matriks varian deterministik dari kanonik (24 baris, id unik,
    baseline kontrol selalu ada); canonical tak-valid = ValueError;
  - gerbang kontrol fail-closed: tanpa probe baseline / baseline tidak
    menerbitkan code -> ValueError (bukan temuan);
  - klasifikasi: lintas-origin + javascript = high CWE-601 confirmed
    L3; http-downgrade & implicit = medium CWE-319 confirmed L3;
    code-replay 2x200 = high CWE-294; same-origin lax = low L1
    unconfirmed; no-state = info L1; server strict = NOL temuan;
  - anti-FP: probe behavior (implicit/no-state) yang balik ke kanonik
    TIDAK memicu temuan lax same-origin;
  - redaksi: nilai code/access_token tidak pernah menulis keluar
    (marker REDACTED), host tetap tampil;
  - kontrak findings: semua finding lolos validate_finding; id
    deterministik; CLI exit 0/1/2.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import oauth_redirect_audit as ora  # noqa: E402
from findings import validate_finding  # noqa: E402

CANON = "https://app.lab.local/callback"


def _ev(probes, exchanges=None):
    ev = {"target": "auth.lab.local", "probes": probes}
    if exchanges is not None:
        ev["exchanges"] = exchanges
    return ev


class MatrixTest(unittest.TestCase):
    def test_matrix_deterministic_unique_ids(self):
        rows1 = ora.build_redirect_matrix(CANON)
        rows2 = ora.build_redirect_matrix(CANON)
        self.assertEqual(rows1, rows2)
        ids = [r["id"] for r in rows1]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[0], "baseline")
        self.assertGreaterEqual(len(ids), 20)
        # varian kelas redirect membawa redirect_uri berbeda dari kanonik
        for r in rows1:
            if r["class"] == "redirect":
                self.assertNotEqual(r["redirect_uri"], CANON)

    def test_matrix_invalid_canonical(self):
        for bad in ("", "bukan-url", "/path/tanpa/host",
                    "ftp://x/y"):
            with self.assertRaises(ValueError):
                ora.build_redirect_matrix(bad)

    def test_matrix_variants_content(self):
        rows = {r["id"]: r for r in ora.build_redirect_matrix(CANON)}
        self.assertEqual(rows["subdomain-suffix"]["redirect_uri"],
                         "https://app.lab.local.evil.example/callback")
        self.assertEqual(rows["authority-confusion"]["redirect_uri"],
                         "https://app.lab.local@evil.example/callback")
        self.assertEqual(rows["http-downgrade"]["redirect_uri"],
                         "http://app.lab.local/callback")
        self.assertEqual(rows["case-host"]["redirect_uri"],
                         "https://APP.LAB.LOCAL/callback")
        self.assertTrue(rows["implicit"]["set_params"]
                        ["response_type"], "token")


class ClassificationTest(unittest.TestCase):
    def test_full_vulnerable_server(self):
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": f"{CANON}?code=SECRET-CODE-1&state=s1"},
            {"id": "subdomain-suffix",
             "redirect_uri": "https://app.lab.local.evil.example/callback",
             "status": 302,
             "location": "https://app.lab.local.evil.example/callback"
                         "?code=SECRET-CODE-2"},
            {"id": "javascript-scheme",
             "redirect_uri": "javascript://app.lab.local/callback",
             "status": 302,
             "location": "javascript://app.lab.local/callback"
                         "?code=SECRET-CODE-3"},
            {"id": "http-downgrade", "redirect_uri": "http://app.lab.local"
                                                     "/callback",
             "status": 302,
             "location": "http://app.lab.local/callback?code=SECRET-CODE-4"},
            {"id": "trailing-slash", "redirect_uri": CANON + "/",
             "status": 302, "location": CANON + "/?code=SECRET-CODE-5"},
            {"id": "implicit", "status": 302,
             "location": CANON + "#access_token=SECRET-TOK-1"},
            {"id": "no-state", "status": 302,
             "location": CANON + "?code=SECRET-CODE-6"},
            {"id": "no-pkce", "status": 302,
             "location": CANON + "?code=SECRET-CODE-7"},
        ]
        findings, stats, notes = ora.audit_evidence(
            _ev(probes, [{"id": "code-replay", "attempts": [200, 200]}]),
            None)
        by_title = {f["title"][:30]: f for f in findings}
        self.assertTrue(any(f["severity"] == "high" and f["cwe"] == "CWE-601"
                            and f["verdict"] == 3
                            and f["status"] == "confirmed"
                            for f in findings),
                        "lintas-origin harus high L3")
        self.assertTrue(any(f["cwe"] == "CWE-294" and f["verdict"] == 3
                            for f in findings), "replay harus high")
        self.assertTrue(any(f["cwe"] == "CWE-319"
                            and "implicit" in f["title"]
                            and f["verdict"] == 3 for f in findings))
        self.assertTrue(any(f["cwe"] == "CWE-601" and "TLS" in
                            f["description"]
                            and "http-downgrade" in f["param"]
                            and f["verdict"] == 3 for f in findings),
                        "downgrade http = lintas-origin + cleartext")
        self.assertTrue(any(f["verdict"] == 1
                            and f["status"] == "unconfirmed"
                            and "trailing-slash" in f["param"]
                            for f in findings))
        self.assertTrue(any(f["severity"] == "info"
                            and "state" in f["title"] for f in findings))
        self.assertTrue(any("PKCE" in f["title"] for f in findings))
        for f in findings:
            self.assertEqual(validate_finding(f), [])
        # redaksi: nilai code/token tak pernah menulis keluar
        blob = json.dumps(findings)
        for secret in ("SECRET-CODE-", "SECRET-TOK-1"):
            self.assertNotIn(secret, blob)
        self.assertIn("REDACTED", blob)
        # host tetap tampil utk korelasi
        self.assertIn("app.lab.local", blob)

    def test_anti_fp_behavior_probe_not_lax(self):
        # implicit + no-state diterbitkan ke kanonik = BUKAN temuan lax
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=C1&state=s"},
            {"id": "no-state", "status": 302,
             "location": CANON + "?code=C2"},
            {"id": "implicit", "status": 302,
             "location": CANON + "#access_token=T"},
        ]
        findings, _, _ = ora.audit_evidence(_ev(probes), None)
        lax = [f for f in findings if "longgar" in f["title"]]
        self.assertEqual(lax, [], "behavior probe tak boleh jadi lax")
        self.assertEqual(len(findings), 2)  # implicit + no-state saja

    def test_anti_fp_behavior_probe_with_canonical_uri(self):
        # bukti nyata: behavior probe ikut mencatat redirect_uri
        # kanonik — tetap BUKAN temuan lax
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=C1&state=s"},
            {"id": "no-pkce", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=C2"},
            {"id": "implicit", "redirect_uri": CANON, "status": 302,
             "location": CANON + "#access_token=T"},
            {"id": "no-state", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=C3"},
        ]
        findings, _, _ = ora.audit_evidence(_ev(probes), None)
        lax = [f for f in findings if "longgar" in f["title"]]
        self.assertEqual(lax, [])
        self.assertEqual(len(findings), 3)  # no-pkce + implicit + no-state

    def test_strict_server_no_findings(self):
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=OK1&state=s"},
            {"id": "foreign-origin", "redirect_uri": "https://evil.example"
                                                     "/cb",
             "status": 400, "location": ""},
            {"id": "subdomain-suffix",
             "redirect_uri": "https://app.lab.local.evil.example/callback",
             "status": 400, "location": ""},
            {"id": "implicit", "status": 400, "location": ""},
            {"id": "path-append", "redirect_uri": CANON + "/extra",
             "status": 302, "location": CANON + "?code=NORM"},
        ]
        findings, stats, _ = ora.audit_evidence(_ev(probes), None)
        self.assertEqual(findings, [])
        self.assertEqual(stats["rejected"], 3)
        self.assertEqual(stats["issued"], 2)

    def test_unknown_probe_rejected_no_finding(self):
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=OK2"},
            {"id": "custom-idea", "redirect_uri": "https://other.example/",
             "status": 500, "location": ""},
        ]
        findings, _, notes = ora.audit_evidence(_ev(probes), CANON)
        self.assertEqual(findings, [])
        self.assertTrue(any("custom-idea" in n for n in notes))

    def test_malformed_probes_failclosed_notes(self):
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=OK3"},
            {"id": "weird", "status": "abc", "location": ""},
            "bukan-objek",
        ]
        findings, _, notes = ora.audit_evidence(_ev(probes), None)
        self.assertEqual(findings, [])
        self.assertEqual(len(notes), 2)

    def test_replay_patterns(self):
        base = [{"id": "baseline", "redirect_uri": CANON, "status": 302,
                 "location": CANON + "?code=OK4"}]
        good, _, _ = ora.audit_evidence(
            _ev(base, [{"id": "code-replay", "attempts": [200, 200]}]), None)
        self.assertEqual(len(good), 1)
        self.assertEqual(good[0]["cwe"], "CWE-294")
        # pemakaian kedua ditolak = BUKAN replay
        clean, _, _ = ora.audit_evidence(
            _ev(base, [{"id": "code-replay", "attempts": [200, 400]}]), None)
        self.assertEqual(clean, [])
        # satu percobaan saja = tidak bisa diklaim
        single, _, _ = ora.audit_evidence(
            _ev(base, [{"id": "code-replay", "attempts": [200]}]), None)
        self.assertEqual(single, [])

    def test_fail_closed_gates(self):
        with self.assertRaises(ValueError):  # tanpa baseline
            ora.audit_evidence(_ev([{"id": "x", "status": 400,
                                     "location": ""}]), None)
        with self.assertRaises(ValueError):  # baseline ditolak
            ora.audit_evidence(_ev([{"id": "baseline",
                                     "redirect_uri": CANON,
                                     "status": 400, "location": ""}]), None)
        with self.assertRaises(ValueError):  # probes kosong
            ora.audit_evidence(_ev([]), None)
        with self.assertRaises(ValueError):  # baseline error page
            ora.audit_evidence(_ev([{"id": "baseline",
                                     "redirect_uri": CANON,
                                     "status": 302,
                                     "location": CANON + "?error=xyz"}]),
                                None)

    def test_canonical_origin_from_baseline(self):
        # tanpa --canonical: origin diambil dari baseline
        probes = [
            {"id": "baseline", "redirect_uri": CANON, "status": 302,
             "location": CANON + "?code=OK5"},
            {"id": "custom", "redirect_uri": "https://evil.example/x",
             "status": 302, "location": "https://evil.example/x?code=OK6"},
        ]
        findings, _, _ = ora.audit_evidence(_ev(probes), None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["canonical"],
                         "https://app.lab.local")


class CliTest(unittest.TestCase):
    def test_cli_matrix_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "matrix.json"
            rc = ora.main(["--canonical", CANON, "--matrix",
                           "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], ora.SCHEMA)
            self.assertGreaterEqual(len(doc["matrix"]), 20)
            # evidence vuln -> exit 1
            ev = _ev([
                {"id": "baseline", "redirect_uri": CANON, "status": 302,
                 "location": CANON + "?code=C9&state=s"},
                {"id": "foreign-origin",
                 "redirect_uri": "https://evil.example/cb",
                 "status": 302,
                 "location": "https://evil.example/cb?code=C9"},
            ])
            evp = Path(td) / "ev.json"
            evp.write_text(json.dumps(ev), encoding="utf-8")
            fout = Path(td) / "f.json"
            rc = ora.main(["--evidence", str(evp), "--out", str(fout)])
            self.assertEqual(rc, 1)
            doc = json.loads(fout.read_text(encoding="utf-8"))
            self.assertTrue(any(f["cwe"] == "CWE-601"
                                for f in doc["findings"]))
            # evidence strict -> exit 0
            ev2 = _ev([
                {"id": "baseline", "redirect_uri": CANON, "status": 302,
                 "location": CANON + "?code=CA&state=s"},
                {"id": "foreign-origin",
                 "redirect_uri": "https://evil.example/cb",
                 "status": 400, "location": ""},
            ])
            ev2p = Path(td) / "ev2.json"
            ev2p.write_text(json.dumps(ev2), encoding="utf-8")
            rc = ora.main(["--evidence", str(ev2p),
                           "--out", str(fout)])
            self.assertEqual(rc, 0)
            # tanpa argumen -> exit 2
            self.assertEqual(ora.main([]), 2)
            # evidence rusak -> exit 2
            bad = Path(td) / "bad.json"
            bad.write_text("{bukan json", encoding="utf-8")
            self.assertEqual(ora.main(["--evidence", str(bad),
                                       "--out", str(fout)]), 2)
            # matrix tanpa canonical -> exit 2
            self.assertEqual(ora.main(["--matrix"]), 2)
            # baseline hilang -> exit 2
            nobase = Path(td) / "nb.json"
            nobase.write_text(json.dumps(
                _ev([{"id": "x", "status": 400, "location": "k"}])
            ), encoding="utf-8")
            self.assertEqual(ora.main(["--evidence", str(nobase),
                                       "--out", str(fout)]), 2)


if __name__ == "__main__":
    unittest.main()
