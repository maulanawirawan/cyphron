"""Nol jaringan — test openapi_spec_audit (audit anti-pola OpenAPI 3.x).

Fixture dibangun inline mengikuti struktur OpenAPI 3.x JSON; perilaku cek
diuji terhadap tabel anti-pola sumber (additionalProperties/maxLength/
pattern/enum/password-TLS/error-schema/readOnly) + fail-closed wadah.
Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("tools",):
    sys.path.insert(0, str(ROOT / sub))

import openapi_spec_audit as osa  # noqa: E402

TOOL = ROOT / "tools" / "openapi_spec_audit.py"


def _spec(**over: object) -> dict:
    """Spec minimal yang 'baik': https, auth dideklarasikan, skema rapat."""
    base: dict = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1.0"},
        "servers": [{"url": "https://api.example.com"}],
        "components": {"securitySchemes": {"bearer": {"type": "http",
                                                      "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": {
            "/v1/items": {
                "post": {
                    "requestBody": {"content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "name": {"type": "string", "maxLength": 8,
                                         "pattern": "^[a-z]+$"},
                                "kind": {"type": "string",
                                         "enum": ["a", "b"]},
                            },
                        }}}},
                    "responses": {
                        "200": {"description": "ok"},
                        "400": {"description": "bad", "content": {
                            "application/json": {"schema": {
                                "type": "object"}}}},
                    },
                },
            },
        },
    }
    base.update(over)
    return base


class TestFailClosed(unittest.TestCase):
    """Wadah tidak valid -> ValueError / exit 2, bukan 'bersih'."""

    def test_openapi_v2_ditolak(self):
        with self.assertRaises(ValueError):
            osa.audit_spec({"swagger": "2.0", "paths": {"/x": {}}})

    def test_paths_kosong_ditolak(self):
        with self.assertRaises(ValueError):
            osa.audit_spec({"openapi": "3.1.0", "paths": {}})

    def test_paths_bukan_objek_ditolak(self):
        with self.assertRaises(ValueError):
            osa.audit_spec({"openapi": "3.1.0", "paths": []})

    def test_bukan_json_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "spec.json"
            p.write_text("bukan json {", encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--spec", str(p)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)

    def test_file_hilang_exit_2(self):
        r = subprocess.run(
            [sys.executable, str(TOOL), "--spec", "TIDAK-ADA-xyz.json"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


class TestAuthChecks(unittest.TestCase):
    def test_spec_baik_bersih(self):
        findings, summary, notes = osa.audit_spec(_spec())
        self.assertEqual(findings, [])
        self.assertEqual(summary["operations"], 1)
        self.assertEqual(notes, [])

    def test_tanpa_auth_sama_sekali_high(self):
        spec = _spec()
        spec.pop("components")
        spec.pop("security")
        findings, _, _ = osa.audit_spec(spec)
        self.assertEqual([f["check"] for f in findings],
                         ["no-auth-defined"])

    def test_scheme_ada_tapi_operasi_tanpa_security(self):
        spec = _spec()
        spec["security"] = []  # global kosong eksplisit
        findings, _, _ = osa.audit_spec(spec)
        self.assertEqual([f["check"] for f in findings],
                         ["op-no-security"])
        self.assertEqual(findings[0]["severity"], "high")


class TestServerChecks(unittest.TestCase):
    def test_server_http_non_local_medium(self):
        spec = _spec(servers=[{"url": "http://api.example.com"}])
        findings, _, notes = osa.audit_spec(spec)
        checks = [f["check"] for f in findings]
        self.assertIn("server-url-http", checks)
        self.assertEqual(notes, [])

    def test_server_http_lokal_disaring(self):
        spec = _spec(servers=[{"url": "http://localhost:3000"}])
        findings, _, notes = osa.audit_spec(spec)
        self.assertNotIn("server-url-http", [f["check"] for f in findings])
        self.assertTrue(any("lokal" in n for n in notes))

    def test_password_http_high_https_tidak(self):
        prop = {"password": {"type": "string", "format": "password"}}
        def _mk(url: str) -> dict:
            return _spec(servers=[{"url": url}], paths={
                "/login": {"post": {
                    "requestBody": {"content": {"application/json": {
                        "schema": {"type": "object",
                                   "properties": prop}}}},
                    "responses": {"200": {"description": "ok"}}}}})
        f_http, _, _ = osa.audit_spec(_mk("http://api.example.com"))
        self.assertIn("password-no-tls", [x["check"] for x in f_http])
        self.assertEqual([x["severity"] for x in f_http
                          if x["check"] == "password-no-tls"], ["high"])
        f_https, _, _ = osa.audit_spec(_mk("https://api.example.com"))
        self.assertNotIn("password-no-tls", [x["check"] for x in f_https])


class TestRequestBodyChecks(unittest.TestCase):
    def _body(self, schema: dict) -> dict:
        return _spec(paths={"/v1/x": {"post": {
            "requestBody": {"content": {"application/json": {
                "schema": schema}}},
            "responses": {"200": {"description": "ok"}}}}})

    def test_additional_true_eksplisit_medium(self):
        sch = {"type": "object", "additionalProperties": True,
               "properties": {"a": {"type": "string", "maxLength": 4}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-props", "req-string-nopattern"])
        self.assertEqual(findings[0]["severity"], "medium")

    def test_additional_default_hanya_level_atas_info(self):
        sch = {"type": "object", "properties": {"a": {
            "type": "object", "properties": {"b": {"type": "string",
                                                   "maxLength": 4}}}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        # nested object tanpa additionalProperties TIDAK diberi temuan deflt
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-deflt", "req-string-nopattern"])

    def test_string_tanpa_maxlength_medium(self):
        sch = {"type": "object", "properties": {
            "a": {"type": "string"}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-deflt", "req-string-nomax",
                          "req-string-nopattern"])

    def test_saringan_format_dan_enum(self):
        sch = {"type": "object", "properties": {
            "d": {"type": "string", "format": "date-time"},
            "e": {"type": "string", "enum": ["x"]}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        # format/enum disaring; top-level object tetap kena cek deflt
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-deflt"])

    def test_fixedvocab_tanpa_enum_info(self):
        sch = {"type": "object", "properties": {
            "status": {"type": "string", "maxLength": 4}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-deflt", "req-fixedvocab-noenum",
                          "req-string-nopattern"])

    def test_read_only_medium(self):
        sch = {"type": "object", "properties": {
            "id": {"type": "string", "readOnly": True, "maxLength": 4,
                   "pattern": "^[a-z]+$"}}}
        findings, _, _ = osa.audit_spec(self._body(sch))
        self.assertEqual([f["check"] for f in findings],
                         ["req-additional-deflt", "req-read-only"])

    def test_ref_diresolve_dan_siklus_aman(self):
        spec = _spec()
        spec["components"]["schemas"] = {
            "Pet": {"type": "object",
                    "additionalProperties": True,
                    "properties": {"friend": {"$ref": "#/components/"
                                                     "schemas/Pet"}}}}
        spec["paths"] = {"/v1/pet": {"post": {
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Pet"}}}},
            "responses": {"200": {"description": "ok"}}}}}
        findings, _, _ = osa.audit_spec(spec)
        self.assertIn("req-additional-props", [f["check"] for f in findings])

    def test_ref_eksternal_dicatat_notes(self):
        spec = _spec()
        spec["paths"] = {"/v1/x": {"post": {
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": "https://other.example/x.json"}}}},
            "responses": {"200": {"description": "ok"}}}}}
        findings, _, notes = osa.audit_spec(spec)
        self.assertEqual(findings, [])
        self.assertTrue(any("tidak terresolve" in n for n in notes))


class TestResponseChecks(unittest.TestCase):
    def test_error_tanpa_schema_info(self):
        spec = _spec()
        spec["paths"] = {"/v1/x": {"get": {"responses": {
            "404": {"description": "no"},
            "5XX": {"description": "no"},
            "200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object"}}}},
        }}}}
        findings, summary, _ = osa.audit_spec(spec)
        self.assertEqual([f["check"] for f in findings],
                         ["resp-error-noschema", "resp-error-noschema"])
        self.assertEqual(summary["error_responses"], 2)
        self.assertEqual(summary["error_responses_noschema"], 2)

    def test_2xx_tidak_dicek(self):
        spec = _spec()
        spec["paths"] = {"/v1/x": {"get": {"responses": {
            "200": {"description": "ok"}}}}}
        findings, _, _ = osa.audit_spec(spec)
        self.assertEqual(findings, [])


class TestCli(unittest.TestCase):
    def test_exit_0_bersih_dan_exit_1_dengan_temuan(self):
        with tempfile.TemporaryDirectory() as td:
            clean = Path(td) / "clean.json"
            clean.write_text(json.dumps(_spec()), encoding="utf-8")
            r0 = subprocess.run([sys.executable, str(TOOL), "--spec",
                                 str(clean)], capture_output=True, text=True)
            self.assertEqual(r0.returncode, 0)

            bad = _spec()
            bad.pop("components")
            bad.pop("security")
            fp = Path(td) / "bad.json"
            fp.write_text(json.dumps(bad), encoding="utf-8")
            r1 = subprocess.run([sys.executable, str(TOOL), "--spec",
                                 str(fp)], capture_output=True, text=True)
            self.assertEqual(r1.returncode, 1)
            self.assertIn("no-auth-defined", r1.stdout)

    def test_fail_on_medium_mengabaikan_info(self):
        with tempfile.TemporaryDirectory() as td:
            sch = _spec()
            sch["paths"]["/v1/items"]["post"]["requestBody"]["content"][
                "application/json"]["schema"]["properties"]["extra"] = {
                "type": "string", "maxLength": 4}
            fp = Path(td) / "spec.json"
            fp.write_text(json.dumps(sch), encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--spec",
                                str(fp), "--fail-on", "medium"],
                               capture_output=True, text=True)
            # hanya temuan info (nopattern) -> tidak memicu exit 1
            self.assertEqual(r.returncode, 0)

    def test_json_output_tersimpan(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "laporan.json"
            fp = Path(td) / "spec.json"
            fp.write_text(json.dumps(_spec()), encoding="utf-8")
            r = subprocess.run([sys.executable, str(TOOL), "--spec",
                                str(fp), "--json", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["kind"], "openapi-spec-audit")
            self.assertIn("summary", doc)


if __name__ == "__main__":
    unittest.main()
