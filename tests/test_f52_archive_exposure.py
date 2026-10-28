"""Test F52 — audit arsip kemasan: asar (Electron) + APK/zip.

NOL jaringan; arsip dibangun sendiri di fixture. Yang dikunci:
  - asar: header pickle diurai (fail-closed), entri teks + sourcemap
    di dalam arsip ter-audit dgn provenance #entry;
  - apk/zip: entri teks + classes.dex via strings surface;
  - arsip bersih = satu baris AMAN; format tak dikenal = error meta.
"""
from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import bundle_exposure as be  # noqa: E402
from findings import validate_finding  # noqa: E402

NL = chr(10)


def _build_asar(entries: dict[str, bytes]) -> bytes:
    """Asar minimal — layout disk chromium pickle ASLI (sama dgn
    yang diurai _asar_parse): header_buf = [uint32 json_size][json]
    [pad4]; disk = [uint32 4+header_buf_len][header_buf][payload]."""
    header = {"files": {}}
    payload = b""
    offset = 0
    for name, blob in entries.items():
        header["files"][name] = {"size": str(len(blob)),
                                 "offset": str(offset)}
        payload += blob
        offset += len(blob)
    header_json = json.dumps(header).encode()
    pad4 = (4 - len(header_json) % 4) % 4
    header_buf = (struct.pack("<II", 4, len(header_json)) + header_json
                  + bytes(pad4))
    out = struct.pack("<II", 4, len(header_buf)) + header_buf
    return out + payload


class AsarTest(unittest.TestCase):
    def test_entries_sourcemap_and_secret_detected(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "app.asar"
            sourcemap = json.dumps({
                "sources": ["src/auth.ts"],
                "sourcesContent": [
                    'fetch(API+"/internal/reset");' + NL]}).encode()
            f.write_bytes(_build_asar({
                "main.js": (b'const API="https://api.example-app.com/v2";'
                            b'fetch(API+"/auth/login");'
                            b'const k="sk_live_51H8xTestKey0000";'),
                "main.js.map": sourcemap}))
            rows, meta = be.audit_archive(f)
        self.assertEqual(meta["entries_scanned"], 2)
        kinds = {r.get("kind") for r in rows}
        self.assertIn("urls", kinds)
        self.assertIn("api_paths", kinds)
        self.assertIn("secret-literal", kinds)
        self.assertIn("sourcemap", kinds)
        # endpoint dari source asli sourcemap terlihat dgn provenance
        api_row = next(r for r in rows if r.get("kind") == "api_paths")
        self.assertTrue(any("/internal/reset" in i
                            for i in api_row["items"]))
        self.assertTrue(any("#sources[0]" in fl
                            for fl in api_row["files"]))
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_corrupt_header_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "broken.asar"
            f.write_bytes(b"bukan asar sama sekali")
            rows, meta = be.audit_archive(f)
        self.assertEqual(rows, [])
        self.assertIn("error", meta)


class ApkTest(unittest.TestCase):
    def test_zip_entries_and_dex_strings(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "app.apk"
            dex = (b"dex\x0a" + b"\x00" * 20
                   + b"https://api.example-app.com/v2/push"
                   + b"\x00" * 4 + b"AKIAIOSFODNN7EXAMPLE")
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("assets/config.json", json.dumps({
                    "endpoint": "https://api.example-app.com/v2"}))
                zf.writestr("classes.dex", dex)
                zf.writestr("META-INF/", "")
            rows, meta = be.audit_archive(f)
        self.assertEqual(meta["entries_scanned"], 2)
        kinds = {r.get("kind") for r in rows}
        self.assertIn("urls", kinds)
        self.assertIn("secret-literal", kinds)
        # dex ikut lewat strings surface (URL + AKIA secret)
        secret = next(r for r in rows
                      if r.get("kind") == "secret-literal")
        self.assertEqual(secret["verdict"], 1)
        self.assertIn("classes.dex", secret["target_url"])

    def test_clean_zip_single_aman(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "clean.zip"
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("readme.txt", "tidak ada apa apa")
            rows, meta = be.audit_archive(f)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)

    def test_unknown_format_error(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "x.rar"
            f.write_bytes(b"RAR!")
            rows, meta = be.audit_archive(f)
        self.assertEqual(rows, [])
        self.assertIn("error", meta)


if __name__ == "__main__":
    unittest.main()
