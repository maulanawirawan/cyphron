"""Test F49 — bundle exposure audit (sisi defensif kelas tool RE).

NOL jaringan. Yang dikunci: URL/path API/secret ber-format/flag debug
terdeteksi; kode bersih = satu baris AMAN; fail-closed file tidak ada;
kontrak valid semua baris.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import bundle_exposure as be  # noqa: E402
from findings import validate_finding  # noqa: E402


def _write(tmp: Path, content: str) -> Path:
    f = tmp / "app.js"
    f.write_text(content, encoding="utf-8")
    return f


class BundleExposureTest(unittest.TestCase):
    def test_endpoints_secret_flag_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = _write(Path(td),
                       'const API = "https://api.example-app.com/v2";\n'
                       'fetch(API + "/auth/login");\n'
                       'fetch(API + "/admin/export-all");\n'
                       'const DEBUG_SECRET = "sk_live_51H8xTestKey0000";\n'
                       'var adminMode = true;\n')
            rows, meta = be.audit_bundle(f)
        kinds = {r.get("kind") for r in rows}
        self.assertIn("urls", kinds)
        self.assertIn("api_paths", kinds)
        self.assertIn("secret-literal", kinds)
        self.assertIn("debug-flag", kinds)
        self.assertEqual(meta["api_paths"], 2)
        self.assertTrue(all(validate_finding(r) == [] for r in rows))
        # L0 inventaris utk URL/path; L1 lead utk secret/flag
        self.assertTrue(any(r["verdict"] == 1 for r in rows))

    def test_clean_code_single_aman(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = _write(Path(td), "export function add(a, b) {\n"
                                 "  return a + b;\n}\n")
            rows, meta = be.audit_bundle(f)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(meta["exposures"], 0)

    def test_placeholder_still_lead_not_claim(self):
        # nilai secret-shaped tetap LEAD (verifikasi manual) — tidak
        # pernah diklaim pasti nyata
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            f = _write(Path(td), 'const k = "ghp_' + "a" * 36 + '";\n')
            rows, meta = be.audit_bundle(f)
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertEqual(rows[0]["cwe"], "CWE-798")

    def test_missing_file_fail_closed(self):
        rows, meta = be.audit_bundle(Path("Z:/tidak/ada.js"))
        self.assertEqual(rows, [])
        self.assertIn("error", meta)

    def test_demo_bundle_end_to_end(self):
        # bundle nyata yang dipakai verifikasi rea — hasil harus setara
        f = ROOT / "scratch" / "rea-target-app" / "app.js"
        if not f.exists():
            self.skipTest("fixture demo tidak ada")
        rows, meta = be.audit_bundle(f)
        self.assertEqual(meta["api_paths"], 2)
        self.assertEqual(meta["secrets"], 1)


class TreeAuditTest(unittest.TestCase):
    """F50 — pohon bundle: walk bounded, sourcemap ter-deploy = lead
    (CWE-540) + isinya ikut diaudit, dedup lintas-file (fakta unik =
    satu baris dgn daftar file)."""

    def _mk_tree(self, td: Path) -> Path:
        dist = td / "dist"
        dist.mkdir(parents=True)
        nl = chr(10)
        (dist / "app.js").write_text(
            'const API="https://api.example-app.com/v2";' + nl +
            'fetch(API+"/auth/login");' + nl +
            'const k="sk_live_51H8xTestKey0000";' + nl, encoding="utf-8")
        (dist / "vendor.js").write_text(
            'fetch("https://cdn.vendor.example/v2/track");' + nl +
            'var debugMode = true;' + nl, encoding="utf-8")
        (dist / "app.js.map").write_text(json.dumps({
            "version": 3, "sources": ["src/app.ts"],
            "sourcesContent": [
                '// internal saja' + nl +
                'fetch(API+"/internal/debug");' + nl]}), encoding="utf-8")
        (dist / "readme.txt").write_text("bukan bundle", encoding="utf-8")
        return dist

    def test_tree_dedup_and_sourcemap(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            dist = self._mk_tree(Path(td))
            rows, meta = be.audit_tree(dist)
        self.assertEqual(meta["files_found"], 3)  # .txt tidak dipindai
        self.assertEqual(meta["sourcemaps"], 1)
        kinds = {r.get("kind") for r in rows}
        self.assertIn("sourcemap", kinds)
        self.assertIn("urls", kinds)
        self.assertIn("api_paths", kinds)
        # dedup: baris URL menggabungkan kedua file produksi
        urls_row = next(r for r in rows if r.get("kind") == "urls")
        self.assertEqual(sorted(urls_row["files"]),
                         ["app.js", "vendor.js"])
        # endpoint internal dari source asli dalam sourcemap terlihat,
        # dan file sumbernya tercatat sebagai app.js.map#sources[0]
        api_row = next(r for r in rows if r.get("kind") == "api_paths")
        self.assertTrue(any("/internal/debug" in i
                            for i in api_row["items"]))
        self.assertIn("app.js.map#sources[0]", api_row["files"])
        # secret lead membawa daftar file
        secret = next(r for r in rows if r.get("kind") == "secret-literal")
        self.assertEqual(secret["files"], ["app.js"])
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_tree_clean_single_aman(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            dist = Path(td) / "dist"
            dist.mkdir()
            (dist / "ok.js").write_text(
                "export const add = (a, b) => a + b;" + chr(10),
                encoding="utf-8")
            rows, meta = be.audit_tree(dist)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)

    def test_tree_missing_dir_fail_closed(self):
        rows, meta = be.audit_tree(Path("Z:/tidak/ada"))
        self.assertEqual(rows, [])
        self.assertIn("error", meta)


class RestoreTest(unittest.TestCase):
    """F51 — restore source asli dari sourcemap: artefak fisik 'yang
    bisa direcover attacker'; anti-traversal WAJIB (disiplin lfi)."""

    def test_restore_writes_safe_sources_blocks_traversal(self):
        import json as _json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            dist = td / "dist"
            dist.mkdir()
            (dist / "app.js.map").write_text(_json.dumps({
                "sources": ["../src/evil.ts", "src/ok.ts",
                            "C:/win/evil.ts"],
                "sourcesContent": ["HARUS DITOLAK",
                                   "const ok = 1;",
                                   "HARUS DITOLAK"]}), encoding="utf-8")
            restore = td / "restored"
            rows, meta = be.audit_tree(dist, restore_dir=restore)
            self.assertEqual(meta["restored"], 1)
            self.assertEqual(meta["restore_blocked"], 2)
            ok_file = restore / "app.js" / "src" / "ok.ts"
            self.assertTrue(ok_file.exists())
            self.assertEqual(ok_file.read_text(encoding="utf-8"),
                             "const ok = 1;")
            # tidak ada file baru di luar folder restore
            outside = [p for p in td.rglob("evil.ts")]
            self.assertEqual(outside, [])


class BinarySurfaceTest(unittest.TestCase):
    """F51 — binary strings surface: ASCII + UTF-16LE dgn offset byte;
    secret = lead L1 (CWE-798); bersih = AMAN; fail-closed."""

    def _bin(self, td: Path, content: bytes) -> Path:
        f = td / "app.exe"
        f.write_bytes(content)
        return f

    def test_real_module_ascii_utf16_offsets(self):
        import tempfile
        import binary_strings_surface as bs
        with tempfile.TemporaryDirectory() as td:
            data = (b"MZ" + b"\x00" * 40
                    + b"https://api.example-app.com/v2/auth"
                    + b"\x00" * 4 + b"sk_live_51H8xTestKey0000"
                    + b"\x00" * 4
                    + "https://telemetry.example.com/ping".encode(
                        "utf-16-le"))
            rows, meta = bs.audit_binary(self._bin(Path(td), data))
        self.assertEqual(meta["urls"], 2)
        self.assertEqual(meta["secrets"], 1)
        url_row = next(r for r in rows if r.get("kind") == "urls")
        offsets = [i["offset_hex"] for i in url_row["items"]]
        self.assertEqual(len(offsets), 2)
        self.assertTrue(all(o.startswith("0x") for o in offsets))
        secret = next(r for r in rows
                      if r.get("kind") == "secret-literal")
        self.assertEqual(secret["verdict"], 1)
        self.assertEqual(secret["cwe"], "CWE-798")
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_clean_binary_single_aman(self):
        import tempfile
        import binary_strings_surface as bs
        with tempfile.TemporaryDirectory() as td:
            rows, meta = bs.audit_binary(
                self._bin(Path(td), b"MZ" + b"\x00" * 64))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], 0)

    def test_missing_binary_fail_closed(self):
        import binary_strings_surface as bs
        rows, meta = bs.audit_binary(Path("Z:/tidak/ada.exe"))
        self.assertEqual(rows, [])
        self.assertIn("error", meta)


if __name__ == "__main__":
    unittest.main()
