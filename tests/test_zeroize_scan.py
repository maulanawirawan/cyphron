"""Nol jaringan — test zeroize_scan (zeroization material sensitif).

Kasus mengikuti spesifikasi internal: buffer kunci tanpa wipe = lead; memset
polos tidak dihitung (DSE); approved-wipe API membersihkan; komentar/
string tidak dihitung; nama non-rahasia (public key, path) dilewati.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import zeroize_scan as zs  # noqa: E402

C_TANPA_WIPE = """#include <string.h>

void pakai_kunci(void) {
    unsigned char api_key[32];
    memcpy(api_key, input, 32);
    proses(api_key, 32);
}
"""

C_DENGAN_WIPE = """#include <string.h>
#include <openssl/crypto.h>

void pakai_kunci(void) {
    unsigned char api_key[32];
    memcpy(api_key, input, 32);
    proses(api_key, 32);
    OPENSSL_cleanse(api_key, sizeof(api_key));
}
"""

C_MEMSET_POLOS = """void simpan_secret(void) {
    char secret_buf[64];
    isi(secret_buf);
    memset(secret_buf, 0, 64);
}
"""

C_COPY = """void salin_token(void) {
    char token_buf[64];
    muat(token_buf);
    char salinan[64];
    memcpy(salinan, token_buf, 64);
}
"""

C_BERSIH = """/* komentar: unsigned char api_key[32]; di komentar bukan kode */
void tanpa_rahasia(void) {
    char nama_file[64];
    salam("password di string bukan deklarasi");
    pakai(nama_file);
}
"""

RUST_TANPA = """fn muat_kunci() {
    let mut api_key = vec![0u8; 32];
    muat(&mut api_key);
    pakai(&api_key);
}
"""

RUST_WIPE = """use zeroize::Zeroize;

fn muat_kunci() {
    let mut api_key = vec![0u8; 32];
    muat(&mut api_key);
    pakai(&api_key);
    api_key.zeroize();
}
"""

C_GLOBAL = """unsigned char static_key[32];

void init(void) {
    muat(static_key, 32);
}
"""


def kinds(fs):
    return [f["kind"] for f in fs]


class TestC(unittest.TestCase):
    """Nol jaringan — C/C++."""

    def test_tanpa_wipe(self):
        fs = zs.scan_source(C_TANPA_WIPE, "a.c")
        self.assertIn("secret-buffer-tanpa-wipe", kinds(fs))
        self.assertIn("secret-copy-memcpy", kinds(fs))  # memcpy(api_key, input,..)
        for f in fs:
            self.assertEqual(f["severity"], "medium")

    def test_approved_wipe_menghapus_lead(self):
        fs = zs.scan_source(C_DENGAN_WIPE, "b.c")
        self.assertNotIn("secret-buffer-tanpa-wipe", kinds(fs))

    def test_memset_polos_tidak_dihitung(self):
        fs = zs.scan_source(C_MEMSET_POLOS, "c.c")
        self.assertIn("secret-buffer-tanpa-wipe", kinds(fs))

    def test_copy_memicu_tersendiri(self):
        fs = zs.scan_source(C_COPY, "d.c")
        self.assertIn("secret-copy-memcpy", kinds(fs))
        line = [f["line"] for f in fs if f["kind"] == "secret-copy-memcpy"][0]
        self.assertEqual(line, 5)

    def test_komentar_dan_string_dilewati(self):
        fs = zs.scan_source(C_BERSIH, "e.c")
        self.assertEqual(fs, [], msg=str(fs))

    def test_global_buffer(self):
        fs = zs.scan_source(C_GLOBAL, "g.c")
        self.assertIn("secret-buffer-global", kinds(fs))

    def test_nama_tidak_sensitive(self):
        src = "void f(void) { char monkey[32]; char pub_key[32]; isi(monkey, pub_key); }\n"
        fs = zs.scan_source(src, "n.c")
        self.assertEqual(fs, [], msg=str(fs))

    def test_kurung_tak_seimbang(self):
        fs = zs.scan_source("void f(void) { char api_key[8];", "x.c")
        self.assertEqual(kinds(fs), ["file-unparsed"])
        self.assertEqual(fs[0]["severity"], "high")


class TestRust(unittest.TestCase):
    """Nol jaringan — Rust."""

    def test_tanpa_zeroize(self):
        fs = zs.scan_source(RUST_TANPA, "a.rs")
        self.assertIn("secret-buffer-tanpa-wipe", kinds(fs))

    def test_zeroize_menghapus_lead(self):
        fs = zs.scan_source(RUST_WIPE, "b.rs")
        self.assertNotIn("secret-buffer-tanpa-wipe", kinds(fs))

    def test_string_bukan_deklarasi(self):
        src = 'fn f() { let s = "password di string"; pakai(s); }\n'
        fs = zs.scan_source(src, "c.rs")
        self.assertEqual(fs, [], msg=str(fs))


class TestMain(unittest.TestCase):
    """Nol jaringan — CLI + exit codes + meta."""

    def write(self, td: Path, name: str, text: str) -> str:
        p = td / name
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bersih = self.write(td, "ok.c", C_BERSIH)
            self.assertEqual(zs.main(["--source", bersih]), 0)
            kotor = self.write(td, "ko.c", C_TANPA_WIPE)
            self.assertEqual(zs.main(["--source", kotor]), 1)
            self.assertEqual(
                zs.main(["--source", kotor, "--fail-on", "high"]), 0)
            self.assertEqual(zs.main(["--source", str(td / "tak-ada.c")]), 2)

    def test_direktori_ekstensi_difilter(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            self.write(td, "a.c", C_TANPA_WIPE)
            self.write(td, "b.txt", C_TANPA_WIPE)   # bukan target
            self.write(td, "c.rs", RUST_TANPA)
            self.assertEqual(zs.main(["--source", str(td)]), 1)

    def test_json_out(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            kotor = self.write(td, "ko.c", C_TANPA_WIPE)
            out = td / "o.json"
            self.assertEqual(zs.main(["--source", kotor, "--json", str(out)]), 1)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], zs.SCHEMA)
            self.assertEqual(data["meta"]["scanned"], 1)
            self.assertGreaterEqual(data["meta"]["findings"], 2)


if __name__ == "__main__":
    unittest.main()
