"""Nol jaringan — test crypto_constant_scan (#0941/#0940, konstanta kripto
tertanam + API import PE + artefak terenkripsi).

Fixtures = blob/PE sintetis dibangun byte-per-byte (konstanta dari
spesifikasi publik algoritma; PE dari spesifikasi PE/COFF Microsoft).
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import crypto_constant_scan as ccs  # noqa: E402

AES_SBOX = ccs._AES_SBOX
CHACHA = b"expand 32-byte k"
RSA_PEM = b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"


def _blob(*parts: bytes) -> bytes:
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Builder PE sintetis (2 section: .text berisi payload, .idata berisi import)
# ---------------------------------------------------------------------------

IMAGE_BASE = 0x400000


def _mk_pe(text_payload: bytes = b"",
           imports: list[tuple[str, list[str]]] | None = None) -> bytes:
    """PE32 sintetis: .text (payload) + .idata (tabel import lengkap).

    Tata letak file: [0x000 DOS/PE/opt][0x200 .text raw][0x400 .idata raw].
    .idata vaddr = 0x2000, rawptr = 0x400 -> RVA = 0x2000 + (off - 0x400).
    """
    opt_size = 224
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    pe = bytearray(24)                             # sig(4) + COFF(20)
    pe[:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 4, 0x014C, 2, 0, 0, 0, opt_size, 0x2102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)          # PE32
    struct.pack_into("<I", opt, 16, 0x1000)        # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, IMAGE_BASE)
    struct.pack_into("<I", opt, 56, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt, 60, 0x200)         # FileAlignment
    struct.pack_into("<I", opt, 92, 16)            # NumberOfRvaAndSizes
    dd_base = 96

    import_rva = import_size = 0
    idata = bytearray()
    if imports:
        desc_size = 20 * (len(imports) + 1)        # + zero terminator
        thunk_off0 = desc_size                     # offset relatif dlm body
        thunk_total = sum(4 * (len(fns) + 1) for _d, fns in imports)
        names_off0 = thunk_off0 + thunk_total

        hint_blob = bytearray()
        name_rvas: dict[str, int] = {}
        dll_rvas: dict[str, int] = {}
        for dll, fns in imports:
            for fn in fns:
                name_rvas[fn] = 0x2000 + names_off0 + len(hint_blob)
                hint_blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
                if len(hint_blob) % 2:
                    hint_blob += b"\x00"
        for dll, fns in imports:
            dll_rvas[dll] = 0x2000 + names_off0 + len(hint_blob)
            hint_blob += dll.encode() + b"\x00"

        thunk_blob = bytearray()
        thunk_rva_of_dll: dict[str, int] = {}
        for dll, fns in imports:
            thunk_rva_of_dll[dll] = 0x2000 + thunk_off0 + len(thunk_blob)
            for fn in fns:
                thunk_blob += struct.pack("<I", name_rvas[fn])
            thunk_blob += struct.pack("<I", 0)     # terminator per DLL

        desc_blob = bytearray()
        for dll, fns in imports:
            desc_blob += struct.pack("<IIIII", thunk_rva_of_dll[dll], 0, 0,
                                     dll_rvas[dll], thunk_rva_of_dll[dll])
        desc_blob += b"\x00" * 20

        idata = bytearray(desc_blob + thunk_blob + hint_blob)
        import_rva = 0x2000
        import_size = desc_size
    idata = idata.ljust(0x600, b"\x00")

    struct.pack_into("<II", opt, dd_base + 8, import_rva, import_size)

    text_raw = bytearray(0x200)
    text_raw[:len(text_payload)] = text_payload

    out = bytearray()
    out += dos + pe + opt
    # section table (40 byte per entri: nama8 + 4 int + 12 kosong + chars)
    out += b".text\x00\x00\x00" + struct.pack(
        "<IIII", 0x200, 0x1000, 0x200, 0x200) + b"\x00" * 12 + \
        struct.pack("<I", 0x60000020)
    out += b".idata\x00\x00" + struct.pack(
        "<IIII", 0x600, 0x2000, 0x600, 0x400) + b"\x00" * 12 + \
        struct.pack("<I", 0xC0000040)
    # raw section pertama dijanjikan di rawptr 0x200 -> pad ke 0x200
    out += b"\x00" * (0x200 - len(out))
    out += text_raw
    out += idata
    return bytes(out)


class TestConstants(unittest.TestCase):
    def test_constants_found_with_offsets(self):
        blob = _blob(b"A" * 1000, AES_SBOX, b"B" * 16, CHACHA)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            self.assertEqual(r["verdict"], "PRIMITIVES-PRESENT")
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("const.aes-sbox", ids)
            self.assertIn("const.chacha20-const", ids)
            sbox = next(f for f in r["findings"]
                        if f["id"] == "const.aes-sbox")
            self.assertEqual(sbox["evidence"]["offsets"], [1000])
            self.assertEqual(sbox["evidence"]["family"], "symmetric")
        finally:
            p.unlink()

    def test_clean_blob_no_false_positive(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x41" * 4096)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            self.assertEqual(r["verdict"], "NONE-KNOWN-FOUND")
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("meta.no-known-primitive", ids)
            # tidak ada temuan selain catatan meta
            self.assertTrue(all(i.startswith("meta.") for i in ids))
        finally:
            p.unlink()

    def test_incomplete_constant_not_matched(self):
        # anti-FP: konstanta terpotong tidak boleh dicocokkan — S-box
        # yang dipotong TANPA 16-byte prefix-nya tetap tak dikenali
        blob = _blob(b"expand 32-byt", b"\x00" * 64,
                     AES_SBOX[16:-1], b"\x00" * 32)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            self.assertEqual(r["verdict"], "NONE-KNOWN-FOUND")
        finally:
            p.unlink()

    def test_aes_sbox_partial_only(self):
        blob = _blob(b"\x00" * 300, AES_SBOX[:16], b"\x00" * 300)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("const.aes-sbox-partial", ids)
            self.assertNotIn("const.aes-sbox", ids)
            part = next(f for f in r["findings"]
                        if f["id"] == "const.aes-sbox-partial")
            self.assertEqual(part["severity"], "low")
        finally:
            p.unlink()


class TestPemDer(unittest.TestCase):
    def test_private_key_pem_medium(self):
        blob = _blob(b"\x00" * 128, RSA_PEM, b"\x00" * 64)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            f = next(x for x in r["findings"]
                     if x["id"] == "pem.pem-rsa-private")
            self.assertEqual(f["severity"], "medium")
        finally:
            p.unlink()

    def test_der_rsa_lead(self):
        # bentuk RSAPublicKey: SEQUENCE(len) langsung modulus
        der = b"\x30\x82\x01\x0a\x02\x82\x01\x00" + b"\xc4" * 256
        blob = _blob(b"\x00" * 64, der, b"\x00" * 32)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {x["id"] for x in r["findings"]}
            self.assertIn("der.rsa-modulus-lead", ids)
        finally:
            p.unlink()

    def test_der_rsa_private_form(self):
        # bentuk RSAPrivateKey: SEQUENCE, versi 02 01 00, lalu modulus
        der = b"\x30\x82\x01\x20\x02\x01\x00\x02\x82\x01\x00" + b"\x9a" * 256
        blob = _blob(der)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {x["id"] for x in r["findings"]}
            self.assertIn("der.rsa-modulus-lead", ids)
        finally:
            p.unlink()

    def test_no_der_false_positive(self):
        blob = _blob(b"\x30\x82\x01\x0a", b"\x02\x82\x02\x00", b"\x00" * 64)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {x["id"] for x in r["findings"]}
            self.assertNotIn("der.rsa-modulus-lead", ids)
        finally:
            p.unlink()


class TestPeImports(unittest.TestCase):
    def test_crypto_imports_and_hybrid_combo(self):
        pe = _mk_pe(
            text_payload=RSA_PEM,
            imports=[("advapi32.dll", ["CryptAcquireContextW",
                                       "CryptEncrypt"]),
                     ("bcrypt.dll", ["BCryptEncrypt"])])
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            fh.write(pe)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            self.assertEqual(r["verdict"], "PRIMITIVES-PRESENT")
            self.assertIsNotNone(r["pe"])
            self.assertEqual(r["pe"]["crypto_api_count"], 3)
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("pe.crypto-api-imports", ids)
            self.assertIn("combo.hybrid-encryption-signature", ids)
            api = next(f for f in r["findings"]
                       if f["id"] == "pe.crypto-api-imports")
            self.assertIn("CryptEncrypt", api["evidence"]["apis"])
            self.assertIn("advapi32.dll", api["evidence"]["by_dll"])
        finally:
            p.unlink()

    def test_pe_without_crypto_imports(self):
        pe = _mk_pe(imports=[("kernel32.dll", ["ExitProcess"])])
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            fh.write(pe)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {f["id"] for f in r["findings"]}
            self.assertNotIn("pe.crypto-api-imports", ids)
            self.assertNotIn("combo.hybrid-encryption-signature", ids)
            self.assertTrue(r["pe"]["import_parse_ok"])
        finally:
            p.unlink()

    def test_mz_but_broken_pe_fail_closed(self):
        blob = b"MZ" + b"\x00" * 500
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            r = ccs.scan(p)
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("pe.import-unreadable", ids)
        finally:
            p.unlink()


class TestArtifactMode(unittest.TestCase):
    def test_tail_entropy_and_header(self):
        jpeg = b"\xff\xd8\xff\xe0" + b"AB" * 200 + os.urandom(2048)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(jpeg)
            p = Path(fh.name)
        try:
            r = ccs.scan(p, artifact=True)
            f = next(x for x in r["findings"]
                     if x["id"] == "artifact.tail-high-entropy")
            self.assertEqual(f["severity"], "medium")
            sizes = [m["bytes"] for m in f["evidence"]["matches"]]
            self.assertIn(2048, sizes)
            self.assertEqual(r["artifact"]["header_magic"]["kind"], "jpeg")
        finally:
            p.unlink()

    def test_no_tail_entropy_clean_text(self):
        data = b"\x89PNG\r\n" + b"the quick brown fox " * 200
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(data)
            p = Path(fh.name)
        try:
            r = ccs.scan(p, artifact=True)
            ids = {f["id"] for f in r["findings"]}
            self.assertNotIn("artifact.tail-high-entropy", ids)
            self.assertEqual(r["artifact"]["header_magic"]["kind"], "png")
        finally:
            p.unlink()


class TestCli(unittest.TestCase):
    def test_exit_2_missing_file(self):
        self.assertEqual(ccs.main(["--file", "does-not-exist.bin"]), 2)

    def test_exit_2_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            p = Path(fh.name)
        try:
            self.assertEqual(ccs.main(["--file", str(p)]), 2)
        finally:
            p.unlink()

    def test_exit_gate(self):
        # threshold: exit 1 bila verdict >= fail-on
        blob = _blob(b"\x00" * 64, CHACHA)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        clean = Path(p.parent) / (p.name + ".clean")
        clean.write_bytes(b"\x41" * 512)
        try:
            self.assertEqual(
                ccs.main(["--file", str(p), "--fail-on",
                          "PRIMITIVES-PRESENT"]), 1)
            self.assertEqual(
                ccs.main(["--file", str(p), "--fail-on",
                          "NONE-KNOWN-FOUND"]), 1)
            self.assertEqual(
                ccs.main(["--file", str(clean), "--fail-on",
                          "PRIMITIVES-PRESENT"]), 0)
            self.assertEqual(
                ccs.main(["--file", str(clean), "--fail-on",
                          "NONE-KNOWN-FOUND"]), 1)
        finally:
            p.unlink()
            clean.unlink()

    def test_out_writes_json(self):
        blob = _blob(b"\x00" * 32, AES_SBOX)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "s.bin"
            src.write_bytes(blob)
            dst = Path(td) / "o.json"
            self.assertEqual(ccs.main(["--file", str(src), "--out",
                                       str(dst)]), 1)
            obj = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(obj["schema"], ccs.SCHEMA)
            self.assertEqual(obj["sha256"],
                             hashlib.sha256(blob).hexdigest())
            self.assertTrue(obj["read_only"])

    def test_subprocess_report(self):
        blob = _blob(b"\x00" * 32, CHACHA)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            p = Path(fh.name)
        try:
            proc = subprocess.run(
                [sys.executable, str(TOOLS / "crypto_constant_scan.py"),
                 "--file", str(p)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 1)
            obj = json.loads(proc.stdout)
            self.assertEqual(obj["verdict"], "PRIMITIVES-PRESENT")
        finally:
            p.unlink()

    def test_oversize_fail_closed(self):
        old = ccs.MAX_FILE_BYTES
        ccs.MAX_FILE_BYTES = 8
        try:
            with tempfile.NamedTemporaryFile(delete=False) as fh:
                fh.write(b"1234567890")
                p = Path(fh.name)
            try:
                self.assertEqual(ccs.main(["--file", str(p)]), 2)
            finally:
                p.unlink()
        finally:
            ccs.MAX_FILE_BYTES = old


if __name__ == "__main__":
    unittest.main()
