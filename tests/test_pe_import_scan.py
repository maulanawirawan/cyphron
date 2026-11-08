"""Nol jaringan — test pe_import_scan (triase statis PE: IAT capability,
resource ter-embed, overlay, timestamp; fail-closed).

Fixture PE dibangun di runtime dari spesifikasi PE/COFF terpublikasi
(minimal PE32: DOS header, COFF, optional header 16 data directory,
satu section, import table, resource tree 3 tingkat, overlay).
"""
from __future__ import annotations

import json
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import pe_import_scan as pis  # noqa: E402

VA = 0x1000
VSIZE = 0x2000
RAW_PTR = 0x200
RAW_SIZE = 0x2000


def _build_pe32(timestamp: int = 1735630930,
                imports: "list[tuple[str, list[str]]] | None" = None,
                resource: "bytes | None" = None,
                overlay: bytes = b"") -> bytes:
    """Bangun minimal PE32 i386 sah dari spesifikasi publik."""
    body = bytearray(RAW_SIZE)
    alloc = 0

    def put(blob: bytes, align: int = 4) -> int:
        nonlocal alloc
        off = alloc + ((-alloc) % align)
        if off + len(blob) > RAW_SIZE:
            raise ValueError("body penuh")
        body[off:off + len(blob)] = blob
        alloc = off + len(blob)
        return off

    def rva(off: int) -> int:
        return VA + off

    # ---- import table ----
    imp_desc_rva = 0
    if imports:
        n = len(imports)
        desc_off = put(b"\x00" * (20 * (n + 1)))
        imp_desc_rva = rva(desc_off)
        for di, (dll, funcs) in enumerate(imports):
            dll_off = put(dll.encode("ascii") + b"\x00", align=2)
            thunk_off = put(b"\x00" * (4 * (len(funcs) + 1)))
            for fi, fn in enumerate(funcs):
                if fn.startswith("#ordinal-"):
                    struct.pack_into(
                        "<I", body, thunk_off + 4 * fi,
                        0x80000000 | int(fn.split("-")[1]))
                else:
                    hn_off = put(b"\x00\x00" + fn.encode("ascii") +
                                 b"\x00", align=2)
                    struct.pack_into("<I", body, thunk_off + 4 * fi,
                                     rva(hn_off))
            struct.pack_into("<IIIII", body, desc_off + 20 * di,
                             rva(thunk_off), 0, 0, rva(dll_off),
                             rva(thunk_off))

    # ---- resource tree 3 tingkat ----
    res_root_rva = 0
    if resource is not None:
        root_off = put(b"\x00" * 24, align=8)
        l1_off = put(b"\x00" * 24, align=8)
        l2_off = put(b"\x00" * 24, align=8)
        blob_off = put(resource)
        data_off = put(struct.pack("<II", rva(blob_off), len(resource)))
        for d in (root_off, l1_off, l2_off):
            struct.pack_into("<HH", body, d + 12, 0, 1)  # 1 id-entry
        struct.pack_into("<II", body, root_off + 16, 10,
                         0x80000000 | (l1_off - root_off))
        struct.pack_into("<II", body, l1_off + 16, 1,
                         0x80000000 | (l2_off - root_off))
        struct.pack_into("<II", body, l2_off + 16, 0x409,
                         data_off - root_off)
        res_root_rva = rva(root_off)

    # ---- headers ----
    hdr = bytearray(0x80)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    pe = bytearray()
    pe += hdr
    pe += struct.pack("<I", 0x00004550)
    pe += struct.pack("<HHIIIHH", 0x014C, 1, timestamp, 0, 0, 224, 0x22)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 28, 0x400000)      # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)         # FileAlignment
    struct.pack_into("<I", opt, 56, VA + VSIZE)    # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)         # SizeOfHeaders
    struct.pack_into("<I", opt, 96, 16)            # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 96 + 1 * 8, imp_desc_rva,
                     20 * (len(imports) + 1) if imports else 0)
    struct.pack_into("<II", opt, 96 + 2 * 8, res_root_rva,
                     96 if resource is not None else 0)
    pe += opt
    pe += struct.pack("<8sIIIIIIHHl", b".text", VSIZE, VA, RAW_SIZE,
                      RAW_PTR, 0, 0, 0, 0, 0)
    pe = pe[:0x200].ljust(0x200, b"\x00")
    return bytes(pe) + bytes(body) + overlay


def _write(tmp: "tempfile._TemporaryFileWrapper | Path", data: bytes) -> Path:
    p = Path(tmp.name if hasattr(tmp, "name") else tmp)
    p.write_bytes(data)
    return p


class Entropy(unittest.TestCase):
    def test_bounds(self) -> None:
        self.assertEqual(pis.shannon_entropy(b""), 0.0)
        self.assertEqual(pis.shannon_entropy(b"\x00" * 1000), 0.0)
        uni = bytes(range(256)) * 4
        self.assertAlmostEqual(pis.shannon_entropy(uni), 8.0, places=5)

    def test_less_entropy_than_uniform(self) -> None:
        skew = b"\x00" * 900 + b"\x01" * 100
        self.assertLess(pis.shannon_entropy(skew), 1.0)


class CleanPE(unittest.TestCase):
    def test_benign_imports_no_findings(self) -> None:
        data = _build_pe32(imports=[
            ("kernel32.dll", ["CreateFileA", "CloseHandle"]),
            ("user32.dll", ["MessageBoxA"]),
        ])
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as fh:
            fh.write(data)
            path = Path(fh.name)
        try:
            res = pis.scan(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(res["summary"]["total"], 0)
        self.assertEqual(res["imports"]["total_imports"], 3)
        self.assertEqual(res["imports"]["clusters"], [])

    def test_common_network_api_not_flagged(self) -> None:
        # WSAStartup/connect/getaddrinfo TIDAK di tabel sinyal (anti-FP)
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as fh:
            fh.write(_build_pe32(imports=[
                ("ws2_32.dll", ["WSAStartup", "connect", "getaddrinfo"]),
            ]))
            path = Path(fh.name)
        try:
            res = pis.scan(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(res["summary"]["total"], 0)


class CapabilityClassification(unittest.TestCase):
    def _scan(self, data: bytes) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as fh:
            fh.write(data)
            path = Path(fh.name)
        try:
            return pis.scan(path)
        finally:
            path.unlink(missing_ok=True)

    def test_single_high_signal_api(self) -> None:
        res = self._scan(_build_pe32(imports=[
            ("kernel32.dll", ["VirtualAllocEx"]),
        ]))
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertIn("iat-capability/injection", by_id)
        self.assertEqual(by_id["iat-capability/injection"]["level"],
                         "high")

    def test_crypto_alone_is_info(self) -> None:
        res = self._scan(_build_pe32(imports=[
            ("advapi32.dll", ["CryptAcquireContextA", "CryptEncrypt",
                              "CryptDecrypt"]),
        ]))
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertEqual(by_id["iat-capability/crypto"]["level"], "info")

    def test_dropper_combo_requires_three_clusters(self) -> None:
        # 2 klaster saja TIDAK memicu catatan kombinasi (anti-FP)
        res = self._scan(_build_pe32(imports=[
            ("kernel32.dll", ["VirtualAllocEx"]),
            ("wininet.dll", ["URLDownloadToFileA", "InternetOpenA"]),
        ]))
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertNotIn("pola dropper",
                         by_id["iat-capability/injection"]["note"])
        # 3 klaster (tambah evasion) -> kombinasi dropper
        res2 = self._scan(_build_pe32(imports=[
            ("kernel32.dll", ["VirtualAllocEx"]),
            ("wininet.dll", ["URLDownloadToFileA"]),
            ("kernel32.dll", ["IsDebuggerPresent"]),
        ]))
        by_id2 = {f["id"]: f for f in res2["findings"]}
        self.assertIn("pola dropper",
                      by_id2["iat-capability/injection"]["note"])
        self.assertEqual(by_id2["iat-capability/injection"]["level"],
                         "high")

    def test_ordinal_import_recorded(self) -> None:
        res = self._scan(_build_pe32(imports=[
            ("shell32.dll", ["#ordinal-42"]),
        ]))
        self.assertEqual(res["imports"]["total_imports"], 1)
        hits = res["imports"]["hits"]
        self.assertEqual(hits, [])  # ordinal tak dikenali nama = tanpa sinyal


class ResourceOverlay(unittest.TestCase):
    def _scan(self, data: bytes) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as fh:
            fh.write(data)
            path = Path(fh.name)
        try:
            return pis.scan(path)
        finally:
            path.unlink(missing_ok=True)

    def test_embedded_pe_resource_high(self) -> None:
        blob = b"MZ" + b"\x00" * 512  # magic MZ di resource
        res = self._scan(_build_pe32(resource=blob))
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("resource/embedded-pe", ids)
        f = next(f for f in res["findings"]
                 if f["id"] == "resource/embedded-pe")
        self.assertEqual(f["level"], "high")
        self.assertEqual(f["resource_path"], [10, 1, 0x409])

    def test_high_entropy_resource_medium(self) -> None:
        rng = random.Random(1234)
        blob = bytes(rng.getrandbits(8) for _ in range(4096))
        res = self._scan(_build_pe32(resource=blob))
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("resource/high-entropy", ids)
        self.assertNotIn("resource/embedded-pe", ids)

    def test_small_low_entropy_resource_no_finding(self) -> None:
        res = self._scan(_build_pe32(resource=b"konfigurasi XML" * 8))
        ids = [f["id"] for f in res["findings"]
               if f["id"].startswith("resource/")]
        self.assertEqual(ids, [])

    def test_overlay_zip_signature_medium(self) -> None:
        res = self._scan(_build_pe32(
            overlay=b"\x00" * 128 + b"PK\x03\x04" + b"\x00" * 64))
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertEqual(by_id["overlay/known-signature"]["level"],
                         "medium")
        self.assertEqual(by_id["overlay/known-signature"]["signature"],
                         "zip")

    def test_overlay_plain_info_not_leveled(self) -> None:
        res = self._scan(_build_pe32(overlay=b"abc" * 50))
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertEqual(by_id["overlay/present"]["level"], "info")

    def test_no_overlay_no_finding(self) -> None:
        res = self._scan(_build_pe32())
        self.assertFalse(any(f["id"].startswith("overlay/")
                             for f in res["findings"]))


class TimestampAnomaly(unittest.TestCase):
    def _scan(self, timestamp: int) -> dict:
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as fh:
            fh.write(_build_pe32(timestamp=timestamp))
            path = Path(fh.name)
        try:
            return pis.scan(path)
        finally:
            path.unlink(missing_ok=True)

    def test_future_timestamp_low(self) -> None:
        year_2100 = (2100 - 1970) * 31556926
        res = self._scan(year_2100)
        f = next(f for f in res["findings"]
                 if f["id"] == "timestamp/anomali")
        self.assertEqual(f["level"], "low")
        self.assertEqual(f["year"], 2100)

    def test_zero_timestamp_info(self) -> None:
        res = self._scan(0)
        by_id = {f["id"]: f for f in res["findings"]}
        self.assertEqual(by_id["timestamp/zero"]["level"], "info")

    def test_normal_timestamp_no_finding(self) -> None:
        res = self._scan(1735630930)  # akhir 2024 — rentang wajar
        self.assertFalse(any(f["id"].startswith("timestamp/")
                             for f in res["findings"]))


class FailClosed(unittest.TestCase):
    def _must_raise(self, data: bytes) -> None:
        with self.assertRaises(pis.PEFormatError):
            with tempfile.NamedTemporaryFile(suffix=".exe",
                                             delete=False) as fh:
                fh.write(data)
                path = Path(fh.name)
            try:
                pis.scan(path)
            finally:
                path.unlink(missing_ok=True)

    def test_not_pe(self) -> None:
        self._must_raise(b"ini teks biasa, bukan PE" * 8)

    def test_bad_pe_signature(self) -> None:
        data = bytearray(_build_pe32())
        off = struct.unpack_from("<I", data, 0x3C)[0]
        struct.pack_into("<I", data, off, 0x00004551)
        self._must_raise(bytes(data))

    def test_lfanew_outside(self) -> None:
        data = bytearray(_build_pe32())
        struct.pack_into("<I", data, 0x3C, len(data) + 100)
        self._must_raise(bytes(data))

    def test_truncated_section_table(self) -> None:
        # section table span 0x178..0x1A0; potong di tengahnya
        data = _build_pe32()[:390]
        self._must_raise(data)

    def test_oversized_file_rejected(self) -> None:
        data = _build_pe32() + b"\x00" * (pis.MAX_FILE_BYTES + 1)
        self._must_raise(data)


class MainExitCodes(unittest.TestCase):
    def _run(self, argv: list[str]) -> int:
        return pis.main(argv)

    def test_exit0_clean_and_json_out(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "clean.exe"
            src.write_bytes(_build_pe32(imports=[
                ("kernel32.dll", ["CreateFileA"])]))
            out = Path(td) / "hasil.json"
            rc = self._run(["--source", str(src), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "cyphron.pe-import-scan/1")
            self.assertEqual(doc["summary"]["total"], 0)
            self.assertEqual(doc["results"][0]["checked"],
                             ["imports", "resources", "overlay",
                              "timestamp"])

    def test_exit1_on_fail_on_any(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "bad.exe"
            src.write_bytes(_build_pe32(imports=[
                ("kernel32.dll", ["VirtualAllocEx", "WriteProcessMemory"]),
                ("wininet.dll", ["URLDownloadToFileA"]),
                ("kernel32.dll", ["IsDebuggerPresent"]),
            ]))
            self.assertEqual(
                self._run(["--source", str(src), "--fail-on", "any"]), 1)

    def test_exit2_non_pe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "teks.txt"
            src.write_bytes(b"bukan PE" * 40)
            self.assertEqual(self._run(["--source", str(src)]), 2)

    def test_exit2_missing_source(self) -> None:
        self.assertEqual(self._run(["--source", "zombie-tidak-ada.exe"]), 2)


if __name__ == "__main__":
    unittest.main()
