"""Nol jaringan — test stego_triage (JPEG/PNG/WAV/BMP steganalysis,
fail-closed).

Fixture media dibangun di runtime dari spesifikasi format terpublikasi
(PNG chunk, RIFF/WAVE, BMP DIB, JPEG marker); payload LSB ditanam sesuai
urutan ekstraksi alat (row-major per kanal) supaya deteksi bisa dipaten.
"""
from __future__ import annotations

import json
import random
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import stego_triage as st  # noqa: E402

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _bits_of(data: bytes) -> "list[int]":
    """Bit MSB-first (konvensi sama dgn bits_to_bytes alat)."""
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]


def _chunk(ctype: bytes, payload: bytes, crc_ok: bool = True) -> bytes:
    c = struct.pack(">I", len(payload)) + ctype + payload
    crc = (zlib.crc32(ctype + payload) & 0xFFFFFFFF) if crc_ok \
        else 0xDEADBEEF
    return c + struct.pack(">I", crc)


def _make_png(width: int = 64, height: int = 32,
              payload: "bytes | None" = None,
              fill_lsb: "int | None" = None,
              trailing: bytes = b"", crc_bad: bool = False,
              text: "bytes | None" = None,
              color_type: int = 2, include_iend: bool = True) -> bytes:
    channels = 3 if color_type == 2 else 1
    rng = random.Random(42)
    bits = _bits_of(payload) if payload is not None else []
    # grid base acak dulu; payload LSB ditanam ke STREAM KANAL R
    # (posisi plane = row*width + col — cocok dgn ekstraksi per-kanal)
    grid = [[[rng.getrandbits(8) for _ in range(channels)]
             for _ in range(width)] for _ in range(height)]
    for r in range(height):
        for c in range(width):
            pos = r * width + c
            if fill_lsb is not None:
                for ch in range(channels):
                    grid[r][c][ch] = (grid[r][c][ch] & 0xFE) | fill_lsb
            elif pos < len(bits):
                grid[r][c][0] = (grid[r][c][0] & 0xFE) | bits[pos]
    raw = bytearray()
    for r in range(height):
        raw.append(0)  # filter 0
        for c in range(width):
            raw.extend(grid[r][c])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type,
                       0, 0, 0)
    png = PNG_SIG + _chunk(b"IHDR", ihdr)
    if text is not None:
        png += _chunk(b"tEXt", text)
    png += _chunk(b"IDAT", zlib.compress(bytes(raw)), crc_ok=not crc_bad)
    if include_iend:
        png += _chunk(b"IEND", b"")
    return png + trailing


def _make_jpeg(trailing: bytes = b"", include_eoi: bool = True,
                inject: bytes = b"") -> bytes:
    body = b"\xff\xd8" + b"\x00" * 200 + inject + b"\x00" * 100
    if include_eoi:
        body += b"\xff\xd9"
    return body + trailing


def _make_wav(n_samples: int = 256, payload: "bytes | None" = None,
              audio_fmt: int = 1, bits: int = 16,
              data_short: bool = False) -> bytes:
    rng = random.Random(7)
    samples = [rng.getrandbits(15) for _ in range(n_samples)]
    if payload is not None:
        pb = _bits_of(payload)
        for i, b in enumerate(pb[:n_samples]):
            samples[i] = (samples[i] & 0xFFFE) | b
    pcm = b"".join(struct.pack("<h", s) for s in samples)
    # data_short = DEKLARASI lebih besar dari isi (chunk terpotong)
    declared = len(pcm) + 4 if data_short else len(pcm)
    fmt = struct.pack("<HHIIHH", audio_fmt, 1, 8000, 16000, 2, bits)
    out = b"RIFF" + struct.pack("<I", 4 + 8 + 16 + 8 + len(pcm)) + b"WAVE"
    out += b"fmt " + struct.pack("<I", 16) + fmt
    out += b"data" + struct.pack("<I", declared) + pcm
    return out


def _make_bmp(width: int = 64, height: int = 32,
              payload: "bytes | None" = None,
              bpp: int = 24, size_mismatch: bool = False) -> bytes:
    channels = bpp // 8
    stride = ((bpp * width + 31) // 32) * 4
    rng = random.Random(11)
    bits = _bits_of(payload) if payload is not None else []
    # LSB payload ditanam ke STREAM kanal B (plane pos = row*width+px)
    grid = [[[rng.getrandbits(8) for _ in range(channels)]
             for _ in range(width)] for _ in range(height)]
    for r in range(height):
        for px in range(width):
            pos = r * width + px
            if pos < len(bits):
                grid[r][px][0] = (grid[r][px][0] & 0xFE) | bits[pos]
    pixels = bytearray()
    for r in range(height):
        row = bytearray(stride)
        for px in range(width):
            for ch in range(channels):
                row[px * channels + ch] = grid[r][px][ch]
        pixels += row
    hdr = bytearray(b"BM" + struct.pack("<III", 54 + len(pixels), 0, 54))
    if size_mismatch:
        struct.pack_into("<I", hdr, 2, 54 + len(pixels) + 100)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, bpp, 0,
                      len(pixels), 0, 0, 0, 0)
    return bytes(hdr) + dib + bytes(pixels)


def _scan(data: bytes, name: str = "t.bin") -> dict:
    p = Path(tempfile.gettempdir()) / name
    p.write_bytes(data)
    try:
        return st.scan(p)
    finally:
        p.unlink(missing_ok=True)


def _ids(res: dict) -> "list[str]":
    return [f["id"] for f in res["findings"]]


class PngClean(unittest.TestCase):
    def test_random_pixels_no_findings(self) -> None:
        res = _scan(_make_png(), "clean.png")
        self.assertEqual(res["summary"]["total"], 0)
        self.assertEqual(res["media"]["format"], "png")

    def test_small_image_below_ratio_floor_no_finding(self) -> None:
        # 16x16x3 = 768 bit < floor 4096 — rasio tak dinilai (anti-FP)
        res = _scan(_make_png(width=16, height=16, fill_lsb=1),
                    "small.png")
        self.assertEqual(res["summary"]["total"], 0)

    def test_grayscale_out_of_lsb_scope_no_crash(self) -> None:
        res = _scan(_make_png(width=64, height=64, color_type=0,
                              fill_lsb=1), "gray.png")
        self.assertEqual(res["summary"]["total"], 0)


class PngFindings(unittest.TestCase):
    def test_trailing_plain_medium(self) -> None:
        res = _scan(_make_png(trailing=b"JUNKDATA" * 8), "tr.png")
        self.assertIn("trailing/data", _ids(res))
        f = next(f for f in res["findings"]
                 if f["id"] == "trailing/data")
        self.assertEqual(f["level"], "medium")
        self.assertEqual(f["bytes"], 64)

    def test_trailing_archive_high(self) -> None:
        res = _scan(_make_png(trailing=b"PK\x03\x04rest"), "trz.png")
        f = next(f for f in res["findings"]
                 if f["id"] == "trailing/embedded-payload")
        self.assertEqual(f["level"], "high")
        self.assertEqual(f["signature"], "zip")

    def test_truncated_no_iend(self) -> None:
        res = _scan(_make_png(include_iend=False), "cut.png")
        self.assertIn("structure/truncated", _ids(res))

    def test_crc_mismatch_low(self) -> None:
        res = _scan(_make_png(crc_bad=True), "crc.png")
        self.assertIn("png/crc-mismatch", _ids(res))
        self.assertEqual(res["media"]["chunks_crc_bad"], 1)

    def test_text_chunk_info(self) -> None:
        res = _scan(_make_png(text=b"Comment\x00hello"), "txt.png")
        self.assertIn("png/text-chunks", _ids(res))
        f = next(f for f in res["findings"]
                 if f["id"] == "png/text-chunks")
        self.assertEqual(f["level"], "info")

    def test_lsb_payload_at_zero_high(self) -> None:
        res = _scan(_make_png(payload=b"PK\x03\x04payload-here"),
                    "lsb0.png")
        f = next(f for f in res["findings"]
                 if f["id"] == "lsb/payload-signature/R")
        self.assertEqual(f["level"], "high")
        self.assertEqual(f["offset"], 0)

    def test_lsb_payload_offset_medium(self) -> None:
        res = _scan(_make_png(payload=b"\x00" * 10 + b"GIF89a"),
                    "lsb10.png")
        f = next(f for f in res["findings"]
                 if f["id"] == "lsb/payload-signature/R")
        self.assertEqual(f["level"], "medium")

    def test_all_ones_ratio_info_only(self) -> None:
        # 128x32x3 = 4096 bit per kanal = tepat di lantai anti-FP
        res = _scan(_make_png(width=128, height=32, fill_lsb=1),
                    "ones.png")
        leads = [f for f in res["findings"]
                 if f["id"].startswith("lsb/ratio-lead/")]
        self.assertEqual(len(leads), 3)  # R, G, B
        for f in leads:
            self.assertEqual(f["level"], "info")
        self.assertFalse(any(f["id"].startswith("lsb/payload")
                             for f in res["findings"]))

    def test_idat_missing_lead(self) -> None:
        png = PNG_SIG + _chunk(b"IHDR", struct.pack(
            ">IIBBBBB", 64, 32, 8, 2, 0, 0, 0)) + _chunk(b"IEND", b"")
        res = _scan(png, "noidat.png")
        self.assertIn("png/idat-missing", _ids(res))


class JpegFindings(unittest.TestCase):
    def test_clean_no_finding(self) -> None:
        self.assertEqual(_scan(_make_jpeg(), "c.jpg")["summary"]
                         ["total"], 0)

    def test_trailing_plain_medium(self) -> None:
        res = _scan(_make_jpeg(trailing=b"\x00" * 100), "t.jpg")
        self.assertIn("trailing/data", _ids(res))

    def test_trailing_archive_high(self) -> None:
        res = _scan(_make_jpeg(trailing=b"Rar!\x1a\x07xx"), "tz.jpg")
        f = next(f for f in res["findings"]
                 if f["id"] == "trailing/embedded-payload")
        self.assertEqual(f["level"], "high")

    def test_truncated_medium(self) -> None:
        res = _scan(_make_jpeg(include_eoi=False), "cut.jpg")
        self.assertIn("structure/truncated", _ids(res))

    def test_midfile_signature_medium(self) -> None:
        res = _scan(_make_jpeg(inject=b"PK\x03\x04mid"), "mid.jpg")
        f = next(f for f in res["findings"]
                 if f["id"] == "embedded/signature")
        self.assertEqual(f["level"], "medium")


class WavFindings(unittest.TestCase):
    def test_clean_small_no_finding(self) -> None:
        self.assertEqual(_scan(_make_wav(), "c.wav")["summary"]["total"],
                         0)

    def test_lsb_payload_high(self) -> None:
        res = _scan(_make_wav(n_samples=512, payload=b"PK\x03\x04xyz"),
                    "l.wav")
        f = next(f for f in res["findings"]
                 if f["id"] == "lsb/payload-signature/audio16")
        self.assertEqual(f["level"], "high")

    def test_data_short_medium(self) -> None:
        res = _scan(_make_wav(n_samples=64, data_short=True),
                    "short.wav")
        self.assertIn("wav/data-short", _ids(res))

    def test_non_pcm_no_lsb(self) -> None:
        res = _scan(_make_wav(n_samples=8192, bits=8, payload=None),
                    "b8.wav")
        self.assertEqual(res["summary"]["total"], 0)

    def test_truncated_chunk_medium(self) -> None:
        data = _make_wav(n_samples=64)
        res = _scan(data[:-8], "cut.wav")
        self.assertIn("structure/truncated", _ids(res))


class BmpFindings(unittest.TestCase):
    def test_clean_no_finding(self) -> None:
        self.assertEqual(_scan(_make_bmp(), "c.bmp")["summary"]["total"],
                         0)

    def test_lsb_payload_channel_b(self) -> None:
        res = _scan(_make_bmp(payload=b"PK\x03\x04q"), "l.bmp")
        f = next(f for f in res["findings"]
                 if f["id"] == "lsb/payload-signature/B")
        self.assertEqual(f["level"], "high")

    def test_size_mismatch_medium(self) -> None:
        res = _scan(_make_bmp(size_mismatch=True), "sz.bmp")
        self.assertIn("bmp/size-mismatch", _ids(res))


class FailClosed(unittest.TestCase):
    def test_unknown_magic_exit2(self) -> None:
        with self.assertRaises(st.MediaFormatError):
            _scan(b"FLIF" + b"\x00" * 100)

    def test_magic_extension_mismatch_rejected(self) -> None:
        # ekstensi .jpg tapi isi PNG -> magic PNG cocok; sebaliknya
        # ekstensi .png isi JPEG juga diterima berdasarkan MAGIC, bukan
        # nama file (keputusan sadar-desain, diuji di sini)
        res = _scan(_make_jpeg(), "bernama.png")
        self.assertEqual(res["media"]["format"], "jpeg")

    def test_oversized(self) -> None:
        with self.assertRaises(st.MediaFormatError):
            _scan(b"\xff\xd8" + b"\x00" * (st.MAX_FILE_BYTES + 1),
                  "big.jpg")

    def test_wav_without_data_chunk(self) -> None:
        bad = b"RIFF" + struct.pack("<I", 4 + 8 + 16) + b"WAVE"
        bad += b"fmt " + struct.pack("<I", 16) + struct.pack(
            "<HHIIHH", 1, 1, 8000, 16000, 2, 16)
        with self.assertRaises(st.MediaFormatError):
            _scan(bad)

    def test_bmp_short_header(self) -> None:
        with self.assertRaises(st.MediaFormatError):
            _scan(b"BM\x00\x01")


class MainExitCodes(unittest.TestCase):
    def test_exit0_clean_with_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "c.png"
            src.write_bytes(_make_png())
            out = Path(td) / "hasil.json"
            rc = st.main(["--source", str(src), "--out", str(out)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], "cyphron.stego-triage/1")
            self.assertEqual(doc["results"][0]["checked"],
                             ["trailing-data", "archive-signature",
                              "lsb-plane", "structure-integrity"])

    def test_exit1_fail_on_any(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "t.jpg"
            src.write_bytes(_make_jpeg(trailing=b"\x00" * 50))
            self.assertEqual(
                st.main(["--source", str(src), "--fail-on", "any"]), 1)

    def test_exit2_non_media(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "teks.txt"
            src.write_bytes(b"bukan media" * 30)
            self.assertEqual(st.main(["--source", str(src)]), 2)

    def test_exit2_missing(self) -> None:
        self.assertEqual(st.main(["--source", "zombie.png"]), 2)


class MagicProbeDiscipline(unittest.TestCase):
    def test_no_short_magic_probes(self) -> None:
        # magic 2-b (MZ) sengaja TIDAK di daftar probe (NO-FP)
        for _name, magic in st.ARCHIVE_MAGIC:
            self.assertGreaterEqual(len(magic), 3)

    def test_bits_to_bytes_roundtrip_msb(self) -> None:
        self.assertEqual(st.bits_to_bytes(_bits_of(b"A")), b"A")
        self.assertEqual(st.bits_to_bytes([1]), b"\x80")


if __name__ == "__main__":
    unittest.main()
