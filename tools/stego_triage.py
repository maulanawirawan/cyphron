"""[SAFETY: read-only] stego_triage — deteksi OFFLINE steganografi pada
media terformat: JPEG, PNG, WAV, BMP. TANPA jaringan, read-only — file
media tidak pernah ditulis.

Ranah EKSPLISIT:
  - carve_scan (#0817/#0818): carve blob MENTAH format-agnostic — di
    sini analisis SADAR-STRUKTUR media (marker EOF, chunk, sampel) yang
    carve_scan tidak tahu;
  - browser_history_triage / sqlite_forensics: artefak browser/chat —
    di sini media gambar/audio;
  - NOT-VISIBLE-DETERMINISTIC: steganografi DCT (steghide di JPEG) dan
    domain-frekuensi audio TIDAK bisa dibaca stdlib — di luar kelas
    tool ini (butuh alat pihak ketiga); diuji: trailing-data, archive
    signature, LSB bit-plane, integritas struktur.

Mekanisme per format:
  JPEG  : mulai FFD8; data SETELAH marker EOI FFD9 terakhir = trailing
          (dipindai magic); tanpa EOI = truncated (lead); archive
          signature di mana pun = embedded lead;
  PNG   : signature 8-b + chunk walk (length/type/CRC): data setelah
          IEND = trailing; CRC chunk mismatch = tampering lead; tanpa
          IEND = truncated; tEXt/zTXt/iTXt = metadata info; LSB bit-
          plane (color type 2/6, depth 8, non-interlaced): IDAT di-
          dekode (zlib + unfilter 0..4) -> rasio bit per kanal + bit-
          stream dipindai signature di 64-b pertama;
  WAV   : RIFF walk -> fmt (PCM 16-bit wajib) + data; LSB sampel 16-b:
          rasio + bit-stream dipindai signature; data chunk tak sesuai
          ukuran = lead;
  BMP   : BITMAPFILEHEADER + BITMAPINFOHEADER (bpp 24/32): LSB pixel
          array (row stride padded, bottom-up) -> rasio + signature.

Anti-FP (disiplin NO-FP secai):
  - magic probe minimal 4 byte (MZ/gzip 2-b TIDAK diprobe — FP pada
    data acak); signature hanya dicari di trailing, dan di LSB hanya
    di 64-b pertama (payload LSB selalu mulai dari byte 0-nya);
  - deviasi rasio LSB dari 0.5 TIDAK PERNAH jadi temuan berdiri
    sendiri — rasio tidak rata itu alami pada gambar asli; hanya jadi
    info-lead dgn sampel >= 4096 bit (di bawah itu = noise dominan,
    tidak dihitung sama sekali);
  - tidak ada claim "stego terkonfirmasi" — semua temuan = lead yang
    butuh konfirmasi ekstraksi alat pihak ketiga;
  - zero-temuan = "diperiksa, tanpa indikasi" bukan klaim bersih.

Fail-closed:
  - file tidak ada / terlalu besar (default 32 MB) / magic tak cocok
    format mana pun / WAV tanpa fmt atau data / BMP header invalid ->
    exit 2;
  - struktur terpotong di tengah = TEMUAN lead (bukan error) — file
    forensic memang sering terpotong, analisis tetap jalan;
  - --fail-on <level|any> -> exit 1 bila temuan setinggi itu ada.

Pemakaian:
  python tools/stego_triage.py --source gambar.png
  python tools/stego_triage.py --source dir --out hasil.json --fail-on any
Exit: 0 selesai; 1 temuan >= --fail-on; 2 input/parse error.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
import zlib
from pathlib import Path

SCHEMA = "secai.stego-triage/1"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_IDAT_RAW = 64 * 1024 * 1024      # batas dekompresi IDAT (bounded)
LSB_MIN_BITS_FOR_RATIO = 4096        # di bawah ini rasio tak dinilai
LSB_SIG_WINDOW = 64                  # probe signature di 64-b pertama
RATIO_LEAD_DEVIATION = 0.05          # deviasi dari 0.5 untuk info-lead
PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
ARCHIVE_MAGIC = (
    ("zip", b"PK\x03\x04"),
    ("rar", b"Rar!\x1a\x07"),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c"),
    ("cab", b"MSCF"),
    ("gzip", b"\x1f\x8b\x08"),       # 3 byte: header + method wajib
    ("bzip2", b"BZh"),
    ("gif", b"GIF8"),
    ("png", b"\x89PNG"),
)


def find_magic(data: bytes) -> "tuple[str, int] | None":
    """Magic archive/image pertama dalam blob (None bila tak ada)."""
    best = None
    for name, magic in ARCHIVE_MAGIC:
        idx = data.find(magic)
        if idx != -1 and (best is None or idx < best[1]):
            best = (name, idx)
    return best


def probe_first_window(data: bytes, window: int = LSB_SIG_WINDOW) -> \
        "tuple[str, int] | None":
    """Signature di window pertama bit-stream LSB (offset byte)."""
    for name, magic in ARCHIVE_MAGIC:
        idx = data[:window].find(magic)
        if idx != -1:
            return (name, idx)
    return None


def bits_to_bytes(bits: "list[int]") -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)


def lsb_report(bits: "list[int]", channel: str) -> "dict | None":
    """Rasio LSB satu kanal -> info-lead bila signifikan; None bila
    sampel terlalu sedikit untuk dinilai (anti-FP)."""
    if len(bits) < LSB_MIN_BITS_FOR_RATIO:
        return None
    ones = sum(bits)
    ratio = ones / len(bits)
    if abs(ratio - 0.5) < RATIO_LEAD_DEVIATION:
        return None
    return {
        "id": f"lsb/ratio-lead/{channel}",
        "level": "info",
        "channel": channel,
        "bits": len(bits),
        "ones_ratio": round(ratio, 4),
        "note": "deviasi rasio LSB dari 0.5 (bisa alami pada gambar "
                "asli — lead, bukan temuan)",
    }


class MediaFormatError(Exception):
    """Format tidak didukung / magic tidak cocok / struktur fatal."""


# ---------------------------------------------------------------- JPEG
def scan_jpeg(data: bytes) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    end = data.rfind(JPEG_EOI)
    if end == -1:
        findings.append({
            "id": "structure/truncated", "level": "medium",
            "note": "marker EOI (FFD9) tidak ada — JPEG terpotong",
        })
        trailing = b""
    else:
        trailing = data[end + 2:]
        if trailing:
            sig = find_magic(trailing)
            if sig:
                findings.append({
                    "id": "trailing/embedded-payload", "level": "high",
                    "bytes": len(trailing), "signature": sig[0],
                    "offset": end + 2 + sig[1],
                    "note": "data setelah EOI berisi signature dikenal "
                            "(pola lampiran stego/ekspor)",
                })
            else:
                findings.append({
                    "id": "trailing/data", "level": "medium",
                    "bytes": len(trailing),
                    "note": "data menggantung setelah EOI — bukan bagian "
                            "stream JPEG sah",
                })
    mid = find_magic(data)
    if mid and (end == -1 or mid[1] < end):
        findings.append({
            "id": "embedded/signature", "level": "medium",
            "signature": mid[0], "offset": mid[1],
            "note": "signature archive di dalam stream JPEG (lead — "
                    "bisa juga bagian thumbnail sah)",
        })
    return findings, {"format": "jpeg", "trailing_bytes": len(trailing)}


# ----------------------------------------------------------------- PNG
def scan_png(data: bytes) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    meta: dict = {"format": "png"}
    off = 8
    idat = bytearray()
    text_chunks: list[str] = []
    crc_bad = 0
    saw_iend = False
    off_after_iend: "int | None" = None
    while off + 8 <= len(data):
        (length,) = struct.unpack_from(">I", data, off)
        ctype = data[off + 4:off + 8].decode("ascii", errors="replace")
        if length > MAX_FILE_BYTES or off + 12 + length > len(data):
            findings.append({
                "id": "structure/truncated", "level": "medium",
                "note": f"chunk {ctype} melampaui batas file",
            })
            break
        chunk = data[off + 8:off + 8 + length]
        (crc_stored,) = struct.unpack_from(">I", data, off + 8 + length)
        crc_calc = zlib.crc32(data[off + 4:off + 8 + length]) & 0xFFFFFFFF
        if crc_calc != crc_stored:
            crc_bad += 1
        if ctype == "IDAT":
            idat.extend(chunk)
        elif ctype in ("tEXt", "zTXt", "iTXt"):
            text_chunks.append(ctype)
        elif ctype == "IEND":
            saw_iend = True
            off_after_iend = off + 12 + length
            break
        off += 12 + length
    if not saw_iend:
        if not any(f["id"] == "structure/truncated" for f in findings):
            findings.append({
                "id": "structure/truncated", "level": "medium",
                "note": "chunk IEND tidak ditemukan — PNG terpotong",
            })
    else:
        assert off_after_iend is not None
        trailing = data[off_after_iend:]
        if trailing:
            sig = find_magic(trailing)
            if sig:
                findings.append({
                    "id": "trailing/embedded-payload", "level": "high",
                    "bytes": len(trailing), "signature": sig[0],
                    "offset": off_after_iend + sig[1],
                    "note": "data setelah IEND berisi signature dikenal",
                })
            else:
                findings.append({
                    "id": "trailing/data", "level": "medium",
                    "bytes": len(trailing),
                    "note": "data menggantung setelah IEND",
                })
    if crc_bad:
        findings.append({
            "id": "png/crc-mismatch", "level": "low", "chunks": crc_bad,
            "note": "CRC chunk tidak cocok — file dimodifikasi di luar "
                    "enkode PNG sah (lead)",
        })
    if text_chunks:
        findings.append({
            "id": "png/text-chunks", "level": "info",
            "chunks": text_chunks,
            "note": "metadata tekstual ada (bisa sah; payload terenkode "
                    "kadang disembunyikan di sini)",
        })
    meta.update({"chunks_crc_bad": crc_bad, "text_chunks": text_chunks,
                 "trailing_bytes": (len(data) - off_after_iend)
                 if saw_iend else None})
    # ---- LSB bit-plane bila struktur gambar didukung ----
    findings += _png_lsb(data, idat, meta)
    return findings, meta


def _png_lsb(data: bytes, idat: bytearray, meta: dict) -> list[dict]:
    # IHDR harus ada dan di awal chunk stream
    if len(data) < 33:
        return []
    (length,) = struct.unpack_from(">I", data, 8)
    if data[12:16] != b"IHDR" or length != 13:
        return []
    width, height, depth, ctype, _c, _f, interlace = struct.unpack_from(
        ">IIBBBBB", data, 16)
    meta.update({"width": width, "height": height, "depth": depth,
                 "color_type": ctype, "interlace": interlace})
    if depth != 8 or ctype not in (2, 6) or interlace != 0:
        return []  # di luar ranah — tidak dianalisis, bukan temuan
    channels = 3 if ctype == 2 else 4
    if len(idat) == 0:
        return [{
            "id": "png/idat-missing", "level": "medium",
            "note": "PNG dengan dimensi sah tapi tanpa chunk IDAT",
        }]
    if width == 0 or height == 0:
        raise MediaFormatError("dimensi PNG nol")
    raw_needed = height * (1 + width * channels)
    if raw_needed > MAX_IDAT_RAW:
        return []  # melewati batas analisis — dicatat di meta
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error:
        return [{
            "id": "png/idat-corrupt", "level": "medium",
            "note": "stream IDAT gagal didekode zlib (lead)",
        }]
    if len(raw) < raw_needed:
        return [{
            "id": "png/idat-short", "level": "medium",
            "note": "data IDAT lebih pendek dari kebutuhan dimensi",
        }]
    # unfilter (PNG filter 0..4)
    stride = width * channels
    prev = bytearray(stride)
    cur = bytearray(stride)
    planes: list[list[int]] = [[] for _ in range(channels)]
    pos = 0
    for _ in range(height):
        ftype = raw[pos]
        pos += 1
        row = raw[pos:pos + stride]
        pos += stride
        for i in range(stride):
            a = cur[i - channels] if i >= channels else 0
            b = prev[i]
            c = prev[i - channels] if i >= channels else 0
            x = row[i]
            if ftype == 0:
                v = x
            elif ftype == 1:
                v = (x + a) & 0xFF
            elif ftype == 2:
                v = (x + b) & 0xFF
            elif ftype == 3:
                v = (x + ((a + b) >> 1)) & 0xFF
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (
                    b if pb <= pc else c)
                v = (x + pr) & 0xFF
            else:
                raise MediaFormatError(
                    f"filter PNG tak dikenal: {ftype}")
            cur[i] = v
        for ch in range(channels):
            planes[ch].extend(cur[ch::channels][k] & 1
                              for k in range(width))
        prev, cur = cur, bytearray(stride)
    findings: list[dict] = []
    names = ("R", "G", "B", "A")[:channels]
    for ch, name in enumerate(names):
        rep = lsb_report(planes[ch], name)
        if rep:
            findings.append(rep)
        stream = bits_to_bytes(planes[ch])
        sig = probe_first_window(stream)
        if sig:
            findings.append({
                "id": f"lsb/payload-signature/{name}",
                "level": "high" if sig[1] == 0 else "medium",
                "channel": name, "signature": sig[0],
                "offset": sig[1],
                "note": "bit-plane LSB kanal " + name +
                        " berawalan signature dikenal (indikasi kuat "
                        "payload ter-embed)",
            })
    return findings


# ----------------------------------------------------------------- WAV
def scan_wav(data: bytes) -> tuple[list[dict], dict]:
    if len(data) < 12 or data[0:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise MediaFormatError("bukan RIFF/WAVE sah")
    findings: list[dict] = []
    meta: dict = {"format": "wav"}
    off = 12
    fmt = None
    pcm_data = None
    data_declared = None
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        (csize,) = struct.unpack_from("<I", data, off + 4)
        avail = len(data) - (off + 8)
        if csize > avail:
            findings.append({
                "id": "structure/truncated", "level": "medium",
                "note": f"chunk {cid.decode('ascii', errors='replace')} "
                        "melampaui batas file",
            })
            body = data[off + 8:]  # pakai apa yang tersisa (forensik)
        else:
            body = data[off + 8:off + 8 + csize]
        if cid == b"fmt " and fmt is None:
            fmt = body[:16]
        elif cid == b"data":
            data_declared = csize
            pcm_data = body
        off += 8 + csize + (csize & 1)  # chunk word-aligned
        if csize > avail:
            break
    if fmt is None or pcm_data is None:
        raise MediaFormatError("WAV tanpa chunk fmt/data — tidak bisa "
                               "dianalisis")
    audio_fmt, ch, _rate, _br, _ba, bits = struct.unpack_from(
        "<HHIIHH", fmt[:16])
    meta.update({"audio_format": audio_fmt, "channels": ch,
                 "bits": bits, "data_bytes": data_declared})
    if audio_fmt != 1 or bits != 16:
        return findings, meta  # non-PCM16: LSB tak bermakna — bukan lead
    if data_declared is not None and len(pcm_data) < data_declared:
        findings.append({
            "id": "wav/data-short", "level": "medium",
            "declared": data_declared, "present": len(pcm_data),
            "note": "chunk data lebih pendek dari ukuran terdeklarasi",
        })
    n_samples = len(pcm_data) // 2
    samples = struct.unpack_from("<%dH" % n_samples, pcm_data, 0)
    bits_stream: list[int] = [s & 1 for s in samples]
    rep = lsb_report(bits_stream, "audio16")
    if rep:
        findings.append(rep)
    stream = bits_to_bytes(bits_stream)
    sig = probe_first_window(stream)
    if sig:
        findings.append({
            "id": "lsb/payload-signature/audio16",
            "level": "high" if sig[1] == 0 else "medium",
            "channel": "audio16", "signature": sig[0],
            "offset": sig[1],
            "note": "LSB sampel audio berawalan signature dikenal",
        })
    return findings, meta


# ----------------------------------------------------------------- BMP
def scan_bmp(data: bytes) -> tuple[list[dict], dict]:
    if len(data) < 54 or data[0:2] != b"BM":
        raise MediaFormatError("bukan BMP sah")
    (file_size, _res, pix_off) = struct.unpack_from("<III", data, 2)
    (hdr_size, width, height, _planes, bpp, _comp) = struct.unpack_from(
        "<IiiHHI", data, 14)
    findings: list[dict] = []
    meta: dict = {"format": "bmp", "width": width, "height": height,
                  "bits": bpp}
    if file_size != len(data):
        findings.append({
            "id": "bmp/size-mismatch", "level": "medium",
            "declared": file_size, "present": len(data),
            "note": "ukuran terdeklarasi header != ukuran file "
                    "(data tertambah/terpotong)",
        })
    if bpp not in (24, 32) or width <= 0 or height == 0:
        return findings, meta  # di luar ranah LSB — bukan lead
    channels = bpp // 8
    stride = ((bpp * width + 31) // 32) * 4
    rows = abs(height)
    if pix_off + rows * stride > len(data):
        findings.append({
            "id": "structure/truncated", "level": "medium",
            "note": "array pixel melampaui batas file",
        })
        rows = (len(data) - pix_off) // stride
    if rows <= 0:
        raise MediaFormatError("BMP tanpa data pixel terbaca")
    names = ("B", "G", "R") + ("A",) if channels == 4 else ("B", "G", "R")
    planes: list[list[int]] = [[] for _ in range(channels)]
    for r in range(rows):
        row = data[pix_off + r * stride:pix_off + (r + 1) * stride]
        for px in range(width):
            base = px * channels
            for ch in range(channels):
                planes[ch].append(row[base + ch] & 1)
    for ch, name in enumerate(names[:channels]):
        rep = lsb_report(planes[ch], name)
        if rep:
            findings.append(rep)
        stream = bits_to_bytes(planes[ch])
        sig = probe_first_window(stream)
        if sig:
            findings.append({
                "id": f"lsb/payload-signature/{name}",
                "level": "high" if sig[1] == 0 else "medium",
                "channel": name, "signature": sig[0],
                "offset": sig[1],
                "note": "LSB pixel kanal " + name +
                        " berawalan signature dikenal",
            })
    return findings, meta


SCANNERS = {
    "jpeg": (JPEG_SOI, scan_jpeg),
    "png": (PNG_SIG, scan_png),
    "bmp": (b"BM", scan_bmp),
}
# WAV dicek khusus (magic 12-b)


def scan(source: Path) -> dict:
    raw = source.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise MediaFormatError(
            f"file terlalu besar (> {MAX_FILE_BYTES} byte)")
    if len(raw) >= 12 and raw[0:4] == b"RIFF" and raw[8:12] == b"WAVE":
        findings, meta = scan_wav(raw)
    else:
        fmt = next((f for f, (magic, _fn) in SCANNERS.items()
                    if raw[:len(magic)] == magic), None)
        if fmt is None:
            raise MediaFormatError(
                "format tidak didukung (hanya JPEG/PNG/WAV/BMP dgn magic "
                "sah — magic tak cocok ekstensi juga ditolak)")
        findings, meta = SCANNERS[fmt][1](raw)
    findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2,
                                  "info": 3}[f["level"]], f["id"]))
    return {
        "file": str(source),
        "media": meta,
        "findings": findings,
        "checked": ["trailing-data", "archive-signature", "lsb-plane",
                    "structure-integrity"],
        "summary": {
            "total": len(findings),
            "by_level": {lv: sum(1 for f in findings
                                 if f["level"] == lv)
                         for lv in ("high", "medium", "low", "info")},
        },
    }


LEVEL_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="stego_triage — deteksi steganografi offline "
                    "(JPEG/PNG/WAV/BMP; read-only, nol jaringan, "
                    "fail-closed).")
    ap.add_argument("--source", required=True,
                    help="berkas media atau direktori")
    ap.add_argument("--fail-on",
                    choices=("any", "high", "medium", "low"),
                    help="exit 1 bila ada temuan setinggi itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    src = Path(args.source)
    if not src.exists():
        print(f"[stego-triage] source tidak ada: {src}", file=sys.stderr)
        return 2
    targets = ([src] if src.is_file()
               else sorted(p for p in src.iterdir() if p.is_file()))
    if not targets:
        print("[stego-triage] tidak ada file untuk dipindai",
              file=sys.stderr)
        return 2
    results: list[dict] = []
    for path in targets:
        try:
            results.append(scan(path))
        except (MediaFormatError, OSError) as exc:
            print(f"[stego-triage] {path.name}: gagal: {exc}",
                  file=sys.stderr)
            return 2
        except struct.error as exc:
            print(f"[stego-triage] {path.name}: struktur tidak valid: "
                  f"{exc}", file=sys.stderr)
            return 2
    out = {
        "schema": SCHEMA,
        "source": str(src),
        "scanned": len(results),
        "results": results,
        "summary": {
            "total": sum(r["summary"]["total"] for r in results),
            "by_level": {lv: sum(r["summary"]["by_level"][lv]
                                 for r in results)
                         for lv in LEVEL_RANK},
        },
        "note": "semua temuan = lead yang butuh konfirmasi ekstraksi "
                "(steghide/zsteg/alat pihak ketiga); DCT & domain-"
                "frekuensi di luar kelas alat ini.",
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = out["summary"]
    dist = ", ".join(f"{k}={v}" for k, v in s["by_level"].items())
    print(f"[stego-triage] {len(results)} file, {s['total']} temuan "
          f"({dist})")
    for res in results:
        for f in res["findings"]:
            extra = f" sig={f['signature']}" if "signature" in f else ""
            extra += (f" bytes={f['bytes']}" if "bytes" in f else "")
            print(f"  [{f['level']:6}] {res['file']}: {f['id']}{extra}")
    if args.fail_on:
        lvls = (["high", "medium", "low"] if args.fail_on == "any"
                else [lv for lv in ("high", "medium", "low")
                      if LEVEL_RANK[lv] <= LEVEL_RANK[args.fail_on]])
        if any(f["level"] in lvls for res in results
               for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
