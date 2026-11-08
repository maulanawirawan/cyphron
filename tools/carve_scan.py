r"""[SAFETY: read-only] carve_scan — pindai signature & ukur (carve) berkas
ter-embed di blob mentah (image disk, dump unallocated, firmware, memori
tertuang). NOL jaringan, read-only, stdlib murni.

Port INTI DETERMINISTIK dari dua skill antrean SKILL-PORT-QUEUE:
  #0817 mukul975/Anthropic-Cybersecurity-Skills
       'performing-file-carving-with-foremost'  -> ukur header/footer
  #0818 mukul975/Anthropic-Cybersecurity-Skills
       'performing-firmware-extraction-with-binwalk' -> pindai magic +
       profil entropi blok
(Konsep sumber Apache-2.0, atribusi di sini — foremost/binwalk tetap alat
pihak ketiga; yang diport = mekanisme signature+entropi, bukan kodenya.)

Mekanisme:
  1. SCAN   — cari magic header/footer pada tabel signature bawaan
              (tepat byte, offset apa pun) + signature offset-tetap
              (superblock ext 0xEF53 di 0x438, ISO9660 "CD001" di 0x8001).
              Pasangan header->footer = CARVABLE; header tanpa footer =
              UNCLOSed (dicatat, tidak diukur — anti-FP: tidak menebak
              akhir berkas).
  2. ENTROPY— profil entropi Shannon per blok (--block, default 4096):
              >=7.0 terkompresi/terenkripsi, <=1.0 padding/kosong —
              ala `binwalk -E`; menuntun triase region menarik.
  3. CARVE  — ekstraksi pasangan header->footer ke direktori (--carve)
              dgn batas ukuran (--min-size/--max-size, default 64 B
              .. 50 MB) + SHA-256 tiap hasil; footer ZIP = EOCD +22 byte
              agar berkas utuh. Header fuzzy (JFFS2 2-byte) dicatat dgn
              confidence rendah, TIDAK diukur.

Verdict: setiap hit adalah FAKTA STRUKTUR (offset bisa diverifikasi via
poc hexdump) -> status confirmed, evidence_kind "arithmetic", verdict L3
DETERMINISTICALLY_VERIFIED. Tool ini INVENTARIS FORENSIK — tidak pernah
mengklaim berkas jahat/kotor; konten hasil ukur dianalisis tool lain
(binary_strings_surface, packer_scan, maldoc_triage, ...).

Fail-closed: file tidak ada / < 16 byte / --carve tidak bisa ditulis ->
exit 2. Blob tanpa satu pun hit = meta terisi, temuan info nol (BUKAN
dianggap "tidak ada apa-apa" secara diam-diam: meta.total_hits=0 eksplisit
+ pesan).

Pemakaian:
  python tools/carve_scan.py --blob image.dd --out f.json
  python tools/carve_scan.py --blob fw.bin --block 8192 --out f.json
  python tools/carve_scan.py --blob image.dd --carve out_dir/ --out f.json
Exit: 0 tanpa hit, 1 ada hit/temuan, 2 error input.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.carve-scan/1"
MAX_BLOB_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB — baca penuh di memori
DEFAULT_MIN_CARVE = 64
DEFAULT_MAX_CARVE = 50 * 1024 * 1024

# header, footer (None = header-only), nama, fuzzy
SIGNATURES: list[tuple[bytes, bytes | None, str, bool]] = [
    (b"\x89PNG\r\n\x1a\n", b"IEND\xae\x42\x60\x82", "png", False),
    (b"\xff\xd8\xff", b"\xff\xd9", "jpeg", False),
    (b"%PDF-", b"%%EOF", "pdf", False),
    (b"PK\x03\x04", b"PK\x05\x06", "zip", False),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", None, "ole", False),
    (b"SQLite format 3\x00", None, "sqlite", False),
    (b"\x7fELF", None, "elf", False),
    (b"hsqs", None, "squashfs-le", False),   # SquashFS little-endian
    (b"sqsh", None, "squashfs-be", False),   # SquashFS big-endian
    (b"\x1f\x8b\x08", None, "gzip", False),
    (b"BZh", None, "bzip2", False),
    (b"\xfd7zXZ\x00", None, "xz", False),
    (b"7z\xbc\xaf\x27\x1c", None, "7z", False),
    (b"Rar!\x1a\x07", None, "rar", False),
    (b"\x56\x19\x05\x27", None, "uboot-uimage", False),
    # JFFS2 node magic 2-byte — sangat mudah FP, confidence rendah
    (b"\x19\x85", None, "jffs2-node", True),
]

# signature offset-tetap: (nama, offset, bytes)
FIXED_OFFSET: list[tuple[str, int, bytes]] = [
    ("ext234-superblock", 0x438, b"\x53\xef"),
    ("iso9660", 0x8001, b"CD001"),
]

ENTROPY_HIGH = 7.0
ENTROPY_LOW = 1.0
MAX_ENTROPY_BLOCKS = 512  # batas temuan entropi (blob besar = ringkas)


def shannon_entropy(data: bytes) -> float:
    """Entropi Shannon 0..8 per byte; data kosong = 0.0."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def scan_signatures(blob: bytes) -> dict[str, list[dict]]:
    """Cari semua signature. Return {jenis: [hit]} — hit = offset+meta."""
    hits: dict[str, list[dict]] = {}
    for header, footer, name, fuzzy in SIGNATURES:
        lst: list[dict] = []
        start = 0
        while True:
            off = blob.find(header, start)
            if off < 0:
                break
            end_off = -1
            if footer is not None:
                end_off = blob.find(footer, off + len(header))
            lst.append({
                "offset": off,
                "footer_offset": end_off if end_off >= 0 else None,
                "carvable": end_off >= 0,
                "fuzzy": fuzzy,
            })
            start = off + 1
        if lst:
            hits[name] = lst
    for name, off, magic in FIXED_OFFSET:
        if off + len(magic) <= len(blob) and blob[off:off + len(magic)] == magic:
            hits[name] = [{"offset": off, "footer_offset": None,
                           "carvable": False, "fuzzy": False}]
    return hits


def entropy_profile(blob: bytes, block: int) -> list[dict]:
    """Entropi per blok; hanya blok menonjol yang dikembalikan."""
    out: list[dict] = []
    for i in range(0, len(blob), block):
        chunk = blob[i:i + block]
        ent = shannon_entropy(chunk)
        if ent >= ENTROPY_HIGH or ent <= ENTROPY_LOW:
            out.append({
                "offset": i,
                "entropy": ent,
                "class": "compressed-or-encrypted" if ent >= ENTROPY_HIGH
                         else "padding-or-empty",
            })
        if len(out) >= MAX_ENTROPY_BLOCKS:
            break
    return out


def hexdump_poc(blob: bytes, offset: int, width: int = 32) -> str:
    chunk = blob[offset:offset + width]
    hx = " ".join(f"{b:02x}" for b in chunk)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{offset:#08x}  {hx}  |{asc}|"


def carve_all(blob: bytes, hits: dict[str, list[dict]], out_dir: Path,
              min_size: int, max_size: int) -> tuple[list[dict], list[dict]]:
    """Ukur semua pasangan header->footer. Return (hasil, dilewati)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    carved: list[dict] = []
    skipped: list[dict] = []
    counters: dict[str, int] = {}
    for name, lst in sorted(hits.items()):
        for h in lst:
            if not h["carvable"]:
                continue
            footer_sig_len = 0
            for header, footer, sig_name, _ in SIGNATURES:
                if sig_name == name and footer is not None:
                    # footer ZIP = awal EOCD; record EOCD utuh = 22 byte,
                    # jadi ekstra = 22 - len(footer) = 18
                    extra = 18 if name == "zip" else 0
                    footer_sig_len = len(footer) + extra
                    break
            size = h["footer_offset"] + footer_sig_len - h["offset"]
            rec = {"type": name, "offset": h["offset"], "size": size}
            if not (min_size <= size <= max_size):
                rec["reason"] = ("size-out-of-bounds "
                                 f"(min={min_size}, max={max_size})")
                skipped.append(rec)
                continue
            counters[name] = counters.get(name, 0) + 1
            fname = f"{name}_{counters[name]:04d}_{h['offset']:08x}.bin"
            dest = out_dir / fname
            dest.write_bytes(blob[h["offset"]:h["offset"] + size])
            carved.append({
                "type": name,
                "offset": h["offset"],
                "size": size,
                "file": str(dest),
                "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
            })
    return carved, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] carve_scan — pindai signature & "
                    "carve berkas ter-embed di blob mentah (NOL jaringan)")
    ap.add_argument("--blob", required=True, help="file blob mentah")
    ap.add_argument("--out", default="carve_scan_findings.json")
    ap.add_argument("--carve", default=None,
                    help="direktori hasil ukur (opsional)")
    ap.add_argument("--block", type=int, default=4096,
                    help="ukuran blok entropi (default 4096)")
    ap.add_argument("--min-size", type=int, default=DEFAULT_MIN_CARVE)
    ap.add_argument("--max-size", type=int, default=DEFAULT_MAX_CARVE)
    args = ap.parse_args(argv)

    p = Path(args.blob)
    if not p.is_file():
        print(f"[carve_scan] blob tidak ada: {p} (fail-closed)",
              file=sys.stderr)
        return 2
    size = p.stat().st_size
    if size > MAX_BLOB_BYTES:
        print(f"[carve_scan] blob terlalu besar ({size} > {MAX_BLOB_BYTES}) "
              "(fail-closed)", file=sys.stderr)
        return 2
    if size < 16:
        print(f"[carve_scan] blob terlalu kecil ({size} byte) "
              "(fail-closed)", file=sys.stderr)
        return 2
    if args.block <= 0 or args.min_size < 0 or args.max_size < args.min_size:
        print("[carve_scan] parameter --block/--min-size/--max-size "
              "tidak wajar (fail-closed)", file=sys.stderr)
        return 2
    blob = p.read_bytes()

    hits = scan_signatures(blob)
    total_hits = sum(len(v) for v in hits.values())

    carved: list[dict] = []
    skipped: list[dict] = []
    if args.carve:
        try:
            carved, skipped = carve_all(blob, hits, Path(args.carve),
                                        args.min_size, args.max_size)
        except OSError as exc:
            print(f"[carve_scan] gagal menulis direktori ukur: {exc} "
                  "(fail-closed)", file=sys.stderr)
            return 2

    ent_blocks = entropy_profile(blob, args.block)

    findings: list[dict] = []
    for name, lst in sorted(hits.items()):
        for h in lst:
            kind = "carvable" if h["carvable"] else (
                "fixed-offset" if name in dict(
                    (n, True) for n, _, _ in FIXED_OFFSET) else "signature")
            sev = "info"
            if h["fuzzy"]:
                sev = "info"
            findings.append(make_finding(
                tool="carve-scan",
                title=f"signature {name} @ {h['offset']:#x} ({kind})",
                severity=sev,
                description=(
                    f"Magic {name} pada offset {h['offset']:#x} "
                    f"({h['offset']}) blob {p.name}"
                    + (f", footer @ {h['footer_offset']:#x}"
                       if h["footer_offset"] is not None else
                       ", header-only (tanpa footer — tidak diukur)"
                       if kind != "fixed-offset" else
                       ", signature offset-tetap")),
                recommendation=(
                    "Analisis konten dengan tool lanjutan "
                    "(binary_strings_surface / packer_scan / maldoc_triage); "
                    "offset diverifikasi hexdump"),
                file_path=str(p),
                poc=hexdump_poc(blob, h["offset"]),
                evidence_kind="arithmetic",
                finding_class="evidence",
                confidence=0.5 if h["fuzzy"] else 1.0,
                status="confirmed",
                verdict=2,
                extra={"signature": name, "offset": h["offset"],
                       "carvable": h["carvable"], "fuzzy": h["fuzzy"],
                       "schema": SCHEMA},
            ))
    for c in ent_blocks[:64]:
        findings.append(make_finding(
            tool="carve-scan",
            title=f"blok entropi {c['class']} @ {c['offset']:#x} "
                  f"(H={c['entropy']})",
            severity="info",
            description=(
                f"Blok {args.block} byte @ {c['offset']:#x} entropi "
                f"{c['entropy']} — "
                + ("terkompresi/terenkripsi kemungkinan besar" if
                   c["class"] == "compressed-or-encrypted" else
                   "padding/kosong")),
            recommendation="Gunakan region ini utk memandu carve/rekayasa "
                           "lanjutan; entropi tinggi BUKAN bukti enkripsi "
                           "malisius (kompresi juga)",
            file_path=str(p),
            evidence_kind="arithmetic",
            finding_class="observation",
            confidence=0.9,
            status="confirmed",
            verdict=2,
            extra={"block": args.block, "entropy": c["entropy"],
                   "offset": c["offset"], "schema": SCHEMA},
        ))

    meta = {
        "schema": SCHEMA,
        "blob": str(p),
        "blob_size": size,
        "total_hits": total_hits,
        "by_type": {k: len(v) for k, v in sorted(hits.items())},
        "carved": carved,
        "carve_skipped": skipped,
        "entropy_blocks": args.block,
        "entropy_regions": len(ent_blocks),
        "entropy_max_reported": 64,
        "note": "inventaris forensik struktural — bukan penilaian "
                "malisius; hasil ukur dianalisis tool lain",
    }
    write_findings(args.out, findings, meta)
    # exit code mengikuti SIGNATURE (tujuan utama); observasi entropi
    # tetap ditulis tapi tidak mengubah exit code
    if total_hits:
        print(f"[carve_scan] {total_hits} hit, {len(carved)} ter-ukur, "
              f"{len(ent_blocks)} region entropi menonjol -> {args.out}")
        return 1
    print(f"[carve_scan] 0 hit pada {size} byte ({len(ent_blocks)} region "
          f"entropi) — meta eksplisit total_hits=0 (bukan diam-diam) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
