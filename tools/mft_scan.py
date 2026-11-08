r"""[SAFETY: read-only] mft_scan — parser NTFS $MFT untuk pemulihan
metadata file terhapus.

Port konsep dari antrean SKILL-PORT-QUEUE #0220 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-mft-for-deleted-file-
recovery' — MFTECmd/analyzeMFT). Dibangun from scratch dari struktur
$MFT yang dipublikasikan terbuka (NTFS on-disk format), stdlib-only,
NOL jaringan, read-only: file $MFT diekstrak dulu (mis. dari image
forensik) lalu diberikan sebagai input biasa.

Mekanisme:
  - iterasi record 1024-byte (default; --record-size untuk lainnya)
  - validasi magic 'FILE' + fixup Update Sequence Array (2 byte akhir
    tiap 512-byte sector ditukar dgn entri USA) — fixup tidak cocok =
    record korup, TIDAK dilaporkan isinya (fail-closed)
  - flags record 0x0001 = in-use; BIT JELAS = file/direktori TERHAPUS
  - atribut $STANDARD_INFORMATION (0x10) dan $FILE_NAME (0x30):
    timestamp FILETIME (100ns sejak 1601) -> ISO 8601, nama, parent
    ref, ukuran, direktori/file
  - data resident TIDAK diekstrak (scope: metadata, bukan carving)

Output JSON: daftar entri {mft_ref, deleted, is_dir, name, size,
parent_ref, times{...}} + ringkasan. Filter --deleted-only untuk
kasus pemulihan file terhapus.

Pemakaian:
  python tools/mft_scan.py --mft '\$MFT' --out mft.json
  python tools/mft_scan.py --mft mft.bin --deleted-only --limit 50
Exit: 0 sukses (walau ada record korup — dihitung, tak dipendam);
2 input error (bukan $MFT, file tiada, tidak ada record valid).
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

SCHEMA = "secai.mft-scan/1"

MFT_MAGIC = b"FILE"
EPOCH_DIFF_1601_1970 = 11644473600_0000000  # 100ns
RECORD_SIZE_DEFAULT = 1024

ATTR_SI = 0x10   # $STANDARD_INFORMATION
ATTR_FN = 0x30   # $FILE_NAME
ATTR_END = 0xFFFFFFFF


def filetime_to_iso(ft: int) -> str | None:
    """FILETIME (100ns sejak 1601) -> ISO 8601 UTC; 0/nol -> None."""
    if ft <= 0:
        return None
    unix_s = (ft - EPOCH_DIFF_1601_1970) / 10_000_000
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(unix_s, tz=timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _apply_fixup(rec: bytes, record_size: int) -> bytes | None:
    """Terapkan Update Sequence Array; None bila fixup tidak cocok."""
    if len(rec) < record_size:
        rec = rec + b"\x00" * (record_size - len(rec))
    # header: USA offset di 0x04, ukurannya (words) di 0x06
    usn_off, usn_count = struct.unpack_from("<HH", rec, 0x04)
    if usn_off < 0x30 or usn_count < 2:
        return None
    usa = struct.unpack_from("<" + "H" * usn_count, rec, usn_off)
    check = usa[0]                      # USN (nilai pengganti saat ini)
    sector_size = 512
    for i in range(1, usn_count):
        end = i * sector_size - 2
        if end + 2 > record_size:
            return None
        if struct.unpack_from("<H", rec, end)[0] != check:
            return None                 # korup — fail-closed
        if i < usn_count:
            struct.pack_into("<H", rec, end, usa[i])
    return rec


def _parse_times_fn(content: bytes) -> dict:
    c, m, mm, a = struct.unpack_from("<4Q", content, 8)
    return {"created": filetime_to_iso(c), "modified": filetime_to_iso(m),
            "mft_modified": filetime_to_iso(mm), "accessed": filetime_to_iso(a)}


def _parse_attr(content_off: int, content_len: int, rec: bytes) -> dict:
    return {"content_off": content_off, "content_len": content_len}


def parse_record(rec_raw: bytes, record_size: int, ref: int) -> dict | None:
    """Parse satu record; None = korup (bukan record $MFT valid)."""
    if len(rec_raw) < 48 or rec_raw[:4] != MFT_MAGIC:
        return None
    rec = _apply_fixup(bytearray(rec_raw), record_size)
    if rec is None:
        return None
    flags = struct.unpack_from("<H", rec, 0x16)[0]
    in_use = bool(flags & 0x0001)
    is_dir = bool(flags & 0x0002)
    first_off = struct.unpack_from("<H", rec, 0x14)[0]
    if first_off >= record_size:
        return None

    entry: dict = {
        "mft_ref": ref, "deleted": not in_use, "is_dir": is_dir,
        "name": None, "size": None, "parent_ref": None, "times": {},
        "corrupt_attrs": False,
    }
    off = first_off
    while off + 16 <= record_size:
        (atype, alen) = struct.unpack_from("<II", rec, off)
        if atype == ATTR_END or alen < 16:
            break
        if off + alen > record_size:
            entry["corrupt_attrs"] = True
            break
        non_resident = rec[off + 8]
        try:
            if atype == ATTR_SI and non_resident == 0:
                clen, coff = struct.unpack_from("<HH", rec, off + 16)
                # coff absolut terhadap awal record (bukan relatif attr)
                if coff + clen <= record_size and clen >= 32:
                    c, m, mm, a = struct.unpack_from("<4Q", rec, coff)
                    entry["times"].update({
                        "si_created": filetime_to_iso(c),
                        "si_modified": filetime_to_iso(m),
                        "si_mft_modified": filetime_to_iso(mm),
                        "si_accessed": filetime_to_iso(a),
                    })
            elif atype == ATTR_FN and non_resident == 0:
                clen, coff = struct.unpack_from("<HH", rec, off + 16)
                if coff + clen <= record_size and clen >= 66:
                    parent = struct.unpack_from("<Q", rec, coff)[0]
                    entry["parent_ref"] = parent & 0xFFFFFFFFFFFF
                    c = rec[coff + 64]
                    ns = rec[coff + 65]
                    raw = rec[coff + 66:coff + 66 + c * 2]
                    name = raw.decode("utf-16-le", errors="replace")
                    # Win32 namespace yang diawali $I30 = nama NTFS
                    # internal index; simpan apa adanya (honest)
                    entry["name"] = name
                    entry["name_space"] = ns
                    _, _, _, _, alloc, real = struct.unpack_from(
                        "<6Q", rec, coff + 8)
                    entry["size"] = real
                    entry["times"].update(_parse_times_fn(
                        rec[coff:coff + clen]))
        except struct.error:
            entry["corrupt_attrs"] = True
            break
        off += alen
    return entry


def scan(mft_path: Path, record_size: int = RECORD_SIZE_DEFAULT,
         deleted_only: bool = False, limit: int | None = None) -> dict:
    data = mft_path.read_bytes()
    if len(data) < record_size:
        raise ValueError(
            f"file terlalu kecil untuk satu record {record_size}B")

    entries: list[dict] = []
    corrupt = 0
    total = 0
    for i in range(0, len(data) - record_size + 1, record_size):
        total += 1
        rec = parse_record(data[i:i + record_size], record_size, i //
                           record_size)
        if rec is None:
            corrupt += 1
            continue
        if deleted_only and not rec["deleted"]:
            continue
        entries.append(rec)
        if limit is not None and len(entries) >= limit:
            break

    if total and corrupt == total:
        raise ValueError(
            "tidak ada record $MFT valid (magic FILE/fixup gagal semua) — "
            "bukan file $MFT?")
    n_deleted = sum(1 for e in entries if e["deleted"])
    return {
        "schema": SCHEMA,
        "file": str(mft_path),
        "record_size": record_size,
        "records_scanned": total,
        "records_corrupt": corrupt,
        "entries_returned": len(entries),
        "deleted_in_page": n_deleted,
        "deleted_only": deleted_only,
        "entries": entries,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Parser NTFS $MFT — metadata file terhapus "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--mft", required=True, help="path file $MFT mentah")
    ap.add_argument("--record-size", type=int, default=RECORD_SIZE_DEFAULT,
                    help="ukuran record MFT (default 1024)")
    ap.add_argument("--deleted-only", action="store_true",
                    help="hanya entri terhapus (flag in-use jelas)")
    ap.add_argument("--limit", type=int, help="batasi jumlah entri keluar")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.mft)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    if args.record_size < 512 or args.record_size % 512 != 0:
        print("ERROR: record-size harus kelipatan 512", file=sys.stderr)
        return 2
    try:
        result = scan(path, args.record_size, args.deleted_only,
                      args.limit)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
