"""test_mft_scan — parser NTFS $MFT (#0220), nol jaringan.

Fixtures = record $MFT sintetis dibangun byte-per-byte (struktur dari
spesifikasi on-disk NTFS yang terbuka).
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import mft_scan  # noqa: E402

REC_SIZE = 1024
FT_2020 = 132223104000000000          # 2020-01-01T00:00:00Z
FT_2021 = 132669792000000000          # 2021-06-01T00:00:00Z
FT_ZERO = 0


def _mk_record(in_use: bool, is_dir: bool, name: str = "a.txt",
               parent: int = 5, times: tuple[int, ...] = (FT_2020, FT_2021),
               size: int = 1234, break_fixup: bool = False) -> bytes:
    rec = bytearray(REC_SIZE)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 0x04, 0x30, 3)   # USA di 0x30, 3 word
    struct.pack_into("<H", rec, 0x14, 0x38)       # attr pertama di 0x38
    flags = (0x0001 if in_use else 0) | (0x0002 if is_dir else 0)
    struct.pack_into("<H", rec, 0x16, flags)
    struct.pack_into("<I", rec, 0x18, 0x200)      # bytes in use
    struct.pack_into("<I", rec, 0x1C, REC_SIZE)
    # USA: USN=0x0001 + 2 entri per-sector
    struct.pack_into("<HHH", rec, 0x30, 0x0001, 0xDEAD, 0xBEEF)
    struct.pack_into("<H", rec, 510, 0x0001)
    struct.pack_into("<H", rec, 1022, 0x0001)
    if break_fixup:
        struct.pack_into("<H", rec, 510, 0xFFFF)

    off = 0x38
    # $STANDARD_INFORMATION (resident): 4 FILETIME
    si_content = struct.pack("<4Q", times[0], times[1], times[0], times[1])
    si_len = 24 + len(si_content)
    struct.pack_into("<II", rec, off, 0x10, si_len)
    rec[off + 8] = 0                              # resident
    struct.pack_into("<HH", rec, off + 16, len(si_content), off + 24)
    rec[off + 24:off + 24 + len(si_content)] = si_content
    off += si_len
    # $FILE_NAME (resident): parent, times, ukuran, nama
    nb = name.encode("utf-16-le")
    fn_content = (struct.pack("<Q", parent)
                  + struct.pack("<4Q", times[0], times[1], times[0],
                                times[1])
                  + struct.pack("<Q", size * 2)
                  + struct.pack("<Q", size)
                  + struct.pack("<IIBB", 0, 0, len(name), 3)
                  + nb)
    fn_len = 24 + len(fn_content)
    struct.pack_into("<II", rec, off, 0x30, fn_len)
    rec[off + 8] = 0
    struct.pack_into("<HH", rec, off + 16, len(fn_content), off + 24)
    rec[off + 24:off + 24 + len(fn_content)] = fn_content
    off += fn_len
    struct.pack_into("<II", rec, off, 0xFFFFFFFF, 0)
    return bytes(rec)


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "mft_scan.py"), "--mft", str(path),
         *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _mk_mft(tmp_path: Path, records: list[bytes]) -> Path:
    p = tmp_path / "MFT.bin"
    p.write_bytes(b"".join(records))
    return p


def test_deleted_file_recovered(tmp_path):
    p = _mk_mft(tmp_path, [
        _mk_record(True, False, name="hidup.txt"),
        _mk_record(False, False, name="terhapus.txt", parent=9,
                   size=4096),
    ])
    rc, out = _run(p, "--deleted-only")
    assert rc == 0
    ents = out["entries"]
    assert len(ents) == 1
    e = ents[0]
    assert e["deleted"] is True and e["is_dir"] is False
    assert e["name"] == "terhapus.txt"
    assert e["parent_ref"] == 9
    assert e["size"] == 4096
    assert e["times"]["si_created"] == "2020-01-01T00:00:00Z"
    assert e["times"]["modified"] == "2021-06-01T00:00:00Z"


def test_in_use_excluded_by_filter_included_without(tmp_path):
    recs = [_mk_record(True, False, name="hidup.txt"),
            _mk_record(False, False, name="mati.txt")]
    p = _mk_mft(tmp_path, recs)
    rc, out = _run(p)
    assert rc == 0 and len(out["entries"]) == 2
    rc, out = _run(p, "--deleted-only")
    assert [e["name"] for e in out["entries"]] == ["mati.txt"]


def test_deleted_directory_flagged(tmp_path):
    p = _mk_mft(tmp_path, [_mk_record(False, True, name="folder_x")])
    rc, out = _run(p)
    e = out["entries"][0]
    assert e["deleted"] and e["is_dir"]


def test_corrupt_fixup_counted_not_silent(tmp_path):
    p = _mk_mft(tmp_path, [
        _mk_record(True, False, name="ok.txt"),
        _mk_record(True, False, name="korup.txt", break_fixup=True),
    ])
    rc, out = _run(p)
    assert rc == 0
    assert out["records_corrupt"] == 1
    assert [e["name"] for e in out["entries"]] == ["ok.txt"]
    assert out["records_scanned"] == 2


def test_all_corrupt_exit2(tmp_path):
    p = _mk_mft(tmp_path, [_mk_record(True, False, break_fixup=True)])
    rc, out = _run(p)
    assert rc == 2 and out is None


def test_not_mft_exit2(tmp_path):
    p = tmp_path / "bukan.bin"
    p.write_bytes(b"\x00" * 4096)
    rc, out = _run(p)
    assert rc == 2


def test_too_small_exit2(tmp_path):
    p = tmp_path / "kecil.bin"
    p.write_bytes(b"FILE" + b"\x00" * 10)
    rc, out = _run(p)
    assert rc == 2


def test_zero_filetime_null(tmp_path):
    p = _mk_mft(tmp_path, [_mk_record(False, False, times=(FT_ZERO,
                                                           FT_2021))])
    rc, out = _run(p)
    e = out["entries"][0]
    assert e["times"]["si_created"] is None
    assert e["times"]["si_modified"] == "2021-06-01T00:00:00Z"


def test_limit(tmp_path):
    recs = [_mk_record(False, False, name=f"f{i}.txt") for i in range(5)]
    p = _mk_mft(tmp_path, recs)
    rc, out = _run(p, "--limit", "2")
    assert out["entries_returned"] == 2


def test_out_file_read_only(tmp_path):
    p = _mk_mft(tmp_path, [_mk_record(True, False)])
    before = p.read_bytes()
    rc, out = _run(p, "--out", str(tmp_path / "o.json"))
    assert rc == 0 and p.read_bytes() == before
    saved = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "cyphron.mft-scan/1"


def test_filetime_conversion():
    assert mft_scan.filetime_to_iso(FT_2020) == "2020-01-01T00:00:00Z"
    assert mft_scan.filetime_to_iso(0) is None
    assert mft_scan.filetime_to_iso(-5) is None


def test_missing_file_exit2(tmp_path):
    rc, out = _run(tmp_path / "tiada.bin")
    assert rc == 2
