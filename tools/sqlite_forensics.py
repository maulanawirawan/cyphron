r"""[AUDIT: read-only] sqlite_forensics — forensik OFFLINE berkas basis
data SQLite generik (browser, aplikasi mobile, chat, cache): parse header
100-byte, inventaris freelist (halaman terhapus), carving string dari
halaman freelist + unallocated space + freeblock chain di halaman
B-tree hidup, best-effort parse rekord teks dari halaman freelist yang
headernya masih utuh, parse frame WAL (page inventory, restart,
overlap freelist), status rollback journal, dan inventaris tabel/row
aktif via sqlite3 read-only immutable. TANPA jaringan, tanpa tulis ke
berkas sumber, tanpa kredensial.

Mengisi antrean port SKILL-PORT-QUEUE #0896 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-sqlite-database-forensics';
atribusi konsep freelist/WAL/unallocated recovery, lisensi sumber
Apache-2.0). Struktur berkas diimplementasi FROM SCRATCH dari spesifikasi
publik SQLite (https://www.sqlite.org/fileformat2.html) — termasuk
koreksi posisi field (text encoding di offset 56, bukan 52) — tanpa
menyalin kode sumber skill.

Pembagian ranah (TIDAK diduplikasi):
  - skema browser (urls/visits/moz_places, epoch WebKit 1601) ->
    browser_history_triage; di sini analisis STRUKTUR generik apa pun
    berkas SQLite, termasuk rekord terhapus yang tidak dilihat tool
    skema-browser.
  - carving berkas biner generik -> carve_scan; di sini carve sadar-
    struktur SQLite (halaman/freelist/freeblock/WAL).
  - rekonstruksi rekord penuh lintas-overflow & corrupted-export
    komersial = di luar kelas; scope: halaman tanpa-overflow, teks
    per kolom best-effort.

Input -> mekanisme -> output:
  - Input : --db FILE (wajib), --wal FILE, --journal FILE (opsional),
            --min-len N (default 6), --max-strings N per halaman
            (default 50). Baca-saja; sqlite3 dibuka mode=ro+immutable
            (tidak pernah menulis).
  - Mekanisme: header -> validasi -> freelist walk (cycle-guard) ->
            carve per halaman -> WAL frame inventory -> journal magic ->
            inventaris live via sqlite3 ro -> temuan deterministik.
  - Output: JSON {schema, db, integrity, freelist, carved, wal, journal,
            tables, findings, notes, verdict}.

Cek (temuan):
  carved-credential-pattern (high): string ter-carve cocok pola
                         kredensial (AKIA/ASIA, gh*_36, xox-, JWT,
                         PRIVATE KEY, sk_live_, db://user:pass@) —
                         REDAKSI (pola + halaman + panjang, tanpa nilai).
  integrity-size-mismatch  (medium): ukuran berkas != page_count x
                         page_size (terpotong/tamper; header bisa
                         basi bila crash — tetap dilaporkan sbg fakta).
  freelist-count-mismatch  (medium): jumlah halaman freelist hasil walk
                         != header (freelist tak konsisten = korupsi /
                         dimanipulasi).
  freelist-chain-cycle     (medium): trunk chain melingkar (korupsi).
  freelist-page-out-of-range (medium): nomor halaman freelist di luar
                         ukuran berkas.
  wal-pagesize-mismatch    (medium): page size WAL != db.
  wal-freelist-overlap     (medium): WAL menulis ulang halaman yang kini
                         di freelist — kandidat data pasca-penghapusan.
  journal-pending          (low)  : rollback journal valid & tidak kosong
                         — transaksi belum selesai, data mungkin hanya
                         ada di journal.
  journal-magic-invalid    (medium): -journal berisi data tapi magic
                         salah (bukan journal SQLite / korup).

Catatan metode (bukan temuan):
  - wal-frames-present: WAL berisi frame = data yang mungkin belum di-
    checkpoint ke db utama — inventaris halaman disediakan.
  - best-effort rekord terhapus: hanya halaman freelist dgn header B-tree
    utuh & tanpa overflow; kegagalan parse dihitung, bukan dibungkam.
  - zero freelist + zero unallocated = TIDAK diartikan "dibersihkan"
    (bisa perilaku normal VACUUM) — anti-klaim.

Anti-FP: pola kredensial beranchored (kosakata paste_triage/repo-
secret-scan); klasifikasi string eksplisit per kategori; cap output per
halaman; encoding diikuti header (UTF-8/UTF-16le/be).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default low); 2 error input
(bukan SQLite / page size tidak sah / berkas tak ada).

Pemakaian:
  python tools/sqlite_forensics.py --db History --wal History-wal
  python tools/sqlite_forensics.py --db msgstore.db --min-len 8 \
      --out forensik.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import struct
import sys
from pathlib import Path

SCHEMA = "secai.sqlite-forensics/1"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MAGIC = b"SQLite format 3\x00"
JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
WAL_MAGICS = (0x377F0682, 0x377F0683)

PAGE_INDEX_INTERIOR = 0x02
PAGE_TABLE_INTERIOR = 0x05
PAGE_INDEX_LEAF = 0x0A
PAGE_TABLE_LEAF = 0x0D
BTREE_TYPES = (PAGE_INDEX_INTERIOR, PAGE_TABLE_INTERIOR,
               PAGE_INDEX_LEAF, PAGE_TABLE_LEAF)

ENCODINGS = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}

VALUE_PATTERNS = (
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-temp-cred", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{22,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("stripe-secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("db-conn-with-pass", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
        r"://[^/\s:@]+:[^/\s:@]+@")),
)

URL_RE = re.compile(r"\bhttps?://\S{4,}", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PATH_RE = re.compile(r"(?:/[A-Za-z0-9._-]{2,}){2,}|"
                     r"\b[A-Za-z]:\\(?:[\w.-]+\\?){2,}")
SQL_RE = re.compile(
    r"\b(SELECT\s.{4,}|INSERT\s+INTO\s.{4,}|UPDATE\s+\w+\s+SET\s.{4,}|"
    r"DELETE\s+FROM\s.{4,}|CREATE\s+TABLE\s.{4,})", re.IGNORECASE)
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
JSON_RE = re.compile(r'\{"[^{}]{4,400}":[^{}]{0,400}\}')


def _add(findings: "list[dict]", fid: str, sev: str, msg: str,
         poc: str) -> None:
    findings.append({"id": fid, "severity": sev, "message": msg,
                     "poc": poc[:400]})


def _read_varint(buf: bytes, pos: int) -> "tuple[int, int]":
    """(nilai, pos-berikut) varint SQLite; raise IndexError bila terpotong."""
    value = 0
    for i in range(9):
        if pos + i >= len(buf):
            raise IndexError("varint terpotong")
        byte = buf[pos + i]
        if i == 8:
            value = (value << 8) | byte
            return value, pos + 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, pos + i + 1
    return value, pos + 9


def _decode_record(payload: bytes) -> "list[str]":
    """Decode rekord SQLite (header serial types) -> nilai teks saja."""
    try:
        header_len, pos = _read_varint(payload, 0)
        if header_len < 1 or header_len > len(payload):
            return []
        types: "list[int]" = []
        while pos < header_len:
            st, pos = _read_varint(payload, pos)
            types.append(st)
            if len(types) > 64:
                return []  # pengaman: rekord tak masuk akal
        values: "list[str]" = []
        body = payload[header_len:]
        off = 0
        for st in types:
            if st == 0:
                continue
            if 1 <= st <= 4:
                size = st
            elif st == 5:
                size = 6
            elif st == 6:
                size = 8
            elif st == 7:
                size = 8
            elif st == 8 or st == 9:
                size = 0
            elif st >= 12 and st % 2 == 0:
                size = (st - 12) // 2          # blob
            elif st >= 13:
                size = (st - 13) // 2          # text
            else:
                return []                       # 10/11 reserved -> rusak
            if off + size > len(body):
                return []
            if st >= 13 and size:
                values.append(body[off:off + size]
                              .decode("utf-8", "replace"))
            off += size
        return values
    except (IndexError, struct.error):
        return []


def _parse_leaf_cells(page: bytes, page_size: int, usable: int,
                      first_byte_offset: int
                      ) -> "tuple[int, int, list[list[str]]]":
    """Best-effort parse halaman B-tree LEAF tabel (0x0D):
    (ncells, gagal_parse, [nilai-teks per rekord]). Defensive bounds."""
    try:
        ptype = page[first_byte_offset]
        if ptype != PAGE_TABLE_LEAF:
            return 0, 0, []
        ncell = struct.unpack(">H",
                              page[first_byte_offset + 3:
                                   first_byte_offset + 5])[0]
        content_start = struct.unpack(
            ">H", page[first_byte_offset + 5:first_byte_offset + 7])[0]
        if content_start == 0:
            content_start = 65536
        if ncell == 0 or ncell > page_size // 4:
            return 0, 0, []
        ptr_end = first_byte_offset + 8 + ncell * 2
        if ptr_end > page_size or content_start > page_size:
            return ncell, ncell, []
        records: "list[list[str]]" = []
        fails = 0
        for i in range(ncell):
            off = struct.unpack(
                ">H",
                page[first_byte_offset + 8 + i * 2:
                     first_byte_offset + 10 + i * 2])[0]
            if off < ptr_end or off >= usable:
                fails += 1
                continue
            try:
                payload_len, pos = _read_varint(page, off)
                rowid, pos = _read_varint(page, pos)
                if payload_len > usable - pos or payload_len > usable // 2:
                    fails += 1
                    continue
                # tanpa penanganan overflow: payload harus utuh
                values = _decode_record(page[pos:pos + payload_len])
                if values:
                    records.append(values)
                elif payload_len:
                    fails += 1
            except IndexError:
                fails += 1
        return ncell, fails, records
    except (struct.error, IndexError):
        return 0, 0, []


def _carve_strings(page: bytes, encoding: str, min_len: int,
                   limit: int) -> "list[str]":
    """String printable dari blok byte mentah, encoding-aware."""
    if encoding.startswith("utf-16"):
        # decode run UTF-16: karakter ASCII pada byte genap/ganjil
        step = 2
        nul = b"\x00\x00" if encoding.endswith("le") else b"\x00\x00"
        texts: "list[str]" = []
        i = 0
        cur: "list[bytes]" = []
        while i + 1 < len(page):
            pair = page[i:i + 2]
            if pair[1] == 0 and 0x20 <= pair[0] < 0x7F:
                cur.append(pair)
            else:
                if len(cur) >= min_len:
                    texts.append(b"".join(cur).decode(encoding, "replace"))
                    if len(texts) >= limit * 4:
                        break
                cur = []
            i += step
        if len(cur) >= min_len:
            texts.append(b"".join(cur).decode(encoding, "replace"))
        return texts[:limit]
    texts = []
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % max(min_len, 4), page):
        texts.append(m.group(0).decode("latin-1"))
        if len(texts) >= limit:
            break
    return texts[:limit]


def _classify(strings: "list[str]") -> "dict[str, list[str]]":
    out: "dict[str, list[str]]" = {"url": [], "email": [], "path": [],
                                   "sql": [], "base64": [], "json": [],
                                   "other": []}
    for s in strings:
        if URL_RE.search(s):
            out["url"].append(s)
        elif EMAIL_RE.search(s):
            out["email"].append(s)
        elif PATH_RE.match(s.strip()):
            out["path"].append(s)
        elif SQL_RE.search(s):
            out["sql"].append(s)
        elif BASE64_RE.fullmatch(s.strip()):
            out["base64"].append(s)
        elif JSON_RE.match(s.strip()):
            out["json"].append(s)
        else:
            out["other"].append(s)
    for k in out:
        out[k] = sorted(set(out[k]))[:30]
    return out


def _redact(s: str) -> str:
    """Redaksi nilai kredensial di SEMUA output (temuan disimpulkan
    dari string asli SEBELUM fungsi ini dipanggil)."""
    out = s
    for pname, pattern in VALUE_PATTERNS:
        out = pattern.sub(
            lambda m, _p=pname: f"<redacted:{_p}:len={len(m.group(0))}>",
            out)
    return out


def _check_credential(strings: "list[str]", label: str,
                      findings: "list[dict]") -> None:
    for s in strings:
        for pname, pattern in VALUE_PATTERNS:
            if pattern.search(s):
                _add(findings, "carved-credential-pattern", "high",
                     f"{label}: string ter-carve cocok pola kredensial "
                     f"'{pname}' (panjang {len(s)}) — verifikasi & "
                     f"rotasi bila konteks sensitif",
                     f"{label}:<redacted pattern={pname} len={len(s)}>")
                break


def parse_header(data: bytes) -> dict:
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    return {
        "page_size": page_size,
        "write_version": data[18],
        "read_version": data[19],
        "change_counter": struct.unpack(">I", data[24:28])[0],
        "page_count": struct.unpack(">I", data[28:32])[0],
        "freelist_trunk": struct.unpack(">I", data[32:36])[0],
        "freelist_count": struct.unpack(">I", data[36:40])[0],
        "schema_format": struct.unpack(">I", data[44:48])[0],
        "text_encoding": struct.unpack(">I", data[56:60])[0],
        "version_valid_for": struct.unpack(">I", data[92:96])[0],
        "sqlite_version": struct.unpack(">I", data[96:100])[0],
    }


def walk_freelist(data: bytes, hdr: dict) -> "tuple[list[int], list[int], dict]":
    """(trunks, leaves, stats) — walk trunk chain dgn cycle-guard."""
    page_size = hdr["page_size"]
    total_pages = max(hdr["page_count"], len(data) // page_size)
    trunks: "list[int]" = []
    leaves: "list[int]" = []
    seen: "set[int]" = set()
    trunk = hdr["freelist_trunk"]
    while trunk != 0:
        if trunk in seen:
            return trunks, leaves, {"cycle": True}
        seen.add(trunk)
        if trunk < 1 or trunk > total_pages:
            return trunks, leaves, {"out_of_range": trunk}
        off = (trunk - 1) * page_size
        if off + 8 > len(data):
            return trunks, leaves, {"truncated": trunk}
        next_trunk, nleaf = struct.unpack(">II", data[off:off + 8])
        if nleaf > (page_size - 8) // 4:
            return trunks, leaves, {"bad_leaf_count": trunk}
        leaf_pages = [struct.unpack(
            ">I", data[off + 8 + i * 4:off + 12 + i * 4])[0]
            for i in range(nleaf)]
        trunks.append(trunk)
        leaves.extend(leaf_pages)
        trunk = next_trunk
    return trunks, leaves, {}


def analyze_wal(path: "Path | None", page_size: int,
                freelist_set: "set[int]",
                findings: "list[dict]") -> dict:
    if path is None:
        return {"present": False}
    if not path.is_file():
        return {"present": False, "missing": True}
    data = path.read_bytes()
    if len(data) < 32:
        return {"present": True, "empty": True}
    magic, fmt, wpage, ckpt, salt1, salt2, c1, c2 = struct.unpack(
        ">8I", data[:32])
    if magic not in WAL_MAGICS:
        return {"present": True, "magic_valid": False}
    info: dict = {"present": True, "magic_valid": True,
                  "checksum_big_endian": magic == WAL_MAGICS[1],
                  "page_size": wpage, "checkpoint_seq": ckpt,
                  "salt": [salt1, salt2], "frames": 0, "pages": [],
                  "salt_changes": 0, "freelist_overlap": 0}
    if wpage != page_size:
        _add(findings, "wal-pagesize-mismatch", "medium",
             f"page size WAL ({wpage}) != db ({page_size}) — WAL tidak "
             f"cocok dgn berkas ini", str(path))
        return info
    off = 32
    frame_size = 24 + page_size
    seen_pages: "set[int]" = set()
    while off + frame_size <= len(data):
        pgno, dbsize, fs1, fs2 = struct.unpack(">4I", data[off:off + 16])
        if fs1 != salt1 or fs2 != salt2:
            info["salt_changes"] += 1
        if pgno in freelist_set:
            info["freelist_overlap"] += 1
        seen_pages.add(pgno)
        info["frames"] += 1
        off += frame_size
    info["pages"] = sorted(seen_pages)[:200]
    info["distinct_pages"] = len(seen_pages)
    if info["freelist_overlap"]:
        _add(findings, "wal-freelist-overlap", "medium",
             f"{info['freelist_overlap']} frame WAL menulis ulang "
             f"halaman yang kini di freelist — kandidat data "
             f"pasca-penghapusan di WAL", str(path))
    return info


def analyze_journal(path: "Path | None",
                    findings: "list[dict]") -> dict:
    if path is None:
        return {"present": False}
    if not path.is_file():
        return {"present": False, "missing": True}
    size = path.stat().st_size
    if size == 0:
        return {"present": True, "size": 0, "state": "rolled-back"}
    data = path.read_bytes()
    if data[:8] == JOURNAL_MAGIC:
        _add(findings, "journal-pending", "low",
             "rollback journal valid & tidak kosong — transaksi mungkin "
             "belum selesai (data mungkin hanya di journal)",
             str(path))
        return {"present": True, "size": size, "magic_valid": True,
                "state": "pending"}
    if data[:8] == b"\x00" * 8:
        # header journal ditulis dgn magic SAAT SYNC PERTAMA; transaksi
        # yang masih terbuka sah punya kepala nol (fakta format, bukan
        # korupsi) — tetap sinyal transaksi in-flight
        _add(findings, "journal-pending", "low",
             f"rollback journal {size} byte dgn kepala belum-tertulis "
             f"(transaksi in-flight, magic menyusul saat sync) — data "
             f"mungkin hanya di journal", str(path))
        return {"present": True, "size": size, "magic_valid": None,
                "state": "in-flight"}
    _add(findings, "journal-magic-invalid", "medium",
         f"berkas -journal berisi {size} byte tapi magic salah — bukan "
         f"journal SQLite valid / korupsi", str(path))
    return {"present": True, "size": size, "magic_valid": False}


def live_inventory(db_path: Path, notes: "list[str]") -> "list[dict]":
    """Inventaris tabel aktif via sqlite3 mode=ro+immutable (no-write)."""
    out: "list[dict]" = []
    uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            rows = con.execute(
                "SELECT name, type FROM sqlite_master "
                "WHERE type IN ('table','view') ORDER BY name").fetchall()
            for name, _t in rows:
                try:
                    cnt = con.execute(
                        f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                except sqlite3.Error:
                    cnt = None  # virtual table/corrupt — dihitung, bukan
                    # dibuang senyap
                out.append({"name": name, "rows": cnt})
        finally:
            con.close()
    except sqlite3.Error as exc:
        notes.append(f"sqlite3 ro gagal: {exc} — inventaris live kosong, "
                     "carving struktur tetap berlaku")
    return out


def _parse_args(argv: "list[str] | None") -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Forensik offline berkas SQLite generik "
                    "(freelist/WAL/unallocated)")
    ap.add_argument("--db", required=True, help="berkas basis data SQLite")
    ap.add_argument("--wal", help="berkas -wal pendamping")
    ap.add_argument("--journal", help="berkas -journal pendamping")
    ap.add_argument("--min-len", type=int, default=6,
                    help="panjang minimum string ter-carve (default 6)")
    ap.add_argument("--max-strings", type=int, default=50,
                    help="cap string per halaman (default 50)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="low")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    db_path = Path(args.db)
    if not db_path.is_file():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"berkas tak ada: {args.db}"}),
              file=sys.stderr)
        return 2
    data = db_path.read_bytes()
    if len(data) < 100 or data[:16] != MAGIC:
        print(json.dumps({"schema": SCHEMA,
                          "error": "bukan berkas SQLite (magic header "
                                   "tidak cocok)"}), file=sys.stderr)
        return 2
    hdr = parse_header(data)
    if hdr["page_size"] < 512 or hdr["page_size"] > 65536 or \
            hdr["page_size"] & (hdr["page_size"] - 1):
        print(json.dumps({"schema": SCHEMA,
                          "error": f"page size tidak sah: "
                                   f"{hdr['page_size']}"}),
              file=sys.stderr)
        return 2

    findings: "list[dict]" = []
    notes: "list[str]" = []
    usable = hdr["page_size"] - data[20]
    enc = ENCODINGS.get(hdr["text_encoding"], "utf-8")

    # --- integritas ---
    expected = hdr["page_count"] * hdr["page_size"]
    if expected != len(data):
        _add(findings, "integrity-size-mismatch", "medium",
             f"ukuran berkas {len(data)} != page_count({hdr['page_count']})"
             f" x page_size({hdr['page_size']}) = {expected} — terpotong "
             f"atau header basi (crash)", f"size={len(data)}")

    # --- freelist ---
    trunks, leaves, fl_stats = walk_freelist(data, hdr)
    fl_set = set(leaves) | set(trunks)
    freelist_info = {
        "trunk_pages": trunks, "leaf_pages": leaves[:500],
        "trunk_count": len(trunks), "leaf_count": len(leaves),
        "header_count": hdr["freelist_count"], **fl_stats,
    }
    if fl_stats.get("cycle"):
        _add(findings, "freelist-chain-cycle", "medium",
             "trunk chain freelist melingkar — freelist korup",
             "freelist")
    elif fl_stats.get("out_of_range"):
        _add(findings, "freelist-page-out-of-range", "medium",
             f"halaman freelist {fl_stats['out_of_range']} di luar "
             f"ukuran berkas", "freelist")
    if len(trunks) + len(leaves) != hdr["freelist_count"] \
            and not fl_stats:
        _add(findings, "freelist-count-mismatch", "medium",
             f"freelist walk = {len(trunks) + len(leaves)} halaman, "
             f"header = {hdr['freelist_count']} — freelist tidak "
             f"konsisten", "freelist")

    # --- carving: halaman freelist ---
    carved: dict = {"freelist_pages": {}, "unallocated_pages": {},
                    "totals": {}}
    all_strings: "list[str]" = []
    deleted_records: "list[dict]" = []
    for pg in leaves[:500]:
        if pg < 1 or (pg - 1) * hdr["page_size"] + hdr["page_size"] \
                > len(data):
            continue
        page = data[(pg - 1) * hdr["page_size"]:pg * hdr["page_size"]]
        ncell, fails, records = _parse_leaf_cells(page, hdr["page_size"],
                                                  usable, 0)
        if records:
            for vals in records[:20]:
                deleted_records.append({"page": pg, "values": [
                    v[:80] for v in vals[:8]]})
        strings = _carve_strings(page, enc, args.min_len,
                                 args.max_strings)
        all_strings.extend(strings)
        cls = _classify([_redact(s) for s in strings])
        if any(cls[k] for k in cls) or records:
            carved["freelist_pages"][pg] = {
                "cells": ncell, "parse_fails": fails,
                "records": len(records), "strings": cls}
    _check_credential(all_strings, "freelist", findings)

    # --- carving: unallocated + freeblock di halaman hidup ---
    total_pages = len(data) // hdr["page_size"]
    scanned_live = 0
    for pg in range(1, min(total_pages, 5000) + 1):
        off = (pg - 1) * hdr["page_size"]
        if pg in fl_set:
            continue
        page = data[off:off + hdr["page_size"]]
        ptype = page[0]
        if ptype not in (PAGE_TABLE_LEAF, PAGE_INDEX_LEAF):
            continue
        hdr_size = 12 if ptype in (PAGE_INDEX_INTERIOR,
                                   PAGE_TABLE_INTERIOR) else 8
        ncell = struct.unpack(">H", page[3:5])[0]
        if ncell > hdr["page_size"] // 4:
            continue
        content_start = struct.unpack(">H", page[5:7])[0]
        if content_start == 0:
            content_start = 65536
        ptr_end = hdr_size + ncell * 2
        scanned_live += 1
        unalloc = b""
        if ptr_end < content_start <= hdr["page_size"]:
            unalloc += page[ptr_end:content_start]
        # freeblock chain
        fb = struct.unpack(">H", page[1:3])[0]
        seen_fb: "set[int]" = set()
        while fb and fb not in seen_fb and fb + 4 <= hdr["page_size"]:
            seen_fb.add(fb)
            nxt, size = struct.unpack(">HH", page[fb:fb + 4])
            unalloc += page[fb + 4:fb + size]
            fb = nxt
        if unalloc:
            strings = _carve_strings(unalloc, enc, args.min_len,
                                     args.max_strings)
            if strings:
                all_strings.extend(strings)
                carved["unallocated_pages"][pg] = \
                    _classify([_redact(s) for s in strings])
    _check_credential(all_strings, "unallocated", findings)
    carved["totals"] = {
        "strings_carved": len(all_strings),
        "live_leaf_pages_scanned": scanned_live,
        "freelist_leaf_pages_carved": len(carved["freelist_pages"]),
        "unallocated_pages_with_strings":
            len(carved["unallocated_pages"]),
    }
    carved["deleted_record_candidates"] = deleted_records[:50]

    # --- WAL & journal ---
    wal_info = analyze_wal(Path(args.wal) if args.wal else None,
                           hdr["page_size"], fl_set, findings)
    journal_info = analyze_journal(
        Path(args.journal) if args.journal else None, findings)
    if isinstance(wal_info.get("frames"), int) and wal_info["frames"]:
        notes.append(f"WAL berisi {wal_info['frames']} frame "
                     f"({wal_info.get('distinct_pages', 0)} halaman "
                     f"unik) — data mungkin belum di-checkpoint")
    if wal_info.get("salt_changes"):
        notes.append(f"{wal_info['salt_changes']} frame WAL dgn salt "
                     f"beda — sisa generasi checkpoint sebelumnya")

    # --- inventaris live ---
    tables = live_inventory(db_path, notes)

    findings.sort(key=lambda f: -SEV_ORDER.get(f["severity"], 0))
    threshold = SEV_ORDER[args.fail_on]
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in findings),
                default=0)
    result = {
        "schema": SCHEMA,
        "db": {
            "path": str(db_path), "size": len(data),
            "page_size": hdr["page_size"], "page_count": hdr["page_count"],
            "journal_mode": "wal" if hdr["write_version"] == 2
                            else "rollback",
            "text_encoding": enc,
            "change_counter": hdr["change_counter"],
            "schema_format": hdr["schema_format"],
            "sqlite_version": hdr["sqlite_version"],
        },
        "integrity": {"expected_size": expected, "actual_size": len(data)},
        "freelist": freelist_info,
        "carved": carved,
        "wal": wal_info,
        "journal": journal_info,
        "tables": tables,
        "fail_on": args.fail_on,
        "findings": findings,
        "notes": notes,
        "verdict": "findings" if worst >= threshold else "clean",
    }
    out_text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(out_text, encoding="utf-8")
    print(out_text)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
