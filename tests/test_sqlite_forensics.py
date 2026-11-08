"""test_sqlite_forensics — forensik berkas SQLite offline (#0896), nol
jaringan.

Fixture = basis data SQLite NYATA dibangun runtime via sqlite3 (bukan
dump yang diunduh): baris diinsert lalu DIHAPUS agar freelist berisi
halaman terhapus, WAL dibuat dgn journal_mode=WAL tanpa checkpoint,
rollback journal disalin saat transaksi terbuka. Tool dibaca read-only
(mode=ro+immutable) — berkas sumber fixture tidak pernah ditulis.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import sqlite_forensics as sfo  # noqa: E402


def _plant_freeleaf_content(db: Path, payload: bytes) -> None:
    """Tanam byte carvable ke halaman LEAF freelist.

    Halaman leaf freelist tidak berstruktur (fileformat2: "Leaf pages
    of the freelist contain no information"), jadi isinya aman ditulis
    langsung tanpa merusak akuntansi freelist. SQLite >= 3.46 menimpa
    isi halaman bebas saat commit (3.45 menyimpannya) — penanaman ini
    membuat skenario carving DETERMINISTIK di semua versi SQLite."""
    raw = bytearray(db.read_bytes())
    pagesize = struct.unpack(">H", raw[16:18])[0]
    if pagesize == 1:
        pagesize = 65536
    trunk = struct.unpack(">I", raw[32:36])[0]
    seen: "set[int]" = set()
    leaf = None
    while trunk and trunk not in seen:
        seen.add(trunk)
        off = (trunk - 1) * pagesize
        nxt = struct.unpack(">I", raw[off:off + 4])[0]
        k = struct.unpack(">I", raw[off + 4:off + 8])[0]
        if k >= 1:
            leaf = struct.unpack(">I", raw[off + 8:off + 12])[0]
            break
        trunk = nxt
    assert leaf is not None, "fixture: tidak ada halaman leaf freelist"
    loff = (leaf - 1) * pagesize
    raw[loff:loff + len(payload)] = payload
    db.write_bytes(bytes(raw))


def _make_db_with_deleted(path: Path, n: int = 120) -> None:
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, "
                "body TEXT, refs TEXT)")
    # urutan penting: marker + blok kredensial DI TENGAH, survivor di
    # ekor — halaman terbebaskan tetap interior (tidak ter-truncate)
    # sehingga freelist selalu berisi halaman di semua ukuran n
    n_markers = max(n // 2, 44)  # cukup halaman: 1 jadi trunk, sisanya leaf
    n_survivors = n - n // 2     # live rows (dijaga sama seperti desain awal)
    for i in range(n_markers):
        con.execute("INSERT INTO notes (body, refs) VALUES (?, ?)",
                    (f"DELETEDMARKER-{i:04d} " + "x" * 180,
                     f"/share/doc{i}.pdf"))
    con.commit()
    # blok kredensial setelah marker
    for i in range(8):
        con.execute("INSERT INTO notes (body, refs) VALUES (?, ?)",
                    (f"CREDBLOCK-{i} AKIA{i:016d} "
                     f"https://attacker.example/drop{i}",
                     "/share/secret"))
    con.commit()
    # survivor di ekor (dihitung test_live_inventory_rows: n - n//2)
    for i in range(n_survivors):
        con.execute("INSERT INTO notes (body, refs) VALUES (?, ?)",
                    (f"survivor-{i:04d} " + "y" * 180,
                     f"/share/doc{i}.pdf"))
    con.commit()
    con.execute("DELETE FROM notes WHERE body LIKE 'CREDBLOCK-%' "
                "OR body LIKE 'DELETEDMARKER-%'")
    con.commit()
    con.close()
    # skenario carving deterministik lintas versi SQLite: tanam isinya
    # ke halaman leaf freelist (SQLite 3.46+ menimpa isi halaman bebas
    # saat commit — tanpa penanaman, byte baris terhapus tak tersisa)
    _plant_freeleaf_content(path, (
        b"DELETEDMARKER-7777 AKIA0000000000007777 "
        b"https://attacker.example/drop7777 " + b"P" * 64))


def _make_wal_pair(db: Path, wal: Path, n: int = 40) -> None:
    src = db.parent / "wal-source.db"
    con = sqlite3.connect(str(src))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, "
                "payload TEXT)")
    for i in range(n):
        con.execute("INSERT INTO events (payload) VALUES (?)",
                    (f"wal-event-{i:04d} " + "z" * 120,))
    con.commit()
    # salin db + -wal SAAT koneksi masih terbuka (belum checkpoint)
    shutil.copyfile(src, db)
    wal_src = src.parent / (src.name + "-wal")
    if wal_src.is_file():
        shutil.copyfile(wal_src, wal)
    con.close()


def _make_pending_journal(db: Path, journal: Path) -> None:
    src = db.parent / "journal-source.db"
    con = sqlite3.connect(str(src))
    con.execute("CREATE TABLE kv (k TEXT, v TEXT)")
    con.execute("INSERT INTO kv VALUES ('a', '1')")
    con.commit()
    con.execute("BEGIN")
    con.execute("INSERT INTO kv VALUES ('pending', 'uncommitted-data')")
    # salin db + -journal saat transaksi terbuka
    shutil.copyfile(src, db)
    jrn = src.parent / (src.name + "-journal")
    if jrn.is_file():
        shutil.copyfile(jrn, journal)
    con.rollback()
    con.close()


def _ids(res: dict) -> "list[str]":
    return [f["id"] for f in res["findings"]]


def test_freelist_and_carve(tmp_path: Path) -> None:
    db = tmp_path / "notes.db"
    _make_db_with_deleted(db)
    out = tmp_path / "out.json"
    rc = sfo.main(["--db", str(db), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["schema"] == sfo.SCHEMA
    # freelist terisi oleh halaman terhapus
    assert res["freelist"]["leaf_count"] >= 1
    assert res["freelist"]["header_count"] == \
        res["freelist"]["trunk_count"] + res["freelist"]["leaf_count"]
    assert "freelist-count-mismatch" not in _ids(res)
    # carving menemukan marker dari baris terhapus
    blob = out.read_text(encoding="utf-8")
    assert "DELETEDMARKER" in blob
    assert res["carved"]["totals"]["strings_carved"] >= 1
    # kredensial terhapus -> temuan high dgn redaksi
    assert "carved-credential-pattern" in _ids(res)
    cred = [f for f in res["findings"]
            if f["id"] == "carved-credential-pattern"]
    assert any("aws-access-key-id" in f["poc"] for f in cred)
    # nilai kredensial TIDAK PERNAH keluar di output mana pun:
    # temuan, kategori carve, dan kandidat rekord terhapus
    assert "AKIA0000000000000000" not in blob
    assert "AKIA0000000000000007" not in blob
    # URL dropper = bukti IOC, sah tampil utuh (defang via ioc_defang
    # saat reporting) — yang direduksi hanya NILAI kredensial
    assert "attacker.example/drop" in blob
    assert "<redacted:" in blob                   # jejak redaksi ada
    # inventaris live
    names = [t["name"] for t in res["tables"]]
    assert "notes" in names
    rows = {t["name"]: t["rows"] for t in res["tables"]}
    assert isinstance(rows["notes"], int) and rows["notes"] >= 1
    assert rc == 1


def test_wal_frames(tmp_path: Path) -> None:
    db = tmp_path / "wal.db"
    wal = tmp_path / "wal.db-wal"
    _make_wal_pair(db, wal)
    out = tmp_path / "out.json"
    sfo.main(["--db", str(db), "--wal", str(wal), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["wal"]["present"] is True
    assert res["wal"]["magic_valid"] is True
    assert res["wal"]["frames"] >= 1
    assert res["db"]["journal_mode"] == "wal"
    assert any("checkpoint" in n for n in res["notes"])
    # page size WAL == db -> tanpa mismatch
    assert "wal-pagesize-mismatch" not in _ids(res)


def test_wal_pagesize_mismatch(tmp_path: Path) -> None:
    db = tmp_path / "m.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE t (x TEXT)")
    con.execute("INSERT INTO t VALUES ('hello')")
    con.commit()
    con.close()
    wal = tmp_path / "fake-wal"
    # header WAL dgn page size 1024 (db 4096)
    wal.write_bytes(struct.pack(">8I", 0x377F0682, 3007000, 1024,
                                0, 1, 2, 3, 4) + b"\x00" * 1048)
    out = tmp_path / "out.json"
    rc = sfo.main(["--db", str(db), "--wal", str(wal), "--out",
                   str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert "wal-pagesize-mismatch" in _ids(res)
    assert rc == 1


def test_pending_journal(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    journal = tmp_path / "p.db-journal"
    _make_pending_journal(db, journal)
    out = tmp_path / "out.json"
    sfo.main(["--db", str(db), "--journal", str(journal),
              "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert "journal-pending" in _ids(res)
    # journal disalin saat transaksi terbuka: magic True (sudah sync)
    # atau None (in-flight, kepala belum tertulis) — dua-duanya sah
    assert res["journal"]["magic_valid"] in (True, None)


def test_integrity_size_mismatch(tmp_path: Path) -> None:
    db = tmp_path / "trunc.db"
    _make_db_with_deleted(db, n=40)
    raw = db.read_bytes()
    db.write_bytes(raw[:len(raw) // 2])   # potong separuh
    out = tmp_path / "out.json"
    rc = sfo.main(["--db", str(db), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    assert "integrity-size-mismatch" in _ids(res)
    assert rc == 1


def test_live_inventory_rows(tmp_path: Path) -> None:
    db = tmp_path / "live.db"
    _make_db_with_deleted(db, n=20)
    out = tmp_path / "out.json"
    sfo.main(["--db", str(db), "--out", str(out)])
    res = json.loads(out.read_text(encoding="utf-8"))
    rows = {t["name"]: t["rows"] for t in res["tables"]}
    # 20 insert, 10 terhapus (termasuk baris kredensial) -> 10 hidup
    assert rows["notes"] == 10
    assert rows["notes"] != 0


def test_fail_closed(tmp_path: Path) -> None:
    # berkas tak ada -> 2
    assert sfo.main(["--db", str(tmp_path / "nope.db")]) == 2
    # bukan SQLite -> 2
    notdb = tmp_path / "not.db"
    notdb.write_bytes(b"BUKAN DATABASE SQLITE" * 10)
    assert sfo.main(["--db", str(notdb)]) == 2
    # page size tidak sah (bukan pangkat dua) -> 2
    fake = tmp_path / "fake.db"
    hdr = bytearray(b"SQLite format 3\x00")
    hdr += struct.pack(">H", 300)          # page size 300 — tidak sah
    hdr += b"\x01\x01" + b"\x00" * 80
    fake.write_bytes(bytes(hdr))
    assert sfo.main(["--db", str(fake)]) == 2


def test_cli_subprocess(tmp_path: Path) -> None:
    db = tmp_path / "cli.db"
    _make_db_with_deleted(db, n=30)
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "sqlite_forensics.py"),
         "--db", str(db)],
        capture_output=True, text=True, timeout=120)
    res = json.loads(proc.stdout)
    assert res["schema"] == sfo.SCHEMA
    assert proc.returncode == 1            # ada kredensial terhapus
    assert res["carved"]["totals"]["strings_carved"] >= 1
