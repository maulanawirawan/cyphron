"""Indeks Exploit-DB (files_exploits.csv) — referensi exploit PUBLIK.

Ini KATALOG: edb_reference hanya menunjuk EDB-ID; tidak ada satu pun
exploit yang dijalankan. Pencocokan konservatif:
- baris dengan nama produk + versi eksplisit -> "terkait versi ini",
- baris dengan nama produk saja -> hanya dihitung (bukan klaim versi).
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path


def load_index(csv_path: Path) -> list[dict]:
    """Parse files_exploits.csv (utf-8 dengan toleransi). Baris rusak = skip."""
    rows: list[dict] = []
    text = Path(csv_path).read_text(encoding="utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not row.get("id") or not row.get("description"):
            continue
        rows.append({"id": row["id"], "description": row["description"],
                     "type": row.get("type") or "",
                     "platform": row.get("platform") or "",
                     "date": row.get("date_published") or ""})
    return rows


def _version_re(version: str) -> str:
    """'3.4.0.7' -> regex versi longgar aman (titik = literal)."""
    return re.escape(version).replace(r"\.", r"\.")


def find_exploits(rows: list[dict], names: list[str], version: str | None = None,
                  limit: int = 5) -> tuple[list[dict], int]:
    """Cari entri exploit utk nama produk (wajib) + versi (bila diberikan).

    Return (daftar entri versi-eksplisit urut id, jumlah entri nama-saja).
    Nama dipakai kata-utuh (\\b) agar 'PHP' tidak menelan 'PHPMyAdmin'.
    """
    versioned: list[dict] = []
    name_only = 0
    seen: set[str] = set()
    name_alts = "|".join(re.escape(n) for n in names if n)
    if not name_alts:
        return [], 0
    name_rx = re.compile(rf"(?i)(?<![A-Za-z])({name_alts})(?![A-Za-z])")
    ver_rx = (re.compile(rf"(?i)(?<![0-9.]){_version_re(version)}(?![0-9.])")
              if version and version != "*" else None)
    for row in rows:
        desc = row["description"]
        if not name_rx.search(desc):
            continue
        if ver_rx is not None and ver_rx.search(desc):
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            versioned.append(row)
        else:
            # nama ada tanpa versi spesifik — hanya dihitung (bukan klaim)
            name_only += 1
    versioned.sort(key=lambda r: int(r["id"]) if str(r["id"]).isdigit() else 0)
    return versioned[:limit], name_only
