"""Feed NVD 1.1 -> kb/data/cpe.sqlite (indeks CPE<->CVE, sqlite3 stdlib).

Schema (lihat docs/ROADMAP-GODTIER-KNOWLEDGE.md §4):
- cpe(cpe23, vendor, product, version, update_kw)
- cve(id, published, modified, cvss_score, cvss_vector, cwe, description)
- cve_cpe(cve_id, cpe23, version_start_incl, version_end_incl,
          version_start_excl, version_end_excl)

Versi dibandingkan SEMANTIK (numerik per komponen); batas/binding yang tak
bisa diparse = ambigu -> pemanggil (cve_matcher) WAJIB menolak klaim dari
baris ambigu (zero-FP).
"""

from __future__ import annotations

import gzip
import json
import os
import sqlite3
from pathlib import Path

from .paths import resolve_kb_dir

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cpe (
  cpe23 TEXT PRIMARY KEY, vendor TEXT, product TEXT, version TEXT,
  update_kw TEXT);
CREATE TABLE IF NOT EXISTS cve (
  id TEXT PRIMARY KEY, published TEXT, modified TEXT, cvss_score REAL,
  cvss_vector TEXT, cwe TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS cve_cpe (
  cve_id TEXT, cpe23 TEXT, version_start_incl TEXT, version_end_incl TEXT,
  version_start_excl TEXT, version_end_excl TEXT);
CREATE INDEX IF NOT EXISTS idx_cpe_vp ON cpe(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cc ON cve_cpe(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_score ON cve(cvss_score);
"""


def parse_cpe23(uri: str) -> tuple[str, str, str, str, str] | None:
    """cpe:2.3:a:vendor:product:ver:update:... -> (part, vendor, product,
    version, update). None bila bentuknya tidak standar."""
    parts = str(uri).split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
    update = parts[6] if len(parts) > 6 else "*"
    if not vendor or not product:
        return None
    return part, vendor, product, version, update


def vtuple(version: str) -> tuple | None:
    """'3.4.0.7' -> (3,4,0,7); ada komponen non-numerik -> None (ambigu)."""
    parts = str(version).strip().split(".")
    out: list[int] = []
    for p in parts:
        if not p.isdigit():
            return None
        out.append(int(p))
    return tuple(out) if out else None


def _cmp(a: tuple, b: tuple) -> int:
    """-1/0/+1 dengan padding nol (2.3 == 2.3.0)."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_bounds(version: str, start_incl: str | None,
                      end_incl: str | None, start_excl: str | None,
                      end_excl: str | None) -> bool | None:
    """True/False = pasti; None = ambigu (jangan klaim dari None)."""
    v = vtuple(version)
    if v is None:
        return None
    for bound, label in ((start_incl, "si"), (start_excl, "se"),
                         (end_incl, "ei"), (end_excl, "ee")):
        if not bound:
            continue
        b = vtuple(bound)
        if b is None:
            return None  # bound non-numerik -> ambigu
        c = _cmp(v, b)
        if label == "si" and c < 0:
            return False   # version < start_incl
        if label == "se" and c <= 0:
            return False   # version <= start_excl
        if label == "ei" and c > 0:
            return False   # version > end_incl
        if label == "ee" and c >= 0:
            return False   # version >= end_excl
    return True


def _iter_cpe_match(nodes: list) -> list[dict]:
    out: list[dict] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        out.extend(m for m in node.get("cpe_match", []) if isinstance(m, dict))
        out.extend(_iter_cpe_match(node.get("children", [])))
    return out


def _feed_rows(item: dict):
    """Satu CVE_Items -> (cve_row, [(cpe_cpe row, ...)])."""
    meta = item.get("cve", {})
    cve_id = (meta.get("CVE_data_meta") or {}).get("ID") or ""
    if not cve_id:
        return None, []
    descs = (meta.get("description") or {}).get("description_data") or []
    description = ""
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            description = d["value"][:500]
            break
    v3 = ((item.get("impact") or {}).get("baseMetricV3") or {}).get("cvssV3") or {}
    score = v3.get("baseScore")
    vector = v3.get("vectorString") or ""
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    cwe = ""
    try:
        cwe = (meta.get("problemtype") or {}).get("problemtype_data")[0][
            "description"][0]["value"] or ""
    except (IndexError, TypeError, KeyError):
        pass
    cve_row = (cve_id, item.get("publishedDate") or "",
               item.get("lastModifiedDate") or "", score, vector, cwe,
               description)
    pairs: list[tuple] = []
    for m in _iter_cpe_match((item.get("config") or {}).get("nodes", [])):
        uri = m.get("cpe23Uri") or ""
        parsed = parse_cpe23(uri)
        if parsed is None:
            continue
        pairs.append((cve_id, uri,
                      m.get("versionStartIncluding"),
                      m.get("versionEndIncluding"),
                      m.get("versionStartExcluding"),
                      m.get("versionEndExcluding")))
    return cve_row, pairs


def build_sqlite(kb_dir: Path | str | None = None,
                 db_path: Path | str | None = None) -> dict:
    """Bangun/ perbarui cpe.sqlite dari feed di kb/data/nvd/ (atomik)."""
    d = resolve_kb_dir(kb_dir)
    # feed 1.1 (nvdcve-1.1-*) maupun hasil API 2.0 (nvd-api-*) berformat sama
    feeds = sorted((d / "nvd").glob("*.json.gz"))
    if not feeds:
        return {"error": "tidak ada feed NVD di kb/data/nvd/ — jalankan kb sync"}
    db = Path(db_path) if db_path else d / "cpe.sqlite"
    tmp = db.with_name("cpe.sqlite.tmp")
    if tmp.exists():
        tmp.unlink()
    con = sqlite3.connect(str(tmp))
    con.executescript(_SCHEMA)
    n_cve = n_pair = 0
    for feed in feeds:
        raw = json.loads(gzip.decompress(feed.read_bytes())
                         .decode("utf-8", errors="replace"))
        for item in raw.get("CVE_Items", []):
            cve_row, pairs = _feed_rows(item)
            if cve_row is None:
                continue
            con.execute("INSERT OR IGNORE INTO cve VALUES (?,?,?,?,?,?,?)",
                        cve_row)
            n_cve += 1
            for pair in pairs:
                con.execute("INSERT OR IGNORE INTO cve_cpe VALUES (?,?,?,?,?,?)",
                            pair)
                parsed = parse_cpe23(pair[1])
                if parsed is None:
                    continue
                _part, vendor, product, version, update = parsed
                con.execute("INSERT OR IGNORE INTO cpe VALUES (?,?,?,?,?)",
                            (pair[1], vendor, product, version, update))
                n_pair += 1
    con.commit()
    cpe_rows = con.execute("SELECT COUNT(*) FROM cpe").fetchone()[0]
    con.close()
    os.replace(tmp, db)
    return {"db": str(db), "cves": n_cve, "cpe_rows": cpe_rows,
            "cve_cpe_rows": n_pair, "feeds": [f.name for f in feeds]}


def query_cves_for_product(db_path: Path | str, vendor: str,
                           product: str, version: str) -> tuple[list[dict], int]:
    """CPE -> CVE yang rentang versinya PASTI cocok (ambigu dibuang).
    Return (rows urut CVSS desc, jumlah ambigu)."""
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    rows: list[dict] = []
    ambiguous = 0
    try:
        cur = con.execute(
            """SELECT cc.cpe23, cc.version_start_incl, cc.version_end_incl,
                      cc.version_start_excl, cc.version_end_excl,
                      c.id, c.cvss_score, c.cvss_vector, c.cwe,
                      c.description
               FROM cpe p
               JOIN cve_cpe cc ON cc.cpe23 = p.cpe23
               JOIN cve c ON c.id = cc.cve_id
               WHERE p.vendor = ? AND p.product = ?
               ORDER BY c.cvss_score DESC""",
            (vendor, product))
        for r in cur:
            cpe_ver = parse_cpe23(r["cpe23"])
            cpe_version = cpe_ver[3] if cpe_ver else "*"
            if cpe_version not in ("*", "-", ""):
                # CVE menunjuk versi eksak — cocok hanya bila identik;
                # versi target tak terbaca = ambigu, bukan kebetulan cocok
                a, b = vtuple(version), vtuple(cpe_version)
                if a is None or b is None or a != b:
                    continue
            v = version_in_bounds(version, r["version_start_incl"],
                                  r["version_end_incl"],
                                  r["version_start_excl"],
                                  r["version_end_excl"])
            if v is None:
                ambiguous += 1
                continue
            if not v:
                continue
            rows.append(dict(r))
    finally:
        con.close()
    seen: set[str] = set()
    unique = []
    for row in rows:
        if row["id"] in seen:
            continue
        seen.add(row["id"])
        unique.append(row)
    unique.sort(key=lambda x: (-(x["cvss_score"] or 0), x["id"]))
    return unique, ambiguous
