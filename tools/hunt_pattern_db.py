"""[ABH-W3: pattern memory] hunt_pattern_db — basis pengetahuan pola
LINTAS-SESI/LINTAS-TARGET dari hasil hunt yang terkonfirmasi.

Port konsep dari awarexone/Agentic-Bug-Hunter (MIT) — memory/pattern_db.py
+ memory/rotation.py + commands/remember.md (patterns.jsonl: pola sukses
terindeks kelas vuln + tech-stack, dedup per triplet, rotasi ukuran file).
Atribusi konsep, lisensi sumber MIT. Dibangun FROM SCRATCH untuk kontrak
cyphron: stdlib, argparse + type hints, fail-closed, nol jaringan.

RANAH EKSPLISIT (mini-program ABH-PORT — anti-tabrakan):
  - session_ledger.py = rantai bukti PER-SESI (fact/intent) — TIDAK
    disentuh; tool ini bukan jurnal sesi dan tidak menyimpan bukti mentah.
  - triage_advisor.py = loop belajar PRIORITAS dari outcomes laporan —
    TIDAK disentuh; tool ini tidak menilai prioritas.
  - tool ini (W3)     = pengetahuan lintas-sesi/lintas-target: "kelas
    vuln X lewat teknik Y pernah berhasil di tech-stack Z".

Entri (JSONL, satu baris = satu pola):
  target, vuln_class, technique : wajib non-kosong; dedup per triplet
                                  (target, vuln_class, technique)
  tech_stack    : daftar teknologi (opsional); match = irisan SEBAGIAN
                  dihitung (satu token yang sama sudah cukup)
  outcome       : accepted | duplicate | informative | not_applicable |
                  false_positive | pending (default pending; nilai lain
                  ditolak — fail-closed)
  evidence_ref  : wajib non-kosong — tanpa rujukan bukti pola TIDAK
                  disimpan ("no proof, no memory")
  ts            : ISO-8601 UTC, diisi otomatis saat add

Rotasi: otomatis saat add bila ukuran file >= --max-bytes (backup
file.1 .. file.N terbatas --keep, terlama dihapus); subkomando rotate
memicu rotasi dengan ambang sama. Baris JSONL rusak TIDAK pernah
diabaikan diam-diam: dihitung di meta (lines_corrupt + detail baris &
galat) pada SETIAP operasi. Baris rusak tak mungkin menabrak dedup
(kuncinya tak terbaca), jadi add tetap jalan — tapi hitungannya
selalu dilaporkan.

Subkomando:
  add    --target T --vuln-class K --technique Q [--tech-stack a,b]
         [--outcome accepted] --evidence-ref R [--db F] [--max-bytes N]
         [--keep N]      -> 0 tersimpan; 1 duplikat; 2 input rusak
  match  [--vuln-class K] [--tech-stack a,b] [--db F] [--limit N]
                          -> 0 ada kena; 1 tanpa kena; 2 file tak ada/rusak
  rotate [--db F] [--max-bytes N] [--keep N]
                          -> 0 (rotated true/false sesuai ambang); 2 galat
  stats  [--db F]        -> 0; 2 file tak ada

Pemakaian:
  python tools/hunt_pattern_db.py add --target shop.example.com \
      --vuln-class idor --technique numeric-id-swap \
      --tech-stack python,django --outcome accepted \
      --evidence-ref "findings.json#3"
  python tools/hunt_pattern_db.py match --vuln-class idor \
      --tech-stack django,nginx
  python tools/hunt_pattern_db.py rotate --db hunt-patterns.jsonl
  python tools/hunt_pattern_db.py stats

Nol jaringan: seluruh operasi murni I/O file lokal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "hunt_pattern_db/v1"

DEFAULT_DB = "hunt-patterns.jsonl"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_KEEP = 3

REQUIRED_FIELDS = ("target", "vuln_class", "technique")
KNOWN_OUTCOMES = ("accepted", "duplicate", "informative", "not_applicable",
                  "false_positive", "pending")
# Urutan kepercayaan untuk sorting match (tinggi dulu).
OUTCOME_RANK = {"accepted": 4, "pending": 3, "duplicate": 2, "informative": 2,
                "not_applicable": 1, "false_positive": 0}


class InputError(ValueError):
    """Input rusak/invalid — dipetakan ke exit 2 (fail-closed)."""


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def dedup_key(entry: dict) -> tuple[str, str, str]:
    """Kunci dedup: (target, vuln_class, technique) ternormalisasi."""
    return (_norm(entry.get("target", "")),
            _norm(entry.get("vuln_class", "")),
            _norm(entry.get("technique", "")))


def validate_entry(target: str, vuln_class: str, technique: str,
                   tech_stack: str, outcome: str,
                   evidence_ref: str) -> dict:
    """Susun + validasi satu entri; galat = InputError (exit 2)."""
    vals = {"target": (target or "").strip(),
            "vuln_class": (vuln_class or "").strip(),
            "technique": (technique or "").strip()}
    for k, v in vals.items():
        if not v:
            raise InputError(f"field wajib '{k}' kosong (fail-closed)")
    stack = [t.strip() for t in (tech_stack or "").split(",") if t.strip()]
    out = (outcome or "pending").strip()
    if out not in KNOWN_OUTCOMES:
        raise InputError(
            f"outcome '{out}' tidak dikenal (harus salah satu dari "
            f"{', '.join(KNOWN_OUTCOMES)})")
    ref = (evidence_ref or "").strip()
    if not ref:
        raise InputError(
            "evidence_ref wajib non-kosong — tanpa rujukan bukti pola "
            "tidak disimpan (no proof, no memory)")
    entry = {"target": vals["target"],
             "vuln_class": vals["vuln_class"],
             "technique": vals["technique"],
             "tech_stack": stack,
             "outcome": out,
             "evidence_ref": ref,
             "ts": datetime.now(timezone.utc)
                   .strftime("%Y-%m-%dT%H:%M:%SZ")}
    return entry


def read_db(path: Path, required: bool = True) -> tuple[list[dict], dict]:
    """Baca seluruh baris JSONL + meta.

    Baris rusak (bukan JSON) dihitung dan dilaporkan di meta.corrupt —
    tidak pernah dibuang diam-diam. required=True dan file tak ada =
    InputError (exit 2, fail-closed).
    """
    meta = {"lines_total": 0, "lines_ok": 0, "lines_corrupt": 0,
            "corrupt": []}
    if not path.exists():
        if required:
            raise InputError(f"basis pola tidak ada: {path}")
        return [], meta
    entries: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            meta["lines_total"] += 1
            try:
                e = json.loads(s)
            except json.JSONDecodeError as exc:
                meta["lines_corrupt"] += 1
                meta["corrupt"].append({"line": lineno, "error": str(exc)})
                continue
            if not isinstance(e, dict):
                meta["lines_corrupt"] += 1
                meta["corrupt"].append(
                    {"line": lineno, "error": "baris bukan objek JSON"})
                continue
            meta["lines_ok"] += 1
            entries.append(e)
    return entries, meta


def needs_rotation(path: Path, max_bytes: int) -> bool:
    try:
        return path.stat().st_size >= max_bytes
    except FileNotFoundError:
        return False


def rotate_file(path: Path, keep: int) -> bool:
    """Geser file -> file.1 -> file.2 ... terbatas --keep. True bila file
    digeser. Pemanggil menjamin operasi ini berjalan satu-proses."""
    oldest = Path(str(path) + f".{keep}")
    if oldest.exists():
        oldest.unlink()
    for i in range(keep - 1, 0, -1):
        src = Path(str(path) + f".{i}")
        if src.exists():
            os.replace(src, Path(str(path) + f".{i + 1}"))
    if path.exists():
        os.replace(path, Path(str(path) + ".1"))
        return True
    return False


def list_backups(path: Path, keep: int) -> list[dict]:
    out = []
    for i in range(1, keep + 1):
        bp = Path(str(path) + f".{i}")
        if bp.exists():
            out.append({"path": bp.name, "bytes": bp.stat().st_size})
    return out


def op_add(args: argparse.Namespace) -> tuple[int, dict]:
    path = args.db
    entry = validate_entry(args.target, args.vuln_class, args.technique,
                           args.tech_stack, args.outcome, args.evidence_ref)
    if path.exists():
        entries, meta = read_db(path, required=True)
        if dedup_key(entry) in {dedup_key(e) for e in entries}:
            return 1, {"schema": SCHEMA, "op": "add", "file": str(path),
                       "saved": False, "duplicate": True,
                       "dedup_key": list(dedup_key(entry)),
                       "meta": meta,
                       "note": "duplikat (target, vuln_class, technique) "
                               "— tidak ditulis ulang"}
    else:
        meta = {"lines_total": 0, "lines_ok": 0, "lines_corrupt": 0,
                "corrupt": []}
        path.parent.mkdir(parents=True, exist_ok=True)
    rotated = False
    if path.exists() and needs_rotation(path, args.max_bytes):
        rotated = rotate_file(path, args.keep)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
    meta["lines_ok"] += 1
    meta["lines_total"] += 1
    return 0, {"schema": SCHEMA, "op": "add", "file": str(path),
               "saved": True, "duplicate": False, "rotated": rotated,
               "entry": entry, "meta": meta}


def op_match(args: argparse.Namespace) -> tuple[int, dict]:
    entries, meta = read_db(args.db, required=True)
    q_class = _norm(args.vuln_class) if args.vuln_class else None
    q_stack: set[str] | None = None
    if args.tech_stack:
        q_stack = {_norm(t) for t in args.tech_stack.split(",")
                   if t.strip()}
    hits: list[dict] = []
    for e in entries:
        if q_class and _norm(e.get("vuln_class", "")) != q_class:
            continue
        matched: list[str] = []
        if q_stack is not None:
            estack = {_norm(t) for t in (e.get("tech_stack") or [])}
            matched = sorted(q_stack & estack)
            if not matched:
                continue  # irisan kosong = bukan kena; sebagian pun dihitung
        hit = dict(e)
        hit["matched_tech"] = matched
        hits.append(hit)
    hits.sort(key=lambda h: (OUTCOME_RANK.get(h.get("outcome", ""), 0),
                             h.get("ts", "")), reverse=True)
    if args.limit is not None:
        if args.limit < 1:
            raise InputError("--limit harus >= 1")
        hits = hits[:args.limit]
    return (0 if hits else 1), {
        "schema": SCHEMA, "op": "match", "file": str(args.db),
        "query": {"vuln_class": args.vuln_class,
                  "tech_stack": sorted(q_stack) if q_stack else None},
        "matches": hits, "count": len(hits), "meta": meta,
        "note": "match = kelas vuln eksak + irisan tech-stack sebagian "
                "(satu token sama sudah kena); sort outcome-tertinggi "
                "lalu terbaru"}


def op_rotate(args: argparse.Namespace) -> tuple[int, dict]:
    path = args.db
    if not path.exists():
        raise InputError(f"basis pola tidak ada: {path}")
    rotated = False
    if needs_rotation(path, args.max_bytes):
        rotated = rotate_file(path, args.keep)
    entries, meta = read_db(path, required=False)
    return 0, {"schema": SCHEMA, "op": "rotate", "file": str(path),
               "rotated": rotated, "max_bytes": args.max_bytes,
               "keep": args.keep, "backups": list_backups(path, args.keep),
               "meta": meta,
               "note": "rotasi hanya bila ukuran >= max_bytes; backup "
                       "file.1..file.N terbatas keep"}


def op_stats(args: argparse.Namespace) -> tuple[int, dict]:
    entries, meta = read_db(args.db, required=True)
    by_class: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    by_target: dict[str, int] = {}
    for e in entries:
        by_class[e.get("vuln_class", "?")] = \
            by_class.get(e.get("vuln_class", "?"), 0) + 1
        by_outcome[e.get("outcome", "?")] = \
            by_outcome.get(e.get("outcome", "?"), 0) + 1
        by_target[e.get("target", "?")] = \
            by_target.get(e.get("target", "?"), 0) + 1
    size = args.db.stat().st_size if args.db.exists() else 0
    return 0, {"schema": SCHEMA, "op": "stats", "file": str(args.db),
               "total_entries": len(entries), "bytes": size,
               "by_vuln_class": by_class, "by_outcome": by_outcome,
               "by_target": by_target,
               "backups": list_backups(args.db, args.keep),
               "meta": meta}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", type=Path, default=Path(DEFAULT_DB),
                       help=f"file JSONL basis pola (default "
                            f"{DEFAULT_DB})")
        p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                       help="ambang rotasi otomatis (default 10 MB)")
        p.add_argument("--keep", type=int, default=DEFAULT_KEEP,
                       help="jumlah backup rotasi dipertahankan "
                            "(default 3)")
        p.add_argument("--out", type=Path, default=None,
                       help="tulis laporan JSON ke file (default stdout)")

    p_add = sub.add_parser("add", help="simpan satu pola")
    p_add.add_argument("--target", required=True)
    p_add.add_argument("--vuln-class", required=True, dest="vuln_class")
    p_add.add_argument("--technique", required=True)
    p_add.add_argument("--tech-stack", default="",
                       help="teknologi dipisah koma, mis. python,django")
    p_add.add_argument("--outcome", default="pending",
                       help="|".join(KNOWN_OUTCOMES))
    p_add.add_argument("--evidence-ref", required=True, dest="evidence_ref")
    common(p_add)

    p_match = sub.add_parser("match", help="cari pola kena")
    p_match.add_argument("--vuln-class", default=None, dest="vuln_class")
    p_match.add_argument("--tech-stack", default=None,
                         help="irisan sebagian dihitung (koma)")
    p_match.add_argument("--limit", type=int, default=None)
    common(p_match)

    p_rot = sub.add_parser("rotate", help="rotasi bila lewat ambang")
    common(p_rot)

    p_stats = sub.add_parser("stats", help="statistik basis pola")
    common(p_stats)
    return ap


OPS = {"add": op_add, "match": op_match, "rotate": op_rotate,
       "stats": op_stats}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc, report = OPS[args.cmd](args)
    except InputError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if getattr(args, "out", None):
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
