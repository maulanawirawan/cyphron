"""[LEGION] Session ledger — memori jangka panjang tiga lapis untuk sesi
kerja panjang (nightrun, operator AI, handover antar sesi).

Terinspirasi mekanisme "History" sapper-v2 (fact-intent graph): sesi mati,
graph-nya yang survive — penerus baca graph dan langsung kerja tanpa
mengulang dari nol. Dibangun from scratch dengan kontrak secai: bukti
opsional tapi selalu bisa di-drill, baris korup tidak boleh meracuni
graph secara senyap (fail-closed: dihitung dan dilaporkan).

Tiga lapis recall (perpustakaan, bukan dinding teks):
  - title    : ID + judul sebaris — untuk kejelasan isyarat (gist)
  - summary  : + ringkasan satu kalimat — untuk keputusan
  - evidence : + muatan bukti penuh — untuk verifikasi

Dua jenis entri (append-only JSONL, satu file, tahan sesi mati):
  fact  : observasi terkonfirmasi ("flag sudah di tangan" versi kerja
          penilaian: fakta yang sudah dicek, bukan dugaan)
  intent: satuan kerja yang diusulkan DARI fakta — siklus
          usul → kerjakan → selesai (tutup dengan --note)

Pemakaian:
  python tools/session_ledger.py fact "target X merespons 200 tanpa auth" \
      --summary "permukaan lembut, layak scan penuh" \
      --evidence "headers: server=caddy; length=1204"
  python tools/session_ledger.py intent --from F001 "jalankan tier0 scan"
  python tools/session_ledger.py recall --layer title --status open
  python tools/session_ledger.py done I001 --note "scan selesai, 3 temuan"

Default ledger file: `session-ledger.jsonl` di CWD (bukan intel/ — file
itu tidak dikelola manifest intel_sync).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

SCHEMA_VERSION = 1
VALID_INTENT_STATUS = ("open", "done", "dropped")


def now_iso() -> str:
    """Timestamp UTC ISO-8601 (offset eksplisit)."""
    import datetime
    return (datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S+00:00"))


def load_entries(path: Path) -> tuple[list[dict], list[str]]:
    """Baca JSONL ledger -> (entri_valid, daftar_baris_korup).

    Baris korup TIDAK di-skip senyap — dikembalikan agar pelapor bisa
    menampilkannya (baris rusak = data bukti yang setengah hidup; tidak
    boleh pura-pura tidak ada, tapi juga tidak boleh mematikan graph).
    """
    if not path.exists():
        return [], []
    entries: list[dict] = []
    corrupt: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if not isinstance(data, dict) or "type" not in data:
                raise ValueError("bukan entri ledger")
            entries.append(data)
        except (json.JSONDecodeError, ValueError):
            corrupt.append(line[:200])
    return entries, corrupt


def next_id(entries: list[dict], prefix: str) -> str:
    """ID berurutan per prefix (F001, F002, I001...) — murni dari isi
    file, bukan dari memori sesi; dua proses baca file yang sama akan
    menghitung ID sama → append-only file + satu penulis per sesi."""
    highest = 0
    for entry in entries:
        eid = entry.get("id") or ""
        if eid.startswith(prefix):
            try:
                highest = max(highest, int(eid[len(prefix):]))
            except ValueError:
                continue
    return f"{prefix}{highest + 1:03d}"


def add_fact(path: Path, title: str, summary: str | None = None,
             evidence: str | None = None) -> dict:
    """Catat fakta terkonfirmasi. Wajib punya minimal judul yang bisa
    berdiri sendiri (lapis judul harus cukup untuk isyarat)."""
    if not title.strip():
        raise ValueError("fakta tanpa judul = tidak bisa di-recall — tolak")
    entries, _ = load_entries(path)
    fact = {
        "type": "fact", "id": next_id(entries, "F"),
        "at": now_iso(), "title": title.strip(),
        "summary": (summary or "").strip() or None,
        "evidence": (evidence or "").strip() or None,
        "schema": SCHEMA_VERSION,
    }
    append_line(path, fact)
    return fact


def add_intent(path: Path, title: str, from_ids: list[str] | None = None,
               summary: str | None = None) -> dict:
    """Usulkan pekerjaan DARI fakta — fail-closed: ID fakta yang tidak
    ada ditolak (intent melayang tanpa dasar = dugaan, bukan graph)."""
    if not title.strip():
        raise ValueError("intent tanpa judul — tolak")
    from_ids = list(from_ids or [])
    entries, _ = load_entries(path)
    known = {e["id"] for e in entries if e.get("type") == "fact"}
    unknown = [fid for fid in from_ids if fid not in known]
    if unknown:
        raise ValueError(
            f"intent merujuk fakta yang tidak ada di ledger: {unknown}")
    intent = {
        "type": "intent", "id": next_id(entries, "I"),
        "at": now_iso(), "title": title.strip(),
        "summary": (summary or "").strip() or None,
        "from": sorted(from_ids), "status": "open",
        "note": None, "done_at": None,
        "schema": SCHEMA_VERSION,
    }
    append_line(path, intent)
    return intent


def close_intent(path: Path, intent_id: str, status: str,
                 note: str | None = None) -> dict:
    """Tutup intent (done/dropped) — append event penutup; riwayat tetap
    utuh (append-only: versi lama tidak pernah ditimpa)."""
    if status not in ("done", "dropped"):
        raise ValueError("status penutupan harus done/dropped")
    entries, _ = load_entries(path)
    target = next((e for e in entries
                   if e.get("id") == intent_id and e.get("type") == "intent"),
                  None)
    if target is None:
        raise ValueError(f"intent {intent_id} tidak ada di ledger")
    # status efektif: file append-only — entry asli selalu "open",
    # penutupan hidup di event close (fail-closed: dobel tutup = tolak)
    closes = {e["target"]: e for e in entries if e.get("type") == "close"}
    effective = (closes[intent_id]["status"]
                 if intent_id in closes else target.get("status"))
    if effective != "open":
        raise ValueError(
            f"intent {intent_id} sudah {effective} — jangan "
            "ditutup dua kali")
    event = {
        "type": "close", "id": next_id(entries, "C"),
        "at": now_iso(), "target": intent_id, "status": status,
        "note": (note or "").strip() or None, "schema": SCHEMA_VERSION,
    }
    append_line(path, event)
    return event


def recall(path: Path, layer: str = "title", status: str | None = None,
           entry_type: str | None = None) -> dict:
    """Baca graph per lapis; intent diekspansi dengan status efektifnya
    (event close di-aplikasi, karena file append-only)."""
    entries, corrupt = load_entries(path)
    closes = {e["target"]: e for e in entries if e.get("type") == "close"}

    rows: list[dict] = []
    for entry in entries:
        if entry.get("type") == "close":
            continue
        row = dict(entry)
        if entry["type"] == "intent":
            closed = closes.get(entry["id"])
            if closed:
                row["status"] = closed["status"]
                row["note"] = closed.get("note")
                row["done_at"] = closed.get("at")
            if status and row.get("status") != status:
                continue
        elif status:
            continue  # filter status hanya bermakna untuk intent
        if entry_type and entry["type"] != entry_type:
            continue

        if layer == "title":
            row = {k: row.get(k) for k in
                   ("type", "id", "at", "title", "status")}
        elif layer == "summary":
            row = {k: row.get(k) for k in
                   ("type", "id", "at", "title", "summary", "status",
                    "from", "note", "done_at")}
        # layer "evidence": semua field
        rows.append(row)
    return {"entries": rows, "corrupt_lines": corrupt,
            "counts": {"facts": sum(1 for r in rows
                                    if r["type"] == "fact"),
                       "intents": sum(1 for r in rows
                                      if r["type"] == "intent")}}


def append_line(path: Path, entry: dict) -> None:
    """Append satu baris JSON (path dibuat kalau belum ada)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ledger sesi tiga lapis (fakta / intent / recall) — "
                    "memori yang survive antar sesi.")
    parser.add_argument("--ledger", default="session-ledger.jsonl",
                        help="file ledger JSONL (default session-ledger.jsonl)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fact = sub.add_parser("fact", help="catat fakta terkonfirmasi")
    p_fact.add_argument("title")
    p_fact.add_argument("--summary", default=None)
    p_fact.add_argument("--evidence", default=None)

    p_intent = sub.add_parser("intent", help="usulkan pekerjaan dari fakta")
    p_intent.add_argument("title")
    p_intent.add_argument("--from", dest="from_ids", nargs="*",
                          default=[], help="ID fakta dasar (F001 ...)")
    p_intent.add_argument("--summary", default=None)

    p_done = sub.add_parser("done", help="tutup intent")
    p_done.add_argument("intent_id")
    p_done.add_argument("--note", default=None)
    p_done.add_argument("--dropped", action="store_true",
                        help="tandai dibuang, bukan selesai")

    p_recall = sub.add_parser("recall", help="baca graph per lapis")
    p_recall.add_argument("--layer", choices=("title", "summary", "evidence"),
                          default="title")
    p_recall.add_argument("--status", default=None,
                          help="filter intent: open/done/dropped")
    p_recall.add_argument("--type", dest="entry_type", default=None,
                          choices=("fact", "intent"))
    p_recall.add_argument("--json", action="store_true",
                          help="keluaran JSON penuh")

    args = parser.parse_args(argv)
    path = Path(args.ledger)

    try:
        if args.cmd == "fact":
            entry = add_fact(path, args.title, args.summary, args.evidence)
            print(f"{entry['id']}  {entry['title']}")
        elif args.cmd == "intent":
            entry = add_intent(path, args.title, args.from_ids, args.summary)
            print(f"{entry['id']}  {entry['title']}  "
                  f"(from {','.join(entry['from']) or '-'})")
        elif args.cmd == "done":
            event = close_intent(path, args.intent_id,
                                 "dropped" if args.dropped else "done",
                                 args.note)
            print(f"{event['id']}  {event['target']} -> {event['status']}")
        elif args.cmd == "recall":
            report = recall(path, args.layer, args.status, args.entry_type)
            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
                return 0
            for row in report["entries"]:
                if row["type"] == "intent":
                    print(f"{row['id']}  [{row.get('status', 'open'):>7}]  "
                          f"{row.get('title')}")
                else:
                    print(f"{row['id']}  {row.get('title')}")
            if report["corrupt_lines"]:
                print(f"PERINGATAN: {len(report['corrupt_lines'])} baris "
                      "korup dilewati — periksa file ledger", file=sys.stderr)
            print(f"({report['counts']['facts']} fakta, "
                  f"{report['counts']['intents']} intent)")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
