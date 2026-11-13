r"""[SAFETY: read-only + local-write] log_chain_verify — rantai integritas
log tamper-evident: bangun ledger hash-chain SHA-256 atas baris log,
verifikasi rantai, dan lokalisasi entry yang dirusak. "Blockchain" di
sini = hash chaining append-only (setiap chain_hash mengikat prev_hash +
content_hash), BUKAN jaringan P2P — checkpoint ke timestamp service
eksternal = live ops, di luar tool.

Deviasi dari sumber yang DOKUMENTASIKAN: chain_hash sumber memasukkan
timestamp ingestion ke dalam hash; di sini chain_hash = SHA-256(
prev_hash + "|" + content_hash) — deterministik dan bisa diverifikasi
ulang kapan pun tanpa side-channel, sementara timestamp ingestion
disimpan sebagai METADATA entri (tidak masuk hash) agar verifikasi
tidak bergantung pada ketersediaan jam kolektor.

Ranah tool tetangga: session_ledger = memori jangka panjang sesi
agent (bukan log target); secret_history_scan/zeroize_scan = isi
rahasia. Tool ini = bukti log TIDAK DIUBAH setelah ledger dibangun —
untuk chain-of-custody (cf. METHODS seksi 40) log lab/berizin.

Sub-perintah:
  chain     : --logs FILE[,FILE...] / --dir DIR --out LEDGER.jsonl
              (satu baris log = satu entri: {i, src, line,
              content_hash, prev_hash, chain_hash, ts}; genesis
              prev_hash = 64x'0')
  verify    : --ledger LEDGER.jsonl [--recheck FILE[,FILE...]]
              -> temuan tamper (lokalisasi entry pertama yang putus)
  checkpoint: --ledger LEDGER.jsonl -> SHA-256 dari chain_hash
              terakhir (bahan anchor eksternal; pengiriman ke TSA =
              langkah manual/live ops)

Temuan verify (semua high, deterministik, zero-FP atas ledger):
  ledger-malformed  : baris ledger bukan JSON valid / field hilang
  ledger-gap        : indeks tidak kontigu (entri hilang/sisipan)
  prev-hash-break   : prev_hash entri != chain_hash entri sebelumnya
  chain-hash-break  : chain_hash tidak cocok rekomputasi (TITIK
                      TAMPER PERTAMA — semua setelahnya ikut putus)
  content-drift     : --recheck: isi file sekarang != content_hash
  source-missing    : --recheck: file sumber tidak ada / terpotong

Fail-closed: input tidak terbaca / ledger kosong / nol baris log ->
exit 2 (bukti kosong tidak pernah "bersih"). File log >64MB ditolak
(explisit, bukan parse diam-diam sebagian).

Exit: chain/checkpoint -> 0 sukses, 2 error input.
      verify -> 0 utuh; 1 ada tamper/drift; 2 error input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

SCHEMA = "secai.log-chain-verify/1"
GENESIS = "0" * 64
MAX_BYTES = 64 * 1024 * 1024
LEDGER_FIELDS = {"i", "src", "line", "content_hash", "prev_hash",
                 "chain_hash", "ts"}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_lines(path: Path) -> "list[tuple[int, str]]":
    if not path.is_file():
        raise ValueError(f"file tidak ada: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"melebihi batas ukuran 64MB: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        out.append((n, raw))
    return out


def _collect_files(logs_arg: "str | None", dir_arg: "str | None") \
        -> "list[Path]":
    files: "list[Path]" = []
    if logs_arg:
        for part in logs_arg.split(","):
            p = Path(part.strip())
            if not p.is_file():
                raise ValueError(f"file log tidak ada: {p}")
            files.append(p)
    if dir_arg:
        d = Path(dir_arg)
        if not d.is_dir():
            raise ValueError(f"bukan direktori: {d}")
        files.extend(sorted(p for p in d.rglob("*")
                            if p.is_file() and p.suffix.lower()
                            in {".log", ".txt", ".jsonl"}))
    if not files:
        raise ValueError("tidak ada input log (fail-closed)")
    return files


def cmd_chain(args: argparse.Namespace) -> int:
    files = _collect_files(args.logs, args.dir)
    prev = GENESIS
    entries: "list[dict]" = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for f in files:
        for lineno, content in _read_lines(f):
            content_hash = _sha256_hex(content.encode("utf-8"))
            chain_hash = _sha256_hex(
                f"{prev}|{content_hash}".encode("ascii"))
            entries.append({"i": len(entries), "src": str(f),
                            "line": lineno, "content_hash": content_hash,
                            "prev_hash": prev, "chain_hash": chain_hash,
                            "ts": ts})
            prev = chain_hash
    if not entries:
        print(json.dumps({"schema": SCHEMA,
                          "error": "nol baris log — fail-closed"}),
              file=sys.stderr)
        return 2
    out = Path(args.out)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"schema": SCHEMA, "type": "ledger",
                             "entries": len(entries)}) + "\n")
        for e in entries:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(json.dumps({"schema": SCHEMA, "entries": len(entries),
                      "head": prev, "ledger": str(out)},
                     ensure_ascii=False))
    return 0


def _load_ledger(path: Path) -> "list[dict]":
    if not path.is_file():
        raise ValueError(f"ledger tidak ada: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"melebihi batas ukuran 64MB: {path}")
    entries: "list[dict]" = []
    header_seen = False
    for n, raw in enumerate(path.read_text(
            encoding="utf-8", errors="replace").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            entries.append({"_malformed_line": n, "_raw_len": len(raw)})
            continue
        if isinstance(obj, dict) and obj.get("type") == "ledger":
            header_seen = True
            continue
        if not isinstance(obj, dict) or not LEDGER_FIELDS <= set(obj):
            entries.append({"_malformed_line": n, "_raw_len": len(raw)})
            continue
        entries.append(obj)
    if not entries:
        raise ValueError("ledger kosong — bukti kosong bukan 'bersih' "
                         "(fail-closed)")
    if not header_seen:
        raise ValueError("header ledger tidak dikenali (bukan output "
                         "secai log_chain_verify)")
    return entries


def cmd_verify(args: argparse.Namespace) -> int:
    entries = _load_ledger(Path(args.ledger))
    findings: "list[dict]" = []

    def add(check: str, i: object, msg: str) -> None:
        findings.append({"check": check, "entry": i, "message": msg})

    prev_chain: "str | None" = None
    expected_i = 0
    for e in entries:
        if "_malformed_line" in e:
            add("ledger-malformed", e["_malformed_line"],
                f"baris ledger #{e['_malformed_line']} bukan entri "
                "JSON valid — ledger dimodifikasi/rusak.")
            prev_chain = None
            expected_i += 1
            continue
        i = e.get("i")
        if i != expected_i:
            add("ledger-gap", i,
                f"indeks {i} tidak kontigu (diharapkan {expected_i}) "
                "— entri hilang atau disisipkan.")
        stored_prev = e.get("prev_hash")
        if prev_chain is not None and stored_prev != prev_chain:
            add("prev-hash-break", i,
                f"prev_hash entri {i} tidak cocok chain_hash entri "
                "sebelumnya — rantai diputus di sini.")
        recomputed = _sha256_hex(
            f"{stored_prev}|{e.get('content_hash')}".encode("ascii"))
        if recomputed != e.get("chain_hash"):
            add("chain-hash-break", i,
                f"chain_hash entri {i} tidak cocok rekomputasi — "
                "TITIK TAMPER PERTAMA (semua entri setelahnya ikut "
                "putus).")
            prev_chain = None
        else:
            prev_chain = e.get("chain_hash")
        expected_i += 1

    # --recheck: bandingkan isi sumber sekarang vs content_hash ledger
    if args.recheck:
        ledger_files: "dict[str, list[dict]]" = {}
        for e in entries:
            if "_malformed_line" in e:
                continue
            ledger_files.setdefault(str(e.get("src")), []).append(e)
        recheck_set = {str(Path(p).resolve())
                       for p in args.recheck.split(",")
                       if p.strip()}
        for src, ents in sorted(ledger_files.items()):
            srcp = Path(src)
            if str(srcp.resolve()) not in recheck_set:
                continue
            if not srcp.is_file():
                add("source-missing", ents[0].get("i"),
                    f"sumber {src} tidak ada — bukti hilang, entri "
                    "ledger tak bisa dipertanggungjawabkan.")
                continue
            try:
                lines = _read_lines(srcp)
            except ValueError as exc:
                add("source-missing", ents[0].get("i"), str(exc))
                continue
            if len(lines) < len(ents):
                add("source-missing", ents[-1].get("i"),
                    f"{src} kini {len(lines)} baris vs ledger "
                    f"{len(ents)} entri — baris dihapus.")
            for e in ents:
                idx = e.get("line")
                if not isinstance(idx, int) or idx > len(lines):
                    continue
                cur = _sha256_hex(lines[idx - 1][1].encode("utf-8"))
                if cur != e.get("content_hash"):
                    add("content-drift", e.get("i"),
                        f"{src}:{idx} berubah vs ledger — isi file "
                        "dimodifikasi SETELAH ledger dibangun.")

    print(json.dumps({"schema": SCHEMA,
                      "entries": len(entries),
                      "tamper": len(findings),
                      "first_break": (findings[0]["entry"]
                                      if findings else None),
                      "findings": findings,
                      "notes": [
                          "verifikasi menyatakan LEDGER internally "
                          "consistent + (bila --recheck) isi sumber "
                          "cocok; keaslian ledger sendiri dijaga "
                          "checkpoint eksternal (TSA = live ops).",
                      ]}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    entries = _load_ledger(Path(args.ledger))
    last = None
    for e in entries:
        if isinstance(e, dict) and "chain_hash" in e:
            last = e.get("chain_hash")
    if not last:
        print(json.dumps({"schema": SCHEMA,
                          "error": "tidak ada chain_hash valid "
                                   "dalam ledger"}),
              file=sys.stderr)
        return 2
    checkpoint = _sha256_hex(last.encode("ascii"))
    print(json.dumps({"schema": SCHEMA, "ledger_head": last,
                      "checkpoint": checkpoint,
                      "note": "anchor checkpoint ini ke timestamp "
                              "service eksternal secara manual "
                              "(live ops, tanpa jaringan dari tool)"},
                     ensure_ascii=False))
    return 0


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ledger hash-chain tamper-evident untuk log lab "
                    "(stdlib, nol jaringan).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_chain = sub.add_parser("chain", help="bangun ledger dari log")
    p_chain.add_argument("--logs", default=None,
                         help="file log dipisah koma (urutan = order)")
    p_chain.add_argument("--dir", default=None,
                         help="direktori *.log/*.txt/*.jsonl")
    p_chain.add_argument("--out", required=True)
    p_chain.set_defaults(func=cmd_chain)

    p_verify = sub.add_parser("verify", help="verifikasi ledger")
    p_verify.add_argument("--ledger", required=True)
    p_verify.add_argument("--recheck", default=None,
                          help="file sumber dipisah koma utk cek drift")
    p_verify.set_defaults(func=cmd_verify)

    p_cp = sub.add_parser("checkpoint",
                          help="checkpoint hash kepala ledger")
    p_cp.add_argument("--ledger", required=True)
    p_cp.set_defaults(func=cmd_checkpoint)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
