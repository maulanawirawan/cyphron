r"""[SAFETY: read-only] zeek_front_scan — deteksi OFFLINE domain fronting
(T1090.004) dari log Zeek: mismatch antara SNI (ssl.log server_name) dan
Host header (http.log host) pada koneksi yang SAMA (join by uid). TANPA
jaringan.

Pembagian ranah (TIDAK diduplikasi):
  - beacon conn.log        -> zeek_beacon_scan (B13)
  - lateral SMB/DCE/NTLM   -> zeek_lateral_scan (B15)
  - tunneling dns.log      -> dns_log_triage (B07)
  - di sini: pasangan ssl.log + http.log (SNI vs Host).

Input -> mekanisme -> output:
  - Input : http.log + ssl.log Zeek (TSV classic dgn header #fields
            ATAU JSON lines) dari sensor lab sendiri.
  - Mekanisme: join records by uid -> cocokkan host vs server_name
            (sama, atau salah satu adalah suffix label dari yang lain
            = domain sama; selain itu = mismatch).
  - Output: temuan {check, severity, uid, orig, resp, sni, host,
            message} + stats (matched/uid-hilang) + notes.

Cek:
  sni-host-mismatch  (high) : SNI != Host pada koneksi sama
                              (T1090.004); verifikasi manual: IP respons
                              milik CDN SNI, bukan milik Host — tanpa
                              itu temuan tetap LEAD.
  fronting-source    (medium): satu sumber (id.orig_h) dengan
                              >= --min-front koneksi mismatch
                              (default 3) — ringkasan per sumber.

Fail-closed:
  - Kedua file wajib; salah satu tidak ada -> exit 2.
  - Tidak ada record ter-parse di salah satu file -> exit 2.
  - uid tidak tersedia di salah satu log = join mustahil -> dicatat
    di notes dan stats.uid_missing (tidak disimpulkan bersih).
  - host/server_name kosong ("-") dilewati dgn hitungan stats
    (HTTP/1.0 dan SNI kosong memang lazim — bukan temuan).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/zeek_front_scan.py --http http.log --ssl ssl.log
  python tools/zeek_front_scan.py --http http.json --ssl ssl.json \
      --min-front 5 --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "secai.zeek-front-scan/1"
MAX_FILE_BYTES = 256 * 1024 * 1024

HTTP_FIELDS = ("uid", "host", "method", "uri", "id.orig_h", "id.resp_h")
SSL_FIELDS = ("uid", "server_name", "id.orig_h", "id.resp_h")


def _get(rec: dict, field: str) -> str:
    """Ambil field Zeek; dukung flat 'id.orig_h' dan nested id.orig_h."""
    if field in rec:
        v = rec[field]
    else:
        v = rec
        for part in field.split("."):
            if not isinstance(v, dict) or part not in v:
                return ""
            v = v[part]
    if isinstance(v, dict):
        return ""
    return str(v) if v is not None else ""


def _unset(val: str) -> str:
    return "" if val in ("-", "", "(empty)") else val


def load_zeek(path: Path, fields_wanted: "tuple[str, ...]") \
        -> "tuple[list[dict], int]":
    """Baca satu log Zeek (TSV #fields / JSONL) -> (records, baris
    rusak). Hanya field yang diminta diambil."""
    recs: list[dict] = []
    bad = 0
    fmt_tsv = False
    cols: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace") \
            .splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                cols = line.split("\t")[1:]
                fmt_tsv = True
            continue
        if line.lstrip().startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            recs.append({f: _get(rec, f) for f in fields_wanted})
        elif fmt_tsv and cols:
            parts = line.split("\t")
            if len(parts) < len(cols):
                bad += 1
                continue
            recs.append(dict(zip(cols, parts)))
        else:
            bad += 1
    return recs, bad


def _same_domain(a: str, b: str) -> bool:
    """Sama persis, atau salah satu adalah suffix label utuh dari yang
    lain (sub.domain == domain). Tanpa daftar PSL — arah sengaja
    konservatif (mengurangi FP, tidak menambah)."""
    a = a.lower().rstrip(".")
    b = b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze(http: "list[dict]", ssl: "list[dict]", min_front: int) \
        -> "tuple[list[dict], dict, list[str]]":
    findings: list[dict] = []
    notes: list[str] = []
    sni_by_uid = {}
    for r in ssl:
        uid = _unset(r.get("uid", ""))
        if uid:
            sni_by_uid[uid] = r
    matched = 0
    uid_missing = 0
    per_source: dict[str, list[tuple[str, str, str]]] = {}
    for r in http:
        uid = _unset(r.get("uid", ""))
        if not uid:
            uid_missing += 1
            continue
        s = sni_by_uid.get(uid)
        if s is None:
            continue
        host = _unset(r.get("host", ""))
        sni = _unset(s.get("server_name", ""))
        if not host or not sni:
            continue
        matched += 1
        if _same_domain(host, sni):
            continue
        orig = r.get("id.orig_h") or s.get("id.orig_h") or ""
        resp = r.get("id.resp_h") or s.get("id.resp_h") or ""
        findings.append({
            "check": "sni-host-mismatch", "severity": "high",
            "uid": uid, "orig": orig, "resp": resp, "sni": sni,
            "host": host,
            "message": f"SNI '{sni}' != Host '{host}' pada koneksi "
                       f"{uid} ({orig} -> {resp}) — kandidat domain "
                       "fronting (T1090.004); verifikasi IP respons "
                       "milik CDN SNI sebelum eskalasi",
        })
        per_source.setdefault(orig, []).append((uid, sni, host))
    for orig, items in per_source.items():
        if len(items) >= min_front:
            findings.append({
                "check": "fronting-source", "severity": "medium",
                "uid": "", "orig": orig, "resp": "", "sni": "",
                "host": "",
                "message": f"{orig} memiliki {len(items)} koneksi "
                           "SNI-vs-Host mismatch — ringkasan per "
                           "sumber (T1090.004)",
            })
    if uid_missing:
        notes.append(f"{uid_missing} record http.log tanpa uid — tidak "
                     "bisa di-join dgn ssl.log (dihitung eksplisit).")
    if not sni_by_uid:
        notes.append("ssl.log tidak memuat record ber-uid — join "
                     "mustahil; cek kecocokan format/export.")
    stats = {"http_records": len(http), "ssl_records": len(ssl),
             "matched_uid": matched, "uid_missing_http": uid_missing,
             "findings": len(findings)}
    return findings, stats, notes


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi OFFLINE domain fronting (SNI vs Host) "
                    "dari http.log + ssl.log Zeek — read-only, nol "
                    "jaringan.")
    ap.add_argument("--http", type=Path, required=True,
                    help="file http.log Zeek (TSV/JSONL)")
    ap.add_argument("--ssl", type=Path, required=True,
                    help="file ssl.log Zeek (TSV/JSONL)")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--min-front", type=int, default=3,
                    help="ambang ringkasan fronting-source per sumber")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    for p in (args.http, args.ssl):
        if not p.is_file():
            print(f"error: file tidak ada: {p}", file=sys.stderr)
            return 2
        if p.stat().st_size > MAX_FILE_BYTES:
            print(f"error: file terlalu besar (> {MAX_FILE_BYTES} B): {p}",
                  file=sys.stderr)
            return 2
    http, bad_h = load_zeek(args.http, HTTP_FIELDS)
    ssl, bad_s = load_zeek(args.ssl, SSL_FIELDS)
    if not http or not ssl:
        print("error: tidak ada record ter-parse (http="
              f"{len(http)}, ssl={len(ssl)}) — bukan log Zeek?",
              file=sys.stderr)
        return 2
    findings, stats, notes = analyze(http, ssl, args.min_front)
    stats["bad_lines_http"] = bad_h
    stats["bad_lines_ssl"] = bad_s
    report = {"schema": SCHEMA, "stats": stats, "findings": findings,
              "notes": notes}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        for f in findings:
            print(f"[{f['severity'].upper():6}] {f['check']}: "
                  f"{f['message']}")
        print(f"-- {stats['findings']} temuan, "
              f"{stats['matched_uid']} koneksi ter-join")
        for n in notes:
            print(f"note: {n}")
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    return 1 if any(rank[f["severity"]] >= rank[args.fail_on]
                    for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
