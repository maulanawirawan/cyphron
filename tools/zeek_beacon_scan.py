r"""[SAFETY: read-only] zeek_beacon_scan — deteksi pola beacon C2 dari
Zeek conn.log secara OFFLINE (TSV classic atau JSON lines, stdlib murni).

Port konsep dari antrean SKILL-PORT-QUEUE #0390 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'detecting-beaconing-patterns-with-
zeek' — grup per pasangan orig/resp, interval antar-koneksi, stdev rendah
relatif thd mean = kandidat beacon; atribusi konsep, lisensi sumber
Apache-2.0). Dibangun FROM SCRATCH: parser log Zeek + statistik interval
(CV/jitter) ditulis sendiri — TIDAK memakai ZAT/pandas/numpy dan tidak
menyalin kode sumber skill. Beda dengan tools/netflow_parse.py (NetFlow
v5 datagram biner): alat ini membaca LOG Zeek TSV/JSON.

Input -> mekanisme -> output:
  - Input : file conn.log Zeek (TSV dengan header #fields, atau JSON
            lines dengan field ts/id.orig_h/id.resp_h/id.resp_p).
            Read-only, NOL jaringan — analisis log milik sendiri/lab.
  - Mekanisme: parse tiap koneksi -> grup per (orig, resp, port) ->
            urutkan ts -> interval antar koneksi -> mean, stdev,
            koefisien variasi CV = stdev/mean.
  - Output: kandidat beacon {pair, conns, mean_interval_s, stdev_s, cv,
            regularity} — LEAD statistik, bukan klaim C2 (perangkat sah
            yang polling juga reguler; konfirmasi butuh konteks
            reputasi dst/port/URL).

Kriteria (semua threshold bisa diatur):
  conns >= --min-conns (default 10)
  cv    <= --max-cv    (default 0.25)   [CV kecil = interval konsisten]
  mean  >= --min-interval (default 5s; membuang burst konkurensi)
  severity: high jika conns >= --strong-conns (default 50) DAN cv lolos;
            selain itu medium.

Fail-closed: file tidak ada -> exit 2; log tanpa header #fields dan bukan
JSON valid -> exit 2; NOL koneksi ter-parse -> exit 2 (bukti kosong tidak
boleh dilaporkan "bersih"); baris tak ter-parse dicatat (maks 10 contoh)
dan tidak pernah dibuang diam-diam.

Exit: 0 bersih; 1 ada kandidat >= --fail-on (default medium); 2 error.

Pemakaian:
  python tools/zeek_beacon_scan.py --log conn.log
  python tools/zeek_beacon_scan.py --log conn.json --format json
  python tools/zeek_beacon_scan.py --log conn.log --min-conns 20 --json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

SCHEMA = "cyphron.zeek-beacon-scan/1"

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}


def _mean(values: "list[float]") -> float:
    return sum(values) / len(values)


def _pstdev(values: "list[float]", mu: float) -> float:
    return math.sqrt(sum((v - mu) ** 2 for v in values) / len(values))


def _parse_tsv_header(lines: "list[str]") -> "tuple[dict[str, int], int] | None":
    """Kembalikan pemetaan nama kolom -> index + baris data pertama."""
    for i, line in enumerate(lines[:60]):
        if line.startswith("#fields"):
            parts = line.split("\t")
            # '#fields' '\x09' 'ts' '\x09' 'uid' ...
            names = parts[1:] if len(parts) > 1 else []
            names = [n.strip() for n in names]
            return {n: idx for idx, n in enumerate(names)}, i + 1
    return None


def parse_conn_log(text: str) -> "tuple[list[dict], list[str]]":
    """Parse isi conn.log -> (koneksi [ts, orig, resp, port], baris_gagal).

    Format ditentukan otomatis: TSV (ada #fields) atau JSON lines.
    Baris komentar/tak ter-parse dikumpulkan (maks 10 contoh).
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    conns: "list[dict]" = []
    bad: "list[str]" = []

    header = _parse_tsv_header(lines)
    if header is not None:
        col, start = header
        need = {"ts", "id.orig_h", "id.resp_h"}
        if not need.issubset(col):
            return [], [f"#fields tanpa kolom wajib: {need - set(col)}"]
        port_col = col.get("id.resp_p")
        for line in lines[start:]:
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < len(col):
                bad.append(line[:120])
                continue
            try:
                ts = float(parts[col["ts"]])
            except ValueError:
                bad.append(line[:120])
                continue
            port = 0
            if port_col is not None:
                try:
                    port = int(parts[port_col])
                except ValueError:
                    port = 0
            conns.append({"ts": ts, "orig": parts[col["id.orig_h"]],
                          "resp": parts[col["id.resp_h"]], "port": port})
        return conns, bad

    # JSON lines
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad.append(line[:120])
            continue
        ident = obj.get("id", obj)
        try:
            ts = float(obj["ts"])
            orig = ident["orig_h"]
            resp = ident["resp_h"]
        except (KeyError, TypeError, ValueError):
            bad.append(line[:120])
            continue
        conns.append({"ts": ts, "orig": str(orig), "resp": str(resp),
                      "port": int(ident.get("resp_p") or 0)})
    return conns, bad


def scan(conns: "list[dict]", *, min_conns: int = 10, max_cv: float = 0.25,
         min_interval: float = 5.0, strong_conns: int = 50) -> dict:
    """Agregat per pasangan + skor keteraturan interval. Tanpa jaringan."""
    groups: "dict[tuple[str, str, int], list[float]]" = {}
    for c in conns:
        groups.setdefault((c["orig"], c["resp"], c["port"]), []).append(c["ts"])

    candidates: "list[dict]" = []
    for (orig, resp, port), stamps in groups.items():
        if len(stamps) < 3:
            continue
        stamps.sort()
        intervals = [b - a for a, b in zip(stamps, stamps[1:])
                     if b - a > 0]
        if len(intervals) < min_conns - 1:
            continue
        mu = _mean(intervals)
        sd = _pstdev(intervals, mu)
        cv = sd / mu if mu > 0 else float("inf")
        if mu < min_interval or cv > max_cv:
            continue
        candidates.append({
            "orig": orig,
            "resp": resp,
            "port": port,
            "conns": len(stamps),
            "intervals_used": len(intervals),
            "mean_interval_s": round(mu, 3),
            "stdev_s": round(sd, 3),
            "cv": round(cv, 4),
            "regularity": round(1.0 - cv, 4),
            "first_ts": stamps[0],
            "last_ts": stamps[-1],
            "severity": ("high" if len(stamps) >= strong_conns
                         else "medium"),
            "message": (f"{orig} -> {resp}:{port} terhubung "
                        f"{len(stamps)}x dgn interval mean {mu:.1f}s, "
                        f"CV {cv:.3f} (konsisten = kandidat beacon)."),
        })

    candidates.sort(key=lambda c: (-c["conns"], c["cv"]))
    all_ts = [c["ts"] for c in conns]
    log_window = (round(max(all_ts) - min(all_ts), 3)
                  if len(all_ts) >= 2 else None)
    return {
        "schema": SCHEMA,
        "connections_total": len(conns),
        "pairs_total": len(groups),
        "log_window_s": log_window,
        "candidates": candidates,
        "verdict": ("BEACON_PATTERN_DETECTED" if candidates
                    else "CLEAN_NO_REGULAR_PAIR"),
        "note": "LEAD statistik — layanan sah yang polling (agent update, "
                "monitoring) juga reguler; konfirmasi dgn reputasi host, "
                "port, volume data sebelum tindakan.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="zeek_beacon_scan — deteksi kandidat beacon C2 dari "
                    "Zeek conn.log (read-only, nol jaringan).")
    ap.add_argument("--log", required=True, help="file conn.log (TSV/JSON)")
    ap.add_argument("--min-conns", type=int, default=10,
                    help="koneksi minimum per pasangan (default 10)")
    ap.add_argument("--max-cv", type=float, default=0.25,
                    help="CV maksimum (default 0.25; kecil = konsisten)")
    ap.add_argument("--min-interval", type=float, default=5.0,
                    help="mean interval minimum detik (default 5; buang "
                         "burst konkuren)")
    ap.add_argument("--strong-conns", type=int, default=50,
                    help="koneksi utk severity high (default 50)")
    ap.add_argument("--fail-on", choices=["medium", "high"], default="medium")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.log)
    if not path.is_file():
        print(f"[zeek] file tidak ada: {path}", file=sys.stderr)
        return 2
    conns, bad = parse_conn_log(path.read_text(encoding="utf-8",
                                              errors="replace"))
    if not conns:
        print("[zeek] NOL koneksi ter-parse (fail-closed); contoh baris "
              f"gagal: {bad[:3]}", file=sys.stderr)
        return 2

    result = scan(conns, min_conns=args.min_conns, max_cv=args.max_cv,
                  min_interval=args.min_interval,
                  strong_conns=args.strong_conns)
    result["unparsed_lines"] = len(bad)
    result["unparsed_examples"] = bad[:10]

    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        print(f"verdict       : {result['verdict']}")
        print(f"connections   : {result['connections_total']} "
              f"(pairs={result['pairs_total']}, "
              f"unparsed={result['unparsed_lines']})")
        for c in result["candidates"]:
            print(f"  [{c['severity']:6}] {c['message']}")
        print(f"note          : {result['note']}")

    worst = max((SEV_ORDER[c["severity"]] for c in result["candidates"]),
                default=0)
    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
