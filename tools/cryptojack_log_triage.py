"""[SAFETY: read-only] cryptojack_log_triage — triase OFFLINE log proxy/DNS
untuk indikasi cryptojacking (coin-miner) di jaringan yang dipantau.

Format input yang dikenali (deteksi otomatis per baris):
  - Squid access.log    : 'IP IDENT USER [ts] "METHOD URL" STATUS BYTES ...'
  - format sederhana    : 'ts<TAB>src<TAB>method<TAB>host<TAB>uri<TAB>port
                           <TAB>status<TAB>bytes' (ts epoch atau '-'),
                           'IP host uri' juga diterima
  - DNS sederhana       : 'IP query [QTYPE]' (token pertama WAJIB IP valid)
Baris yang tak cocok format mana pun TIDAK dibuang: dihitung + disampel.

Mekanisme deteksi (semua lead berbasis bukti, ambang bisa diatur):
  - pool-domain      : host/zona cocok indikator pool penambangan yang
                       dikenal umum (nama pool populer + akhiran generik
                       pool, via kata kunci — daftar statis deterministik)
  - stratum-port     : tujuan port stratum umum (3333/4444/5555/7777/
                       14444/14433/9999)
  - jsonrpc-mining   : URI/query mengandung token JSON-RPC miner
                       ("mining.submit", "mining.subscribe", "eth_",
                       "stratum")
  - highhash-uri     : URI memuat pola hashrate (hashrate, "Mh/s", "H/s",
                       xmrig, cryptonight)
  - long-uniform     : (proxy) sesi ke host sama >= --conn-min koneksi
                       dengan interval berstempel waktu relatif teratur
                       (stdev <= --uniform-sd detik) dan durasi total
                       >= --uniform-mins menit

Fail-closed: file kosong / nol baris ter-parse -> exit 2. Semua temuan =
LEAD "teramati di log" untuk investigasi, bukan klaim infeksi terkonfirmasi.

Pemakaian:
  python tools/cryptojack_log_triage.py --log proxy.log --out triase.json
  python tools/cryptojack_log_triage.py --log dns.log --conn-min 20
Exit: 0 sukses (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.cryptojack-log-triage/1"

# Kata kunci pool penambangan yang dikenal umum (statis, deterministik).
_POOL_KEYS = (
    "xmrpool", "nanopool", "f2pool", "ethermine", "supportxmr", "minexmr",
    "2miners", "nicehash", "miningpoolhub", "coinhive", "deepminer",
    "cryptonight", "monerohash", "pool.hashvault", "c3pool", "herominers",
    "zergpool", "luckpool", "minemoney", "wikil?", "proxy_pool",
)

_STRATUM_PORTS = {"3333", "4444", "5555", "7777", "8888", "9999",
                  "14444", "14433", "5555", "45700"}

_NUM_RE = re.compile(r"^\d+(?:\.\d+)?$")
_STRATUM_SCHEME = re.compile(r"stratum(\+tcp|\+ssl)?://", re.I)
_MINING_TOKENS = re.compile(
    r"(mining\.(submit|subscribe|authorize)|jsonrpc|\"method\"\s*:\s*\"mining|"
    r"\beth_(submit|getwork|proxy)\b|cryptonight|xmrig|monero(?:o)?\b|"
    r"randomx|hashrate|\b[HMK]?h/s\b|t\d+[a-z]/[a-z0-9]{6,}@)", re.I)
_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)(?:\.[a-z0-9\-]+)*"
    r"\.[a-z]{2,24}$", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_UNPARSED_SAMPLE_MAX = 10


def _pool_hit(host: str) -> str | None:
    low = host.lower()
    for key in _POOL_KEYS:
        if key in low:
            return key
    # akhiran generik: label pool-like dengan TLD berbasis pool umum
    if re.search(r"(pool|mine|miner)[a-z0-9\-]*\.(com|net|org|io|xyz|pro)$",
                 low):
        return "generic-pool-suffix"
    return None


def parse_log(text: str):
    """Parse baris log -> list (src, host_or_query, port, ts_or_None,
    bytes, fmt). Baris tak dikenal -> unparsed."""
    rows, unparsed = [], []
    for ln in text.splitlines():
        line = ln.strip()
        if not line:
            continue
        src = host = uri = method = ""
        port = ""
        ts = None
        nbytes = 0
        fmt = ""
        # Squid: IP IDENT USER [ts] "METHOD URI proto/ver" STATUS BYTES
        m = re.match(
            r"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"(\S+)\s+(\S+)[^\"]*\"\s+"
            r"(\d{3})\s+(\d+)", line)
        if m:
            src, ts_s, method, uri = m.group(1), m.group(2), m.group(3), \
                m.group(4)
            nbytes = int(m.group(6))
            try:
                import calendar
                import email.utils as eut
                ts = eut.parsedate_to_datetime(ts_s).timestamp()
            except Exception:
                ts = None
            m2 = re.match(r"^(?:[a-z]+://)?([^/:]+)(?::(\d+))?", uri, re.I)
            if m2:
                host, port = m2.group(1), m2.group(2) or ""
            fmt = "squid"
        else:
            # DNS sederhana: 'IP query [QTYPE]'
            m3 = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)(?:\s+(\w+))?$",
                          line)
            if m3 and _HOST_RE.match(m3.group(2)) or (
                    m3 and _IP_RE.match(m3.group(2))):
                src, host, fmt = m3.group(1), m3.group(2), "dns"
                uri = host
            else:
                # format sederhana TAB/SPASI: ts src method host uri port
                # status bytes (parts[1] wajib host-like — mencegah baris
                # DNS 'IP query QTYPE' salah masuk jalur ini)
                parts = line.split()
                if (len(parts) >= 4 and _NUM_RE.match(parts[0])
                        and (_IP_RE.match(parts[1]) or _HOST_RE.match(parts[1]))):
                    ts_s, src = parts[0], parts[1]
                    try:
                        ts = float(ts_s)
                    except ValueError:
                        ts = None
                    host = parts[3] if len(parts) > 3 else ""
                    uri = parts[4] if len(parts) > 4 else host
                    port = parts[5] if len(parts) > 5 else ""
                    fmt = "simple"
                    method = ""
                elif len(parts) >= 3 and _IP_RE.match(parts[0]):
                    src, host, fmt = parts[0], parts[1], "minimal"
                    uri = host
                else:
                    unparsed.append(line[:160])
                    continue
        rows.append((src, host or uri, port, ts, nbytes, fmt, uri, method))
    return rows, unparsed


def analyze(rows, conn_min: int, uniform_sd: float, uniform_mins: float):
    findings: list[dict] = []

    pool_by_src: dict[str, dict] = {}
    stratum_by_src: dict[str, dict] = {}
    token_by_src: dict[str, dict] = {}
    per_conn: dict[tuple[str, str], list] = {}

    for src, host, port, ts, nbytes, fmt, uri, method in rows:
        low_host = (host or "").lower()
        low_uri = (uri or "").lower()
        if _STRATUM_SCHEME.search(low_uri):
            stratum_by_src.setdefault(src, {"hosts": set(), "hits": 0})
            stratum_by_src[src]["hosts"].add(host[:80])
            stratum_by_src[src]["hits"] += 1
        if _MINING_TOKENS.search(low_uri) or _MINING_TOKENS.search(low_host):
            token_by_src.setdefault(src, {"samples": [], "hits": 0})
            token_by_src[src]["hits"] += 1
            if len(token_by_src[src]["samples"]) < 3:
                token_by_src[src]["samples"].append(uri[:120])
        pool = _pool_hit(low_host)
        if pool:
            st = pool_by_src.setdefault(src, {"pool_keys": set(),
                                              "hosts": set(), "hits": 0})
            st["pool_keys"].add(pool)
            st["hosts"].add(host[:80])
            st["hits"] += 1
        if port and port in _STRATUM_PORTS:
            stratum_by_src.setdefault(src, {"hosts": set(), "hits": 0})
            stratum_by_src[src]["hosts"].add(f"{host}:{port}")
            stratum_by_src[src]["hits"] += 1
        if ts is not None and (host or uri):
            per_conn.setdefault((src, host or uri), []).append(ts)

    # 1. pool-domain
    for src, st in sorted(pool_by_src.items()):
        findings.append({
            "type": "pool-domain", "severity": "high",
            "src": src,
            "detail": (f"{st['hits']} permintaan ke host pool penambangan "
                       f"({', '.join(sorted(st['pool_keys']))}) dari {src}"),
            "evidence": {"hits": st["hits"], "hosts": sorted(st["hosts"])[:5],
                         "pool_keys": sorted(st["pool_keys"])},
        })

    # 2. stratum-port / skema stratum
    for src, st in sorted(stratum_by_src.items()):
        findings.append({
            "type": "stratum-usage", "severity": "high",
            "src": src,
            "detail": (f"{st['hits']} permintaan dengan indikator stratum "
                       f"(skema/port pool) dari {src}"),
            "evidence": {"hits": st["hits"], "hosts": sorted(st["hosts"])[:5]},
        })

    # 3. jsonrpc-mining / highhash-uri
    for src, st in sorted(token_by_src.items()):
        findings.append({
            "type": "mining-token-uri", "severity": "high",
            "src": src,
            "detail": (f"{st['hits']} URI/query memuat token miner "
                       f"(jsonrpc/stratum/hashrate) dari {src}"),
            "evidence": {"hits": st["hits"],
                         "samples": st["samples"]},
        })

    # 4. long-uniform: koneksi berinterval teratur & berdurasi panjang
    for (src, host), tss in sorted(per_conn.items()):
        if len(tss) < conn_min:
            continue
        tss = sorted(tss)
        spans = [b - a for a, b in zip(tss, tss[1:]) if b > a]
        if len(spans) < 2:
            continue
        sd = statistics.pstdev(spans)
        duration_min = (tss[-1] - tss[0]) / 60.0
        if sd <= uniform_sd and duration_min >= uniform_mins:
            findings.append({
                "type": "long-uniform", "severity": "medium",
                "src": src,
                "detail": (f"{len(tss)} koneksi ke {host[:80]} berinterval "
                           f"teratur (stdev {sd:.1f}s) selama "
                           f"{duration_min:.0f} menit"),
                "evidence": {"connections": len(tss),
                             "interval_stdev_s": round(sd, 2),
                             "duration_min": round(duration_min, 1),
                             "first": tss[0], "last": tss[-1]},
            })
    return findings


def triage_file(path: Path, conn_min: int, uniform_sd: float,
                uniform_mins: float) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError("file kosong")
    rows, unparsed = parse_log(text)
    if not rows:
        raise ValueError("tidak ada baris log yang ter-parse")
    fmt_hist = Counter(r[5] for r in rows)
    findings = analyze(rows, conn_min, uniform_sd, uniform_mins)
    return {
        "schema": SCHEMA,
        "file": str(path),
        "lines_total": len(text.splitlines()),
        "parsed": len(rows),
        "by_format": {k: v for k, v in sorted(fmt_hist.items())},
        "unparsed_count": len(unparsed),
        "unparsed_sample": unparsed[:_UNPARSED_SAMPLE_MAX],
        "src_unique": len({r[0] for r in rows}),
        "finding_count": len(findings),
        "findings": findings,
        "thresholds": {"conn_min": conn_min, "uniform_sd": uniform_sd,
                       "uniform_mins": uniform_mins},
        "note": "semua temuan = LEAD teramati di log, bukan klaim infeksi "
                "terkonfirmasi",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase log proxy/DNS utk indikasi cryptojacking "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--log", required=True,
                    help="file log proxy/DNS (squid access log / DNS "
                         "sederhana / format simple)")
    ap.add_argument("--conn-min", type=int, default=10,
                    help="koneksi minimum utk analisis long-uniform "
                         "(default 10)")
    ap.add_argument("--uniform-sd", type=float, default=2.0,
                    help="stdev interval maksimum (detik, default 2.0)")
    ap.add_argument("--uniform-mins", type=float, default=5.0,
                    help="durasi total minimum (menit, default 5.0)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.log)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, args.conn_min, args.uniform_sd,
                             args.uniform_mins)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
