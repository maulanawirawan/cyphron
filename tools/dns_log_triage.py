"""[SAFETY: read-only] dns_log_triage — triase OFFLINE log kueri DNS utk
indikasi eksfiltrasi (DNS tunneling), DGA, dan penyalahgunaan TXT.

Port konsep dari antrean SKILL-PORT-QUEUE #0197 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-dns-logs-for-exfiltration'
— heuristik panjang subdomain, entropi Shannon, volume TXT, ambang
DGA; lisensi skill sumber Apache-2.0, atribusi konsep — kode ini
ditulis from scratch, stdlib-only, NOL jaringan: input = file log
kueri DNS hasil ekspor lab/berizin, TIDAK menghubungi resolver
maupun API reputasi apa pun).

Format input yang dikenali (deteksi otomatis per baris, ketat):
  - Zeek dns.log   : file berawalan direktif '#' (#separator/#fields);
                     butuh field ts, id.orig_h, query, qtype_name
  - BIND query log : 'DD-Mon-YYYY HH:MM:SS[.f] ... client IP#port:
                     ... query: NAMA IN TYPE ...' (bulan diurai manual,
                     bebas locale)
  - sederhana      : 'IP query [QTYPE]' (token pertama WAJIB IP valid;
                     mencegah token tanggal terbaca sbg sumber)
Baris yang tak cocok format mana pun TIDAK dibuang: dihitung +
disampel (unparsed_sample).

Mekanisme deteksi (semua lead berbasis bukti, ambang bisa diatur):
  - tunnel-candidate : per (sumber, domain) >= --tunnel-queries kueri
                       DAN panjang subdomain rata-rata >= --subdomain-
                       len; estimasi byte terenkode (faktor base64 0.75)
                       disertakan
  - txt-abuse        : per sumber, jumlah kueri TXT >= --txt-min
                       (>=1000 critical / >=500 high / lainnya medium)
  - dga-candidate    : per sumber, >= --dga-unique domain kedua unik
                       yang memicu aturan kelas karakter (len > --dga-len
                       DAN rasio vokal < 0.2 ATAU rasio digit > 0.3)
                       ATAU entropi Shannon >= 3.5 (label >= 8 char)
  - beacon-candidate : per (sumber, domain) >= --beacon-min kueri
                       berstempel waktu dengan interval antar-kueri
                       relatif teratur (stdev <= 2s)
  - null-queries     : qtype NULL/PRIVATE (hampir tidak pernah sah)
  - tool-signature   : label zona alat tunneling publik (.dnscat.,
                       .dns2tcp., .iodine., .dnscapy.)

Fail-closed: file kosong / nol baris ter-parse -> exit 2. Semua
temuan = LEAD "teramati di log" untuk investigasi, bukan klaim
kompromi terkonfirmasi.

Pemakaian:
  python tools/dns_log_triage.py --log dns.log --out triase.json
  python tools/dns_log_triage.py --log dns.log --txt-min 50
Exit: 0 sukses (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "secai.dns-log-triage/1"

# Akhiran publik dua-tingkat umum (subset deterministik, bukan PSL penuh)
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.id", "or.id", "web.id",
    "ac.id", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
    "or.jp", "com.br", "com.mx", "co.in", "co.za", "com.sg", "com.my",
    "com.tr", "com.ar", "co.kr", "com.hk", "com.tw", "com.cn",
    "com.vn", "com.ph",
}

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_RE_BIND = re.compile(
    r"^(?P<date>\d{1,2}-[A-Za-z]{3}-\d{4})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?\s+.*?client\s+(?:@\S+\s+)?(?P<src>\S+?)#\d+"
    r".*?query:\s*(?P<query>\S+)\s+IN\s+(?P<qtype>[A-Z0-9]+)\b",
    re.IGNORECASE,
)

_TOOL_SIGNS = re.compile(
    r"\.(?:dnscat|dns2tcp|iodine|dnscapy)[0-9]*\.")

_UNPARSED_SAMPLE_MAX = 20


def _entropy(text: str) -> float:
    """Entropi Shannon karakter (bit/char), 0 utk string kosong."""
    if not text:
        return 0.0
    counts = Counter(text.lower())
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _split_query(query: str) -> tuple[str, str, str]:
    """Kembalikan (registrable, subdomain, sld) dari nama kueri.

    subdomain = gabungan label di depan registrable (bisa kosong).
    sld = label kedua-terakhir (label pertama registrable).
    """
    labels = query.rstrip(".").split(".")
    if len(labels) < 2 or not all(labels):
        return query.rstrip("."), "", ""
    suffix2 = ".".join(labels[-2:])
    depth = 3 if suffix2 in _MULTI_SUFFIX else 2
    depth = min(depth, len(labels))
    registrable = ".".join(labels[-depth:])
    sub = ".".join(labels[:-depth])
    sld = labels[-depth]
    return registrable, sub, sld


def _parse_bind_ts(date_s: str, time_s: str, frac: str | None) -> float | None:
    try:
        d, mon_s, y = date_s.split("-")
        mon = _MONTHS.get(mon_s.lower())
        if mon is None:
            return None
        h, m, s = (int(x) for x in time_s.split(":"))
        micro = int((frac or "0").ljust(6, "0")[:6])
        dt = datetime(int(y), mon, int(d), h, m, s, micro,
                      tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _parse_line(line: str) -> tuple[str, str, str, float | None, str] | None:
    """Satu baris -> (src, query, qtype, ts_epoch|None, format)."""
    m = _RE_BIND.match(line)
    if m:
        src = m.group("src")
        try:
            ipaddress.ip_address(src)
        except ValueError:
            return None
        ts = _parse_bind_ts(m.group("date"), m.group("time"),
                            m.group("frac"))
        if ts is None:
            return None
        return (src, m.group("query").rstrip(".").lower(),
                m.group("qtype").upper(), ts, "bind")
    parts = line.split()
    if len(parts) in (2, 3):
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            return None
        qtype = parts[2].upper() if len(parts) == 3 else "A"
        return (parts[0], parts[1].rstrip(".").lower(), qtype, None,
                "simple")
    return None


def _parse_zeek(text: str) -> tuple[list[tuple], list[str]]:
    """Parse file Zeek dns.log (direktif '#' + TSV)."""
    fields: list[str] | None = None
    rows: list[tuple] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            continue
        if fields is None:
            unparsed.append(line)
            continue
        vals = line.split("\t")
        row = dict(zip(fields, vals))
        try:
            ts = float(row["ts"])
            src = row["id.orig_h"]
            ipaddress.ip_address(src)
            query = row["query"].rstrip(".").lower()
            if not query:
                raise KeyError("query kosong")
        except (KeyError, ValueError):
            unparsed.append(line)
            continue
        qtype = row.get("qtype_name", "A").upper()
        rows.append((src, query, qtype, ts, "zeek"))
    if fields is None or not any(
            f in (fields or []) for f in ("ts", "id.orig_h", "query")):
        raise ValueError("direktif #fields Zeek tidak memuat field "
                         "ts/id.orig_h/query")
    return rows, unparsed


def parse_log(text: str) -> tuple[list[tuple], list[str]]:
    """Deteksi format & urai seluruh file."""
    if "#separator" in text or "#fields" in text:
        return _parse_zeek(text)
    rows: list[tuple] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        rec = _parse_line(line)
        if rec is None:
            unparsed.append(line)
        else:
            rows.append(rec)
    return rows, unparsed


def analyze(rows: list[tuple], subdomain_len: int, tunnel_queries: int,
            txt_min: int, dga_unique: int, dga_len: int,
            beacon_min: int) -> list[dict]:
    """Heuristik eksfiltrasi DNS — setiap temuan disertai bukti."""
    findings: list[dict] = []

    per_dom: dict[tuple[str, str], list[tuple]] = {}
    per_src_txt: Counter = Counter()
    txt_domains: dict[str, set[str]] = {}
    per_src_null: Counter = Counter()
    dga_hits: dict[str, dict[str, str]] = {}
    sig_hits: dict[str, list[str]] = {}

    for src, query, qtype, _ts, _fmt in rows:
        registrable, sub, sld = _split_query(query)
        per_dom.setdefault((src, registrable), []).append((query, sub))
        if qtype == "TXT":
            per_src_txt[src] += 1
            txt_domains.setdefault(src, set()).add(registrable)
        if qtype in ("NULL", "PRIVATE"):
            per_src_null[src] += 1
        low = query.lower()
        if _TOOL_SIGNS.search(low):
            sig_hits.setdefault(src, []).append(query)
        # DGA pada label kedua-terakhir domain (SLD)
        reason = ""
        if len(sld) > dga_len and sld.isascii() and sld.isalnum():
            vowels = sum(1 for c in sld.lower() if c in "aeiou")
            digits = sum(1 for c in sld if c.isdigit())
            vr, dr = vowels / len(sld), digits / len(sld)
            if vr < 0.2 or dr > 0.3:
                reason = (f"kelas-karakter (vokal {vr:.2f}, "
                          f"digit {dr:.2f})")
        if not reason and len(sld) >= 8 and _entropy(sld) >= 3.5:
            reason = f"entropi {_entropy(sld):.2f} >= 3.5"
        if reason:
            dga_hits.setdefault(src, {})[registrable] = reason

    # 1. tunnel-candidate per (sumber, domain)
    for (src, dom), items in sorted(per_dom.items()):
        subs = [s for _q, s in items if s]
        if len(items) < tunnel_queries or not subs:
            continue
        lens = [len(s) for s in subs]
        avg_len = sum(lens) / len(lens)
        if avg_len < subdomain_len:
            continue
        est_bytes = int(sum(lens) * 0.75)
        sample = sorted({s[:80] for s in subs})[:3]
        findings.append({
            "type": "tunnel-candidate", "severity": "high",
            "src": src, "domain": dom,
            "detail": f"{len(items)} kueri ke {dom} dengan subdomain "
                      f"rata-rata {avg_len:.0f} char (>= {subdomain_len})",
            "evidence": {
                "queries": len(items),
                "unique_subdomains": len(set(subs)),
                "subdomain_len_avg": round(avg_len, 1),
                "subdomain_len_max": max(lens),
                "exfil_bytes_est": est_bytes,
                "sample_subdomains": sample,
            },
        })

    # 2. txt-abuse per sumber
    for src, n in per_src_txt.most_common():
        if n < txt_min:
            continue
        sev = "critical" if n >= 1000 else ("high" if n >= 500
                                            else "medium")
        findings.append({
            "type": "txt-abuse", "severity": sev, "src": src,
            "detail": f"{n} kueri TXT dari {src} "
                      f"(>= ambang {txt_min})",
            "evidence": {
                "txt_queries": n,
                "unique_txt_domains": len(txt_domains.get(src, ())),
                "sample_domains": sorted(
                    txt_domains.get(src, ()))[:5],
            },
        })

    # 3. dga-candidate per sumber
    for src, doms in sorted(dga_hits.items()):
        if len(doms) < dga_unique:
            continue
        sample = sorted(doms)[:5]
        findings.append({
            "type": "dga-candidate", "severity": "high", "src": src,
            "detail": f"{len(doms)} domain unik men-trigger aturan DGA "
                      f"(>= {dga_unique})",
            "evidence": {
                "unique_domains": len(doms),
                "sample": {d: doms[d] for d in sample},
            },
        })

    # 4. null-queries per sumber
    for src, n in per_src_null.most_common():
        findings.append({
            "type": "null-queries", "severity": "medium", "src": src,
            "detail": f"{n} kueri qtype NULL/PRIVATE dari {src}",
            "evidence": {"null_queries": n},
        })

    # 5. tool-signature per sumber
    for src, queries in sorted(sig_hits.items()):
        findings.append({
            "type": "tool-signature", "severity": "high", "src": src,
            "detail": "kueri memuat label zona alat tunneling publik",
            "evidence": {
                "queries": len(queries),
                "sample": sorted(set(queries))[:5],
            },
        })

    # 6. beacon-candidate: butuh stempel waktu
    timed: dict[tuple[str, str], list[float]] = {}
    for src, query, _q, ts, _fmt in rows:
        if ts is None:
            continue
        registrable, _sub, _sld = _split_query(query)
        timed.setdefault((src, registrable), []).append(ts)
    for (src, dom), tss in sorted(timed.items()):
        if len(tss) < beacon_min:
            continue
        tss = sorted(tss)
        intervals = [b - a for a, b in zip(tss, tss[1:]) if b > a]
        if not intervals:
            continue
        mean = sum(intervals) / len(intervals)
        var = sum((v - mean) ** 2 for v in intervals) / (len(intervals)
                                                         - 1)
        std = var ** 0.5
        if std > 2.0:
            continue
        findings.append({
            "type": "beacon-candidate", "severity": "medium",
            "src": src, "domain": dom,
            "detail": f"{len(tss)} kueri berkala ke {dom} "
                      f"(interval rata-rata {mean:.1f}s, "
                      f"stdev {std:.2f}s <= 2s)",
            "evidence": {
                "queries": len(tss),
                "interval_mean_s": round(mean, 2),
                "interval_stdev_s": round(std, 3),
            },
        })

    return findings


def triage_file(path: Path, subdomain_len: int = 50,
                tunnel_queries: int = 20, txt_min: int = 100,
                dga_unique: int = 10, dga_len: int = 12,
                beacon_min: int = 5) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError("file kosong")
    rows, unparsed = parse_log(text)
    if not rows:
        raise ValueError("tidak ada baris log DNS yang ter-parse")

    by_format = Counter(r[4] for r in rows)
    qtype_hist = Counter(r[2] for r in rows)
    findings = analyze(rows, subdomain_len, tunnel_queries, txt_min,
                       dga_unique, dga_len, beacon_min)

    out: dict = {
        "schema": SCHEMA,
        "file": str(path),
        "lines_total": len(text.splitlines()),
        "parsed": len(rows),
        "by_format": {k: v for k, v in sorted(by_format.items())},
        "unparsed_count": len(unparsed),
        "unparsed_sample": unparsed[:_UNPARSED_SAMPLE_MAX],
        "queries": len(rows),
        "src_unique": len({r[0] for r in rows}),
        "domain_unique": len(
            {_split_query(r[1])[0] for r in rows}),
        "qtype_top": qtype_hist.most_common(10),
        "finding_count": len(findings),
        "findings": findings,
        "thresholds": {
            "subdomain_len": subdomain_len,
            "tunnel_queries": tunnel_queries,
            "txt_min": txt_min,
            "dga_unique": dga_unique,
            "dga_len": dga_len,
            "beacon_min": beacon_min,
        },
        "note": "semua temuan = LEAD teramati di log, bukan klaim "
                "kompromi terkonfirmasi",
        "read_only": True,
    }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase log kueri DNS utk tunneling/DGA/TXT-abuse "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--log", required=True,
                    help="file log kueri DNS (Zeek dns.log / BIND "
                         "query log / 'IP query [QTYPE]')")
    ap.add_argument("--subdomain-len", type=int, default=50,
                    help="ambang panjang subdomain rata-rata (default 50)")
    ap.add_argument("--tunnel-queries", type=int, default=20,
                    help="minimum kueri per domain utk tunnel "
                         "(default 20)")
    ap.add_argument("--txt-min", type=int, default=100,
                    help="ambang jumlah kueri TXT per sumber (default 100)")
    ap.add_argument("--dga-unique", type=int, default=10,
                    help="minimum domain unik pemicu DGA per sumber "
                         "(default 10)")
    ap.add_argument("--dga-len", type=int, default=12,
                    help="panjang minimum SLD utk aturan kelas-karakter "
                         "(default 12)")
    ap.add_argument("--beacon-min", type=int, default=5,
                    help="minimum kueri berstempel waktu utk beacon "
                         "(default 5)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.log)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, args.subdomain_len,
                             args.tunnel_queries, args.txt_min,
                             args.dga_unique, args.dga_len,
                             args.beacon_min)
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
