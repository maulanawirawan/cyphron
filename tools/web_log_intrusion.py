"""[DEFEND: read-only] web_log_intrusion — analisis offline access log
web untuk jejak upaya intrusi.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/analyzing-web-server-logs-for-intrusion' (antrean SKILL-PORT-
QUEUE #0251; atribusi ide, lisensi sumber Apache-2.0). Dibangun from
scratch TANPA kode sumber itu: parser Combined/Common Log Format +
aturan signature ditulis sendiri dari kelas serangan publik (SQLi/
LFI/traversal/XSS/UA scanner/brute force). Tanpa GeoIP — atribusi
geografis bukan bukti dan menambah dependensi; IP dicatat mentah.

Read-only, NOL jaringan: baca SATU file log lokal, keluarkan temuan
sebagai LEAD ("upaya teramati di log" — bukan klaim kompromi). Ini
alat DEFENSIF untuk pemilik log sendiri / insiden berizin.

Fail-closed:
  - file tidak ada / tidak terbaca        -> exit 2
  - file kosong, atau NOL baris ter-parse -> exit 2 (bukti kosong tidak
    boleh dilaporkan "bersih")
  - baris tak sesuai format               -> dicatat unparsed (maks 20
    contoh di meta), tidak pernah diam-diam dibuang
  - URI diperiksa dalam bentuk mentah MAUPN hasil percent-decode;
    matching dilaporkan dari bentuk yang cocok (evidence tetap mentah)
  - brute force = hitungan deterministik dari timestamp log (window
    geser default 300s, ambang default 50 POST ke endpoint login),
    bukan "tebakan anomali"

Pemakaian:
  python tools/web_log_intrusion.py --log /var/log/nginx/access.log
  python tools/web_log_intrusion.py --log access.log --out findings.json
  python tools/web_log_intrusion.py --log access.log \\
      --bf-window 300 --bf-threshold 50
Exit: 0 selesai (temuan atau bersih); 2 input/format error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "secai.web-log-intrusion/1"
MAX_FILE_BYTES = 256 * 1024 * 1024          # bounded; lebih besar = tolak
MAX_UNPARSED_SAMPLES = 20
MAX_EVIDENCE_CHARS = 300

# Combined Log Format:  ip ident user [ts] "METHOD uri proto" status size "ref" "ua"
# Common Log Format = tanpa pasangan referer/ua.
_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?\s*$'
)
_TS_RE = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})")
MONTHS = {m: i + 1 for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}
# Request line: METHOD uri [proto]. URI BOLEH mengandung spasi literal
# (request malformed yang di-log apa adanya) — proto hanya diakui bila
# benar-benar HTTP/x.y di akhir; sisanya adalah URI.
_REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<uri>.+?)'
    r'(?:\s+(?P<proto>HTTP/[\d.]+))?\s*$')

# (kategori, severity, regex, butuh_uri) — ditulis sendiri; regex dicocokkan
# ke URI mentah dan versi percent-decoded; spasi server biasanya sudah
# ter-encode, jadi kelas spasi fleksibel untuk payload campur.
SIGS: list[tuple[str, str, re.Pattern, bool]] = [
    ("sqli", "high", re.compile(
        r"union(?:\s|%20)+(?:all(?:\s|%20)+)?select"
        r"|(?:'|%27)(?:\s|%20)*(?:or|and)(?:\s|%20)+"
        r"|\b(?:or|and)(?:\s|%20)+(?:\d+|(?:'|%27)[^'\"]*(?:'|%27))"
        r"(?:\s|%20)*="
        r"|\bselect\b.{0,80}\bfrom\b"
        r"|\b(?:sleep|benchmark|waitfor|pg_sleep)\s*\("
        r"|\bxp_cmdshell\b|0x[0-9a-fA-F]{16,}", re.I), True),
    ("lfi-traversal", "high", re.compile(
        r"(?:\.\./|%2e%2e(?:%2f|/)){1,}|"
        r"(?:/|%2f)(?:etc|%65tc)(?:/|%2f)passwd|"
        r"/proc/self/|php://(?:filter|input)|"
        r"(?:/|%2f)windows(?:/|%2f)win\.ini", re.I), True),
    ("xss", "medium", re.compile(
        r"<\s*script|javascript\s*:|\bon(?:error|load|click|mouseover)\s*="
        r"|<\s*(?:img|svg|iframe|body)[^>]*\bon[a-z]+\s*=", re.I), True),
]

# UA scanner (versi di belakang titik tak wajib) — fakta probing, bukan
# kompromi; severity low karena banyak scanner juga dipakai admin sah.
SCANNER_UA_RE = re.compile(
    r"\b(?:nikto|sqlmap|dirbuster|gobuster|wfuzz|ffuf|nuclei|masscan|"
    r"zgrab|acunetix|nessus|openvas|dirsearch|feroxbuster|wpscan|"
    r"arachni|whatweb)\b", re.I)

# endpoint login-ish untuk hitungan brute force (URI path saja)
_LOGIN_PATH_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|auth|session|wp-login\.php|"
    r"user|account(?:/login)?)(?:$|[/?])", re.I)


def parse_timestamp(raw: str) -> "datetime | None":
    """Parse '[15/Jan/2024:10:30:45 +0000]' -> datetime (timezone-aware).

    Return None bila format tak dikenali (baris tetap ter-hit ter-parse
    untuk signature, tapi tidak ikut analisis brute force — tercatat).
    """
    m = _TS_RE.search(raw)
    if not m:
        return None
    day, mon, year, hh, mm, ss, tz = m.groups()
    month = MONTHS.get(mon.capitalize())
    if not month:
        return None
    try:
        sign = 1 if tz[0] == "+" else -1
        offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
        return datetime(int(year), month, int(day), int(hh), int(mm),
                        int(ss), tzinfo=None) - offset  # normalisasi ke UTC
    except ValueError:
        return None


def parse_line(line: str) -> "dict | None":
    """Parse satu baris access log -> dict, atau None bila tak cocok."""
    m = _LINE_RE.match(line)
    if not m:
        return None
    req = _REQUEST_RE.match(m.group("request").strip())
    return {
        "ip": m.group("ip"),
        "user": m.group("user"),
        "ts_raw": m.group("ts"),
        "ts": parse_timestamp(m.group("ts")),
        "method": req.group("method") if req else "",
        "uri": req.group("uri") if req else "",
        "status": int(m.group("status")),
        "size": m.group("size"),
        "ua": m.group("ua") or "",
    }


def _signature_hits(uri: str) -> list[tuple[str, str, str]]:
    """Kembalikan (kategori, severity, bentuk_cocok) untuk satu URI.

    Bentuk percent-decoded didahulukan bila URI memang ter-encode —
    payload penyerang adalah bentuk ter-decode-nya.
    """
    hits: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    decoded = unquote(uri)
    forms: list[tuple[str, str]] = [("uri-raw", uri)]
    if decoded != uri:
        forms.insert(0, ("uri-decoded", decoded))
    for cat, sev, rx, _ in SIGS:
        for label, form in forms:
            if rx.search(form) and cat not in seen:
                seen.add(cat)
                hits.append((cat, sev, label))
                break
    return hits


def _brute_force_groups(entries: list[dict], window_s: int,
                        threshold: int) -> list[dict]:
    """Kelompok POST login per IP dalam window geser; deterministik.

    Satu entri log bisa masuk >1 kelompok (window geser) — kembalikan
    kelompok non-redundan: kelompok yang dicakup kelompok lain dengan
    IP sama dibuang.
    """
    posts: dict[str, list[datetime]] = defaultdict(list)
    for e in entries:
        if e["method"] == "POST" and e["ts"] is not None \
                and _LOGIN_PATH_RE.search(e["uri"]):
            posts[e["ip"]].append(e["ts"])
    groups: list[dict] = []
    for ip, times in sorted(posts.items()):
        times.sort()
        n = len(times)
        for i in range(n):
            j = i
            while j < n and (times[j] - times[i]).total_seconds() <= window_s:
                j += 1
            count = j - i
            if count >= threshold:
                groups.append({
                    "ip": ip,
                    "count": count,
                    "first": times[i].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "last": times[j - 1].strftime("%Y-%m-%dT%H:%M:%SZ"),
                })
    # buang kelompok yang sepenuhnya berada dalam kelompok lain (IP sama)
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for g in groups:
        by_ip[g["ip"]].append(g)
    kept: list[dict] = []
    for ip, gs in by_ip.items():
        gs.sort(key=lambda g: (-g["count"], g["first"]))
        kept.append(gs[0])
    kept.sort(key=lambda g: (-g["count"], g["first"]))
    return kept


def analyze(log_path: Path, window_s: int = 300,
            threshold: int = 50) -> dict:
    """Analisis satu file access log. Fail-closed — lihat docstring."""
    data = log_path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(
            f"file terlalu besar ({len(data)} > {MAX_FILE_BYTES} bytes)")
    text = data.decode("utf-8", errors="replace")
    findings: list[dict] = []
    unparsed: list[int] = []
    entries: list[dict] = []
    total = 0
    for idx, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        total += 1
        parsed = parse_line(line)
        if parsed is None:
            if len(unparsed) < MAX_UNPARSED_SAMPLES:
                unparsed.append(idx)
            continue
        parsed["line"] = idx
        entries.append(parsed)
        uri = parsed["uri"]
        for cat, sev, form in _signature_hits(uri):
            findings.append({
                "category": cat,
                "severity": sev,
                "kind": "log-signature",
                "line": idx,
                "ip": parsed["ip"],
                "method": parsed["method"],
                "uri": uri[:MAX_EVIDENCE_CHARS],
                "status": parsed["status"],
                "matched_form": form,
                "evidence": line[:MAX_EVIDENCE_CHARS],
            })
        if parsed["ua"] and SCANNER_UA_RE.search(parsed["ua"]) \
                and not any(f["line"] == idx for f in findings):
            findings.append({
                "category": "scanner-ua",
                "severity": "low",
                "kind": "log-signature",
                "line": idx,
                "ip": parsed["ip"],
                "method": parsed["method"],
                "uri": uri[:MAX_EVIDENCE_CHARS],
                "status": parsed["status"],
                "matched_form": "user-agent",
                "evidence": line[:MAX_EVIDENCE_CHARS],
            })
    if total == 0:
        raise ValueError("file log kosong — bukti kosong tidak boleh "
                         "dilaporkan bersih (fail-closed)")
    if not entries:
        raise ValueError(
            f"0/{total} baris cocok format Combined/Common Log Format — "
            "format tidak dikenali (fail-closed)")
    bf = _brute_force_groups(entries, window_s, threshold)
    for g in bf:
        findings.append({
            "category": "brute-force",
            "severity": "medium",
            "kind": "log-frequency",
            "line": None,
            "ip": g["ip"],
            "method": "POST",
            "uri": "<login endpoints>",
            "status": None,
            "matched_form": f">= {threshold} POST dalam {window_s}s",
            "evidence": f"{g['count']} POST {g['first']} .. {g['last']}",
        })
    by_cat: dict[str, int] = defaultdict(int)
    for f in findings:
        by_cat[f["category"]] += 1
    by_ip: dict[str, int] = defaultdict(int)
    for e in entries:
        by_ip[e["ip"]] += 1
    findings.sort(key=lambda f: (f["line"] is None, f["line"] or 0,
                                 f["category"]))
    return {
        "schema": SCHEMA,
        "log": str(log_path),
        "lines_total": total,
        "lines_parsed": len(entries),
        "unparsed": {
            "count": total - len(entries),
            "note": "baris tak sesuai format — dicatat, bukan dibuang",
            "sample_lines": unparsed,
        },
        "brute_force": {
            "window_seconds": window_s,
            "threshold": threshold,
            "groups": bf,
        },
        "summary": {
            "findings_total": len(findings),
            "by_category": dict(sorted(by_cat.items())),
            "top_ips": [ip for ip, _ in sorted(
                by_ip.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
        },
        "findings": findings,
        "note": "temuan = UPAYA TERAMATI DI LOG (lead), bukan klaim "
                "kompromi; verifikasi lanjut di host/app terkait",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="web_log_intrusion — analisis offline access log "
                    "untuk jejak upaya intrusi (defensif, fail-closed).")
    ap.add_argument("--log", required=True, help="path file access log")
    ap.add_argument("--window", dest="bf_window", type=int, default=300,
                    help="window brute force detik (default 300)")
    ap.add_argument("--threshold", dest="bf_threshold", type=int,
                    default=50,
                    help="ambang POST login per IP per window (default 50)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    if args.bf_window <= 0 or args.bf_threshold <= 0:
        print("[web-log-intrusion] window/threshold harus positif",
              file=sys.stderr)
        return 2
    log_path = Path(args.log)
    try:
        result = analyze(log_path, window_s=args.bf_window,
                         threshold=args.bf_threshold)
    except (OSError, ValueError) as exc:
        print(f"[web-log-intrusion] gagal: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    print(f"[web-log-intrusion] {result['lines_parsed']}/"
          f"{result['lines_total']} baris ter-parse dari {args.log}")
    print(f"[web-log-intrusion] temuan: {s['findings_total']} "
          f"(per kategori: "
          f"{', '.join(f'{k}={v}' for k, v in s['by_category'].items()) or '-'})")
    for f in result["findings"][:10]:
        loc = f"baris {f['line']}" if f["line"] else f"IP {f['ip']}"
        print(f"  [{f['severity']:6}] {f['category']:14} {loc}")
    if s["findings_total"] > 10:
        print(f"  ... +{s['findings_total'] - 10} lagi (lihat --out)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
