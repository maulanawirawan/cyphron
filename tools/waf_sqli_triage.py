r"""[SAFETY: read-only] waf_sqli_triage — triase OFFLINE log WAF
(ModSecurity audit log, atau JSON/JSONL event WAF generik) untuk
kampanye SQL injection: klasifikasi keluarga payload, agregasi sumber,
dan penanda kemungkinan bypass (request SQLi yang mendapat respons
2xx). TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0461 (mukul975/Anthropic-
Cybersecurity-Skills 'detecting-sql-injection-via-waf-logs' — analisis
log ModSecurity/AWS WAF/Cloudflare utk kampanye SQLi dgn klasifikasi
OWASP; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH: parser audit-log + taksonomi regex ditulis sendiri; skill
sumber memakai kelas agent dgn dependensi tambahan, cyphron stdlib
murni.

Input -> mekanisme -> output:
  - Input : satu file log — ModSecurity audit log (bagian
            --txid-A--/[ts]/-B--/-H--/-Z--), ATAU JSON/JSONL event
            generik (field uri/url/path + message/ruleMessage +
            ip/clientIp + status, field opsional diambil bila ada).
  - Mekanisme: ekstraksi (waktu, ip, URI, pesan rule, status) ->
            klasifikasi keluarga SQLi dari URI ter-dekode + pesan ->
            agregasi per IP.
  - Output: temuan {check, severity, ip, family, ...} + stats +
            notes; URI asli (mentah) tetap disimpan sbg bukti.

Klasifikasi keluarga (regex ditulis sendiri):
  union-select    UNION [ALL] SELECT
  boolean-taut    ' OR 1=1 / ' AND '1'='1 dst.
  time-based      SLEEP()/BENCHMARK()/pg_sleep()/WAITFOR DELAY
  error-based     extractvalue()/updatexml()
  stacked-query   ; DROP/DELETE/INSERT/UPDATE/EXEC
  info-schema     information_schema / sys.tables (enumerasi DB)

Cek:
  sqli-attempt    (high)   : satu request terklasifikasi SQLi
                             (LEAD "upaya teramati di log").
  waf-bypass-possible (high): request SQLi mendapat respons 2xx dari
                             aplikasi — kandidat bypass (bukti
                             keberhasilan butuh verifikasi manual).
  sqli-campaign   (high)   : >= --campaign-threshold request SQLi dari
                             satu IP dalam window --window detik.
  sqlmap-ua       (medium) : UA alat uji SQLi otomatis (sqlmap/
                             havij/jsql) pada request apa pun.

Fail-closed:
  - file tak ada / format tak dikenal / NOL transaksi/event ter-parse
    -> exit 2 (bukti kosong tidak dilaporkan bersih).
  - baris rusak dicatat di meta (maks 10 contoh), tidak dibuang diam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error.

Pemakaian:
  python tools/waf_sqli_triage.py --log /var/log/modsec_audit.log
  python tools/waf_sqli_triage.py --log awswaf.jsonl --fail-on medium
  python tools/waf_sqli_triage.py --log modsec.log --campaign-threshold 10
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "cyphron.waf-sqli-triage/1"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_UNPARSED_SAMPLES = 10
MAX_EVIDENCE_CHARS = 300

# ---------- ModSecurity audit log ----------
_SECT_RE = re.compile(r"^--[0-9a-fA-F-]+-([A-Z])--\s*$")
_A_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+(?P<txid>\S+)\s+(?P<ip>\S+)\s+"
    r"(?P<sport>\d+)\s+(?P<dip>\S+)\s+(?P<dport>\d+)\s*$")
_TS_RE = re.compile(
    r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}
_MSG_RE = re.compile(r"^\s*Message:\s*(.*)$")
_ATTR_RE = re.compile(r"\[(id|msg|severity|tag)\s+\"([^\"]*)\"\]")
_REQ_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)"
                     r"(?:\s+(?P<proto>HTTP/[\d.]+))?\s*$")

# ---------- taksonomi SQLi (ditulis sendiri) ----------
_FAMILIES: list[tuple[str, str, re.Pattern[str]]] = [
    ("union-select", "high",
     re.compile(r"union(\s+all)?\s+select", re.I)),
    ("boolean-taut", "high",
     re.compile(r"('|%27)\s*(or|and)\s*('|%27)?\s*\d+\s*=", re.I)),
    ("time-based", "high",
     re.compile(r"\b(sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|"
                r"waitfor\s+delay|dbms_lock\.sleep)", re.I)),
    ("error-based", "high",
     re.compile(r"\b(extractvalue\s*\(|updatexml\s*\()", re.I)),
    ("stacked-query", "high",
     re.compile(r";\s*(drop\s+table|delete\s+from|insert\s+into|"
                r"update\s+\w+\s+set|shutdown|exec\s*\()", re.I)),
    ("info-schema", "medium",
     re.compile(r"information_schema|sys\.tables|mysql\.user|"
                r"sqlite_master", re.I)),
]
_SQLMAP_UA_RE = re.compile(r"\b(sqlmap|havij|jsql|hackbar)\b", re.I)


def _parse_modsec_ts(val: str) -> datetime | None:
    m = _TS_RE.search(val or "")
    if not m:
        return None
    try:
        day, mon, year, hh, mm, ss, off = (
            m.group(1), _MONTHS.get(m.group(2)), m.group(3),
            m.group(4), m.group(5), m.group(6), m.group(7))
        if not mon:
            return None
        dt = datetime(int(year), mon, int(day), int(hh), int(mm),
                      int(ss), tzinfo=timezone.utc)
        sign = 1 if off.startswith("-") else -1
        delta = timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))
        return dt + sign * delta
    except (ValueError, TypeError):
        return None


def _classify(text: str) -> str:
    for fam, _sev, rx in _FAMILIES:
        if rx.search(text):
            return fam
    return ""


def _family_sev(family: str) -> str:
    return next(sev for fam, sev, _ in _FAMILIES if fam == family)


def parse_modsec(text: str, src: str) -> tuple[list[dict], list[str]]:
    """Parser audit log ModSecurity -> daftar transaksi terurut."""
    tx: dict | None = None
    section = ""
    txs: list[dict] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        m = _SECT_RE.match(line)
        if m:
            sec = m.group(1)
            if sec == "A":
                tx = {"messages": [], "src": src}
                txs.append(tx)
                section = "A"
                continue
            if sec == "Z":
                tx = None
                section = ""
                continue
            section = sec
            continue
        if tx is None:
            continue
        if section == "A":
            am = _A_RE.match(line)
            if am:
                tx["time"] = _parse_modsec_ts(am.group("ts"))
                tx["ip"] = am.group("ip")
                tx["txid"] = am.group("txid")
            elif line.strip() and len(unparsed) < MAX_UNPARSED_SAMPLES:
                unparsed.append(f"A:{line.strip()[:120]}")
        elif section == "B":
            if "method" not in tx:
                rm = _REQ_RE.match(line.strip())
                if rm:
                    tx["method"] = rm.group("method")
                    tx["uri"] = rm.group("uri")
                elif line.strip() and len(unparsed) < MAX_UNPARSED_SAMPLES:
                    unparsed.append(f"B:{line.strip()[:120]}")
            ua = re.search(r"^User-Agent:\s*(.+)$", line, re.I)
            if ua:
                tx["ua"] = ua.group(1).strip()
        elif section == "F":
            st = re.match(r"^HTTP/[\d.]+\s+(\d{3})", line.strip())
            if st:
                tx["status"] = int(st.group(1))
        elif section == "H":
            mm = _MSG_RE.match(line)
            if mm:
                attrs = dict(_ATTR_RE.findall(mm.group(1)))
                tx["messages"].append(attrs)
    out = [t for t in txs if t.get("method")]
    if not out:
        raise ValueError(f"{src}: nol transaksi ModSecurity ter-parse")
    out.sort(key=lambda t: (t.get("time") is None,
                            t.get("time") or datetime.min.replace(
                                tzinfo=timezone.utc)))
    return out, unparsed


def parse_json_waf(text: str, src: str) -> tuple[list[dict], list[str]]:
    """Parser JSON/JSONL event WAF generik (AWS WAF/Cloudflare/NGINX
    JSON) — field dinormalkan, field tak dikenal diabaikan."""
    records: list[dict] = []
    unparsed: list[str] = []
    decoder = json.JSONDecoder()
    for idx, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("[") and "]" in line:
                items = json.loads(line)
            elif line.startswith("{"):
                items = [decoder.decode(line)]
            else:
                raise ValueError("bukan JSON")
        except ValueError:
            unparsed.append(f"L{idx}:{line[:120]}")
            continue
        if not isinstance(items, list):
            items = [items]
        for item in items:
            if not isinstance(item, dict):
                unparsed.append(f"L{idx}: bukan objek")
                continue
            uri = next((item[k] for k in
                        ("uri", "url", "path", "httpRequest", "request")
                        if k in item and item[k]), "")
            if isinstance(uri, dict):  # AWS WAF httpRequest
                inner = uri
                uri = inner.get("uri", "")
                if not item.get("ip"):
                    hdr = inner.get("headers") or []
                    client = item.get("clientIp") or inner.get("clientIp")
                    if client:
                        item.setdefault("ip", client)
                    for h in hdr:
                        if h.get("name", "").lower() == "user-agent":
                            item.setdefault("ua", h.get("value", ""))
            msg = next((item[k] for k in
                        ("message", "ruleMessage", "msg", "rule",
                         "action", "terminatingRuleId")
                        if k in item and item[k]), "")
            ip = next((str(item[k]) for k in
                       ("ip", "clientIp", "remote_addr", "source_ip",
                        "cIp", "client_ip")
                       if k in item and item[k]), "")
            status = next((item[k] for k in
                           ("status", "status_code", "responseCode")
                           if k in item and str(item[k]).isdigit()), "")
            ts_raw = next((item[k] for k in
                           ("timestamp", "time", "@timestamp", "ts")
                           if k in item and item[k]), "")
            t: datetime | None = None
            if isinstance(ts_raw, (int, float)):
                t = datetime.fromtimestamp(ts_raw / 1000.0
                                           if ts_raw > 1e12 else ts_raw,
                                           tz=timezone.utc)
            elif ts_raw:
                try:
                    t = datetime.fromisoformat(
                        str(ts_raw).replace("Z", "+00:00"))
                    if t.tzinfo is None:
                        t = t.replace(tzinfo=timezone.utc)
                except ValueError:
                    t = None
            records.append({
                "time": t, "ip": ip, "uri": str(uri), "method": "",
                "status": int(status) if status else None,
                "messages": [{"msg": str(msg)}], "ua": item.get("ua", ""),
                "src": src,
            })
    out = [r for r in records if r["uri"] or r["messages"][0]["msg"]]
    if not out:
        raise ValueError(f"{src}: nol event WAF JSON ter-parse")
    out.sort(key=lambda t: (t["time"] is None,
                            t["time"] or datetime.min.replace(
                                tzinfo=timezone.utc)))
    return out, unparsed


def triage(recs: list[dict], campaign_threshold: int,
           window_s: float) -> tuple[list[dict], dict, list[str]]:
    findings: list[dict] = []
    per_ip: Counter[str] = Counter()
    per_family: Counter[str] = Counter()
    campaigns: list[tuple[str, int]] = []

    for rec in recs:
        raw_uri = rec.get("uri", "") or ""
        decoded = unquote(raw_uri)
        msg_text = " ".join(a.get("msg", "") for a in
                            rec.get("messages", []))
        ids = [a.get("id", "") for a in rec.get("messages", [])
               if a.get("id")]
        family = _classify(f"{decoded} {msg_text}")
        ua = rec.get("ua", "") or ""
        ts = rec.get("time")
        ts_s = ts.isoformat() if ts else ""
        base = {"ip": rec.get("ip", ""), "ts": ts_s}
        if family:
            per_ip[rec.get("ip", "")] += 1
            per_family[family] += 1
            evidence = {"uri": raw_uri[:MAX_EVIDENCE_CHARS],
                        "family": family,
                        "rule_id": ids[0] if ids else "",
                        "rule_msg": msg_text[:MAX_EVIDENCE_CHARS],
                        "status": rec.get("status")}
            findings.append({
                "check": "sqli-attempt",
                "severity": _family_sev(family),
                "message": f"upaya SQLi terklasifikasi {family}",
                **base, **evidence,
            })
            st = rec.get("status")
            if st and 200 <= st < 300:
                findings.append({
                    "check": "waf-bypass-possible", "severity": "high",
                    "message": "request SQLi mendapat respons "
                               f"{st} dari aplikasi — kandidat bypass "
                               "(verifikasi manual diperlukan)",
                    **base, **evidence,
                })
        if ua and _SQLMAP_UA_RE.search(ua):
            findings.append({
                "check": "sqlmap-ua", "severity": "medium",
                "message": f"user-agent alat uji SQLi otomatis "
                           f"({ua[:80]})",
                **base, "uri": raw_uri[:MAX_EVIDENCE_CHARS],
            })

    wins = timedelta(seconds=window_s)
    by_ip: dict[str, list[datetime]] = {}
    for rec in recs:
        if not rec.get("time") or not rec.get("ip"):
            continue
        if _classify(f"{unquote(rec.get('uri', ''))} "
                     f"{' '.join(a.get('msg', '') for a in rec.get('messages', []))}"):
            by_ip.setdefault(rec["ip"], []).append(rec["time"])
    for ip, times in by_ip.items():
        times.sort()
        left = 0
        best = 0
        for right in range(len(times)):
            while times[right] - times[left] > wins:
                left += 1
            best = max(best, right - left + 1)
        if best >= campaign_threshold:
            campaigns.append((ip, best))

    for ip, burst in sorted(campaigns):
        findings.append({
            "check": "sqli-campaign", "severity": "high", "ip": ip,
            "message": f"{burst} request SQLi dalam {int(window_s)}s "
                       f"(>= ambang {campaign_threshold})",
            "burst": burst,
        })

    stats = {
        "records_total": len(recs),
        "sqli_attempts": sum(per_ip.values()),
        "by_family": dict(sorted(per_family.items())),
        "top_ips": [[ip, n] for ip, n in
                    per_ip.most_common(10)],
    }
    notes: list[str] = []
    if not per_ip:
        notes.append("tidak ada request terklasifikasi SQLi di log "
                     "ini — bukan bukti tidak ada serangan (window "
                     "log/coverage rule terbatas)")
    findings.sort(key=lambda f: (f["check"], f.get("ts", ""),
                                 f.get("ip", "")))
    return findings, stats, notes


def _load_recs(args: argparse.Namespace) -> tuple[list[dict],
                                                   list[str]]:
    path = Path(args.log)
    if not path.exists():
        raise FileNotFoundError(f"{args.log}: file tidak ada")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{args.log} > {MAX_FILE_BYTES} byte")
    text = path.read_text(encoding="utf-8", errors="replace")
    if text.lstrip().startswith("--") and re.search(
            r"^--[0-9a-fA-F-]+-A--\s*$", text, re.M):
        recs, unparsed = parse_modsec(text, str(path))
    else:
        recs, unparsed = parse_json_waf(text, str(path))
    return recs, unparsed


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase OFFLINE log WAF (ModSecurity/JSON) utk "
                    "kampanye SQLi — nol jaringan, read-only")
    ap.add_argument("--log", required=True, help="file log WAF")
    ap.add_argument("--campaign-threshold", type=int, default=5)
    ap.add_argument("--window", type=float, default=300.0,
                    help="window geser kampanye detik (default 300)")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="high")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    args = ap.parse_args(argv)

    try:
        recs, unparsed = _load_recs(args)
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings, stats, notes = triage(recs, args.campaign_threshold,
                                    args.window)
    order = {"high": 0, "medium": 1, "info": 2, "low": 3}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {"unparsed": unparsed,
                 "campaign_threshold": args.campaign_threshold,
                 "window_s": args.window,
                 "fail_on": args.fail_on},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
