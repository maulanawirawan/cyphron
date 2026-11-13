r"""[AUDIT: read-only] browser_history_triage — triase OFFLINE basis data
history peramban (Chrome/Edge Chromium "History", Firefox
"places.sqlite") yang sudah DISALIN dari image/disk — forensik waktu
aktivitas web.

Ranah tetangga eksplisit: history DI LOG jaringan = zeek_beacon_scan/
dns_log_triage; aktivitas file lokal = mft_scan/timestomp_triage;
eksekusi proses = sysmon_triage/lolbin_scan; kredensial tersimpan =
secret scanners. Tool ini HANYA membaca salinan berkas SQLite yang
diberikan — TIDAK membuka profil live, TIDAK menulis ke bukti
(mode=ro&immutable=1), TIDAK memicu jaringan.

Input -> mekanisme -> output:
  - Input   : --source FILE... (satu atau beberapa berkas salinan
              History/History.db/places.sqlite), --top N (default 20),
              --show-query (jangan sembunyikan query string),
              --fail-on (default medium).
  - Mekanisme: deteksi keluarga dari tabel; konversi epoch (WebKit:
              us sejak 1601 -> unix = us/1e6 - 11644473600; Firefox:
              us sejak 1970); gabung visits x urls; cek deterministik:
    visit-direct-ip         (medium): host = literal IPv4/IPv6 —
                                       kunjungan langsung ke IP (C2/
                                       phishing/dev); dari domain
    visit-embedded-credentials (medium): url memuat userinfo@host
                                       (user:pass inline)
    visit-file-scheme       (medium): file:// dibuka peramban — jalur
                                       penanaman umum maldoc/lolbin
    visit-epoch-anomaly     (medium): waktu kunjungan < 1995 atau
                                       > 24 jam ke depan — jam salah /
                                       manipulasi / profil rusak
    download-danger-flagged (medium): unduhan Chromium dgn danger_type
                                       1-7 (dangerous-file/url/content,
                                       uncommon, dangerous-host,
                                       PUA) — label dipetakan, kode
                                       tak dikenal tetap dilaporkan
    visit-nonstandard-port  (low)   : http/https ke port selain 80/443
  - Output  : per sumber {family, urls, visits, first, last,
              top_domains, downloads, search_terms, findings} +
              summary + notes; query string DIMASKING default
              (privacy — sama seperti data_class_scan), --show-query
              utk tampilkan; exit 1 bila temuan >= --fail-on, exit 2
              bila tidak ada berkas yang terbaca sbg basis data yang
              dikenal (fail-closed).

Stdlib sqlite3/json/argparse/ipaddress/urllib.parse. Nol jaringan.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = "browser_history_triage/v1"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

WEBKIT_OFFSET = 11644473600  # detik antara 1601-01-01 dan 1970-01-01
ANOMALY_MIN_UNIX = 788918400  # 1995-01-01

# chromium download_danger_type (yang terdokumentasi publik)
DANGER_LABEL = {
    1: "dangerous-file",
    2: "dangerous-url",
    3: "dangerous-content",
    4: "maybe-dangerous-content",
    5: "uncommon-content",
    6: "dangerous-host",
    7: "potentially-unwanted",
}
# chromium download state
STATE_LABEL = {0: "in-progress", 1: "complete", 2: "cancelled",
               3: "interrupted"}


def _iso(unix: "float | None") -> "str | None":
    if unix is None:
        return None
    try:
        return dt.datetime.fromtimestamp(
            unix, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _mask(url: str) -> str:
    """Sembunyikan kredensial di netloc + query string (privacy);
    --show-query mematikan masking (jalur investigasi sadar risiko)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url[:80]
    if not parts.scheme:
        return url[:80]
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    shown = f"{parts.scheme}://{netloc}{parts.path}"
    if parts.query:
        shown += f"?<masked:{len(parts.query)}>"
    return shown[:160]


def _check_url(url: str, add, src: str, rowid: int) -> None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return
    host = parts.hostname or ""
    if host:
        try:
            ipaddress.ip_address(host)
            add("visit-direct-ip", "medium", f"{src}:urls#{rowid}", host,
                f"kunjungan langsung ke alamat IP ({host}) — bypass "
                "DNS/direct C2 atau host dev; verifikasi manual",
                url)
        except ValueError:
            pass
    if "@" in (parts.netloc or ""):
        add("visit-embedded-credentials", "medium",
            f"{src}:urls#{rowid}", parts.netloc.split("@")[-1],
            "url memuat userinfo@host (kredensial inline di URL)",
            url)
    if parts.scheme == "file":
        add("visit-file-scheme", "medium", f"{src}:urls#{rowid}",
            parts.path[:80], "berkas lokal dibuka lewat file:// — jalur "
            "penanaman umum (maldoc/lolbin)", url)
    if parts.scheme in ("http", "https") and parts.port is not None \
            and parts.port not in (80, 443):
        add("visit-nonstandard-port", "low", f"{src}:urls#{rowid}",
            f"{host}:{parts.port}",
            f"http/https ke port {parts.port}", url)


def _triage_chromium(db: sqlite3.Connection, src: str, add, top: int,
                     show_query: bool) -> dict:
    cur = db.cursor()
    urls = {}
    for uid, url, title, vcount, last in cur.execute(
            "SELECT id, url, title, visit_count, last_visit_time FROM urls"):
        urls[uid] = {"url": url, "title": title or "",
                     "visit_count": vcount or 0,
                     "last": (last / 1_000_000 - WEBKIT_OFFSET)
                     if last else None}
    n_visits = 0
    first = last = None
    domains: "dict[str, int]" = {}
    for (_vid, uid, vtime) in cur.execute(
            "SELECT id, url, visit_time FROM visits"):
        n_visits += 1
        unix = (vtime / 1_000_000 - WEBKIT_OFFSET) if vtime else None
        if unix:
            first = unix if first is None else min(first, unix)
            last = unix if last is None else max(last, unix)
            if unix < ANOMALY_MIN_UNIX or unix > dt.datetime.now(
                    dt.timezone.utc).timestamp() + 86400:
                add("visit-epoch-anomaly", "medium",
                    f"{src}:visits#{_vid}", _iso(unix),
                    f"waktu kunjungan abnormal ({_iso(unix)}) — jam "
                    "perangkat salah, manipulasi, atau profil rusak",
                    urls.get(uid, {}).get("url", ""))
        info = urls.get(uid)
        if not info:
            continue
        try:
            parts = urlsplit(info["url"])
            key = (parts.hostname or "") + (
                f":{parts.port}" if parts.port else "")
        except ValueError:
            key = ""
        if key:
            domains[key] = domains.get(key, 0) + 1
    for uid, info in urls.items():
        _check_url(info["url"], add, src, uid)
    downloads = []
    if _has_table(db, "downloads"):
        for (dpath, tab, total, start, end, state, danger) in cur.execute(
                "SELECT target_path, tab_url, total_bytes, start_time, "
                "end_time, state, danger_type FROM downloads"):
            entry = {"path": Path(dpath or "").name,
                     "source": _mask(tab or "") if not show_query else tab,
                     "bytes": total or 0,
                     "state": STATE_LABEL.get(state, f"code-{state}"),
                     "danger": DANGER_LABEL.get(danger, f"code-{danger}")
                     if danger else "not-dangerous"}
            downloads.append(entry)
            if danger and 1 <= int(danger) <= 7:
                add("download-danger-flagged", "medium",
                    f"{src}:downloads#{dpath}",
                    entry["danger"],
                    f"unduhan ditandai peramban: "
                    f"{DANGER_LABEL.get(danger, f'code-{danger}')} "
                    f"(state {entry['state']})",
                    tab or "")
    search_terms = [t for (t,) in cur.execute(
        "SELECT term FROM keyword_search_terms")] \
        if _has_table(db, "keyword_search_terms") else []
    top = sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {
        "family": "chromium",
        "urls": len(urls), "visits": n_visits,
        "first": _iso(first), "last": _iso(last),
        "top_domains": [{"domain": d, "visits": c} for d, c in top],
        "downloads": downloads,
        "search_terms": search_terms,
    }


def _triage_firefox(db: sqlite3.Connection, src: str, add, top: int) -> dict:
    cur = db.cursor()
    places = {}
    for pid, url, _title, vcount, last in cur.execute(
            "SELECT id, url, title, visit_count, last_visit_date "
            "FROM moz_places"):
        places[pid] = {"url": url, "visit_count": vcount or 0,
                       "last": (last / 1_000_000) if last else None}
    n_visits = 0
    first = last = None
    domains: "dict[str, int]" = {}
    for (_vid, pid, vdate) in cur.execute(
            "SELECT id, place_id, visit_date FROM moz_historyvisits"):
        n_visits += 1
        unix = (vdate / 1_000_000) if vdate else None
        if unix:
            first = unix if first is None else min(first, unix)
            last = unix if last is None else max(last, unix)
            if unix < ANOMALY_MIN_UNIX or unix > dt.datetime.now(
                    dt.timezone.utc).timestamp() + 86400:
                add("visit-epoch-anomaly", "medium",
                    f"{src}:moz_historyvisits#{_vid}", _iso(unix),
                    f"waktu kunjungan abnormal ({_iso(unix)})", "")
        info = places.get(pid)
        if not info:
            continue
        try:
            parts = urlsplit(info["url"])
            key = (parts.hostname or "") + (
                f":{parts.port}" if parts.port else "")
        except ValueError:
            key = ""
        if key:
            domains[key] = domains.get(key, 0) + 1
    for pid, info in places.items():
        _check_url(info["url"], add, src, pid)
    top = sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {
        "family": "firefox",
        "urls": len(places), "visits": n_visits,
        "first": _iso(first), "last": _iso(last),
        "top_domains": [{"domain": d, "visits": c} for d, c in top],
        "downloads": [],  # Firefox: unduhan tidak di places.sqlite
        "search_terms": [],
    }


def _has_table(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,)).fetchone()
    return row is not None


def triage_file(path: Path, add, top: int, show_query: bool) -> "dict | None":
    try:
        db = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1",
                             uri=True)
    except sqlite3.Error as exc:
        add("input-unreadable", "high", str(path), "-",
            f"basis data tidak dapat dibuka: {exc}")
        return None
    try:
        if _has_table(db, "urls") and _has_table(db, "visits"):
            return _triage_chromium(db, path.name, add, top, show_query)
        if _has_table(db, "moz_places") and \
                _has_table(db, "moz_historyvisits"):
            return _triage_firefox(db, path.name, add, top)
        add("input-schema-unknown", "high", str(path), "-",
            "skema bukan Chromium (urls/visits) maupun Firefox "
            "(moz_places/moz_historyvisits) — fail-closed")
        return None
    finally:
        db.close()


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", nargs="+", type=Path, required=True,
                    metavar="FILE",
                    help="salinan History/places.sqlite (bukan live)")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--show-query", action="store_true",
                    help="tampilkan query string (default dimasking)")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium")
    ap.add_argument("--allow-check", action="append", default=[],
                    metavar="NAME")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    allowed = set(args.allow_check)
    findings: "list[dict]" = []

    def add(check, severity, obj, field, message, url=""):
        if check in allowed:
            return
        findings.append({
            "check": check, "severity": severity, "object": obj,
            "field": field, "message": message,
            "url": url if args.show_query else (_mask(url) if url else ""),
        })

    sources = []
    for p in args.source:
        wal = Path(str(p) + "-wal")
        if wal.exists():
            findings.append({
                "check": "source-wal-present", "severity": "low",
                "object": str(p), "field": "-",
                "message": "berkas -wal ada di sebelahnya — salinan "
                           "mungkin belum memuat transisi terakhir; "
                           "salin ulang wal + shm bersama main db",
                "url": "",
            })
        res = triage_file(p, add, args.top, args.show_query)
        if res is not None:
            sources.append(res)

    if not sources:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "tidak ada berkas yang dikenali sebagai basis data "
                     "history Chromium/Firefox — fail-closed, TIDAK "
                     "menyatakan riwayat kosong",
        }), file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold
              for f in findings)
    notes = [
        "bekerja atas SALINAN berkas (mode=ro&immutable=1) — bukti live "
        "tidak disentuh; salin History + -wal + -shm bersamaan",
        "query string url DIMASKING default (privacy) — --show-query utk "
        "tampilkan penuh",
        "cookies/cache/bookmarks/session di luar tool — acuan internal "
        "mencakup artefak itu; sini fokus history + unduhan",
        "tidak ada history = tidak berarti tidak ada aktivitas (clear "
        "history manual / private mode tidak terlihat dari db saja)",
    ]
    if allowed:
        notes.append(f"check disaring: {', '.join(sorted(allowed))}")
    report = {
        "schema": SCHEMA,
        "summary": {
            "sources": len(sources),
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("high", "medium", "low")
            },
        },
        "sources": sources,
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["object"], f["check"]),
        ),
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
