r"""[SAFETY: read-only] webshell_triage — triase OFFLINE access log web
(CLF/combined) untuk aktivitas webshell (T1505.003). TANPA jaringan.

Input -> mekanisme -> output:
  - Input : file access log CLF/combined (Apache/Nginx/IIS ekspor CLF)
            atau --dir.
  - Mekanisme: parse baris -> percent-decode URI -> cek deterministik
            per request + agregasi POST berulang ke path script sama.
  - Output: temuan {check, severity, ip, uri, status, message} + stats
            + notes.

Cek (verdict = LEAD; konten shell sah bisa cocok pola — pakai
--allow-uri/--allow-ip utk allowlist lab):
  webshell-cmd-param    (high)   : parameter query eksekusi perintah
                                   (cmd=/exec=/passthru=/run=/eval=/
                                   system=/command=) atau token output
                                   shell di query (whoami, ipconfig,
                                   net user, /bin/sh, cat /etc/).
  webshell-name         (high)   : nama file shell terkenal (cmd/shell/
                                   aspxspy/ant/bomber/chopper/wso/
                                   b374k/c99/r57/webshell ...).
  script-in-upload-dir  (high)   : file script (.php/.asp/.aspx/.ashx/
                                   .jsp/.jspx/.cgi/.pl) di direktori
                                   upload/media/data — shell yang baru
                                   ter-upload; termasuk trik double
                                   extension (.php;.jpg).
  post-to-static-ext    (medium) : POST dgn status 2xx ke file non-
                                   script (.jpg/.png/.txt ...) —
                                   interaksi dgn file ter-upload.
  tomcat-manager-deploy (high/med): POST ke /manager/html atau
                                   /host-manager — deploy war shell
                                   (200 = high, 401/403 = medium).
  webshell-post-burst   (medium) : >= --burst N POST ke path script
                                   SAMA oleh IP sama dalam window
                                   --window-detik (default 5 / 600s) —
                                   pola interaksi shell berulang.

Fail-closed:
  - Tidak ada baris ter-parse di semua input -> exit 2 (bukan log CLF
    = tidak bisa disimpulkan bersih).
  - Baris malformasi dihitung stats.lines_skipped, tidak dipendam.
  - Timestamp tidak ter-parse = baris tetap dievaluasi utk cek
    per-request, tapi dikecualikan dr agregasi window (dicatat stats).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/webshell_triage.py --log access.log
  python tools/webshell_triage.py --dir logs/ --fail-on medium
  python tools/webshell_triage.py --log access.log \
      --allow-uri '/admin/tools.php' --burst 10
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "secai.webshell-triage/1"
MAX_FILE_BYTES = 512 * 1024 * 1024

CLF_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" '
    r'(\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?')
TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

CMD_PARAM_RE = re.compile(
    r"[?&](?:cmd|exec|passthru|run|eval|system|command|exe|shell)=",
    re.I)
CMD_TOKEN_RE = re.compile(
    r"\bwhoami\b|\bipconfig\b|\bifconfig\b|\bnet(?:\s|%20)user\b"
    r"|\bnet(?:\s|%20)localgroup\b|/bin/(?:sh|bash)\b|/bin/zsh\b"
    r"|\bcat\s+(?:/etc/|%2fetc%2f)|\buname\b|\bid\s*;|\bpwd\b",
    re.I)

SCRIPT_EXT_RE = re.compile(
    r"\.(?:php\d?|phtml|asp|aspx|ashx|asmx|jsp|jspx|jsw|jsv|cgi|pl)$",
    re.I)
UPLOAD_DIR_RE = re.compile(
    r"/(?:uploads?|files?|images?|img|media|attachments?|userfiles?"
    r"|data|temp|tmp|static|assets|sites(?:/[^/?]+)?/files|"
    r"content|download(?:s)?)(?:/|$)", re.I)
DOUBLE_EXT_RE = re.compile(
    r"\.(?:php\d?|phtml|asp|aspx|jsp|jspx)(?:;|%00|\.[a-z0-9]{2,5})\S*$",
    re.I)
STATIC_EXT_RE = re.compile(
    r"\.(?:jpg|jpeg|png|gif|bmp|webp|svg|ico|txt|pdf|zip|rar|css|"
    r"xlsx?|docx?)$", re.I)

WEBSHELL_NAME_RE = re.compile(
    r"(?:^|[/\\])(?:cmd|shell|sh|spy|ant|aspxspy|bomber|chopper|"
    r"china-chopper|wso|b374k|c99|r57|webshell|xcao|behinder|godzilla|"
    r"p0wny|jspshell|cmdjsp|filemanager|adminer(?:_[^/]*)?)"
    r"\.(?:php\d?|phtml|asp|aspx|ashx|jsp|jspx|ashx)$", re.I)

MANAGER_RE = re.compile(r"^/(?:manager|host-manager)/html(?:/|$)", re.I)


def parse_line(line: str) -> "dict | None":
    m = CLF_RE.match(line.strip())
    if m is None:
        return None
    ip, ts_raw, method, uri, status, nbytes, _ref, _ua = m.groups()
    ts = None
    try:
        ts = datetime.strptime(ts_raw, TS_FMT).astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        status_i = int(status)
    except ValueError:
        status_i = 0
    return {"ip": ip, "ts": ts, "method": method, "uri": uri,
            "status": status_i,
            "bytes": int(nbytes) if nbytes.isdigit() else 0}


def _uri_no_query(uri: str) -> str:
    return uri.split("?", 1)[0].split("#", 1)[0]


def _allowed(text: str, allow: frozenset[str]) -> str | None:
    for a in allow:
        if a.lower() in text.lower():
            return a
    return None


def analyze(entries: list[dict], allow_uris: frozenset[str],
            allow_ips: frozenset[str], burst: int,
            window_s: float) -> "tuple[list[dict], dict, list[str]]":
    findings: list[dict] = []
    notes: list[str] = []
    stats = {"lines_total": len(entries), "findings": len(findings),
             "no_timestamp": 0}
    posts: dict[tuple[str, str, datetime], int] = {}
    for e in entries:
        if e["ts"] is None:
            stats["no_timestamp"] += 1
        decoded = unquote(e["uri"])
        if _allowed(decoded + " " + e["ip"], allow_uris) or \
                _allowed(e["ip"], allow_ips):
            continue
        base = {"ip": e["ip"], "uri": decoded, "status": e["status"]}
        path = _uri_no_query(decoded)
        checks: list[tuple[str, str, str]] = []  # (check, sev, msg)
        if CMD_PARAM_RE.search(decoded) or CMD_TOKEN_RE.search(decoded):
            checks.append((
                "webshell-cmd-param", "high",
                "Parameter/token eksekusi perintah di query "
                "(T1505.003)"))
        if WEBSHELL_NAME_RE.search(path):
            checks.append((
                "webshell-name", "high",
                "Nama file webshell terkenal (T1505.003)"))
        if ((SCRIPT_EXT_RE.search(path) and UPLOAD_DIR_RE.search(path))
                or DOUBLE_EXT_RE.search(path)):
            checks.append((
                "script-in-upload-dir", "high",
                "Script di direktori upload/double-extension "
                "(kandidat shell ter-upload, T1505.003)"))
        if e["method"] == "POST" and STATIC_EXT_RE.search(path) and \
                200 <= e["status"] < 300:
            checks.append((
                "post-to-static-ext", "medium",
                "POST sukses ke file statis — interaksi file "
                "ter-upload (lead)"))
        if e["method"] == "POST" and MANAGER_RE.search(path):
            sev = "high" if 200 <= e["status"] < 300 else "medium"
            checks.append((
                "tomcat-manager-deploy", sev,
                f"POST ke Tomcat manager (status {e['status']}) — "
                "deploy aplikasi/war shell (T1505.003)"))
        for check, sev, msg in checks:
            findings.append({
                "check": check, "severity": sev, **base,
                "message": f"{e['ip']} {e['method']} {decoded} "
                           f"({e['status']}) — {msg}",
            })
        if e["method"] == "POST" and SCRIPT_EXT_RE.search(path) \
                and e["ts"] is not None:
            key = (e["ip"], path.lower(), e["ts"])
            posts[key] = posts.get(key, 0) + 1

    # agregasi burst POST per ip+path dalam window
    by_key: dict[tuple[str, str], list[datetime]] = {}
    for (ip, path, ts) in posts:
        by_key.setdefault((ip, path), []).append(ts)
    for (ip, path), times in by_key.items():
        times.sort()
        for i, t in enumerate(times):
            window = [x for x in times
                      if 0 <= (t - x).total_seconds() <= window_s]
            if len(window) >= burst:
                findings.append({
                    "check": "webshell-post-burst", "severity": "medium",
                    "ip": ip, "uri": path, "status": 0,
                    "message": f"{ip} mengirim {len(window)} POST ke "
                               f"{path} dalam {window_s:.0f}s — pola "
                               "interaksi shell berulang (T1505.003)",
                })
                break
    if stats["no_timestamp"]:
        notes.append(
            f"{stats['no_timestamp']} baris tanpa timestamp ter-parse — "
            "dievaluasi utk cek per-request, dikecualikan dr agregasi "
            "window (tidak dipendam).")
    return findings, stats, notes


def _gather_files(args: argparse.Namespace) -> list[Path]:
    if args.log:
        return [args.log]
    if args.dir:
        return sorted(p for p in args.dir.iterdir() if p.is_file())
    raise ValueError("butuh --log atau --dir")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase OFFLINE webshell (T1505.003) dari access "
                    "log CLF/combined — read-only, nol jaringan.")
    ap.add_argument("--log", type=Path, help="file access log")
    ap.add_argument("--dir", type=Path, help="direktori berisi log")
    ap.add_argument("--out", type=Path, help="simpan laporan JSON")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"],
                    default="high")
    ap.add_argument("--allow-uri", default="",
                    help="CSV substring URI/IP sah (anti-FP)")
    ap.add_argument("--allow-ip", default="",
                    help="CSV IP sumber sah (anti-FP)")
    ap.add_argument("--burst", type=int, default=5,
                    help="ambang POST berulang ke path sama")
    ap.add_argument("--window", type=float, default=600.0,
                    help="window agregasi burst (detik)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
    files = _gather_files(args)
    entries: list[dict] = []
    skipped = 0
    for p in files:
        if not p.is_file():
            print(f"error: file tidak ada: {p}", file=sys.stderr)
            return 2
        if p.stat().st_size > MAX_FILE_BYTES:
            print(f"error: file terlalu besar (> {MAX_FILE_BYTES} B): {p}",
                  file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if not line.strip():
                continue
            e = parse_line(line)
            if e is None:
                skipped += 1
            else:
                entries.append(e)
    if not entries:
        print("error: tidak ada baris CLF/combined ter-parse "
              "(bukan access log?)", file=sys.stderr)
        return 2

    allow_uris = frozenset(
        a.strip() for a in args.allow_uri.split(",") if a.strip())
    allow_ips = frozenset(
        a.strip() for a in args.allow_ip.split(",") if a.strip())
    findings, stats, notes = analyze(entries, allow_uris, allow_ips,
                                     args.burst, args.window)
    stats["lines_skipped"] = skipped
    report = {"schema": SCHEMA, "files": [str(f) for f in files],
              "stats": stats, "findings": findings, "notes": notes}
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text_out + "\n", encoding="utf-8")
    if args.json or args.out:
        print(text_out)
    else:
        for f in findings:
            print(f"[{f['severity'].upper():6}] {f['check']}: "
                  f"{f['message']}")
        print(f"-- {len(findings)} temuan, {stats['lines_total']} "
              f"request, {stats['lines_skipped']} baris dilewati")
        for n in notes:
            print(f"note: {n}")
    return 1 if any(rank[f["severity"]] >= rank[args.fail_on]
                    for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
