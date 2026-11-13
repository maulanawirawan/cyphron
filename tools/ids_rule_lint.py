r"""[SAFETY: read-only] ids_rule_lint — linter kualitas aturan IDS Snort 3 /
Suricata (file .rules, parsing teks, tanpa eksekusi engine, nol
jaringan).

Input -> mekanisme -> output:
  - Input : file .rules/.conf/.txt atau direktori (read-only, NOL
            jaringan — TIDAK menjalankan snort/suricata, hanya parsing).
  - Mekanisme: gabung baris continuation '\\', buang komentar '#' dan
            konfigurasi non-rule, parse header (action proto src sport
            dir dst dport) + opsi (key[: value];) -> model per-rule ->
            cek deterministik.
  - Output: daftar lead {rule, line, check, severity, message} + meta.

Cek (semua verdict = LEAD):
  rule-unparsed      (high) : kurung/quote tak tertutup pada satu rule —
                              rule TIDAK dihitung bersih.
  file-unparsed      (high) : kurung tetap terbuka sampai EOF / continuation
                              tak selesai — file tidak dianggap bersih.
  sid-hilang         (high) : tanpa sid -> engine menolak rule.
  sid-duplikat       (high) : sid sama muncul dua kali (di file yang sama).
  action-tak-kenal   (high) : action di luar alert/log/pass/drop/reject/
                              block/sblock/sdrop.
  msg-hilang         (high) : tanpa msg — alert tanpa konteks operator.
  msg-kosong         (medium): msg: "" / whitespace.
  rev-hilang         (medium): tanpa rev — tuning tak terlacak.
  tanpa-match        (info) : tidak ada keyword konten (content/pcre/
                              byte_*/http.*/tls.*/dns.*/ja3*/ssh.*) — sah
                              utk rule decode/metadata vendor, rawan noise
                              utk rule lokal.
  buffer-proto-mismatch (medium): sticky-buffer http.*/tls.*/ssh.* pada
                              proto != tcp/http, dns.* bukan udp/tcp/dns,
                              dst. (protokol layanan Snort 3 diakui).
  priority-janggal   (medium): priority bukan 1-4.
  threshold-rusak    (high) : threshold/detection_filter tanpa count; atau
                              type both/threshold tanpa seconds.
  any-any-terbuka    (info) : header any any -> any any (bidang luas).
  content-tanpa-nocase (info): content campuran huruf besar-kecil tanpa
                              nocase (payload hex/tanpa huruf diabaikan).
  sid-reserved       (info) : sid 1-99 = rentang reserved, jangan dipakai.

Fail-closed: satu rule rusak = lead high dan file TIDAK dihitung bersih;
exit 0 hanya jika semua file seluruhnya bersih. Exit: 0 bersih; 1 ada
lead >= --fail-on (default info, mengikuti yara_rule_lint); 2 error input.

Pemakaian:
  python tools/ids_rule_lint.py --source local.rules
  python tools/ids_rule_lint.py --source rules/ --json hasil.json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secai.ids-rule-lint/1"
RULE_EXTS = {".rules"}

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
SEV_HIGH = "high"
SEV_MED = "medium"
SEV_INFO = "info"

KNOWN_ACTIONS = {"alert", "log", "pass", "drop", "reject", "block",
                 "sblock", "sdrop"}

# protokol layanan Snort 3 — header sah berbentuk `action proto ( ... )`
SERVICE_PROTOS = {"http", "tls", "ssl", "dns", "ssh", "smtp", "smb", "imap",
                  "pop3", "ftp", "ftp-data", "sip", "rfb", "modbus", "dnp3",
                  "enip", "s7comm", "gtp", "dhcp", "ike", "ntp", "msn", "nbss"}

# keyword konten/deteksi — rule tanpa satu pun = header-only
CONTENT_KEYWORDS = {"content", "pcre", "byte_test", "byte_jump", "byte_extract",
                    "isdataat", "bsize", "datasize", "dsize", "base64_decode",
                    "ja3.hash", "ja3s.hash", "ja4.hash"}
CONTENT_PREFIXES = ("http.", "http_", "tls.", "dns.", "ssh.", "ja3.", "ja3s.",
                    "ja4.", "smtp.", "sip.", "mqtt.", "krb5.", "rfb.", "dns_")

# sticky-buffer -> proto yang sah (proto klasik + protokol layanan Snort 3)
BUFFER_PROTO: dict[str, set[str]] = {
    "http.": {"tcp", "http"}, "http_": {"tcp", "http"},
    "tls.": {"tcp", "tls", "ssl"}, "ssh.": {"tcp", "ssh"},
    "dns.": {"udp", "tcp", "dns"}, "smtp.": {"tcp", "smtp"},
    "mqtt.": {"tcp", "mqtt"}, "krb5.": {"tcp", "udp"},
    "rfb.": {"tcp", "rfb"}, "sip.": {"udp", "tcp", "sip"},
    "icmp.": {"icmp"},
}

THR_TYPES_NEEDING_SECONDS = {"both", "threshold", "limit"}


class RuleUnparsed(ValueError):
    """Satu rule tidak bisa diparse — jadi lead high, file tak bersih."""


def iter_rule_text(text: str) -> list[tuple[int, str]]:
    """Gabung continuation '\\', buang komentar & baris kosong ->
    [(line_no, rule_text)]."""
    out: list[tuple[int, str]] = []
    buf = ""
    buf_line = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not buf:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            buf = line
            buf_line = i
        else:
            buf += "\n" + line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip() + " "
            continue
        out.append((buf_line, buf))
        buf = ""
    if buf:
        # continuation tidak pernah selesai -> jadi rule tak tertutup
        out.append((buf_line, buf))
    return out


def split_options(body: str) -> list[tuple[str, str]]:
    """Isi '(...)' -> daftar (key, value) dengan escape ';' sadar."""
    opts: list[tuple[str, str]] = []
    cur = []
    escaped = False
    in_quote = False
    for ch in body:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            cur.append(ch)
            continue
        if ch == ";" and not in_quote:
            part = "".join(cur).strip()
            if part:
                if ":" in part:
                    k, v = part.split(":", 1)
                    opts.append((k.strip(), v.strip()))
                else:
                    opts.append((part.strip(), ""))
            cur = []
            continue
        cur.append(ch)
    if in_quote:
        raise RuleUnparsed("quote tidak tertutup")
    tail = "".join(cur).strip()
    if tail:
        raise RuleUnparsed(f"opsi tidak diakhiri ';': {tail[:40]!r}")
    return opts


def parse_rule(text: str) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Satu rule -> (header dict, opsi). Raise RuleUnparsed.

    Header sah: 7 kolom klasik (action proto src sport dir dst dport) ATAU
    2 kolom protokol layanan Snort 3 (action http/tls/dns/...).
    """
    text = text.strip()
    if not text.endswith(")"):
        raise RuleUnparsed("rule tidak diakhiri ')'")
    open_idx = text.find("(")
    if open_idx < 0:
        raise RuleUnparsed("tidak ada blok opsi '('")
    header_part = text[:open_idx].strip()
    body = text[open_idx + 1:-1]
    header = header_part.split()
    keys = ("action", "proto", "src", "sport", "dir", "dst", "dport")
    if len(header) == 7:
        hdr = dict(zip(keys, header))
        if hdr["dir"] not in ("->", "<>", "<->"):
            raise RuleUnparsed(f"arah tidak valid: {hdr['dir']!r}")
    elif len(header) == 2 and header[1].lower() in SERVICE_PROTOS:
        hdr = {k: "" for k in keys}
        hdr["action"] = header[0]
        hdr["proto"] = header[1]
    else:
        raise RuleUnparsed(
            f"header harus 7 kolom (action proto src sport dir dst dport) "
            f"atau 2 kolom protokol layanan Snort 3, dapat {len(header)}: "
            f"{header_part[:60]!r}")
    opts = split_options(body)
    return hdr, opts


def lint_rule(hdr: dict[str, Any], opts: list[tuple[str, str]],
              rule_no: int, sids_seen: dict[int, int]) -> list[dict[str, Any]]:
    """Cek deterministik satu rule (dipanggil setelah parse sukses)."""
    out: list[dict[str, Any]] = []

    def lead(check: str, sev: str, msg: str) -> None:
        out.append({"rule": rule_no, "check": check, "severity": sev,
                    "message": msg})

    action = hdr["action"].lower()
    if action not in KNOWN_ACTIONS:
        lead("action-tak-kenal", SEV_HIGH, f"action {hdr['action']!r} tidak dikenal")

    kv = {}
    for k, v in opts:
        kv.setdefault(k.lower(), []).append(v)

    sid_vals = kv.get("sid")
    if not sid_vals or not sid_vals[0].strip():
        lead("sid-hilang", SEV_HIGH, "tanpa sid")
    else:
        try:
            sid = int(sid_vals[0].strip())
            if sid in sids_seen:
                lead("sid-duplikat", SEV_HIGH,
                     f"sid {sid} sudah dipakai di rule #{sids_seen[sid]}")
            else:
                sids_seen[sid] = rule_no
            if sid < 100:
                lead("sid-reserved", SEV_INFO,
                     f"sid {sid} di rentang reserved 1-99 — ganti")
        except ValueError:
            lead("sid-hilang", SEV_HIGH, f"sid bukan angka: {sid_vals[0]!r}")

    msgs = kv.get("msg")
    if not msgs:
        lead("msg-hilang", SEV_HIGH, "tanpa msg")
    elif not msgs[0].strip().strip('"'):
        lead("msg-kosong", SEV_MED, "msg kosong")

    if "rev" not in kv or not kv["rev"][0].strip():
        lead("rev-hilang", SEV_MED, "tanpa rev — revisi rule tak terlacak")

    has_content = any(
        k.lower() in CONTENT_KEYWORDS or k.lower().startswith(CONTENT_PREFIXES)
        for k, _ in opts)
    if not has_content:
        lead("tanpa-match", SEV_INFO,
             "tidak ada keyword konten/deteksi — rule header-only; sah utk "
             "rule decode/metadata, rawan noise utk rule lokal")

    proto = hdr["proto"].lower()
    for k, _ in opts:
        kl = k.lower()
        for buf, ok in BUFFER_PROTO.items():
            if kl.startswith(buf) and proto not in ok:
                lead("buffer-proto-mismatch", SEV_MED,
                     f"buffer {buf}* dipakai pada proto {proto!r} "
                     f"(sah: {sorted(ok)})")

    prio = kv.get("priority")
    if prio:
        try:
            p = int(prio[0].strip())
            if not 1 <= p <= 4:
                lead("priority-janggal", SEV_MED,
                     f"priority {p} di luar 1-4")
        except ValueError:
            lead("priority-janggal", SEV_MED,
                 f"priority bukan angka: {prio[0]!r}")

    for tk in ("threshold", "detection_filter"):
        vals = kv.get(tk)
        if not vals:
            continue
        v = vals[0].lower()
        if "count" not in v:
            lead("threshold-rusak", SEV_HIGH,
                 f"{tk} tanpa count — tidak akan compile")
        mtype = re.search(r"type\s+([a-z_]+)", v)
        if mtype and mtype.group(1) in THR_TYPES_NEEDING_SECONDS and "seconds" not in v:
            lead("threshold-rusak", SEV_MED,
                 f"{tk} type {mtype.group(1)} tanpa seconds")

    header_open = {hdr["src"], hdr["sport"], hdr["dst"], hdr["dport"]}
    if header_open == {"any"} and all(header_open):
        lead("any-any-terbuka", SEV_INFO,
             "header any any -> any any — bidang paling luas")

    # content vs nocase: nocase berlaku sampai content berikutnya; payload
    # hex (ada '|') / tanpa huruf diabaikan — case tak relevan
    pending = None
    for k, v in opts:
        kl = k.lower()
        if kl == "content":
            if pending is not None:
                lead("content-tanpa-nocase", SEV_INFO,
                     f"content {pending!r} campuran huruf besar-kecil tanpa nocase")
            raw = _quoted_payload(v)
            pending = raw if (raw and "|" not in raw
                              and any(c.isupper() for c in raw)
                              and any(c.islower() for c in raw)) else None
        elif kl == "nocase":
            pending = None
    if pending is not None:
        lead("content-tanpa-nocase", SEV_INFO,
             f"content {pending!r} campuran huruf besar-kecil tanpa nocase")
    return out


def _quoted_payload(value: str) -> str:
    """Ambil payload dalam quote pertama dari value opsi content
    (Snort 3 boleh menyambung modifier: content:"x", depth 16)."""
    v = value.strip()
    if not v.startswith('"'):
        return v
    escaped = False
    out = []
    for ch in v[1:]:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if ch == '"':
            break
        out.append(ch)
    return "".join(out)


def lint_source(text: str, label: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Lint satu file .rules -> (findings, meta file)."""
    findings: list[dict[str, Any]] = []
    sids_seen: dict[int, int] = {}
    entries = iter_rule_text(text)
    rules = 0
    unparsed = 0
    for line_no, rule_text in entries:
        if "(" not in rule_text:
            findings.append({"rule": line_no, "check": "file-unparsed",
                             "severity": SEV_HIGH,
                             "message": f"baris {line_no}: bukan rule "
                                        f"(tanpa blok opsi): {rule_text[:50]!r}"})
            unparsed += 1
            continue
        rules += 1
        try:
            hdr, opts = parse_rule(rule_text)
        except RuleUnparsed as exc:
            findings.append({"rule": line_no, "check": "rule-unparsed",
                             "severity": SEV_HIGH,
                             "message": f"parse gagal: {exc}"})
            unparsed += 1
            continue
        findings.extend(lint_rule(hdr, opts, line_no, sids_seen))
    meta = {"schema": SCHEMA, "source": label, "rules": rules,
            "unparsed_rules": unparsed}
    return findings, meta


def _iter_sources(src: Path) -> list[Path]:
    if src.is_dir():
        files = sorted(p for p in src.rglob("*")
                       if p.is_file() and p.suffix.lower() in RULE_EXTS)
        if not files:
            raise FileNotFoundError(f"tidak ada file {sorted(RULE_EXTS)} di {src}")
        return files
    if not src.is_file():
        raise FileNotFoundError(f"sumber tidak ada: {src}")
    return [src]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ids_rule_lint — linter kualitas aturan Snort/Suricata "
                    "(read-only, nol jaringan; #0351 #0352)")
    ap.add_argument("--source", required=True,
                    help="file .rules atau direktori")
    ap.add_argument("--json", dest="json_out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="info",
                    help="threshold exit 1 (default info)")
    args = ap.parse_args(argv)

    src = Path(args.source)
    try:
        files = _iter_sources(src)
    except FileNotFoundError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2

    findings: list[dict[str, Any]] = []
    metas: list[dict[str, Any]] = []
    for f in files:
        fnds, meta = lint_source(f.read_text(encoding="utf-8", errors="replace"),
                                 f.name)
        findings.extend(fnds)
        metas.append(meta)

    result = {
        "schema": SCHEMA,
        "source": str(src),
        "files": metas,
        "findings": findings,
        "summary": {
            "files": len(files),
            "rules": sum(m["rules"] for m in metas),
            "unparsed_rules": sum(m["unparsed_rules"] for m in metas),
            "high": sum(1 for x in findings if x["severity"] == "high"),
            "medium": sum(1 for x in findings if x["severity"] == "medium"),
            "info": sum(1 for x in findings if x["severity"] == "info"),
        },
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(text, encoding="utf-8")
    else:
        print(text)
    thr = SEV_ORDER[args.fail_on]
    hit = any(SEV_ORDER[f["severity"]] >= thr for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
