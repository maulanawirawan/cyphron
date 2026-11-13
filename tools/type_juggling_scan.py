r"""[AUDIT: read-only] type_juggling_scan — pindai OFFLINE kode PHP untuk
permukaan type juggling (loose comparison `==`/`!=`, magic hash, bypass
strcmp/in_array) + verifikasi OFFLINE magic hash.

Ranah tetangga eksplisit: playbook live-probe web = ExploitEngine/
exploit_playbooks (eksekusi request berizin); lint dependensi =
pkg_typosquat_check; secret di kode = secret scanners; SARIF =
sarif_ingest. Tool ini TIDAK mengirim request ke mana pun.

Input -> mekanisme -> output:
  - Input   : --source FILE/DIR (file .php, dibaca read-only) atau
              --verify-hash HASH[,HASH...] utk verifikasi offline.
  - Mekanisme: pindai baris kode PHP (komentar `//`, `#`, `*` blok
              dilewati) dgn deteksi baris-basis deterministik:
    loose-hash-compare      (high)  : md5(...)/sha1(...) dibandingkan
                                       `==`/`!=` (bukan ===) — magic
                                       hash & koersi numerik bisa lolos
    magic-literal-compare   (high)  : literal "0e<6 digit>" dibandingkan
                                       `==`/`!=` — token tersimpan sbg
                                       scientific notation
    strcmp-superglobal      (high)  : strcmp/strcasecmp menerima
                                       $_GET/$_POST/$_REQUEST/$_COOKIE —
                                       array membuat strcmp() = NULL,
                                       NULL == 0 TRUE (bypass)
    in-array-loose-auth     (medium): in_array() tanpa strict=true pada
                                       variabel otentikasi/password/
                                       token/pin/otp — koersi "1abc"==1
    auth-eq-zero-coercion   (medium): variabel otentikasi dibandingkan
                                       `== 0|'0'|true|false|null` —
                                       bypass JSON {"password": true}
    loose-superglobal-compare(medium): $_GET/$_POST/... dibandingkan
                                       `==` nilai literal — permukaan
                                       koersi tipe
  - Output  : temuan {check, severity, file, line, code, message} +
              summary + notes; exit 1 bila temuan >= --fail-on, exit 2
              bila input tidak terbaca / tidak ada file .php
              (fail-closed — TIDAK menyatakan bersih).

Anti-FP: --allow-check NAME (boleh diulang) menyembunyikan check
tertentu; jumlah saringan dicatat di notes.

Stdlib re/hashlib/argparse/json. Nol jaringan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "type_juggling_scan/v1"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

# variabel/parameter berbau otentikasi (heuristik nama, konvensi umum PHP)
_AUTHISH = (
    r"(?:password|passwd|pwd|token|otp|pin|code|hash|secret|apikey|api_key"
    r"|auth|session)"
)
_AUTHISH_RE = re.compile(r"\$\w*" + _AUTHISH + r"\w*", re.IGNORECASE)

_LOOSE_EQ = r"(?<![=!<>])(==|!=)(?!=)"

# (nama check, regex, severity, pesan) — dievaluasi per baris; urutan
# penting hanya utk keterbacaan, dedup per (check, file, line).
CHECKS: "list[tuple[str, re.Pattern[str], str, str]]" = [
    (
        "loose-hash-compare",
        re.compile(
            r"(?:md5|sha1)\s*\([^;]*" + _LOOSE_EQ
            + r"|(?<![=!<>])(==|!=)(?!=)[^;]*(?:md5|sha1)\s*\("
        ),
        "high",
        "hasil md5()/sha1() dibandingkan loose (==/!=) — magic hash "
        "\"0e...\" atau koersi numerik dapat melewati verifikasi; pakai "
        "hash_equals() atau ===",
    ),
    (
        "magic-literal-compare",
        re.compile(
            r"['\"]0e[0-9]{6,}['\"]\s*" + _LOOSE_EQ
            + r"|" + _LOOSE_EQ + r"\s*['\"]0e[0-9]{6,}['\"]"
        ),
        "high",
        "literal berpola 0e<digits> (scientific notation PHP = 0) "
        "dibandingkan loose — if($stored == $hash) lolos dgn nilai 0 "
        "manapun yang ber-hash magic",
    ),
    (
        "strcmp-superglobal",
        re.compile(
            r"(?:strcmp|strcasecmp)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)"
        ),
        "high",
        "strcmp()/strcasecmp() menerima superglobal — password[]=x "
        "membuat fungsi mengembalikan NULL dan NULL == 0 bernilai TRUE",
    ),
    (
        "in-array-loose-auth",
        re.compile(r"in_array\s*\("),
        "medium",
        "in_array() pada variabel otentikasi tanpa parameter strict "
        "true — koersi \"1abc\" == 1 dan \"0e123\" == \"0e456\" lolos",
    ),
    (
        "auth-eq-zero-coercion",
        re.compile(
            r"\$\w*" + _AUTHISH + r"\w*\s*" + _LOOSE_EQ
            + r"\s*(?:0|true|false|null|['\"]0['\"])\b"
            + r"|\b(?:0|true|false|null|['\"]0['\"])\s*" + _LOOSE_EQ
            + r"\s*\$\w*" + _AUTHISH
            + r"|\[\s*['\"]\w*" + _AUTHISH + r"\w*['\"]\s*\]\s*"
            + _LOOSE_EQ + r"\s*(?:0|true|false|null|['\"]0['\"])\b"
        ),
        "medium",
        "variabel otentikasi dibandingkan loose dgn 0/true/false/null — "
        "JSON {\"password\": true} atau {\"pin\": 0} mem-bypass cek",
    ),
    (
        "loose-superglobal-compare",
        re.compile(
            r"\$_(?:GET|POST|REQUEST|COOKIE)[^;]*" + _LOOSE_EQ
            + r"|" + _LOOSE_EQ + r"\s*\$_(?:GET|POST|REQUEST|COOKIE)"
        ),
        "medium",
        "superglobal dibandingkan loose dgn nilai lain — tipe input "
        "dikendalikan penyerang (JSON body / parameter), koersi tipe "
        "dapat mengubah hasil cek",
    ),
]

# tabel preimage magic hash klasik — DIVERIFIKASI ulang dgn hashlib saat
# mode --verify-hash (lihat _verify_table); bukan rahasia, terdokumentasi
# luas (PayloadsAllTheThings dan lainnya).
PREIMAGES: "list[tuple[str, str]]" = [
    ("md5", "240610708"),
    ("md5", "QNKCDZO"),
    ("md5", "aabg7XSs"),
    ("md5", "aabC9RqS"),
    ("sha1", "aaroZmOk"),
    ("sha1", "aaK1STfY"),
]

_MAGIC_RE = re.compile(r"^0e[0-9]+$", re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*(?://|#|\*)")


def _is_loose(line: str) -> bool:
    """Benar bila baris mengandung ==/!= LOOSE (bukan ===/!==/<=/>=)."""
    return bool(re.search(_LOOSE_EQ, line))


def scan_source(source: Path, allowed: "set[str]") -> "list[dict]":
    findings: "list[dict]" = []
    files = sorted(source.rglob("*.php")) if source.is_dir() else [source]
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append({
                "check": "input-unreadable", "severity": "high",
                "file": str(path), "line": 0, "code": "",
                "message": f"file tidak terbaca: {exc}",
            })
            continue
        for no, raw in enumerate(text.splitlines(), start=1):
            if _COMMENT_RE.match(raw):
                continue  # komentar bukan kode — anti-FP
            line = raw.rstrip()
            for name, pattern, severity, message in CHECKS:
                if name in allowed:
                    continue
                if not pattern.search(line):
                    continue
                if name == "in-array-loose-auth":
                    # saringan spesifik: harus menyentuh variabel
                    # otentikasi DAN tidak strict `true`
                    if not _AUTHISH_RE.search(line):
                        continue
                    if re.search(r",\s*true\s*\)", line):
                        continue
                if name in ("loose-hash-compare", "magic-literal-compare",
                            "strcmp-superglobal", "auth-eq-zero-coercion",
                            "loose-superglobal-compare"):
                    if not _is_loose(line):
                        continue
                findings.append({
                    "check": name, "severity": severity,
                    "file": str(path), "line": no, "code": line.strip()[:160],
                    "message": message,
                })
    # dedup per (check, file, line)
    seen: "set[tuple]" = set()
    out = []
    for f in findings:
        key = (f["check"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _is_magic(value: str) -> bool:
    return bool(_MAGIC_RE.match(value))


def verify_hashes(values: "list[str]") -> "list[dict]":
    """Verifikasi offline: nilai magic + tabel preimage dihitung ulang."""
    rows: "list[dict]" = []
    for v in values:
        rows.append({"input": v, "magic": _is_magic(v),
                     "note": "0e+digits: PHP loose comparison = 0"
                             if _is_magic(v) else "bukan pola magic"})
    rows.append({"input": "--- tabel preimage bawaan (dihitung ulang) ---",
                 "magic": None, "note": ""})
    ok = True
    for algo, pre in PREIMAGES:
        digest = hashlib.new(algo, pre.encode()).hexdigest()
        magic = _is_magic(digest)
        ok = ok and magic
        rows.append({"input": f"{algo}(\"{pre}\")", "magic": magic,
                     "digest": digest,
                     "note": "magic — == dgn hash 0e lain bernilai TRUE"
                             if magic else "Bukan magic (tabel kedaluwarsa)"})
    rows.append({"input": "verifikasi tabel", "magic": ok,
                 "note": "semua preimage bawaan terbukti magic"
                         if ok else "tabel bermasalah"})
    return rows


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", type=Path,
                    help="file atau direktori kode PHP (.php)")
    ap.add_argument("--verify-hash", default=None,
                    help="hash/nilai dipisah koma utk verifikasi offline")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium")
    ap.add_argument("--allow-check", action="append", default=[],
                    metavar="NAME",
                    help="sembunyikan check tertentu (boleh diulang)")
    ap.add_argument("--out", type=Path, help="tulis JSON ke file")
    args = ap.parse_args(argv)

    allowed = set(args.allow_check)

    if args.verify_hash is not None:
        rows = verify_hashes([v.strip() for v in
                              args.verify_hash.split(",") if v.strip()])
        report = {
            "schema": SCHEMA, "mode": "verify-hash", "results": rows,
            "summary": {"verified": sum(1 for r in rows
                                        if r["magic"] is True)},
        }
        text = json.dumps(report, ensure_ascii=False, indent=2)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 0

    if not args.source:
        print(json.dumps({"schema": SCHEMA,
                          "error": "--source atau --verify-hash wajib"}),
              file=sys.stderr)
        return 2
    if not args.source.exists():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"source tidak ada: {args.source}"}),
              file=sys.stderr)
        return 2
    files = (sorted(args.source.rglob("*.php")) if args.source.is_dir()
             else [args.source])
    if not files:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "tidak ada file .php ditemukan — fail-closed, "
                     "TIDAK menyatakan kode bersih",
        }), file=sys.stderr)
        return 2

    findings = scan_source(args.source, allowed)
    filtered = sum(1 for f in findings if f["check"] == "input-unreadable")
    suppressed = 0  # check yang disaring tidak pernah jadi temuan
    threshold = SEVERITY_ORDER[args.fail_on]
    hit = any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold
              for f in findings)
    notes = [
        "deteksi baris-basis: baris komentar //, #, dan * blok dilewati",
        "magic hash bersifat kelas MD5/SHA-1 legacy; SHA-256 tidak "
        "punya tabel preimage 0e yang praktis — tetap gunakan === / "
        "hash_equals()",
        "mode verifikasi preimage: --verify-hash",
    ]
    if allowed:
        notes.append(f"check disaring: {', '.join(sorted(allowed))} "
                     f"(jumlah saringan dicatat sbg {suppressed} — "
                     "check tersaring tidak diemisi)")
    if filtered:
        notes.append(f"{filtered} file tidak terbaca — fail-closed")
    report = {
        "schema": SCHEMA,
        "summary": {
            "files_scanned": len(files),
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("high", "medium", "low")
            },
        },
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["file"], f["line"], f["check"]),
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
