r"""[SAFETY: read-only] data_class_scan — klasifikasi OFFLINE data sensitif
(PII/finansial/kredensial) di file teks lokal ala custom data identifier.
TANPA jaringan, tanpa S3, tanpa ML.

Port konsep dari antrean SKILL-PORT-QUEUE #0585 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-aws-macie-for-data-
classification'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun
FROM SCRATCH: detektor + Luhn + ladder severity ditulis sendiri dari
konsep Macie publik (custom data identifier: regex + keywords +
maximum-match-distance + severity-levels per occurrencesThreshold;
allow list utk FP). Skill sumber menjalankan Macie di S3 via boto3;
cyphron memindai FILE LOKAL (log/CSV/JSON/HTML lab) — kategori sama
(PII, finansial, kredensial), sumber berbeda. Ranah TIDAK diduplikasi:
secret_history_scan/zeroize_scan/js_secret_scanner_v2 mengejar KREDENSIAL
di tempat spesifik (git history, memori C/C++, evidence JS) — tool ini
klasifikasi ISI file umum, termasuk PII yang bukan kredensial (SSN,
kartu kredit, email).

Input -> mekanisme -> output:
  - Input : file/direktori teks (utf-8; file biner dilewati dgn note);
            --custom utk identifier milik organisasi (konsep Macie:
            name=REGEX[|keyword1|keyword2]); --allow-regex utk allow
            list (konsep Macie allow list).
  - Mekanisme: detektor bawaan per file -> keyword proximity (utk SSN/
            custom dgn keywords, jarak <= --max-distance) -> Luhn utk
            kartu -> ladder severity per threshold kejadian.
  - Output: temuan {check, severity, file, occurrences, sample_masked}
            + summary + notes.

Detektor bawaan (nilai minimum severity; naik dgn ladder kejadian
1/10/50 -> info/medium/high, konsep severity-levels sumber):
  pii-aws-access-key (high)  : AKIA[0-9A-Z]{16} / ASIA[0-9A-Z]{16} —
                               kunci akses AWS adalah data kredensial.
  fin-credit-card    (medium): 13-19 digit (dgn pemisah) yang lulus Luhn;
                               kartu tak-valid TIDAK dilaporkan (anti-FP).
  pii-ssn-us         (medium): \d{3}-\d{2}-\d{4} HANYA bila keyword
                               (ssn/social security) di dalam jarak —
                               format identik telepon AS, tanpa konteks
                               = format-only (dihitung, tak diemisi).
  pii-email          (info)  : alamat email (kategori PII Macie).
  custom             (info)  : identifier organisasi (--custom).

Sifat penting:
  - SAMPEL DIMASKING (4 awal + ... + 4 akhir) — nilai PII penuh tidak
    pernah diecho ke laporan (anti-bocor di artefak triase).
  - allow list diterapkan SEBELUM hitung; jumlah yang tersupresi dicatat
    di summary.suppressed (bukan diam-diam).
  - file biner (byte NUL) dilewati + note; file kosong dihitung.

Fail-closed: tanpa input -> exit 2; --custom tanpa '=' atau regex tak
valid -> exit 2; direktori yang di-scan tanpa file teks -> exit 2 (bukan
klaim bersih).

Exit: 0 bersih; 1 ada temuan >= --fail-on (default info); 2 input tidak
valid.

Pemakaian:
  python tools/data_class_scan.py --file dump.csv --file log.txt
  python tools/data_class_scan.py --dir exports/ --fail-on medium
  python tools/data_class_scan.py --dir exports/ \
      --custom "emp-id=EMP-[0-9]{6}|employee|staff" \
      --allow-regex "@example\\.com" --json hasil.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
# konsep severity-levels Macie sumber: occurrencesThreshold -> severity
LADDER = ((50, "high"), (10, "medium"), (1, "info"))
MAX_FILE_BYTES = 50_000_000
SSN_KEYWORDS = ("ssn", "social security", "social-security")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
BUILTIN_MIN_SEV = {"pii-aws-access-key": "high", "fin-credit-card": "medium",
                   "pii-ssn-us": "medium", "pii-email": "info"}


def _sev_min(a: str, b: str) -> str:
    """Severity lebih tinggi antara dua label (urutan info<medium<high)."""
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b


def _mask(value: str) -> str:
    """Masking bukti: 4 awal + ... + 4 akhir (nilai penuh tak diecho)."""
    clean = value.strip()
    if len(clean) <= 8:
        return "*" * len(clean)
    return f"{clean[:4]}...{clean[-4:]}"


def luhn_valid(digits: str) -> bool:
    """Cek Luhn standar (ISO/IEC 7812-1) — ditulis sendiri, tanpa pustaka."""
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _keyword_near(text: str, start: int, end: int, keywords: "list[str]",
                  max_distance: int) -> bool:
    """Apakah keyword ada di jarak <= max_distance dari match (konsep
    maximumMatchDistance Macie)."""
    window = text[max(0, start - max_distance):
                  min(len(text), end + max_distance)].lower()
    return any(k.lower() in window for k in keywords)


def parse_custom(spec: str) -> dict:
    """--custom 'name=REGEX|kw1|kw2' -> {name, regex, keywords} (konsep
    custom data identifier Macie: regex + keywords)."""
    if "=" not in spec:
        raise ValueError(f"--custom tidak valid: {spec!r} (butuh "
                         "name=REGEX[|keyword|...])")
    name, rest = spec.split("=", 1)
    parts = rest.split("|")
    pattern = parts[0]
    keywords = [k for k in parts[1:] if k]
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"--custom {name!r}: regex tidak valid: {exc}") \
            from None
    name = name.strip()
    if not name or not re.match(r"^[a-zA-Z0-9_.-]+$", name):
        raise ValueError(f"--custom nama tidak sah: {name!r}")
    return {"name": f"custom-{name}", "re": compiled, "keywords": keywords}


def scan_text(text: str, customs: "list[dict]", allow_re: "re.Pattern | None",
              max_distance: int) -> "tuple[dict, dict]":
    """Satu teks -> (hitungan per check + sampel masked, stat saringan).
    Emisi severity final dilakukan caller (ladder per file)."""
    hits: dict[str, list[str]] = {}
    suppressed = 0
    ssn_format_only = 0

    def record(check: str, value: str) -> None:
        nonlocal suppressed
        if allow_re and allow_re.search(value):
            suppressed += 1
            return
        hits.setdefault(check, []).append(value)

    for m in AWS_KEY_RE.finditer(text):
        record("pii-aws-access-key", m.group(0))

    for m in CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if luhn_valid(digits):
            record("fin-credit-card", m.group(0))

    for m in SSN_RE.finditer(text):
        if _keyword_near(text, m.start(), m.end(), SSN_KEYWORDS,
                         max_distance):
            record("pii-ssn-us", m.group(0))
        else:
            ssn_format_only += 1

    for m in EMAIL_RE.finditer(text):
        record("pii-email", m.group(0))

    for cust in customs:
        for m in cust["re"].finditer(text):
            if cust["keywords"] and not _keyword_near(
                    text, m.start(), m.end(), cust["keywords"],
                    max_distance):
                continue  # konsep Macie: keyword wajib dalam jarak
            record(cust["name"], m.group(0))

    return hits, {"suppressed": suppressed, "ssn_format_only": ssn_format_only}


def _ladder_severity(count: int, min_sev: str) -> str:
    sev = min_sev
    for threshold, label in LADDER:
        if count >= threshold and SEV_ORDER[label] > SEV_ORDER[sev]:
            sev = label
    return sev


def scan_files(paths: "list[Path]", customs: "list[dict]",
               allow_re: "re.Pattern | None", max_distance: int,
               findings: list[dict], notes: list[str]) -> dict:
    summary: dict = {"files": 0, "empty_files": 0, "binary_skipped": 0,
                     "suppressed": 0, "ssn_format_only": 0,
                     "custom_identifiers": [c["name"] for c in customs],
                     "occurrences": {}}
    saw_text = False
    for path in paths:
        if path.is_dir():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"{path}: dilewati (ukuran > "
                             f"{MAX_FILE_BYTES} B)")
                continue
            raw = path.read_bytes()
        except OSError as exc:
            notes.append(f"{path}: gagal dibaca ({exc})")
            continue
        if b"\x00" in raw:
            summary["binary_skipped"] += 1
            notes.append(f"{path}: file biner dilewati (byte NUL)")
            continue
        text = raw.decode("utf-8", errors="replace")
        saw_text = True
        if not text.strip():
            summary["empty_files"] += 1
            continue
        summary["files"] += 1
        hits, stats = scan_text(text, customs, allow_re, max_distance)
        summary["suppressed"] += stats["suppressed"]
        summary["ssn_format_only"] += stats["ssn_format_only"]
        for check, values in hits.items():
            summary["occurrences"][check] = \
                summary["occurrences"].get(check, 0) + len(values)
            min_sev = BUILTIN_MIN_SEV.get(check, "info")
            findings.append({
                "check": check,
                "severity": _ladder_severity(len(values), min_sev),
                "file": str(path),
                "occurrences": len(values),
                "sample_masked": _mask(values[0]),
            })
    if not saw_text:
        raise ValueError("tidak ada file teks yang dapat dipindai — "
                         "tidak bisa disimpulkan bersih")
    return summary


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="data_class_scan — klasifikasi OFFLINE data sensitif "
                    "(PII/finansial/kredensial) di file teks lokal; "
                    "fail-closed; sampel selalu dimasking.")
    ap.add_argument("--file", action="append", default=[],
                    help="file teks yang dipindai (boleh berulang)")
    ap.add_argument("--dir", default=None,
                    help="direktori yang dipindai (non-rekursif; file di "
                         "root-nya)")
    ap.add_argument("--custom", action="append", default=[],
                    help="identifier organisasi konsep Macie: "
                         "name=REGEX[|keyword1|keyword2] (boleh berulang)")
    ap.add_argument("--allow-regex", action="append", default=[],
                    help="allow list: nilai yang cocok diabaikan (konsep "
                         "Macie allow list; boleh berulang)")
    ap.add_argument("--max-distance", type=int, default=50,
                    help="jarak maksimum keyword dari match (default 50, "
                         "konsep maximumMatchDistance)")
    ap.add_argument("--json", default=None,
                    help="tulis laporan JSON ke path ini (selain stdout)")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="info",
                    help="severity minimum yang memicu exit 1 (default "
                         "info)")
    args = ap.parse_args(argv)

    if not args.file and not args.dir:
        print("error: minimal satu input (--file / --dir)", file=sys.stderr)
        return 2
    customs: list[dict] = []
    for spec in args.custom:
        try:
            customs.append(parse_custom(spec))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    allow_res: "list[re.Pattern]" = []
    for pattern in args.allow_regex:
        try:
            allow_res.append(re.compile(pattern))
        except re.error as exc:
            print(f"error: --allow-regex tidak valid: {exc}", file=sys.stderr)
            return 2
    allow_re = re.compile("|".join(a.pattern for a in allow_res)) \
        if allow_res else None

    paths: list[Path] = [Path(p) for p in args.file]
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"error: bukan direktori: {d}", file=sys.stderr)
            return 2
        paths.extend(sorted(d.iterdir()))
    for p in paths:
        if not p.exists():
            print(f"error: path tidak ada: {p}", file=sys.stderr)
            return 2

    findings: list[dict] = []
    notes: list[str] = []
    try:
        summary = scan_files(paths, customs, allow_re, args.max_distance,
                             findings, notes)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = {
        "kind": "data-classification-scan",
        "attribution": "konsep #0585 mukul975/implementing-aws-macie-for-"
                       "data-classification (Apache-2.0) — dibangun from "
                       "scratch; kategori PII/finansial/kredensial, tanpa ML",
        "findings": findings,
        "summary": summary,
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    threshold = SEV_ORDER[args.fail_on]
    counted = [f for f in findings
               if SEV_ORDER[f["severity"]] >= threshold]
    if counted:
        print(f"-- {len(counted)} temuan >= {args.fail_on} "
              f"(high={sum(1 for f in findings if f['severity'] == 'high')} "
              f"medium={sum(1 for f in findings if f['severity'] == 'medium')} "
              f"info={sum(1 for f in findings if f['severity'] == 'info')})",
              file=sys.stderr)
    else:
        print(f"-- bersih: tidak ada temuan >= {args.fail_on}",
              file=sys.stderr)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
