r"""[SAFETY: read-only] paste_triage — triase OFFLINE isi paste/dump yang
TERSIMPAN (salinan laporan kebocoran, dump kredensial, isi paste site):
pola kredensial + kata kunci organisasi -> skor prioritas. Nilai
rahasia TIDAK PERNAH tampil penuh di output. TANPA jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0868 (mukul975/
Anthropic-Cybersecurity-Skills 'performing-paste-site-monitoring-for-
credentials'; atribusi konsep, lisensi sumber Apache-2.0). Skill sumber
= monitor LIVE (scraping API Pastebin, GitHub search, loop jaringan) —
sisi jaringan TIDAK diport; inti deterministik yang diekstrak di sini =
ANALISIS ISI paste yang sudah tersimpan: deteksi pola kredensial +
korelasi kata kunci organisasi + klasifikasi severity, from scratch
(pola ditulis ulang dgn disiplin anti-FP, bukan salinan regex skill).

Pembagian ranah (TIDAK diduplikasi):
  - klaim kebocoran (verifikasi sampel/fingerprint/korroboration)
    -> leak_triage
  - secret di repo git -> secret_history_scan / repo-secret-scan
  - secret di binary -> binary_strings_surface
  - defang/refang IOC dari teks bebas -> ioc_defang
  - di sini: isi paste/dump tersimpan -> prioritas respons.

Input -> mekanisme -> output:
  - Input : --paste FILE teks (boleh diulang) + --keyword TERM
            (boleh diulang, case-insensitive: domain, nama proyek,
            nama internal). Baca-saja.
  - Mekanisme: pola kredensial (kunci AWS AKIA + secret HANYA dgn
            konteks assignment, token GitHub ghp_/gho_/github_pat_,
            Slack xox[baprs]-, JWT eyJ.eyJ., header private key,
            email:password dgn pemisah tanda baca, koneksi DB
            user:pass@, api_key/token generic dgn konteks assignment)
            -> temuan per tipe dgn SAMPEL DIREDAKSI (6 char awal +
            panjang); kata kunci organisasi dicari terpisah; severity
            per paste = critical bila kredensial+kata-kunci, high bila
            kata-kunci saja atau kredensial > 10, medium bila
            kredensial 1-10.
  - Output: JSON {schema, stats, findings, notes}; finding =
            {check, severity, paste, message} (+keyword/type/count).

Cek:
  credential-leak        (medium/high/critical): pola kredensial
                         ditemukan — severity mengikuti kombinasi di
                         atas.
  org-keyword-hit        (info): kata kunci organisasi muncul (tanpa
                         kredensial) — layak dicatat utk baseline.
  binary-content-skipped (medium): file berisi NUL bytes — tidak
                         dianalisis penuh, TIDAK dianggap bersih.

Fail-closed:
  - file tidak ada / tak terbaca -> exit 2.
  - nol paste terbaca -> exit 2.
  - isi biner -> binary-content-skipped (dicatat, tak dibuang diam).
  - REDAKSI wajib: sampel maksimal 6 char awal + panjang; nilai penuh
    tidak pernah keluar di findings maupun notes.

Anti-FP: secret AWS 40-char HANYA dgn konteks assignment (bukan 40-char
acak); email:password butuh pemisah ':' ';' '|' ',' (spasi saja tidak);
api_key generic butuh konteks assignment.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/paste_triage.py --paste dump1.txt --paste dump2.txt \
      --keyword corp.example.id --keyword projinternal --out triage.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.paste-triage/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

PATTERNS: "list[tuple[str, re.Pattern[str]]]" = [
    ("aws-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret", re.compile(
        r"(?:aws)?_?secret_?(?:access)?_?key\s*[=:]\s*[\"']?"
        r"([0-9a-zA-Z/+=]{40})\b", re.IGNORECASE)),
    ("github-token", re.compile(r"\b(?:ghp|gho)_[0-9a-zA-Z]{36}\b|"
                                r"\bgithub_pat_[0-9a-zA-Z_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b")),
    ("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("jwt-token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("email-password", re.compile(
        r"[\w.+-]+@[\w-]+\.[\w.-]+\s*[:;|,]\s*(\S{6,})")),
    ("db-connection", re.compile(
        r"\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://"
        r"([^:/\s]+):([^@\s]+)@", re.IGNORECASE)),
    ("api-key-assignment", re.compile(
        r"\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?token)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9_-]{20,})", re.IGNORECASE)),
]


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:6] + "..." + f"(len={len(value)})"


def analyze_paste(text: str, keywords: "list[str]") -> \
        "tuple[list[dict], dict]":
    findings: "list[dict]" = []
    stats: "dict[str, int]" = {name: 0 for name, _ in PATTERNS}
    stats["keyword_hits"] = 0
    total_creds = 0

    for name, rx in PATTERNS:
        matches = rx.findall(text)
        if not matches:
            continue
        stats[name] = len(matches)
        total_creds += len(matches)
        # ambil nilai utk redaksi: group(1) bila ada, selain itu match
        sample = matches[0]
        if isinstance(sample, tuple):
            sample = next((g for g in sample if g), "")
        findings.append({
            "check": "credential-leak", "severity": "medium",
            "type": name,
            "message": f"{len(matches)} kredensial tipe '{name}' — "
                       f"contoh DIREDAKSI: {_redact(str(sample))}; "
                       "verifikasi keaslian sebelum rotasi massal.",
        })

    hits: "list[str]" = []
    for kw in keywords:
        n = text.lower().count(kw.lower())
        if n:
            hits.append(f"{kw} (x{n})")
    if hits:
        stats["keyword_hits"] = len(hits)
        findings.append({
            "check": "org-keyword-hit", "severity": "info",
            "message": "kata kunci organisasi ditemukan: " +
                       ", ".join(hits[:8]),
        })

    # severity kombinasi (konsep skill sumber, deterministik)
    sev = None
    if total_creds and hits:
        sev = "critical"
    elif hits:
        sev = "high"
    elif total_creds > 10:
        sev = "high"
    elif total_creds:
        sev = "medium"
    if sev is not None:
        for f in findings:
            if f["check"] == "credential-leak":
                f["severity"] = sev
        findings.append({
            "check": "paste-verdict", "severity": sev,
            "message": f"prioritas paste: {sev.upper()} "
                       f"({total_creds} kredensial, {len(hits)} kata "
                       "kunci organisasi) — urutan aksi: verifikasi "
                       "validitas, rotasi kredensial terdampak, cek log "
                       "pemakaian, takedown.",
        })
    return findings, stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase isi paste/dump tersimpan offline, nol "
                    "jaringan; nilai rahasia selalu diredaksi.")
    ap.add_argument("--paste", action="append", required=True,
                    metavar="FILE", help="file teks isi paste/dump "
                                         "(boleh diulang)")
    ap.add_argument("--keyword", action="append", default=[],
                    metavar="TERM",
                    help="kata kunci organisasi (boleh diulang)")
    ap.add_argument("--fail-on", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    findings: "list[dict]" = []
    stats: "dict[str, object]" = {"pastes": 0, "binary_skipped": 0,
                                  "total_credentials": 0,
                                  "paste_with_keywords": 0}
    for f in args.paste:
        p = Path(f)
        try:
            if not p.is_file():
                raise ValueError(f"file tidak ada: {p}")
            if p.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"file terlalu besar: {p}")
            raw = p.read_bytes()
        except ValueError as exc:
            print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
                  file=sys.stderr)
            return 2
        stats["pastes"] = int(stats["pastes"]) + 1
        if b"\x00" in raw[:4096]:
            stats["binary_skipped"] = int(stats["binary_skipped"]) + 1
            findings.append({
                "check": "binary-content-skipped", "severity": "medium",
                "paste": p.name,
                "message": "isi mengandung NUL bytes (biner) — tidak "
                           "dianalisis penuh; TIDAK dianggap bersih.",
            })
            continue
        text = raw.decode("utf-8", errors="replace")
        pf, ps = analyze_paste(text, args.keyword)
        for x in pf:
            x["paste"] = p.name
        findings.extend(pf)
        for k, v in ps.items():
            if k == "keyword_hits":
                if v:
                    stats["paste_with_keywords"] = \
                        int(stats["paste_with_keywords"]) + 1
            else:
                stats[k] = int(stats.get(k, 0)) + v
        stats["total_credentials"] = int(stats["total_credentials"]) + \
            sum(v for k, v in ps.items()
                if k not in ("keyword_hits",))

    if not stats["pastes"]:
        print(json.dumps({"schema": SCHEMA, "error": "nol paste"}),
              file=sys.stderr)
        return 2

    threshold = SEV_ORDER[args.fail_on]
    hit = [x for x in findings
           if SEV_ORDER.get(x["severity"], 0) >= threshold]

    notes = [
        "monitor LIVE (scraping Pastebin/GitHub) tidak diport — sisi "
        "jaringan; simpan isi paste dulu, triase di sini.",
        "verifikasi klaim kebocoran (sampel/fingerprint/korroboration) "
        "= leak_triage; ini prioritas ISI yang sudah tersimpan.",
        "REDAKSI wajib: sampel maksimal 6 char awal + panjang — nilai "
        "penuh tidak pernah keluar di output; jangan tempel output ini "
        "ke kanal publik apa adanya.",
        "rotasi kredensial terdampak > menghapus paste — nilai sudah "
        "tersebar (cache/fork/mirror).",
    ]
    if stats.get("binary_skipped"):
        notes.append(f"{stats['binary_skipped']} file biner dilewati "
                     "analisis teks — tercatat eksplisit.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "findings": sorted(
            findings,
            key=lambda x: (-SEV_ORDER.get(x["severity"], 0),
                           x["check"], x.get("paste", ""))),
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
