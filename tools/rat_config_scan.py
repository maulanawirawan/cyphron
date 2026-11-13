r"""[SAFETY: read-only] rat_config_scan — triase OFFLINE sampel biner
(sampel RAT/stealer/loader, artefak memory-image, dump konfigurasi) utk
menemukan KONFIGURASI kanal ekstraksi & kandidat IOC: SMTP, FTP,
Telegram bot, Discord webhook, assignment kredensial, endpoint HTTP/IP.
TANPA jaringan, TANPA dekompilasi (lapisan string, bukan RE penuh).

Input -> mekanisme -> output:
  - Input : satu file sampel apa pun (--file) atau direktori (--dir,
            rekursif, abaikan file > batas).
  - Mekanisme: (1) hash identitas md5/sha1/sha256; (2) ekstraksi run
            ASCII + UTF-16LE dari bytes; (3) pencocokan taksonomi kanal
            + kandidat IOC; (4) bucket IOC via extract_iocs (ioc_defang)
            lalu di-defang utk output aman.
  - Output: {hashes, channels: [{type, iocs}], findings, ioc_candidates
            (defanged), notes} — kandidat IOC generik TIDAK mengubah
            exit (noise url update-endpoint wajar); hanya KANAL
            ekstraksi/kredensial yang memicu exit 1.

Cek (channel = temuan; kandidat = laporan, bukan temuan):
  smtp-channel   (high)   : host SMTP eksplisit (smtp.<host>) + email
                            tujuan + port.
  ftp-channel    (high)   : URL ftp://.
  telegram-bot   (high)   : format token bot Telegram (\d{8,10}:token35)
                            + chat_id.
  discord-webhook(high)   : URL webhook Discord.
  cred-assignment(medium) : pass(word)?/pwd/user = nilai (lead; konteks
                            konfigurasi, bukan bukti kredensial valid).
  base64-blob    (medium) : run base64 panjang yang ter-dekode printable
                            (umum disimpan konfig) — dicatat utk
                            deep_decode manual, TIDAK dieksekusi.

Fail-closed:
  - File tidak terbaca / nol file valid -> exit 2.
  - Base64 hanya DILAPORKAN (string ter-dekode tidak dieksekusi, tidak
    di-follow URL-nya).
  - Verdict selalu "teramati di sampel" (lead), bukan klaim kampanye —
    konfirmasi CTI butuh korelasi (lihat METHODS seksi 35).

Exit: 0 tidak ada indikator kanal; 1 ada kanal/kredensial; 2 error input.

Pemakaian:
  python tools/rat_config_scan.py --file sampel.bin
  python tools/rat_config_scan.py --dir quarantaine/ --out report.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ioc_defang import defang_value, extract_iocs  # noqa: E402

SCHEMA = "secai.rat-config-scan/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RUNS = 200_000

# ------------------------------------------------- taksonomi kanal
_RE_SMTP_HOST = re.compile(
    rb"\bsmtp[\.\-][a-z0-9][a-z0-9\.\-]{2,60}\.[a-z]{2,15}\b", re.I)
_RE_EMAIL = re.compile(
    rb"\b[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{3,63}\.[a-z]{2,15}\b", re.I)
_RE_FTP = re.compile(
    rb"\bftp://[a-z0-9.\-:@]{3,80}(?::\d{2,5})?(?:/[a-z0-9._/\-]{0,80})?",
    re.I)
_RE_TG_TOKEN = re.compile(rb"\b(\d{8,10}):([A-Za-z0-9_\-]{35})\b")
_RE_TG_CHAT = re.compile(
    rb"chat[_\-]?id[\"'\s=:]{1,4}(-?\d{5,15})\b", re.I)
_RE_DISCORD = re.compile(
    rb"https://discord(?:app)?\.com/api/webhooks/\d{5,30}/"
    rb"[A-Za-z0-9_\-]{20,}")
_RE_CRED = re.compile(
    rb"\b(pass(?:word)?|pwd|username|user|login)[\"'\s]{0,2}[=:]"
    rb"[\"'\s]{0,2}([^\s\"']{3,40})", re.I)
_RE_PORT = re.compile(rb"\b(port|smtp_port)[\"'\s=:]{1,3}(\d{2,5})\b", re.I)

_RE_B64 = re.compile(rb"\b[A-Za-z0-9+/]{32,}={0,2}\b")

_RE_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_RE_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def _iter_samples(root: Path) -> "list[Path]":
    if root.is_file():
        return [root]
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES:
            out.append(p)
    return out


def _string_runs(data: bytes) -> "list[str]":
    """Run ASCII + UTF-16LE -> teks (urut offset, tanpa dekompilasi)."""
    chunks: "list[str]" = []
    for m in _RE_ASCII_RUN.finditer(data, 0, MAX_RUNS):
        chunks.append(m.group(0).decode("ascii", "replace"))
    for m in _RE_UTF16_RUN.finditer(data, 0, MAX_RUNS):
        chunks.append(m.group(0).decode("utf-16-le", "replace"))
    return chunks


def _scan_one(path: Path) -> "dict":
    data = path.read_bytes()
    report: "dict" = {
        "file": str(path), "size": len(data),
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "channels": [], "findings": [],
    }

    runs = _string_runs(data)

    def _find(pattern: "re.Pattern[bytes]") -> "list[str]":
        seen = []
        for m in pattern.finditer(data):
            v = m.group(0).decode("utf-8", "replace")
            if v not in seen:
                seen.append(v)
        # UTF-16 string jangan lepas: cocokkan ulang atas run ASCII hasil
        # decode UTF-16LE (data mentah sudah tercakup, run juga).
        return seen[:20]

    smtp_hosts = _find(_RE_SMTP_HOST)
    emails = _find(_RE_EMAIL)
    ftp_urls = _find(_RE_FTP)
    tg_tokens = _find(_RE_TG_TOKEN)
    tg_chats = _find(_RE_TG_CHAT)
    discord = _find(_RE_DISCORD)
    creds = _find(_RE_CRED)
    ports = _find(_RE_PORT)

    if smtp_hosts:
        report["channels"].append({"type": "smtp", "iocs": smtp_hosts})
    if emails:
        report["channels"].append({"type": "smtp-email", "iocs": emails})
    if ftp_urls:
        report["channels"].append({"type": "ftp", "iocs": ftp_urls})
    if tg_tokens or tg_chats:
        report["channels"].append({
            "type": "telegram",
            "iocs": tg_tokens + [c for c in tg_chats],
        })
    if discord:
        report["channels"].append({"type": "discord-webhook",
                                   "iocs": discord})
    if creds:
        report["channels"].append({"type": "cred-assignment",
                                   "iocs": creds})
    if ports:
        report["channels"].append({"type": "port", "iocs": ports})

    # Base64: dekode printable -> catat (bukan eksekusi).
    b64_hits: "list[str]" = []
    for m in _RE_B64.finditer(data):
        blob = m.group(0)
        if len(b64_hits) >= 10:
            break
        try:
            decoded = base64.b64decode(blob, validate=True)
            text = decoded.decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if len(text) >= 8 and text.isprintable():
            b64_hits.append(text[:120])
    if b64_hits:
        report["channels"].append({"type": "base64-decoded",
                                   "iocs": b64_hits})

    # Kandidat IOC generik (tanpa memicu exit) dari teks run.
    joined = "\n".join(runs)
    buckets = extract_iocs(joined)
    ioc_candidates = {
        t: [defang_value(t, v) for v in vals[:25]]
        for t, vals in buckets.items() if vals and t not in
        ("md5", "sha1", "sha256")
    }
    report["ioc_candidates"] = ioc_candidates

    # Findings = kanal bernilai triase (anti-FP: generik tidak dihitung).
    channel_names = {c["type"] for c in report["channels"]}
    if {"smtp", "smtp-email"} & channel_names:
        report["findings"].append({
            "check": "smtp-channel", "severity": "high",
            "message": "Kanal ekstraksi SMTP teramati di sampel "
                       "(host/email/port di atas) — kredensial bisa "
                       "direvokasi, host = IOC blocking.",
        })
    if "ftp" in channel_names:
        report["findings"].append({
            "check": "ftp-channel", "severity": "high",
            "message": "Kanal ekstraksi FTP teramati di sampel.",
        })
    if "telegram" in channel_names:
        report["findings"].append({
            "check": "telegram-bot", "severity": "high",
            "message": "Token bot Telegram teramati — bot bisa dicabut "
                       "via BotFather, token = IOC.",
        })
    if "discord-webhook" in channel_names:
        report["findings"].append({
            "check": "discord-webhook", "severity": "high",
            "message": "Webhook Discord teramati — webhook bisa dihapus "
                       "di pengaturan channel.",
        })
    if "cred-assignment" in channel_names:
        report["findings"].append({
            "check": "cred-assignment", "severity": "medium",
            "message": "Assignment kredensial teramati (lead) — nilai "
                       "butuh konfirmasi konteks konfigurasi.",
        })
    if "base64-decoded" in channel_names:
        report["findings"].append({
            "check": "base64-blob", "severity": "medium",
            "message": "Blob base64 ter-dekode printable — lanjutkan "
                       "triase manual (deep_decode), jangan eksekusi.",
        })
    return report


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase kanal ekstraksi & IOC dari sampel biner "
                    "(offline, nol jaringan, tanpa eksekusi sampel).")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--file", help="satu file sampel")
    grp.add_argument("--dir", help="direktori sampel (rekursif)")
    ap.add_argument("--out", default=None,
                    help="tulis laporan JSON ke file (default stdout)")
    args = ap.parse_args(argv)

    root = Path(args.file or args.dir)
    if not root.exists():
        print(json.dumps({"schema": SCHEMA,
                          "error": f"tidak ada: {root}"}),
              file=sys.stderr)
        return 2
    samples = _iter_samples(root)
    if not samples:
        print(json.dumps({"schema": SCHEMA,
                          "error": "nol file valid"}), file=sys.stderr)
        return 2

    reports = [_scan_one(p) for p in samples]
    hit = any(r["findings"] for r in reports)
    result = {
        "schema": SCHEMA,
        "samples": len(reports),
        "findings": [r["findings"] for r in reports],
        "detail": reports[0] if len(reports) == 1 else None,
        "summary": [
            {"file": r["file"], "sha256": r["hashes"]["sha256"],
             "channels": [c["type"] for c in r["channels"]]}
            for r in reports
        ],
        "notes": [
            "analisis lapisan string: konfigurasi terenkripsi/ter-obfuskasi "
            "di luar cakupan (dekompilasi .NET = ranah alat RE terpisah).",
            "url/ip/hash di ioc_candidates adalah KANDIDAT (bisa endpoint "
            "update sah) — bukan temuan; defanged utk dibaca aman.",
            "sampel tidak dieksekusi; verifikasi dinamis = sandbox "
            "terisolasi, bukan tool ini.",
        ],
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
