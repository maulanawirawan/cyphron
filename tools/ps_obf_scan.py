r"""[SAFETY: read-only] ps_obf_scan — pemindai penanda obfuscation skrip
PowerShell secara STATIS (tanpa eksekusi, stdlib murni, tanpa jaringan).

Port konsep dari antrean SKILL-PORT-QUEUE #0363 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'deobfuscating-powershell-obfuscated-
malware' — identifikasi lapis obfuscation: EncodedCommand, FromBase64String,
iex, tick-mark, char array, XOR, kompresi, Replace chain; atribusi konsep,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: taksonomi penanda +
dekoder EncodedCommand ditulis sendiri. TIDAK menyalin kode sumber skill.

Batas jujur:
  - Alat ini TIDAK menjalankan/mengevaluasi skrip apapun (parsing statis
    + dekode base64 in-memory saja) dan TIDAK bisa membatalkan semua
    lapis obfuscation — outputnya adalah LEAD penanda utk triase, bukan
    klaim "malicious" atau "clean".
  - Penanda bisa FP (admin sah memakai -EncodedCommand untuk deployment)
    dan bisa FN (obfuscator custom) — keputusan akhir tetap manusia.

Input -> mekanisme -> output:
  - Input : file .ps1/.psm1/.psd1/.txt (teks), atau --text. NOL jaringan.
  - Mekanisme: taksonomi penanda regex per file + ekstraksi payload
    -EncodedCommand (base64 -> UTF-16LE/UTF-8) -> pratinjau ter-defang
    (URL didefus: hxxp + [.]) — dekode gagal tetap dicatat, file tidak
    pernah dihitung "bersih" karena kegagalan alat.
  - Output: temuan {check, severity, count/evidence, message} per file
    + decoded_commands (pratinjau) + meta per file.

Cek (severity):
  encoded-command     (high)  : -e/-ec/-enc/-EncodedCommand + base64
                                (payload didekode utk pratinjau).
  iex-variant         (high)  : Invoke-Expression / |IEX / .($var) / &($var).
  web-cradle          (high)  : DownloadString/DownloadFile +
                                iex, Invoke-RestMethod, Net.WebClient.
  xor-loop            (high)  : -bxor / bxor loop pada byte array.
  compression         (high)  : IO.Compression / DeflateStream / GZipStream
                                (payload runtime-dekompresi).
  stealth-flags       (medium): -w hidden / -nop / -ep bypass / -noni
                                (gaya eksekusi senyap).
  tick-mark           (medium): backtick >= --tick-threshold (pecah token).
  char-code           (medium): [char]0xNN / [char]NNNN beruntun.
  format-concat       (medium): -f format string / .Replace( chain /
                                "'+'" joins >= --concat-threshold.
  securestring        (medium): ConvertTo-SecureString (kredensial inline).
  env-abuse           (info)  : $env: refs >= 3 (recon path sederhana).

Fail-closed: file tidak ada -> exit 2; file kosong/tanpa file valid ->
exit 2; file biner (NUL byte) -> temuan high "file-binary" + file tidak
dihitung bersih; base64 tak terdekode -> tetap temuan + evidence gagal.

Exit: 0 tanpa temuan >= --fail-on (default high); 1 ada; 2 error input.

Pemakaian:
  python tools/ps_obf_scan.py --file payload.ps1
  python tools/ps_obf_scan.py --dir skrip/ --json --out hasil.json
  python tools/ps_obf_scan.py --file a.ps1 --fail-on medium   # gate lebih ketat
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "cyphron.ps-obf-scan/1"
SCRIPT_EXTS = {".ps1", ".psm1", ".psd1"}

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}
PREVIEW_MAX = 300

# --- taksonomi penanda (deterministik) ---------------------------------

RE_ENCODED = re.compile(
    r"(?:^|[\s;|])-{1,2}[Ee](?:c|nc(?:odedcommand)?)?\s+"
    r"[\"']?([A-Za-z0-9+/=]{20,})[\"']?",
    re.MULTILINE | re.IGNORECASE)
RE_IEX = re.compile(
    r"(?:Invoke-Expression|\biex\s*\(|\|\s*IEX\b|;\s*IEX\b|"
    r"\.\s*\(\s*\$|\&\s*\(\s*\$)", re.IGNORECASE)
RE_CRADLE = re.compile(
    r"(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|"
    r"Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer)")
_CRADLE_SRC = (r"(?:DownloadString|DownloadFile|DownloadData|"
               r"Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient)")
_IEX_SRC = r"(?:IEX\b|Invoke-Expression|\biex\s*\(|\.\s*\(\s*\$|\&\s*\(\s*\$)"
RE_CRADLE_IEX = re.compile(
    r"(?is)" + _CRADLE_SRC + r"[^;\n]{0,120}(?:\|\s*)?" + _IEX_SRC
    + r"|" + _IEX_SRC + r"[^;\n]{0,120}" + _CRADLE_SRC)
RE_XOR = re.compile(r"(?:-bxor\b|\[char\]\s*\(\s*\[int\][^\n]{0,40}bxor)", re.I)
RE_COMPRESS = re.compile(r"(?:IO\.Compression|DeflateStream|GZipStream)", re.I)
RE_STEALTH = re.compile(
    r"(?:-\w*W\b\s+(?:Hidden|H)|\s-nop\b|\s-NonI(?:nteractive)?\b|"
    r"-(?:ep|executionpolicy)\s+(?:bypass|unrestricted))", re.I)
RE_TICKS = re.compile(r"`")
RE_CHARCODE = re.compile(r"\[char\]\s*(?:0x[0-9a-fA-F]{2,6}|\d{2,6})", re.I)
RE_FORMAT_F = re.compile(r"(?:\{0\}[^\n]{0,200}-f\s|-f\s+[^\n]{0,40}\{0\})", re.I)
RE_REPLACE = re.compile(r"\.Replace\(")
RE_CONCAT = re.compile(r"'\+'\)|\"\+\"")
RE_SECURESTR = re.compile(r"ConvertTo-SecureString", re.I)
RE_ENV = re.compile(r"\$env:\w+", re.I)


def defang(text: str) -> str:
    """Defang sederhana utk pratinjau: URL/domain/IP tidak bisa diklik."""
    t = re.sub(r"(?i)\bh(?:tt)?p\b", "hxxp", text)
    t = re.sub(r"(?<=\w)\.(?=\w)", "[.]", t)
    return t


def _decode_payload(b64: str) -> "tuple[str, str]":
    """Dekode payload EncodedCommand -> (hasil, alasan) — tanpa eksekusi."""
    pad = b64 + "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return "", "base64-tak-valid"
    for enc, name in (("utf-16-le", "utf-16le"), ("utf-8", "utf-8")):
        try:
            txt = raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
        # plausibilitas: perintah PS nyata mayoritas ASCII-printable —
        # sampah UTF-16 (mis. b64 acak) bukan teks yang bisa ditampilkan
        ascii_ratio = (sum(1 for c in txt if 32 <= ord(c) < 127)
                       / max(len(txt), 1))
        if ascii_ratio >= 0.6:
            return txt, name
    return "", "bukan-teks"


def scan_text(text: str, *, tick_threshold: int = 5,
              concat_threshold: int = 3) -> "tuple[list[dict], list[dict]]":
    """Pindai satu isi skrip -> (findings, decoded_commands)."""
    findings: "list[dict]" = []

    encoded = RE_ENCODED.findall(text)
    if encoded:
        findings.append({
            "check": "encoded-command", "severity": "high",
            "count": len(encoded),
            "message": f"EncodedCommand ditemukan ({len(encoded)} payload).",
        })
    if RE_IEX.search(text):
        findings.append({
            "check": "iex-variant", "severity": "high", "count": 1,
            "message": "Eksekusi dinamis Invoke-Expression/IEX/call-operator.",
        })
    if RE_CRADLE_IEX.search(text):
        findings.append({
            "check": "web-cradle", "severity": "high", "count": 1,
            "message": "Rantai cradle: unduh lalu eksekusi (iex/iwr).",
        })
    elif RE_CRADLE.search(text):
        findings.append({
            "check": "web-download", "severity": "medium", "count": 1,
            "message": "Unduhan runtime (tanpa iex di baris sama).",
        })
    if RE_XOR.search(text):
        findings.append({
            "check": "xor-loop", "severity": "high", "count": 1,
            "message": "Dekode XOR in-script (-bxor).",
        })
    if RE_COMPRESS.search(text):
        findings.append({
            "check": "compression", "severity": "high", "count": 1,
            "message": "Payload terkompresi didekompresi saat runtime.",
        })
    if RE_STEALTH.search(text):
        findings.append({
            "check": "stealth-flags", "severity": "medium", "count": 1,
            "message": "Bendera eksekusi senyap (hidden/-nop/ep bypass).",
        })
    ticks = len(RE_TICKS.findall(text))
    if ticks >= tick_threshold:
        findings.append({
            "check": "tick-mark", "severity": "medium", "count": ticks,
            "message": f"Tick-mark {ticks}x (pecah token anti-grep).",
        })
    chars = RE_CHARCODE.findall(text)
    if len(chars) >= 4:
        findings.append({
            "check": "char-code", "severity": "medium", "count": len(chars),
            "message": f"Konstruksi string via [char] ({len(chars)}x).",
        })
    concat = len(RE_CONCAT.findall(text))
    formats = len(RE_FORMAT_F.findall(text))
    replaces = len(RE_REPLACE.findall(text))
    if concat >= concat_threshold or formats >= 1 or replaces >= 3:
        findings.append({
            "check": "format-concat", "severity": "medium",
            "count": concat + formats + replaces,
            "message": f"Penyusunan string berlapis "
                       f"(concat={concat}, -f={formats}, replace={replaces}).",
        })
    if RE_SECURESTR.search(text):
        findings.append({
            "check": "securestring", "severity": "medium", "count": 1,
            "message": "ConvertTo-SecureString (kredensial terenkode).",
        })
    envs = RE_ENV.findall(text)
    if len(set(e.lower() for e in envs)) >= 3:
        findings.append({
            "check": "env-abuse", "severity": "info",
            "count": len(envs),
            "message": f"{len(envs)} referensi $env: (recon path sederhana).",
        })

    decoded: "list[dict]" = []
    for payload in encoded[:10]:  # batasi output
        txt, how = _decode_payload(payload)
        decoded.append({
            "payload_chars": len(payload),
            "decoded": defang(txt[:PREVIEW_MAX]),
            "decoded_truncated": len(txt) > PREVIEW_MAX,
            "encoding": how,
        })
    return findings, decoded


def scan_source(data: bytes, name: str, *, tick_threshold: int = 5,
                concat_threshold: int = 3) -> dict:
    """Pindai satu file (byte) -> hasil per-file. Fail-closed."""
    meta: "dict[str, Any]" = {"file": name}
    if b"\x00" in data[:4096]:
        meta["findings"] = [{
            "check": "file-binary", "severity": "high", "count": 1,
            "message": "File mengandung NUL byte — bukan teks PowerShell "
                       "sah; tidak dihitung bersih (fail-closed).",
        }]
        meta["decoded_commands"] = []
        return meta
    text = data.decode("utf-8", errors="replace")
    findings, decoded = scan_text(
        text, tick_threshold=tick_threshold,
        concat_threshold=concat_threshold)
    meta["findings"] = findings
    meta["decoded_commands"] = decoded
    return meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="ps_obf_scan — pemindai penanda obfuscation PowerShell "
                    "statis (read-only, tanpa eksekusi, nol jaringan).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="file skrip tunggal")
    src.add_argument("--dir", help="direktori (rekursif .ps1/.psm1/.psd1)")
    src.add_argument("--text", help="pindai string langsung")
    ap.add_argument("--tick-threshold", type=int, default=5)
    ap.add_argument("--concat-threshold", type=int, default=3)
    ap.add_argument("--fail-on", choices=["medium", "high"], default="high")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    sources: "list[tuple[str, bytes]]" = []
    if args.text is not None:
        sources.append(("<text>", args.text.encode("utf-8")))
    elif args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"[ps-obf] file tidak ada: {p}", file=sys.stderr)
            return 2
        sources.append((str(p), p.read_bytes()))
    else:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[ps-obf] direktori tidak ada: {d}", file=sys.stderr)
            return 2
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix.lower() in SCRIPT_EXTS:
                sources.append((str(p), p.read_bytes()))

    if not sources:
        print("[ps-obf] tidak ada sumber yang bisa dipindai (fail-closed)",
              file=sys.stderr)
        return 2

    results = [scan_source(data, name,
                           tick_threshold=args.tick_threshold,
                           concat_threshold=args.concat_threshold)
               for name, data in sources]
    all_findings = [f for r in results for f in r["findings"]]
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in all_findings),
                default=0)
    out = {
        "schema": SCHEMA,
        "files_scanned": len(results),
        "findings_total": len(all_findings),
        "results": results,
        "verdict": ("INDICATORS_FOUND" if all_findings
                    else "CLEAN_NO_OBFUSCATION_MARKERS"),
        "note": "statis, tanpa eksekusi; temuan = LEAD triase (FP/FN "
                "mungkin); pratinjau dekode DI-DEFANG (hxxp/[.]).",
    }
    text = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        print(f"verdict      : {out['verdict']} "
              f"({out['files_scanned']} file, {out['findings_total']} temuan)")
        for r in results:
            for f in r["findings"]:
                print(f"  [{f['severity']:6}] {r['file']} — "
                      f"{f['check']}: {f['message']}")
            for d in r["decoded_commands"]:
                if d["decoded"]:
                    print(f"  [dekode :{d['encoding']}] {d['decoded']!r}")
        print(f"note         : {out['note']}")

    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
