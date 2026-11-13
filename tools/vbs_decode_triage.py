"""[SAFETY: read-only] vbs_decode_triage — dekode OFFLINE skrip ter-encode
VBE / JScript.Encode lalu triase isi terdekodenya untuk indikator
eksekusi/unduhan (keluarga malware downloader & dropper VBS).

Port konsep dari entri "decode-vbe" di A-poc/BlueTeam-Tools (Didier
Stevens suite; referensi implementasi format). Kode ini ditulis from
scratch: algoritma dekode diimplementasikan mandiri di atas KONSTANTA
FORMAT JScript.Encode (tabel substitusi 3-byte + kombinasi 64 — bagian
spesifikasi format Microsoft yang publik, disimpan di tools/_vbe_tables.py).
Stdlib-only, NOL jaringan, NOL eksekusi: skrip terdekodenya TIDAK dijalankan,
hanya dianalisis sebagai teks.

Format input yang dikenali:
  - file .vbe/.vbs/.jse/.js berisi blok '#@~^......==...==^#~@'
  - satu file boleh berisi lebih dari satu blok encode
Mekanisme:
  - decode          : ekstrak payload tiap blok, pre-replace escape
                      (@& @# @* @! @$), substitusi per-karakter via tabel +
                      kombinasi index%64 (index hanya bertambah pada ASCII)
  - triase terdekod : indikator eksekusi (WScript.Shell/Run/Execute/
                      regsvr32/powershell/certutil/mshta/rundll32),
                      unduhan (URLDownloadToFile/XMLHttpRequest/adodb.stream/
                      http://|https://), obfuscation (chr()/base64 blob/
                      eval), dan persistence (run/runonce registry key)
  - setiap indikator dilaporkan dengan cuplikan baris ter-redaksi (max 160)

Fail-closed: file kosong / tidak ada blok encode -> exit 2. Temuan = LEAD
triase statis, bukan klaim malware terkonfirmasi.

Pemakaian:
  python tools/vbs_decode_triage.py --file sample.vbe --out triase.json
  python tools/vbs_decode_triage.py --file drop.vbs --redact off
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _vbe_tables import _COMB, _DECODE_RAW

SCHEMA = "secai.vbs-decode-triage/1"

_RE_BLOCK = re.compile(r"#@~\^.{6}==(.+).{6}==\^#~@", re.S)
_RE_ESC = [("@&", "\n"), ("@#", "\r"), ("@*", ">"), ("@!", "<"), ("@$", "@")]

_EXEC_SIGNS = re.compile(
    r"(WScript\.Shell|Shell\.Application|\.Run\b|\.Exec\b|Execute(Global)?\b|"
    r"regsvr32|rundll32|mshta\b|powershell\b|certutil\b|wscript\b|cscript\b|"
    r"cmd\.exe|\bnet user\b|schtasks\b|sc \w+)", re.I)
_DL_SIGNS = re.compile(
    r"(URLDownloadToFile|XMLHttpRequest|ADODB\.Stream|Msxml2\.ServerXMLHTTP|"
    r"https?://[^\s\"']+|GetObject\s*\(\s*\"(script|http))", re.I)
_OBF_SIGNS = re.compile(
    r"(Chr\s*\(\s*\d+|eval\s*\(|exec(ute)?Global|FromBase64String|"
    r"[A-Za-z0-9+/]{120,}={0,2})", re.I)
_PERSIST_SIGNS = re.compile(
    r"(CurrentVersion\\\\?Run\b|CurrentVersion\\\\?RunOnce\b|Startup|"
    r"RegisterStartupScript|SchTasks)", re.I)
_RE_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_RE_URL = re.compile(r"https?://[^\s\"'<>]{8,}")
_UNPARSED_SAMPLE_MAX = 10


def decode_block(payload: str) -> str:
    """Dekode satu payload blok VBE (algoritma mandiri di atas konstanta
    format — lihat docstring)."""
    for a, b in _RE_ESC:
        payload = payload.replace(a, b)
    out = bytearray()
    idx = -1
    for ch in payload:
        b = ord(ch)
        if b < 128:
            idx += 1
        if (b == 9 or 31 < b < 128) and b not in (60, 62, 64):
            triple = _DECODE_RAW.get(b)
            if triple is not None:
                out.append(triple[_COMB[idx % len(_COMB)]])
                continue
        out.extend(ch.encode("latin-1", errors="replace"))
    return out.decode("latin-1", errors="replace")


def _redact(text: str, limit: int = 160) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    return t[:limit] + ("…" if len(t) > limit else "")


def analyze_blocks(decoded: list[str]) -> list[dict]:
    findings: list[dict] = []
    sig_groups = (
        ("exec-indicator", _EXEC_SIGNS, "high"),
        ("download-indicator", _DL_SIGNS, "high"),
        ("obfuscation-indicator", _OBF_SIGNS, "medium"),
        ("persistence-indicator", _PERSIST_SIGNS, "medium"),
    )
    urls: set[str] = set()
    b64_seen = 0
    for bi, text in enumerate(decoded):
        for sig, rx, sev in sig_groups:
            hits = sorted({m.group(0)[:60] for m in rx.finditer(text)})
            if hits:
                findings.append({
                    "type": sig, "severity": sev,
                    "block": bi,
                    "detail": (f"{len(hits)} indikator {sig.split('-')[0]} di "
                               f"blok #{bi}: {', '.join(hits[:4])}"),
                    "evidence": {"hits": hits[:8],
                                 "sample": _redact(text)},
                })
        for m in _RE_URL.finditer(text):
            urls.add(m.group(0)[:120])
        if _RE_B64.search(text):
            b64_seen += 1
    if urls:
        findings.append({
            "type": "url-extraction", "severity": "medium",
            "detail": f"{len(urls)} URL unik di dalam skrip terdekodenya",
            "evidence": {"urls": sorted(urls)[:10]},
        })
    if len(decoded) >= 2 and b64_seen == len(decoded):
        findings.append({
            "type": "b64-dominant", "severity": "medium",
            "detail": (f"semua {len(decoded)} blok memuat blob base64 "
                       f"panjang (pola dropper bertingkat)"),
            "evidence": {"blocks": len(decoded), "b64_blocks": b64_seen},
        })
    return findings


def triage_file(path: Path, redact_off: bool = False) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise ValueError("file kosong")
    matches = list(_RE_BLOCK.finditer(text))
    if not matches:
        raise ValueError("tidak ada blok encode VBE/JScript.Encode ditemukan")
    decoded = []
    for m in matches:
        decoded.append(decode_block(m.group(1)))
    findings = analyze_blocks(decoded)
    if not redact_off:
        for f in findings:
            if f.get("evidence", {}).get("sample"):
                f["evidence"]["sample"] = _redact(f["evidence"]["sample"], 80)
    return {
        "schema": SCHEMA,
        "file": str(path),
        "blocks_total": len(matches),
        "decoded_chars": [len(d) for d in decoded],
        "decoded_preview": [_redact(d, 120) for d in decoded],
        "finding_count": len(findings),
        "findings": findings,
        "note": "triase statis teks terdekodenya — skrip TIDAK dieksekusi",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Dekode VBE/JScript.Encode + triase indikator "
                    "(read-only, NOL eksekusi, NOL jaringan)")
    ap.add_argument("--file", required=True,
                    help="file .vbe/.vbs/.jse/.js berisi blok encode")
    ap.add_argument("--redact", choices=["on", "off"], default="on",
                    help="redaksi cuplikan (default on)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage_file(path, redact_off=(args.redact == "off"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
