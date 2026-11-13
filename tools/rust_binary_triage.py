r"""[AUDIT: read-only] rust_binary_triage — triase OFFLINE biner
terkompilasi Rust (malware & artefak lab): identifikasi kompilasi Rust
dari penanda runtime-nya, ekstraksi versi rustc, inventaris crate (jalur
registry .cargo yang tertanam + nama crate dari simbol legacy-mangled
`_ZN..E`), pemetaan crate -> kelas kapabilitas
(network/crypto/persist/recon/collection/ obfuscation), dan string
relevan-malware ber-offset (URL di-defang).

Keterbatasan yang diakui eksplisit (fail-closed, anti-klaim):
  - simbol v0 mangling (`_R...`) TIDAK didekode penuh (tatabahasa base-62
    + generik terlalu luas utk parser reguler); kehadirannya dihitung dan
    dicatat, nama crate dari simbol hanya diambil dari legacy `_ZN..E`;
  - biner yang di-strip PENUH & tanpa string registry tetap bisa
    teridentifikasi Rust via string runtime panic, tapi inventaris crate
    bisa kosong — kosong BUKAN bukti tanpa-dependensi;
  - verdict menyatakan EVIDENCE, bukan vonis: NO-RUST-EVIDENCE tidak sama
    dengan "bukan Rust".

Ranah tetangga eksplisit (jangan dipindah ke sini):
  - string generik + secret ber-format = binary_strings_surface;
  - konstanta kripto byte-level (S-box, sigma) = crypto_constant_scan;
  - packedness PE = packer_scan; carve blob = carve_scan; APK = apk_
    firebase_scan + mobile_manifest_audit.

Input -> mekanisme -> output:
  - Input : --file PATH (WAJIB, satu berkas).
  - Mekanisme: hitung penanda runtime Rust (panic string, core::panicking,
            std::rt::lang_start, jalur .cargo/registry, versi rustc) ->
            inventaris crate dari pola registry-path + dekode segmen
            legacy-mangle (batas ketat: <= 2000 simbol, <= 512 byte/simbol,
            segmen malformed = simbol dibuang) -> petakan crate dikenal ke
            kelas kapabilitas (lead low) -> ekstrak string ber-keyword
            malware (URL di-defang ioc_defang).
  - Output: JSON (stdout atau --out): verdict, indikator, versi rustc,
            crates {nama: versi}, crate-dari-simbol, kapabilitas, strings.

Verdict (urutan gate --fail-on):
  NO-RUST-EVIDENCE < RUST-POSSIBLE (1 indikator) < RUST-LIKELY
  (>= 2 indikator, atau 1 indikator + versi rustc).
  Exit: 0 selesai; 1 bila verdict >= --fail-on; 2 input error.

Pemakaian:
  python tools/rust_binary_triage.py --file sample.bin
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from ioc_defang import defang_text  # noqa: E402

SCHEMA = "secai.rust-binary-triage/1"
MAX_FILE_BYTES = 64_000_000
MAX_SYMBOLS = 2000
MAX_SYMBOL_LEN = 512
MAX_STRINGS = 40
MAX_CRATES = 512

VERDICTS = ("NO-RUST-EVIDENCE", "RUST-POSSIBLE", "RUST-LIKELY")

INDICATORS: list[tuple[str, str]] = [
    ("panic-string", b"panicked at"),
    ("core-panicking", b"core::panicking"),
    ("lang-start", b"std::rt::lang_start"),
    ("cargo-registry", b".cargo/registry"),
    ("cargo-registry-win", b".cargo\\registry"),
]

_RUSTC_VER_RE = re.compile(rb"rustc[ ](\d+\.\d+\.\d+)")
# jalur registry crates.io: crates.io-<hash>/<crate>-<ver> ATAU
# .cargo/registry/src/<registry>/<crate>-<ver>
_REGISTRY_PATH_RE = re.compile(
    rb"(?:crates\.io-[0-9a-f]{8,}[/\\]|\.cargo[/\\]registry[/\\]src[/\\]"
    rb"[^/\\]+[/\\])([A-Za-z0-9_.\-]+?)-(\d+\.\d+\.\d+)")
_LEGACY_SYMBOL_RE = re.compile(rb"_ZN((?:\d+[!-~]+){1,24})E")
_V0_SYMBOL_RE = re.compile(rb"_R[A-Za-z0-9_]{8,}")
_LEN_PREFIX_RE = re.compile(rb"(\d+)")

RUNTIME_SEGMENTS = {"std", "core", "alloc", "main", "crate", "self",
                    "super", "root", "unwind", "panic_unwind", "test",
                    "gimli", "addr2line", "miniz_oxide", "adler",
                    "rustc_demangle", "hashbrown", "libc", "memchr"}

_CRATE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,30}$")

CAPABILITY_MAP: dict[str, list[str]] = {
    # network
    "reqwest": ["network"], "hyper": ["network"], "ureq": ["network"],
    "attohttpc": ["network"], "surf": ["network"], "isahc": ["network"],
    "curl": ["network"], "tungstenite": ["network-c2-channel"],
    "quinn": ["network"], "socket2": ["network"],
    # async runtime
    "tokio": ["async"], "async-std": ["async"], "smol": ["async"],
    "futures": ["async"],
    # crypto
    "aes": ["crypto"], "aes-gcm": ["crypto"], "chacha20": ["crypto"],
    "chacha20poly1305": ["crypto"], "salsa20": ["crypto"],
    "rsa": ["crypto"], "ring": ["crypto"], "sha1": ["crypto"],
    "sha2": ["crypto"], "md-5": ["crypto"], "hmac": ["crypto"],
    "des": ["crypto"], "rc4": ["crypto"], "block-modes": ["crypto"],
    "elliptic-curve": ["crypto"], "p256": ["crypto"], "p384": ["crypto"],
    "x25519-dalek": ["crypto"], "ed25519-dalek": ["crypto"],
    "curve25519-dalek": ["crypto"], "openssl": ["crypto"],
    # persist / registry
    "winreg": ["persist-registry"], "windows-registry": ["persist-registry"],
    "winapi": ["winapi"], "windows": ["winapi"],
    "windows-sys": ["winapi"], "ntapi": ["winapi-native"],
    "sysinfo": ["recon"], "hostname": ["recon"], "whoami": ["recon"],
    "uname": ["recon"], "local-ip-address": ["recon"],
    "mac_address": ["recon"], "systemstat": ["recon"],
    "os_info": ["recon"],
    # collection
    "screenshots": ["screen-capture"], "arboard": ["clipboard"],
    "clipboard": ["clipboard"], "clipboard-win": ["clipboard"],
    "rdev": ["input-capture"], "device_query": ["input-capture"],
    "global-hotkey": ["input-capture"],
    # archive (eksfil paket)
    "zip": ["archive"], "tar": ["archive"], "flate2": ["archive"],
    "xz2": ["archive"], "zstd": ["archive"], "lz4_flex": ["archive"],
    # evasion / obfuskasi string
    "obfstr": ["string-obfuscation"], "litcrypt": ["string-obfuscation"],
    "goldberg": ["string-obfuscation"],
}

STRING_KEYWORDS = ("http", "socket", "encrypt", "decrypt", "shell",
                   "exec", "cmd", "upload", "download", "persist",
                   "registry", "mutex", "pipe", "inject", "keystroke",
                   "keylog", "screenshot", "credential", "passwd",
                   "ransom")
_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{8,}")
_URL_RE = re.compile(r"https?://\S+")


def _decode_legacy_mangle(payload: bytes) -> list[str] | None:
    """Dekode isi `_ZN<payload>E` -> segmen nama. None = malformed
    (simbol dibuang — fail-closed, bukan ditebak)."""
    segs: list[bytes] = []
    i = 0
    while i < len(payload):
        m = _LEN_PREFIX_RE.match(payload, i)
        if not m:
            return None
        n = int(m.group(1))
        i = m.end()
        if n <= 0 or i + n > len(payload):
            return None
        segs.append(payload[i:i + n])
        i += n
        if len(segs) >= 24:
            return None
    return [s.decode("ascii", "replace") for s in segs] if segs else None


def _crate_from_segments(segs: list[str]) -> str | None:
    """Crate = segmen pertama yang bukan runtime segmen."""
    for seg in segs:
        if seg in RUNTIME_SEGMENTS:
            continue
        if _CRATE_NAME_RE.match(seg):
            return seg
        return None
    return None


def scan(path: Path) -> dict:
    data = path.read_bytes()
    if not data:
        raise ValueError("berkas kosong")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"berkas {len(data)}B > batas pindai "
                         f"{MAX_FILE_BYTES}B")
    findings: list[dict] = []

    # 1) indikator runtime Rust
    seen: list[dict] = []
    for name, marker in INDICATORS:
        n = data.count(marker)
        if n:
            seen.append({"id": name, "count": n})
    rustc_vers = sorted({m.group(1).decode() for m in
                         _RUSTC_VER_RE.finditer(data)})
    if rustc_vers:
        seen.append({"id": "rustc-version", "count": len(rustc_vers)})
    for s in seen:
        if s["id"] != "crates-io-paths":  # ditambahkan belakangan (bila ada)
            _add(findings, f"rust-indicator.{s['id']}", "info",
                 f"penanda runtime Rust '{s['id']}' x{s['count']}",
                 {"count": s["count"]})

    # 2) inventaris crate dari jalur registry
    crates: dict[str, str] = {}
    for m in _REGISTRY_PATH_RE.finditer(data):
        if len(crates) >= MAX_CRATES:
            break
        name = m.group(1).decode("ascii", "replace")
        ver = m.group(2).decode("ascii", "replace")
        if _CRATE_NAME_RE.match(name) and name not in crates:
            crates[name] = ver
    if crates:
        _add(findings, "crates.registry-paths", "info",
             f"{len(crates)} crate dari jalur .cargo/registry tertanam",
             {"crates": dict(sorted(crates.items()))})
    # jalur crates.io-<hash>/ dari >= 3 crate berbeda = indikator
    # kompilasi Rust (build artifact menyematkan path sumber crate);
    # ambang 3 mencegah FP dari dokumen teks yang memakai 1-2 jalur
    if len(crates) >= 3:
        seen.append({"id": "crates-io-paths", "count": len(crates)})
        _add(findings, "rust-indicator.crates-io-paths", "info",
             f"{len(crates)} crate terdaftar via jalur registry "
             "crates.io — indikator kompilasi Rust",
             {"count": len(crates)})

    # 3) crate dari simbol legacy-mangled
    symbol_crates: set[str] = set()
    symbols_seen = 0
    for m in _LEGACY_SYMBOL_RE.finditer(data):
        if symbols_seen >= MAX_SYMBOLS:
            break
        symbols_seen += 1
        if len(m.group(0)) > MAX_SYMBOL_LEN:
            continue
        segs = _decode_legacy_mangle(m.group(1))
        if segs is None:
            continue
        crate = _crate_from_segments(segs)
        if crate:
            symbol_crates.add(crate)
    symbol_crates -= set(crates)
    symbol_crates = {c for c in symbol_crates
                     if _CRATE_NAME_RE.match(c)}
    if symbol_crates:
        _add(findings, "crates.legacy-symbols", "info",
             f"{len(symbol_crates)} crate tambahan dari simbol "
             "_ZN..E (legacy mangling)",
             {"crates": sorted(symbol_crates)})

    # 4) simbol v0: dihitung, TIDAK didekode (keterbatasan eksplisit)
    v0_count = len(_V0_SYMBOL_RE.findall(data))

    # 5) pemetaan kapabilitas dari SEMUA crate yang dikenal
    all_crates = set(crates) | symbol_crates
    caps: list[dict] = []
    for crate in sorted(all_crates):
        for klass in CAPABILITY_MAP.get(crate, []):
            caps.append({"crate": crate, "class": klass,
                         "source": "registry" if crate in crates
                         else "symbol"})
    for c in caps:
        _add(findings, "capability." + c["class"], "low",
             f"crate '{c['crate']}' -> kapabilitas {c['class']} "
             f"(sumber: {c['source']}) — lead utk arah analisis, "
             "bukan vonis", {"crate": c["crate"], "source": c["source"]})

    # 6) string relevan-malware ber-offset
    strings: list[dict] = []
    seen_str: set[str] = set()
    for m in _ASCII_RUN_RE.finditer(data):
        if len(strings) >= MAX_STRINGS:
            break
        s = m.group().decode("ascii")
        low = s.lower()
        if not any(k in low for k in STRING_KEYWORDS):
            continue
        key = s[:120]
        if key in seen_str:
            continue
        seen_str.add(key)
        display = defang_text(s[:200])
        strings.append({"offset": m.start(), "text": display})
    if strings:
        _add(findings, "strings.malware-relevant", "info",
             f"{len(strings)} string relevan-malware (URL di-defang)",
             {"count": len(strings)})

    # verdict
    n_ind = len(seen)
    has_rustc = any(s["id"] == "rustc-version" for s in seen)
    if n_ind >= 2 or (n_ind >= 1 and has_rustc):
        verdict = "RUST-LIKELY"
    elif n_ind == 1:
        verdict = "RUST-POSSIBLE"
    else:
        verdict = "NO-RUST-EVIDENCE"
        _add(findings, "meta.no-rust-evidence", "info",
             "tidak ada penanda runtime Rust — BUKAN klaim 'bukan Rust' "
             "(biner strip-penuh tetap mungkin Rust)")

    return {
        "schema": SCHEMA,
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verdict": verdict,
        "indicators": seen,
        "rustc_versions": rustc_vers,
        "crates": dict(sorted(crates.items())),
        "crates_from_symbols": sorted(symbol_crates),
        "v0_symbols_count": v0_count,
        "capabilities": caps,
        "strings": strings,
        "limitations": [
            "simbol v0 (_R..) tidak didekode — hanya dihitung",
            "inventaris crate kosong != tanpa dependensi",
            "verdict = evidence, bukan vonis malware",
        ],
        "findings": findings,
        "read_only": True,
    }


def _add(findings: list[dict], fid: str, severity: str, detail: str,
         extra: dict | None = None) -> None:
    f = {"id": fid, "severity": severity, "detail": detail}
    if extra:
        f["evidence"] = extra
    findings.append(f)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase biner Rust (read-only, NOL jaringan, tanpa "
                    "dekompilasi)")
    ap.add_argument("--file", required=True, help="path berkas biner")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=VERDICTS, default="RUST-LIKELY",
                    help="gate exit 1 bila verdict >= pilihan ini")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: berkas tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = scan(path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)

    if VERDICTS.index(result["verdict"]) >= VERDICTS.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
