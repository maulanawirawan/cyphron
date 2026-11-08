r"""[SAFETY: read-only] zeroize_scan — pemindai zeroization material sensitif di source.

Port konsep dari antrean SKILL-PORT-QUEUE #0098 (trailofbits/skills
plugin 'zeroize-audit' — deteksi zeroization hilang untuk key/password/
secret; atribusi ide). Dibangun FROM SCRATCH — pola deklarasi, daftar
approved-wipe, dan seluruh mekanisme ditulis sendiri; TIDAK menyalin
skrip plugin. SUBSET source-level: versi lengkap skill sumber butuh
LLVM IR/asm + compile_commands.json + cargo nightly (bukan stdlib,
butuh toolchain) — cakupan alat ini C/C++/Rust pada level teks sumber
saja dan setiap temuan = LEAD perlu-review, bukan klaim. Lisensi
secai: PolyForm NC.

Input -> mekanisme -> output:
  - Input : file .c/.cc/.cpp/.h/.hpp/.rs atau direktori (read-only,
            NOL jaringan, NOL eksekusi kode target).
  - Mekanisme: baris dibersihkan dari komentar (// /* */) dan string
            literal; brace depth menandai scope fungsi; deklarasi buffer
            sensitif (nama memuat key/secret/password/token/credential/
            seed/nonce pada batas segmen) dicocokkan dengan pola C/C++/
            Rust; dalam scope yang sama dicari token approved-wipe.
  - Output: daftar lead {file, line, kind, severity, message} + meta.

Kategori lead:
  secret-buffer-tanpa-wipe (medium): buffer sensitif dideklarasikan,
    scope fungsi berakhir TANPA approved-wipe. memset() polos SENGAJA
    TIDAK dihitung (dead-store elimination bisa menghapusnya — itulah
    inti konsep sumber).
  secret-buffer-global    (medium): buffer sensitif di scope file
    (global/statik) — material kunci statis di binary, review kebiasaan
    wipe.
  secret-copy-memcpy      (medium): memcpy/strcpy dkk. menyalin dari/ke
    identifier sensitif — salinan tak terpantau jejak wipe-nya.
  file-unparsed           (high)  : kurung tak seimbang / tak terbaca —
    file TIDAK dinilai, tidak pernah dihitung bersih (fail-closed).

Presisi di atas recall (NO-FP): nama yang memuat public/pub/path/file/
dir/name/url/uri/env/len/size/count dilewati (public key, path, label —
bukan material rahasia); kata kunci wajib pada batas segmen nama
(api_key cocok, monkey tidak); identifier di dalam komentar dan string
dilewati. Cakupan bahasa: C/C++/Rust; ekstensi lain dilewati (meta).

Exit: 0 bersih; 1 ada lead >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/zeroize_scan.py --source src/
  python tools/zeroize_scan.py --source vault.c --json hasil.json --fail-on high
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secai.zeroize-scan/1"

EXT = {".c", ".cc", ".cpp", ".h", ".hpp", ".rs"}

# approved-wipe: API zeroization yang (secara konsep sumber) tidak bisa
# dihapus compiler / eksplisit aman — ditulis sendiri dari dokumentasi
# publik masing-masing pustaka.
WIPE_C = frozenset({
    "explicit_bzero", "memset_s", "SecureZeroMemory", "OPENSSL_cleanse",
    "sodium_memzero", "CRYPTO_memzero", "explicit_memset",
})
WIPE_RUST = ("zeroize", "Zeroizing")

# kata kunci sensitif pada batas segmen nama (presisi, anti "monkey")
SENSITIVE_RE = re.compile(
    r"(?:^|_)(?:key|secret|password|passwd|token|credential|cred|seed|nonce)"
    r"(?:s)?(?:_|[0-9]|$)")
# nama yang jelas BUKAN material rahasia (public key, path, label, dst.)
NAME_EXCLUDE = ("public", "pub", "path", "file", "dir", "name", "url",
                "uri", "env", "len", "size", "count")

C_DECL_PATTERNS = (
    re.compile(r"\b(?:unsigned\s+)?char\s*\*?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*[;=]"),
    re.compile(r"\b(?:uint8_t|BYTE|byte)\s+\*?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*[;=]"),
    re.compile(r"\bstd::string\s+([A-Za-z_]\w*)\s*[;=(]"),
    re.compile(r"\bstd::vector<\s*(?:unsigned\s+char|std::uint8_t|uint8_t|BYTE|byte)"
               r"\s*>\s+([A-Za-z_]\w*)"),
    re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:malloc|calloc|realloc|mmap)\s*\("),
)
RUST_DECL_RE = re.compile(r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s*"
                          r"(?::\s*([^=;]+))?=\s*([^;]+);")
RUST_BUFFER_HINT = re.compile(r"\b(u8|Vec|String|str|bytes)\b|vec!|\bas_bytes")
COPY_CALL_RE = re.compile(
    r"\b(memcpy|memcpy_s|strcpy|strncpy|strcat|RtlCopyMemory|CopyMemory)\s*\(")


def _is_sensitive(name: str) -> bool:
    low = name.lower()
    if any(x in low for x in NAME_EXCLUDE):
        return False
    return bool(SENSITIVE_RE.search(low))


def strip_line(line: str, in_block: bool) -> tuple[str, bool]:
    """Buang komentar (//, /* */) dan isi string/char literal — teks kode saja."""
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        if in_block:
            j = line.find("*/", i)
            if j == -1:
                i = n
            else:
                in_block = False
                i = j + 2
            continue
        c = line[i]
        if line[i:i + 2] == "//":
            break
        if line[i:i + 2] == "/*":
            in_block = True
            i += 2
            continue
        if c == '"' or c == "'":
            quote = c
            i += 1
            while i < n and line[i] != quote:
                if line[i] == "\\":
                    i += 1
                i += 1
            i += 1
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def _match_c_decl(code: str) -> str | None:
    for rx in C_DECL_PATTERNS:
        m = rx.search(code)
        if m and _is_sensitive(m.group(1)):
            return m.group(1)
    return None


def _match_rust_decl(code: str) -> str | None:
    m = RUST_DECL_RE.search(code)
    if not m:
        return None
    name, typ, val = m.group(1), m.group(2) or "", m.group(3)
    if not _is_sensitive(name):
        return None
    if typ and RUST_BUFFER_HINT.search(typ):
        return name
    if RUST_BUFFER_HINT.search(val):
        return name
    return None


def scan_source(text: str, filename: str) -> list[dict[str, Any]]:
    """Pindai satu file — hasil daftar lead (tanpa klaim terkonfirmasi)."""
    cleaned: list[str] = []
    depths: list[int] = []          # depth SETELAH tiap baris
    depth = 0
    in_block = False
    for raw in text.splitlines():
        code, in_block = strip_line(raw, in_block)
        cleaned.append(code)
        depth += code.count("{") - code.count("}")
        depths.append(depth)
    if depth != 0:
        return [{"file": filename, "line": 0, "kind": "file-unparsed",
                 "severity": "high",
                 "message": f"kurung tak seimbang ({depth:+d}) — file TIDAK dinilai"}]

    findings: list[dict[str, Any]] = []
    n = len(cleaned)
    for idx, code in enumerate(cleaned):
        is_rust = filename.endswith(".rs")
        name = _match_rust_decl(code) if is_rust else _match_c_decl(code)
        if not name:
            continue
        decl_depth = depths[idx - 1] if idx else 0
        floor = 1 if decl_depth >= 1 else 0
        # scope = sampai depth turun di bawah floor (fungsi) / EOF (global)
        end = n
        for j in range(idx, n):
            if depths[j] < floor:
                end = j + 1
                break
        scope = "\n".join(cleaned[idx:end])
        wiped = any(w in scope for w in WIPE_C)
        if not wiped:
            wiped = any(w in scope for w in WIPE_RUST)
        if decl_depth == 0:
            findings.append({"file": filename, "line": idx + 1,
                             "kind": "secret-buffer-global", "severity": "medium",
                             "message": f"buffer sensitif '{name}' di scope file "
                                        f"(global/statik) — material kunci statis, "
                                        f"review kebiasaan wipe (lead)"})
        elif not wiped:
            findings.append({"file": filename, "line": idx + 1,
                             "kind": "secret-buffer-tanpa-wipe", "severity": "medium",
                             "message": f"buffer sensitif '{name}' tidak ada jejak "
                                        f"approved-wipe di scope yang sama (memset "
                                        f"polos tidak dihitung — bisa dihapus DSE) "
                                        f"(lead)"})
        # salinan sensitif di scope yang sama
        name_re = re.compile(rf"\b{re.escape(name)}\b")
        for k, line2 in enumerate(cleaned[idx:end], start=idx):
            cm = COPY_CALL_RE.search(line2)
            if cm and (name_re.search(line2[cm.end():])
                       or name_re.search(line2[:cm.start()])):
                findings.append({"file": filename, "line": k + 1,
                                 "kind": "secret-copy-memcpy", "severity": "medium",
                                 "message": f"{cm.group(1)} menyentuh '{name}' — "
                                            f"salinan secret, jejak wipe dst tak "
                                            f"terpantau (lead)"})
    return findings


def iter_source(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.suffix.lower() in EXT and p.is_file())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pindai zeroization material sensitif di source C/C++/"
                    "Rust (read-only, nol jaringan; subset source-level dari "
                    "konsep zeroize-audit).")
    ap.add_argument("--source", required=True, help="file sumber atau direktori")
    ap.add_argument("--fail-on", choices=["medium", "high"], default="medium",
                    help="ambang exit 1 (default medium)")
    ap.add_argument("--json", metavar="OUT", help="tulis hasil ke file JSON")
    args = ap.parse_args(argv)

    root = Path(args.source)
    if not root.exists():
        print(f"ERROR: sumber tidak ada: {root}", file=sys.stderr)
        return 2
    files = iter_source(root)
    if not files:
        print("ERROR: tidak ada file C/C++/Rust di sumber", file=sys.stderr)
        return 2

    threshold = {"medium": 0, "high": 1}[args.fail_on]
    sev_rank = {"medium": 0, "high": 1}
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {"schema": SCHEMA, "files": len(files),
                            "scanned": 0, "unparsed": 0}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            findings.append({"file": str(f), "line": 0, "kind": "file-unparsed",
                             "severity": "high",
                             "message": f"file tidak bisa dibaca: {e}"})
            meta["unparsed"] += 1
            continue
        meta["scanned"] += 1
        findings.extend(scan_source(text, str(f)))

    counted = [x for x in findings if sev_rank[x["severity"]] >= threshold]
    meta["findings"] = len(findings)
    meta["counted"] = len(counted)
    for x in findings:
        print(f"[{x['severity']:>6}] {x['file']}:{x['line']} {x['kind']}: "
              f"{x['message']}")
    print(f"RINGKAS: {meta['files']} file, {meta['scanned']} dipindai, "
          f"{meta['unparsed']} unparsed, {len(findings)} lead "
          f"({len(counted)} >= ambang {args.fail_on})")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"schema": SCHEMA, "meta": meta, "findings": findings},
                       ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
