r"""[AUDIT: read-only] crypto_constant_scan — identifikasi OFFLINE algoritma
kripto yang TERTANAM di blob biner (exe/dll/so/dump/apak pun) dari tiga
sumber bukti byte-level: (1) konstanta byte algoritma yang dipublikasikan
spesifikasinya (AES S-box, konstanta ChaCha20/Salsa20, init MD5/SHA-1/
SHA-2, tabel CRC32, P-array Blowfish, alfabet Base64), (2) nama API kripto
di tabel import PE (CryptoAPI/CNG/OpenSSL), (3) penanda kunci/serifikat
(PEM, pola DER modulus RSA). Mode opsional --artifact menganalisis SATU
artefak terenkripsi: entropi tail (kandidat key-material ditempel, ukuran
umum RSA) + inventaris preservasi header asli.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'reverse-engineering-ransomware-encryption-routine' (#0941 — atribusi
konsep, lisensi sumber Apache-2.0) dan konsep FindCrypt dari
'reverse-engineering-malware-with-ghidra' (#0940). Dibangun FROM SCRATCH
TANPA menyalin kode sumber itu: tabel konstanta ditulis dari spesifikasi
publik algoritma (FIPS 197, RFC 8439, RFC 1321, FIPS 180-4, ISO 3309),
parser PE ditulis dari spesifikasi PE/COFF Microsoft. Skill sumber =
runbook RE LIVE (IDA/Ghidra/x64dbg/pycryptodome); tool ini memilih sisi
STATIS nol-jaringan: TIDAK melakukan dekompilasi, debugging, atau
dekripsi — hanya mencocokkan byte yang sudah ada di berkas.

Ranah tetangga eksplisit (jangan dipindah ke sini):
  - packedness/entropi section PE = packer_scan;
  - string generik + secret ber-format (AKIA/sk_live_/...) =
    binary_strings_surface;
  - triase artefak ransomware dari MANIFEST daftar berkas + isi note =
    ransom_artifact_triage (tool ini bekerja pada ISI byte satu berkas);
  - token algoritma di kode/KONFIG/IaC (CBOM) = crypto_inventory_scan —
    di sini sasarannya BINER terkompilasi, bukan pohon teks;
  - signature carable multi-berkas = carve_scan.

Input -> mekanisme -> output:
  - Input : --file PATH (WAJIB, satu berkas) + --artifact (opsional).
  - Mekanisme: pencocokan byte-exact konstanta (semua offset dicatat,
            dibatasi MAX_HITS per konstanta) -> bila berkas PE,urai
            tabel import dan cocokkan nama fungsi kripto -> cocokkan
            penanda PEM/DER -> kombinasi bukti simetris + asimetris
            ditandai hybrid-encryption-signature (lead) -> --artifact:
            entropi Shannon tail pada ukuran umum (2048/1024/512/256/
            128) >= 7.5 = kandidat key/ciphertext ditempel + inventaris
            magic header asli.
  - Output: JSON (stdout atau --out) berisi verdict, daftar temuan
            ber-id + severity + offset, inventaris import kripto.

Verdict fail-closed (kehadiran primitif, BUKAN vonis malware):
  - PRIMITIVES-PRESENT : minimal satu bukti konstanta/API/PEM/DER.
  - NONE-KNOWN-FOUND   : tidak ada yang tercocok — TIDAK sama dgn
                         "tanpa kripto" (algoritma custom, tabel yang
                         dihitung runtime, atau crypto yang di-obfuscate
                         tetap tak terlihat; dicatat eksplisit).
  Semua temuan = lead unconfirmed (maks medium): aplikasi sah (TLS
  client, validator lisensi, zip crypto) juga menanam primitif kripto.
  Exit: 0 selesai; 1 bila verdict >= --fail-on; 2 input error (berkas
  hilang/kosong/terlalu besar).

Pemakaian:
  python tools/crypto_constant_scan.py --file sample.exe
  python tools/crypto_constant_scan.py --file encrypted.blob --artifact
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

SCHEMA = "secai.crypto-constant-scan/1"
MAX_FILE_BYTES = 64_000_000
MAX_HITS_PER_CONST = 8
MAX_IMPORTS = 4096

# ---------------------------------------------------------------------------
# Tabel konstanta — byte-exact, dari spesifikasi publik algoritma.
# ---------------------------------------------------------------------------

_AES_SBOX = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
])

CONSTANTS: list[dict] = [
    # --- kripto simetris ---
    {"id": "aes-sbox", "family": "symmetric", "label": "AES S-box (256 byte, FIPS 197)", "data": _AES_SBOX},
    {"id": "chacha20-const", "family": "symmetric", "label": "ChaCha20/Salsa20 sigma 'expand 32-byte k' (RFC 8439)", "data": b"expand 32-byte k"},
    {"id": "chacha16-const", "family": "symmetric", "label": "ChaCha/Salsa 128-bit sigma 'expand 16-byte k'", "data": b"expand 16-byte k"},
    {"id": "blowfish-p", "family": "symmetric", "label": "Blowfish P-array init (digit pi)", "data": bytes([0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44])},
    # --- hash ---
    {"id": "md5-init", "family": "hash", "label": "MD5 init state (RFC 1321, little-endian)", "data": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])},
    {"id": "sha1-init", "family": "hash", "label": "SHA-1 init state (FIPS 180-4, big-endian)", "data": bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0])},
    {"id": "sha256-init", "family": "hash", "label": "SHA-256 init state (FIPS 180-4, big-endian)", "data": bytes([0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A, 0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19])},
    # --- encoding/lain ---
    {"id": "crc32-ieee-table", "family": "checksum", "label": "CRC-32 IEEE tabel entri pertama (ISO 3309)", "data": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99])},
    {"id": "base64-alphabet", "family": "encoding", "label": "Alfabet Base64 standar (RFC 4648)", "data": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
]

# Prefix 16 byte S-box — dipakai HANYA bila S-box penuh tidak ditemukan
# (tabel sebagian yang di-unroll compiler). Match 16-byte masih kuat
# (probabilitas acak ~2^-128) tapi lebih lemah dari 256-byte.
_AES_SBOX_PREFIX = _AES_SBOX[:16]

PEM_MARKERS: list[dict] = [
    {"id": "pem-public-key", "label": "PEM public key", "data": b"-----BEGIN PUBLIC KEY-----", "family": "asymmetric"},
    {"id": "pem-rsa-public", "label": "PEM RSA public key", "data": b"-----BEGIN RSA PUBLIC KEY-----", "family": "asymmetric"},
    {"id": "pem-rsa-private", "label": "PEM RSA PRIVATE KEY TERTANAM", "data": b"-----BEGIN RSA PRIVATE KEY-----", "family": "asymmetric"},
    {"id": "pem-private-key", "label": "PEM PRIVATE KEY TERTANAM", "data": b"-----BEGIN PRIVATE KEY-----", "family": "asymmetric"},
    {"id": "pem-ec-private", "label": "PEM EC PRIVATE KEY TERTANAM", "data": b"-----BEGIN EC PRIVATE KEY-----", "family": "asymmetric"},
    {"id": "pem-certificate", "label": "PEM sertifikat X.509", "data": b"-----BEGIN CERTIFICATE-----", "family": "certificate"},
]

# Lead DER: SEQUENCE 30 82 LL LL [versi 02 01 00 — RSAPrivateKey] lalu
# modulus RSA 02 82 01 00 (INTEGER 256 byte = RSA-2048). Dua bentuk:
# RSAPublicKey (tanpa versi, gap 0) dan RSAPrivateKey (gap 3). Lead low —
# konfirmasi butuh parse ASN.1 lengkap.
_DER_RSA_RE = re.compile(rb"\x30\x82.{2}?(?:\x02\x01\x00)?\x02\x82\x01\x00",
                         re.DOTALL)

# Nama API kripto (exact-match, import PE). Dikelompokkan per keluarga
# agar kombinasi simetris/asimetris bisa dinilai.
CRYPTO_APIS: dict[str, str] = {
    # CryptoAPI (advapi32) — simetris
    "CryptAcquireContextA": "capapi", "CryptAcquireContextW": "capapi",
    "CryptGenKey": "capapi-key", "CryptDeriveKey": "capapi-key",
    "CryptEncrypt": "capapi-enc", "CryptDecrypt": "capapi-enc",
    "CryptImportKey": "capapi-key", "CryptExportKey": "capapi-key",
    "CryptGenRandom": "capi-rng", "CryptCreateHash": "capi-hash",
    # CNG (bcrypt.dll) — simetris + asimetris
    "BCryptOpenAlgorithmProvider": "cng",
    "BCryptGenerateSymmetricKey": "cng-enc",
    "BCryptEncrypt": "cng-enc", "BCryptDecrypt": "cng-enc",
    "BCryptGenerateKeyPair": "cng-asym", "BCryptImportKeyPair": "cng-asym",
    # OpenSSL — simetris + asimetris
    "EVP_EncryptInit_ex": "ssl-enc", "EVP_EncryptUpdate": "ssl-enc",
    "EVP_EncryptFinal_ex": "ssl-enc", "EVP_CIPHER_CTX_new": "ssl-enc",
    "AES_set_encrypt_key": "ssl-enc", "RSA_public_encrypt": "ssl-asym",
    "RAND_bytes": "ssl-rng",
}

SYMMETRIC_FAMILIES = {"symmetric", "capapi", "capapi-enc", "capapi-key", "cng", "cng-enc", "ssl-enc"}
ASYMMETRIC_FAMILIES = {"asymmetric", "cng-asym", "ssl-asym"}

ARTIFACT_TAIL_SIZES = (2048, 1024, 512, 256, 128)
ARTIFACT_TAIL_ENTROPY = 7.5

ARTIFACT_MAGICS: list[tuple[str, bytes]] = [
    ("zip-office", b"PK\x03\x04"), ("png", b"\x89PNG\r\n"),
    ("jpeg", b"\xff\xd8\xff"), ("pdf", b"%PDF-"),
    ("ole-doc", b"\xd0\xcf\x11\xe0"), ("gif", b"GIF8"),
    ("riff", b"RIFF"), ("sqlite", b"SQLite format 3\x00"),
    ("pe", b"MZ"), ("elf", b"\x7fELF"),
]

VERDICTS = ("NONE-KNOWN-FOUND", "PRIMITIVES-PRESENT")


def _entropy(data: bytes) -> float:
    """Entropi Shannon per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    freq: list[int] = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _add(findings: list[dict], fid: str, severity: str, detail: str,
         extra: dict | None = None) -> None:
    f = {"id": fid, "severity": severity, "detail": detail}
    if extra:
        f["evidence"] = extra
    findings.append(f)


def _find_all(data: bytes, needle: bytes, limit: int = MAX_HITS_PER_CONST) -> list[int]:
    hits: list[int] = []
    start = 0
    while len(hits) < limit:
        i = data.find(needle, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    return hits


# ---------------------------------------------------------------------------
# Parser tabel import PE (nama fungsi) — dari spesifikasi PE/COFF publik.
# ---------------------------------------------------------------------------

class PEFail(Exception):
    pass


def _rva_to_off(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            delta = rva - s["vaddr"]
            if delta < s["rawsize"]:
                return s["rawptr"] + delta
            return None
    return None


def _read_cstr(data: bytes, off: int | None, limit: int = 256) -> str | None:
    if off is None or off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        return None
    try:
        return data[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_pe_sections(data: bytes) -> tuple[dict, list[dict]]:
    """Baca header PE minimum utk RVA mapping (spesifikasi PE/COFF)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFail("bukan DOS/PE (magic MZ tidak ada)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) \
            or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEFail("signature PE tidak valid")
    _machine, nsec, _ts, _sym, _nsym, opt_size, _chars = \
        struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt_size < 2 or opt + opt_size > len(data):
        raise PEFail("optional header tidak lengkap")
    opt_magic = struct.unpack_from("<H", data, opt)[0]
    if opt_magic not in (0x10B, 0x20B):
        raise PEFail(f"optional header magic tak dikenal: {opt_magic:#x}")
    dd_base = opt + (112 if opt_magic == 0x20B else 96)
    # NumberOfRvaAndSizes: PE32 di opt+92, PE32+ di opt+108 (layout
    # windows-specific field lebih panjang pada PE32+)
    dd_count = struct.unpack_from("<I", data,
                                  opt + (108 if opt_magic == 0x20B
                                         else 92))[0]
    import_rva = 0
    if dd_count > 1 and dd_base + 16 <= len(data):
        import_rva = struct.unpack_from("<I", data, dd_base + 8)[0]
    sec_table = opt + opt_size
    if sec_table + 40 * nsec > len(data):
        raise PEFail("tabel section tidak lengkap")
    sections = []
    for i in range(nsec):
        base = sec_table + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII",
                                                           data, base + 8)
        sections.append({"vaddr": vaddr, "vsize": vsize,
                         "rawsize": rawsize, "rawptr": rawptr})
    return {"opt_magic": opt_magic, "import_rva": import_rva}, sections


def parse_import_names(data: bytes) -> tuple[list[dict], bool]:
    """(daftar {dll, name}, ok). ok=False = tabel tak terurai penuh
    (fail-closed — dicatat, bukan dianggap kosong)."""
    try:
        pe, sections = parse_pe_sections(data)
    except PEFail:
        return [], False
    if pe["import_rva"] == 0:
        return [], True
    off = _rva_to_off(pe["import_rva"], sections)
    if off is None:
        return [], False
    entry_size = 8 if pe["opt_magic"] == 0x20B else 4
    top_bit = 1 << (entry_size * 8 - 1)
    out: list[dict] = []
    for i in range(MAX_IMPORTS):
        desc = off + i * 20
        if desc + 20 > len(data):
            return out, False
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, desc)
        if oft == 0 and name_rva == 0 and ft == 0:
            return out, True
        dll = _read_cstr(data, _rva_to_off(name_rva, sections)) or "?"
        thunk_rva = oft or ft
        t_off = _rva_to_off(thunk_rva, sections)
        if t_off is None:
            continue
        for _j in range(MAX_IMPORTS):
            t = t_off + _j * entry_size
            if t + entry_size > len(data):
                return out, False
            val = (struct.unpack_from("<Q", data, t)[0] if entry_size == 8
                   else struct.unpack_from("<I", data, t)[0])
            if val == 0:
                break
            if val & top_bit:
                continue  # import per-ordinal — tanpa nama
            hint_off = _rva_to_off(val & 0xFFFFFFFF, sections)
            # IMAGE_IMPORT_BY_NAME = hint 2 byte lalu nama NUL-terminated
            name = _read_cstr(data, hint_off + 2 if hint_off is not None
                              else None, limit=128)
            if name:
                out.append({"dll": dll, "name": name})
                if len(out) >= MAX_IMPORTS:
                    return out, True
    return out, True


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def scan(path: Path, artifact: bool = False) -> dict:
    data = path.read_bytes()
    if not data:
        raise PEFail("berkas kosong")
    if len(data) > MAX_FILE_BYTES:
        raise PEFail(f"berkas {len(data)}B > batas pindai {MAX_FILE_BYTES}B")
    findings: list[dict] = []

    # 1) konstanta algoritma
    const_hits: list[dict] = []
    for c in CONSTANTS:
        offs = _find_all(data, c["data"])
        if offs:
            const_hits.append({"id": c["id"], "family": c["family"],
                               "label": c["label"], "offsets": offs,
                               "count": len(offs)})
    for ch in const_hits:
        _add(findings, f"const.{ch['id']}", "info",
             f"{ch['label']} — {ch['count']} kemunculan "
             f"(offset {', '.join(hex(o) for o in ch['offsets'][:4])})",
             {"offsets": ch["offsets"], "family": ch["family"]})
    if not any(ch["id"] == "aes-sbox" for ch in const_hits):
        offs = _find_all(data, _AES_SBOX_PREFIX)
        if offs:
            _add(findings, "const.aes-sbox-partial", "low",
                 "prefix AES S-box (16 byte) tanpa S-box penuh — tabel "
                 "sebagian (unroll) atau tabel re-computed", {"offsets": offs})
            const_hits.append({"id": "aes-sbox-partial", "family": "symmetric",
                               "label": "AES S-box prefix", "offsets": offs,
                               "count": len(offs)})

    # 2) penanda PEM / DER
    pem_hits: list[dict] = []
    for p in PEM_MARKERS:
        offs = _find_all(data, p["data"])
        if offs:
            pem_hits.append(p | {"offsets": offs})
            sev = "medium" if "PRIVATE" in p["label"] else "info"
            _add(findings, f"pem.{p['id']}", sev,
                 f"{p['label']} di offset {hex(offs[0])} — kunci privat "
                 "tertanam di biner = praktik buruk (lead, bukti saja)",
                 {"offsets": offs, "family": p["family"]})
    der_offs = [m.start() for m in _DER_RSA_RE.finditer(data)
                ][:MAX_HITS_PER_CONST]
    if der_offs:
        _add(findings, "der.rsa-modulus-lead", "low",
             "pola DER modulus RSA-2048 (30 82 .. 02 82 01 00) — lead, "
             "konfirmasi butuh parse ASN.1", {"offsets": der_offs})

    # 3) import PE
    pe_info: dict | None = None
    api_hits: list[dict] = []
    if data[:2] == b"MZ":
        imports, imp_ok = parse_import_names(data)
        api_named = [imp for imp in imports if imp["name"] in CRYPTO_APIS]
        for imp in api_named:
            fam = CRYPTO_APIS[imp["name"]]
            api_hits.append(imp | {"family": fam})
        if api_named:
            names = sorted({imp["name"] for imp in api_named})
            _add(findings, "pe.crypto-api-imports", "medium",
                 f"API kripto di tabel import: {', '.join(names)}",
                 {"apis": names,
                  "by_dll": sorted({imp["dll"] for imp in api_named})})
        if not imp_ok:
            _add(findings, "pe.import-unreadable", "info",
                 "tabel import tak terurai penuh (fail-closed — bukan "
                 "bukti tanpa-import-kripto)")
        pe_info = {"is_pe": True, "imports_total": len(imports),
                   "import_parse_ok": imp_ok,
                   "crypto_api_count": len(api_named)}

    # 4) kombinasi hybrid (simetris + asimetris di berkas yang sama)
    sym = any(ch["family"] in SYMMETRIC_FAMILIES for ch in const_hits) or \
        any(imp["family"] in SYMMETRIC_FAMILIES for imp in api_hits)
    asym = any(p["family"] in ASYMMETRIC_FAMILIES for p in pem_hits) or \
        der_offs or \
        any(imp["family"] in ASYMMETRIC_FAMILIES for imp in api_hits)
    if sym and asym:
        _add(findings, "combo.hybrid-encryption-signature", "medium",
             "bukti kripto simetris + asimetris di berkas yang sama — "
             "pola hybrid encryption (ransomware & aplikasi sah ber-TLS/"
             "lisensi sama-sama cocok; WAJIB review konteks)",
             {"symmetric_evidence": sym, "asymmetric_evidence": asym})

    # 5) mode artefak: tail entropy + inventaris header
    artifact_info: dict | None = None
    if artifact:
        magic = next(({"kind": k, "offset": data.find(m)}
                      for k, m in ARTIFACT_MAGICS if data.find(m) == 0), None)
        tail_matches = []
        for n in ARTIFACT_TAIL_SIZES:
            if len(data) >= n + 256:
                tail = data[-n:]
                ent = _entropy(tail)
                if ent >= ARTIFACT_TAIL_ENTROPY:
                    tail_matches.append({"bytes": n, "entropy": ent})
        if tail_matches:
            best = tail_matches[0]
            _add(findings, "artifact.tail-high-entropy", "medium",
                 f"entropi {best['bytes']} byte terakhir = "
                 f"{best['entropy']} >= {ARTIFACT_TAIL_ENTROPY} — kandidat "
                 "key-material/ciphertext ditempel di tail (ukuran umum "
                 "ciphertext RSA); gabung dgn triase manifest di "
                 "ransom_artifact_triage", {"matches": tail_matches})
        artifact_info = {"header_magic": magic,
                         "tail_high_entropy": tail_matches,
                         "note": "header terjaga = bukan vonis; pola "
                                 "enkripsi parsial/header-preserving "
                                 "memang menyimpan header asli"}

    present = bool(const_hits or pem_hits or der_offs or api_hits)
    verdict = "PRIMITIVES-PRESENT" if present else "NONE-KNOWN-FOUND"
    if not present:
        _add(findings, "meta.no-known-primitive", "info",
             "tidak ada primitif kripto yang dikenali di berkas ini — "
             "BUKAN klaim 'tanpa kripto' (algoritma custom/tabel runtime/"
             "obfusksi tetap tak terlihat)")

    return {
        "schema": SCHEMA,
        "file": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verdict": verdict,
        "pe": pe_info,
        "artifact": artifact_info,
        "findings": findings,
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Identifikasi primitif kripto tertanam di berkas "
                    "biner (read-only, NOL jaringan, tanpa dekompilasi)")
    ap.add_argument("--file", required=True, help="path berkas biner")
    ap.add_argument("--artifact", action="store_true",
                    help="mode artefak terenkripsi: entropi tail + "
                         "inventaris header asli")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=VERDICTS,
                    default="PRIMITIVES-PRESENT",
                    help="gate exit 1 bila verdict >= pilihan ini")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: berkas tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = scan(path, artifact=args.artifact)
    except PEFail as exc:
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
