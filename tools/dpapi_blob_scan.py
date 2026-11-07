"""[SAFETY: read-only] dpapi_blob_scan — inventarisasi blob DPAPI di
file/direktori untuk triase DFIR Windows (CWE-922/insiden credential
access), nol jaringan, TANPA dekripsi.

Konsep dari antrean port skill (SKILL-PORT-QUEUE #0178,
mukul975/abusing-dpapi-for-credential-access — atribusi ide): DPAPI
melindungi kredensial Windows (Credential Manager, browser, WiFi) dan
blob-nya bisa didekripsi offline bila masterkey bocor. Dibangun from
scratch dari struktur MS-DPAPI publik; yang dibangun di sini sisi
TRIASE (defend): MENGINVENTARISKAN blob — siapa pemilik masterkey GUID,
algoritma, konteks — bukan mendekripsi. Dekripsi butuh masterkey =
akses kredensial; di luar kontrak repo ini.

Struktur blob (MS-DPAPI, public):
  dwVersion u32 (=1) | guidProvider 16B (df9d8cd0-1501-11d1-8c7a-
  00c04fc297eb) | dwMasterKeyVersion u32 | guidMasterKey 16B |
  dwFlags u32 | szDescription (u32 len + UTF-16LE) | algCrypt u32 |
  algCryptLen u32 | dwSaltLen u32 + salt | dwStrongKeyLen u32 (+data) |
  dwOpaqueLen u32 + opaque (payload terenkripsi)
Lead yang dilaporkan (dari data, tanpa spekulasi):
  - algoritma lemah (RC4/DES/3DES-112) -> weak-alg
  - flag CRYPTPROTECT_LOCAL_MACHINE -> konteks mesin (bisa dipakai
    account lain di mesin yang sama -> perlu masuk inventaris)
  - flag CRYPTPROTECT_NO_RECOVERY -> tanpa jalur recovery
Fail-closed: path tidak ada -> exit 2; blob terpotong -> dihitung
"malformed", tidak crash; tanpa blob -> ringkasan kosong jujur.
Exit: 0 hasil (+ JSON bila --out); 2 input invalid.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

SCHEMA = "cyphron.dpapi-blob-scan/1"
PROVIDER_DPAPI = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
MAGIC = struct.pack("<I", 1) + PROVIDER_DPAPI  # dwVersion=1 + provider GUID
MAX_BLOBS = 10000

ALG_NAMES: dict[int, str] = {
    0x6601: "CALG_DES", 0x6603: "CALG_3DES", 0x6609: "CALG_3DES_112",
    0x6801: "CALG_RC4", 0x660E: "CALG_AES_128", 0x660F: "CALG_AES_192",
    0x6610: "CALG_AES_256", 0x6611: "CALG_AES_512",
}
WEAK_ALGS = {0x6601, 0x6603, 0x6609, 0x6801}  # DES/3DES/RC4
FLAG_NAMES: dict[int, str] = {
    0x1: "UI_FORBIDDEN", 0x4: "LOCAL_MACHINE", 0x20: "NO_RECOVERY",
    0x40: "VERIFY_PROTECTION", 0x20000000: "SYSTEM",
}


def guid_str(raw: bytes) -> str:
    """Format 16-byte Windows GUID (3 field pertama little-endian)."""
    d1 = struct.unpack("<I", raw[0:4])[0]
    d2 = struct.unpack("<H", raw[4:6])[0]
    d3 = struct.unpack("<H", raw[6:8])[0]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"


def parse_blob(buf: bytes, off: int) -> "dict | None":
    """Parse satu blob DPAPI di offset. None bila struktur tidak sah.

    Melempar tidak apa pun — malformed -> dict dengan flag malformed
    (fail-open terkendali utk triase, TANPA mengarang field).
    """
    if off + 20 > len(buf) or buf[off:off + 20] != MAGIC:
        return None
    blob: dict = {"offset": off}
    p = off + 20
    need = lambda n: p + n <= len(buf)  # noqa: E731
    if not need(4 + 16 + 4):
        blob["malformed"] = "truncated-setelah-provider"
        return blob
    mkver, = struct.unpack_from("<I", buf, p); p += 4
    mk_guid = guid_str(buf[p:p + 16]); p += 16
    flags, = struct.unpack_from("<I", buf, p); p += 4
    blob["masterkey_guid"] = mk_guid
    blob["masterkey_version"] = mkver
    blob["flags"] = f"0x{flags:08x}"
    blob["flag_names"] = [n for bit, n in sorted(FLAG_NAMES.items())
                          if flags & bit]
    if not need(4):
        blob["malformed"] = "truncated-sebelum-description"
        return blob
    dlen, = struct.unpack_from("<I", buf, p); p += 4
    if dlen > 512 or not need(dlen):
        blob["malformed"] = "description-tak-wajar"
        return blob
    blob["description"] = buf[p:p + dlen].decode("utf-16-le",
                                                 errors="replace")
    p += dlen
    if not need(8):
        blob["malformed"] = "truncated-sebelum-alg"
        return blob
    alg, alglen = struct.unpack_from("<II", buf, p); p += 8
    blob["alg_crypt"] = f"0x{alg:04x}"
    blob["alg_name"] = ALG_NAMES.get(alg, "UNKNOWN")
    blob["alg_len_bits"] = alglen
    if not need(4):
        blob["malformed"] = "truncated-sebelum-salt"
        return blob
    slen, = struct.unpack_from("<I", buf, p); p += 4
    if slen > 256 or not need(slen + 4):
        blob["malformed"] = "salt-tak-wajar"
        return blob
    blob["salt_len"] = slen
    p += slen
    stronglen, = struct.unpack_from("<I", buf, p); p += 4
    if stronglen > 4096 or not need(stronglen + 4):
        blob["malformed"] = "strongkey-tak-wajar"
        return blob
    p += stronglen
    oplen, = struct.unpack_from("<I", buf, p); p += 4
    if oplen > len(buf) or not need(oplen):
        blob["malformed"] = "opaque-tak-wajar"
        return blob
    blob["opaque_len"] = oplen
    blob["lead"] = _leads(blob)
    return blob


def _leads(blob: dict) -> "list[str]":
    """Lead defensif murni dari field yang terbaca."""
    leads: "list[str]" = []
    if blob.get("alg_name") in ("CALG_RC4", "CALG_DES", "CALG_3DES_112"):
        leads.append("weak-alg")
    if "LOCAL_MACHINE" in blob.get("flag_names", []):
        leads.append("machine-context")
    if "NO_RECOVERY" in blob.get("flag_names", []):
        leads.append("no-recovery")
    return leads


def scan_buffer(buf: bytes, limit: int = MAX_BLOBS) -> "list[dict]":
    """Cari semua magic blob di buffer, parse masing-masing."""
    out: "list[dict]" = []
    start = 0
    while len(out) < limit:
        idx = buf.find(MAGIC, start)
        if idx < 0:
            break
        # hindari blob tumpang tindih (magic di dalam opaque) — maju
        # melewati blob yang berhasil diparse
        blob = parse_blob(buf, idx)
        if blob is None:
            start = idx + 1
            continue
        out.append(blob)
        start = idx + 20
    return out


def scan_path(path: Path, max_files: int = 2000,
              max_file_mb: int = 64) -> dict:
    """Scan file atau direktori (bounded). Tanpa jaringan, read-only."""
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(f for f in path.rglob("*")
                       if f.is_file() and not f.is_symlink())[:max_files]
    else:
        raise ValueError(f"path tidak ada: {path}")
    scanned = skipped = 0
    blobs: "list[dict]" = []
    for f in files:
        if f.stat().st_size > max_file_mb * 1024 * 1024:
            skipped += 1
            continue
        try:
            data = f.read_bytes()
        except OSError:
            skipped += 1
            continue
        scanned += 1
        for blob in scan_buffer(data):
            blob["file"] = str(f)
            blobs.append(blob)
    leads: "list[str]" = sorted({l for b in blobs for l in b.get("lead", [])})
    return {
        "schema": SCHEMA,
        "path": str(path),
        "files_scanned": scanned,
        "files_skipped": skipped,
        "blobs_found": len(blobs),
        "masterkey_guids": sorted({b["masterkey_guid"] for b in blobs
                                   if "masterkey_guid" in b}),
        "leads": leads,
        "blobs": blobs[:200],
        "note": "read-only inventaris DFIR; TIDAK mendekripsi — dekripsi "
                "butuh masterkey (akses kredensial) dan di luar kontrak.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="dpapi_blob_scan — inventarisasi blob DPAPI untuk "
                    "triase DFIR (read-only, tanpa dekripsi, nol jaringan).")
    ap.add_argument("--path", required=True, help="file atau direktori")
    ap.add_argument("--max-files", type=int, default=2000,
                    help="batas file utk scan direktori (default 2000)")
    ap.add_argument("--max-file-mb", type=int, default=64,
                    help="lewati file lebih besar dari ini MB (default 64)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"[dpapi] path tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = scan_path(path, args.max_files, args.max_file_mb)
    except OSError as exc:
        print(f"[dpapi] gagal membaca (fail-closed): {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[dpapi] files={result['files_scanned']} "
          f"(skip {result['files_skipped']}) blobs={result['blobs_found']}")
    for g in result["masterkey_guids"]:
        print(f"[dpapi] masterkey GUID: {g}")
    for l in result["leads"]:
        print(f"[dpapi] lead: {l}")
    for b in result["blobs"][:5]:
        d = b.get("description", "")
        print(f"[dpapi] blob {b.get('file','?')} @0x{b.get('offset',0):x} "
              f"alg={b.get('alg_name')} desc={d!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
