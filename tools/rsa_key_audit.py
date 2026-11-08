r"""[AUDIT: read-only] rsa_key_audit — audit OFFLINE kekuatan & penyimpanan
kunci RSA (PEM PKCS#1/PKCS#8/SPKI, OpenSSH privat, kunci publik SSH)
sesuai NIST SP 800-57: ukuran modulus, eksponen, passphrase, dan izin
berkas. TANPA mengeksekusi/menyentuh material kripto lebih jauh.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-rsa-key-pair-management' (#0694 — atribusi konsep;
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH TANPA menyalin kode
sumber itu. Generator/rotasi kunci & signing PSS = runbook operasional
(bukan alat audit); yang diekstrak = sisi VALIDASI kunci yang sudah
ada — deterministik, stdlib base64/binascii/struct saja (TANPA lib
kripto; parsing DER/ASN.1 ditulis sendiri, minimalis).

Ranah dibagi eksplisit:
  - cert_chain_audit : sertifikat X.509 (chain, expiry, algoritme
    tanda) — sudah cek rsa-pendek PADA sertifikat. Tool ini melayani
    KUNCI BARE (file kunci privat/publik, authorized_keys) yang tidak
    punya sertifikat — input kelas berbeda.
  - ssl_tls_analyzer / tls_cipher_suites_checker : negosiasi live
    target — di luar kelas offline tool ini.

Input -> mekanisme -> output:
  - Input : --key FILE[,FILE...] dan/atau --dir DIR (ekstensi apa pun;
            file dicoba deteksi format, bukan ditebak dari nama).
            --min-bits (default 2048) — di bawah ini = temuan high.
  - Mekanisme: (1) PEM armor -> base64 -> DER; (2) walker ASN.1
            minimalis: PKCS#1 privat (n=INTEGER ke-2, e=ke-3), PKCS#1
            publik (n,e), PKCS#8 privat (OID rsaEncryption -> OCTET
            STRING -> PKCS#1), SPKI publik (BIT STRING -> PKCS#1
            publik), OpenSSH privat (magic "openssh-key-v1" + cipher
            name), wire kunci publik SSH ("ssh-rsa" + mpint e + mpint
            n); (3) cek deterministik di bawah.
  - Cek    : rsa-kecil          (high)  : bits < --min-bits (1024 =
            faktorisasi praktis; NIST 800-57: >=2048 utk 112-bit).
            rsa-rekomendasi-2030 (info) : 2048 <= bits < 3072 — aman
            s.d. 2030; >=3072 utk pasca-2030 (catatan, bukan gagal).
            eksponen-lemah      (high)  : e == 3 (PKCS#1 v1.5 rentan);
            e bukan 3/65537     (info)  : tidak lazim.
            privat-tanpa-passphrase (medium): PEM privat tanpa ENCRYPTED
            (PKCS#8 "BEGIN PRIVATE KEY", PKCS#1 "BEGIN RSA PRIVATE
            KEY", atau OpenSSH cipher=none).
            izin-terbuka        (medium): POSIX group/other bisa baca
            kunci privat (Windows: dilewati, dicatat di meta).
            parse-gagal         (dihitung di meta, bukan temuan;
            fail-closed — TIDAK pernah dianggap "bukan kunci = aman").
  - Output: findings.json (kontrak cyphron) + meta distribusi ukuran
            kunci; setiap temuan membawa poc ringkas (bit-length,
            eksponen, format) = bukti parse aritmetika.

Verdict: fakta struktur kunci terbukti dari artefak -> status
confirmed, evidence_kind "arithmetic", verdict L3 DETERMINISTICALLY_
VERIFIED dgn poc non-kosong (kontrak make_finding terpenuhi).

Fail-closed: file tidak ada / tidak ada kunci ter-parse -> exit 2;
file lain (EC/DSA/sertifikat/bukan-kunci) dicatat skipped dgn alasan,
tidak diam-diam. NOL jaringan.

Pemakaian:
  python tools/rsa_key_audit.py --key id_rsa,id_rsa.pub --out f.json
  python tools/rsa_key_audit.py --dir keys/ --min-bits 2048
Exit: 0 bersih, 1 ada temuan, 2 error input.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import re
import stat
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.rsa-key-audit/1"
MAX_FILE_BYTES = 8 * 1024 * 1024
MIN_BITS_DEFAULT = 2048
RE_2030 = 3072  # NIST 800-57: >=3072 utk 128-bit (pasca-2030)
STD_EXPONENT = 65537

RE_PEM = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----\s*(.*?)-----END \1-----", re.S)
SSH_KEY_TYPES = ("ssh-rsa", "ssh-ed25519", "ssh-dss",
                 "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                 "ecdsa-sha2-nistp521")


# ---------------------------------------------------------------- DER
class DERError(ValueError):
    pass


def _der_read_len(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise DERError("len out of range")
    b = buf[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7F
    if n == 0 or n > 4 or pos + n > len(buf):
        raise DERError("panjang DER tidak wajar")
    length = int.from_bytes(buf[pos:pos + n], "big")
    return length, pos + n


def der_children(buf: bytes) -> list[tuple[int, bytes]]:
    """Parse STREAM TLV -> [(tag, value_bytes), ...] (minimalis: hanya
    struktur yang dipakai RSA; bukan parser ASN.1 umum)."""
    out = []
    pos = 0
    while pos < len(buf):
        if pos + 2 > len(buf):
            raise DERError("struktur DER terpotong")
        tag = buf[pos]
        length, pos2 = _der_read_len(buf, pos + 1)
        if pos2 + length > len(buf):
            raise DERError("value melebihi buffer")
        out.append((tag, buf[pos2:pos2 + length]))
        pos = pos2 + length
    return out


def _seq_contents(buf: bytes) -> bytes:
    """buf = satu TLV SEQUENCE utuh -> kembalikan ISINYA; stream TLV
    -> apa adanya. Ini yang membuat pemanggil der_children selalu
    bekerja pada stream, bukan pada wrapper tag 0x30."""
    if buf and buf[0] == 0x30:
        _, pos2 = _der_read_len(buf, 1)
        return buf[pos2:]
    return buf


def _ints_from_pkcs1(buf: bytes) -> tuple[int, int] | None:
    """PKCS#1: privat = SEQUENCE{version, n, e, ...} (3 INTEGER
    pertama), publik = SEQUENCE{n, e} (2 INTEGER). -> (n, e)."""
    try:
        children = der_children(_seq_contents(buf))
    except DERError:
        return None
    ints = [v for t, v in children if t == 0x02]
    if len(ints) >= 3:  # privat: version, n, e
        n, e = ints[1], ints[2]
    elif len(ints) == 2:  # publik: n, e
        n, e = ints[0], ints[1]
    else:
        return None
    n = int.from_bytes(n, "big")
    e = int.from_bytes(e, "big")
    if n <= 0 or e <= 0:
        return None
    return n, e


def _pem_body(body_b64: str) -> bytes | None:
    try:
        return base64.b64decode("".join(body_b64.split()), validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_pem_key(text: str) -> dict | None:
    """Kembalikan info kunci RSA dari PEM, atau None bila bukan."""
    m = RE_PEM.search(text)
    if not m:
        return None
    pem_type = m.group(1).strip().upper()
    body = _pem_body(m.group(2))
    if body is None:
        return {"kind": "pem-unreadable", "pem_type": pem_type}
    info: dict = {"pem_type": pem_type}
    if pem_type in ("RSA PRIVATE KEY", "PRIVATE KEY",
                    "ENCRYPTED PRIVATE KEY"):
        info["kind"] = "private"
        if pem_type == "ENCRYPTED PRIVATE KEY" or \
                "PROC-TYPE:" in text.upper():
            # PKCS#8 terenkripsi / PKCS#1 legacy terenkripsi (headers
            # Proc-Type:4,ENCRYPTED) — materi tak terbaca tanpa
            # passphrase; itu justru kondisi yang benar.
            info["encrypted"] = True
            return info
        info["encrypted"] = False
        try:
            children = der_children(body)
        except DERError:
            return {"kind": "pem-unreadable", "pem_type": pem_type}
        if pem_type == "RSA PRIVATE KEY":
            ints = _ints_from_pkcs1(body)
            if ints:
                info["bits"] = ints[0].bit_length()
                info["exponent"] = ints[1]
            else:
                return {"kind": "pem-unreadable", "pem_type": pem_type}
        else:  # PKCS#8 unencrypted: SEQUENCE{ver, SEQ{oid, NULL}, OCTET}
            oid_rsa = False
            octet = None
            try:
                children = der_children(_seq_contents(body))
            except DERError:
                return {"kind": "pem-unreadable", "pem_type": pem_type}
            for t, v in children:
                if t == 0x30:
                    for t2, v2 in _safe_children(v):
                        if t2 == 0x06 and v2[:9] == bytes(
                                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                                 0x01, 0x01, 0x01]):
                            # rsaEncryption 1.2.840.113549.1.1.1 lengkap
                            oid_rsa = True
                if t == 0x04 and octet is None:
                    octet = v
            if not oid_rsa or octet is None:
                return {"kind": "non-rsa", "pem_type": pem_type}
            ints = _ints_from_pkcs1(octet)
            if not ints:
                return {"kind": "pem-unreadable", "pem_type": pem_type}
            info["bits"], info["exponent"] = ints[0].bit_length(), ints[1]
        return info
    if pem_type in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        info["kind"] = "public"
        target = body
        try:
            if pem_type == "PUBLIC KEY":  # SPKI: SEQ{SEQ{oid,NULL}, BITSTR}
                inner = der_children(_seq_contents(body))
                bit = next((v for t, v in inner if t == 0x03), None)
                if bit is None or len(bit) < 2:
                    return {"kind": "pem-unreadable", "pem_type": pem_type}
                target = bit[1:]  # buang byte unused-bits
        except DERError:
            return {"kind": "pem-unreadable", "pem_type": pem_type}
        ints = _ints_from_pkcs1(target)
        if not ints:
            return {"kind": "non-rsa", "pem_type": pem_type}
        info["bits"], info["exponent"] = ints[0].bit_length(), ints[1]
        return info
    if pem_type == "OPENSSH PRIVATE KEY":
        info["kind"] = "private"
        try:
            if not body.startswith(b"openssh-key-v1\x00"):
                return {"kind": "pem-unreadable", "pem_type": pem_type}
            pos = 15
            clen = struct.unpack(">I", body[pos:pos + 4])[0]
            pos += 4
            cipher = body[pos:pos + clen].decode("ascii", "replace")
            info["cipher"] = cipher
            info["encrypted"] = cipher != "none"
        except (struct.error, IndexError):
            return {"kind": "pem-unreadable", "pem_type": pem_type}
        return info
    return None  # PEM lain (CERTIFICATE/EC PARAMETERS/...) = bukan kunci


def _safe_children(buf: bytes) -> list[tuple[int, bytes]]:
    try:
        return der_children(buf)
    except DERError:
        return []


def parse_ssh_public(line: str) -> dict | None:
    """'ssh-rsa AAAA... comment' -> info; None bila bukan kunci SSH."""
    parts = line.split()
    if len(parts) < 2 or parts[0] not in SSH_KEY_TYPES:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    if parts[0] != "ssh-rsa":
        return {"kind": "non-rsa", "ssh_type": parts[0]}
    # wire: [len][ "ssh-rsa" ][len][ mpint e ][len][ mpint n ]
    try:
        pos = 0
        vals = []
        while pos < len(blob) and len(vals) < 3:
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            pos += 4
            vals.append(blob[pos:pos + n])
            pos += n
        if len(vals) < 3 or vals[0] != b"ssh-rsa":
            return {"kind": "non-rsa", "ssh_type": parts[0]}
        e = int.from_bytes(vals[1], "big") or 0
        n_bytes = vals[2]
        bits = int.from_bytes(n_bytes, "big").bit_length() if n_bytes else 0
    except (struct.error, IndexError):
        return None
    if bits <= 0:
        return None
    return {"kind": "public", "ssh_type": "ssh-rsa",
            "bits": bits, "exponent": e}


def parse_file(path: Path) -> dict | None:
    """Deteksi format: PEM dulu, lalu baris SSH publik; None = bukan."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        return None
    if b"\x00" in raw[:8192]:
        return None
    text = raw.decode("utf-8", "replace")
    info = parse_pem_key(text)
    if info is not None:
        return info
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        info = parse_ssh_public(line)
        if info is not None:
            return info
    return None


def _posix_public_read(path: Path) -> bool:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


def audit_file(path: Path, min_bits: int,
               platform: str) -> tuple[list[dict], dict]:
    """Audit satu file kunci -> (findings, note)."""
    notes: dict = {}
    try:
        raw_head = path.read_bytes()[:8192]
    except OSError as e:
        return [], {"path": str(path), "status": "unreadable",
                    "detail": str(e)}
    if len(path.read_bytes()) > MAX_FILE_BYTES:
        return [], {"path": str(path), "status": "skipped",
                    "detail": "terlalu besar"}
    info = parse_file(path)
    if info is None:
        if b"-----BEGIN" in raw_head:
            kind = "pem-lain"
            m = RE_PEM.search(raw_head.decode("utf-8", "replace"))
            label = m.group(1) if m else "tidak dikenal"
            return [], {"path": str(path), "status": "skipped",
                        "detail": f"PEM '{label}' — bukan kunci RSA "
                                  "(cert = cert_chain_audit)"}
        return [], {"path": str(path), "status": "skipped",
                    "detail": "bukan PEM/kunci SSH"}
    if info.get("kind") in ("pem-unreadable", "non-rsa"):
        return [], {"path": str(path), "status": "skipped",
                    "detail": info.get("pem_type")
                    or info.get("ssh_type") or info["kind"]}
    notes["path"] = str(path)
    notes["status"] = "parsed"
    notes["kind"] = info["kind"]
    notes["bits"] = info.get("bits")
    notes["exponent"] = info.get("exponent")
    notes["encrypted"] = info.get("encrypted")

    findings: list[dict] = []
    bits = info.get("bits")
    exp = info.get("exponent")
    fmt = (f"{info['pem_type']}" if info.get("pem_type")
           else f"SSH {info.get('ssh_type')}")
    poc_bits = f"{fmt}: modulus {bits} bit, e={exp}" if bits else f"{fmt}"
    is_private = info["kind"] == "private"

    if bits is not None:
        if bits < min_bits:
            findings.append(make_finding(
                tool="rsa_key_audit",
                title=f"kunci RSA {bits} bit < {min_bits} bit",
                severity="high",
                description=(
                    f"Kunci {fmt} bermodulus {bits} bit — di bawah "
                    f"ambang {min_bits}. {bits}-bit RSA (1024 atau "
                    f"lebih kecil) = faktorisasi praktis; NIST SP "
                    f"800-57 mensyaratkan >= 2048 bit (112-bit) dan "
                    f">= 3072 bit untuk pasca-2030."),
                recommendation="Ganti kunci dengan RSA >= 3072 bit "
                               "(atau Ed25519) dan rotasi penggunaannya.",
                file_path=str(path),
                status="confirmed",
                evidence_kind="arithmetic",
                poc=poc_bits,
                confidence=1.0,
                finding_class="weakness",
                extra={"bits": bits, "min_bits": min_bits},
            ))
        elif bits < RE_2030:
            findings.append(make_finding(
                tool="rsa_key_audit",
                title=f"kunci RSA {bits} bit (112-bit, cukup s.d. 2030)",
                severity="info",
                description=(
                    f"Kunci {fmt} bermodulus {bits} bit = kekuatan "
                    f"112-bit: masih valid hingga ~2030 menurut NIST "
                    f"SP 800-57; untuk pasca-2030 pakai >= 3072 bit. "
                    f"Catatan perencanaan, bukan kegagalan."),
                recommendation="Masukkan ke rencana rotasi kunci "
                               "jangka panjang (3072 bit / Ed25519).",
                file_path=str(path),
                status="confirmed",
                evidence_kind="arithmetic",
                poc=poc_bits,
                confidence=1.0,
                finding_class="weakness",
                extra={"bits": bits},
            ))
    if exp is not None and exp == 3:
        findings.append(make_finding(
            tool="rsa_key_audit",
            title="eksponen RSA e=3",
            severity="high",
            description=(
                f"Kunci {fmt} memakai eksponen publik e=3 — dengan "
                f"padding tidak benar (PKCS#1 v1.5) rentan serangan "
                f" Bleichenbacher-style; e=65537 standar aman."),
            recommendation="Regenerasi kunci dengan e=65537.",
            file_path=str(path),
            status="confirmed",
            evidence_kind="arithmetic",
            poc=poc_bits,
            confidence=1.0,
            finding_class="weakness",
            extra={"exponent": exp},
        ))
    elif exp is not None and exp != STD_EXPONENT:
        findings.append(make_finding(
            tool="rsa_key_audit",
            title=f"eksponen RSA tidak lazim (e={exp})",
            severity="info",
            description=(
                f"Kunci {fmt} memakai e={exp} (bukan 65537 standar). "
                f"Bukan otomatis lemah, tapi di luar praktik umum — "
                f"layak dikonfirmasi."),
            recommendation="Verifikasi kebijakan kunci pemilik; "
                           "standarkan ke 65537.",
            file_path=str(path),
            status="confirmed",
            evidence_kind="arithmetic",
            poc=poc_bits,
            confidence=0.9,
            finding_class="weakness",
            extra={"exponent": exp},
        ))
    if is_private and not info.get("encrypted", False):
        findings.append(make_finding(
            tool="rsa_key_audit",
            title="kunci privat tanpa passphrase",
            severity="medium",
            description=(
                f"Kunci privat {fmt} TIDAK terenkripsi (passphrase "
                f"absen{' — OpenSSH cipher=none' if info.get('cipher') == 'none' else ''})."
                f" Siapa pun yang membaca berkas memakai kuncinya "
                f"langsung; NIST SP 800-57 mensyaratkan proteksi "
                f"penyimpanan (mis. AES-256 passphrase / agent)."),
            recommendation="Enkripsi kunci privat (PKCS#8 ENCRYPTED "
                           "atau OpenSSH bcrypt) + simpan 0600.",
            file_path=str(path),
            status="confirmed",
            evidence_kind="artifact-parse",
            poc=f"{fmt}: encrypted=False"
                + (f", cipher={info.get('cipher')}"
                   if info.get("cipher") else ""),
            confidence=1.0,
            finding_class="weakness",
            extra={"encrypted": False},
        ))
    if is_private and platform == "posix" and _posix_public_read(path):
        findings.append(make_finding(
            tool="rsa_key_audit",
            title="izin berkas kunci privat terbuka",
            severity="medium",
            description=(
                f"Kunci privat {str(path)} bisa dibaca group/other "
                f"(mode bukan 0600) — melanggar NIST SP 800-57 "
                f"penyimpanan kunci privat."),
            recommendation="chmod 600 kunci privat.",
            file_path=str(path),
            status="confirmed",
            evidence_kind="artifact-parse",
            poc="mode group/other readable",
            confidence=1.0,
            finding_class="weakness",
            extra={"posix_perm": "open"},
        ))
    return findings, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="audit kekuatan kunci RSA (offline, stdlib)")
    ap.add_argument("--key", help="koma-pisah daftar file kunci")
    ap.add_argument("--dir", help="direktori pemindaian kunci")
    ap.add_argument("--min-bits", type=int, default=MIN_BITS_DEFAULT)
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args(argv)

    paths: list[Path] = []
    if args.key:
        for part in args.key.split(","):
            part = part.strip()
            if part:
                p = Path(part)
                if not p.is_file():
                    print(f"[rsa_key_audit] file tidak ada: {part}",
                          file=sys.stderr)
                    return 2
                paths.append(p)
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"[rsa_key_audit] direktori tidak ada: {args.dir}",
                  file=sys.stderr)
            return 2
        for p in sorted(d.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                paths.append(p)
    if not paths:
        print("[rsa_key_audit] tanpa --key/--dir: tidak ada kunci "
              "-> tidak ada kesimpulan (fail-closed)", file=sys.stderr)
        return 2

    platform = "posix" if os.name == "posix" else "windows"
    findings: list[dict] = []
    notes: list[dict] = []
    bits_hist: dict[str, int] = {}
    parsed = 0
    for p in paths:
        f, note = audit_file(p, args.min_bits, platform)
        findings.extend(f)
        notes.append(note)
        if note.get("status") == "parsed" and note.get("bits"):
            parsed += 1
            bucket = ">=3072" if note["bits"] >= RE_2030 else str(
                note["bits"])
            bits_hist[bucket] = bits_hist.get(bucket, 0) + 1

    if not any(n["status"] == "parsed" for n in notes) and not findings:
        # tidak ada kunci ter-parse sama sekali = input tidak mengandung
        # kunci RSA yang bisa dinilai — fail-closed, bukan "bersih"
        skipped = sum(1 for n in notes if n["status"] == "skipped")
        print(f"[rsa_key_audit] 0 kunci ter-parse dari {len(notes)} file "
              f"({skipped} skipped) — tidak ada kesimpulan (fail-closed)",
              file=sys.stderr)
        return 2

    meta = {
        "schema": SCHEMA,
        "files": len(paths),
        "parsed": parsed,
        "skipped": sum(1 for n in notes if n["status"] == "skipped"),
        "unreadable": sum(1 for n in notes if n["status"] == "unreadable"),
        "bits_distribution": dict(sorted(bits_hist.items())),
        "min_bits": args.min_bits,
        "perm_check": platform,
        "notes": notes,
        "nist_note": "<2048 high; 2048-3071 = 112-bit cukup s.d. 2030; "
                     ">=3072 disarankan pasca-2030 (SP 800-57)",
    }
    write_findings(args.out, findings, meta)
    if findings:
        print(f"[rsa_key_audit] {len(findings)} temuan dari "
              f"{parsed} kunci ter-parse -> {args.out}")
        return 1
    print(f"[rsa_key_audit] {parsed} kunci bersih (min {args.min_bits} "
          f"bit) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
