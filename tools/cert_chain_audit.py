r"""[SAFETY: read-only] cert_chain_audit — auditor rantai sertifikat X.509
offline (PEM/DER, stdlib murni, tanpa dekripsi dan tanpa jaringan).

Input -> mekanisme -> output:
  - Input : file .pem/.crt/.cer/.der (satu file = satu rantai, urutan
            leaf -> root; PEM boleh multi-cert) atau direktori.
            Read-only, NOL jaringan, tidak memverifikasi tanda tangan
            kriptografi — hanya struktur.
  - Mekanisme: parser DER minimal (TLV, OID, Name, UTCTime/GeneralizedTime,
            SubjectPublicKeyInfo, extensions) -> model per-cert ->
            cek deterministik per sertifikat + per rantai.
  - Output: daftar lead {cert, line, check, severity, message} + meta
            (jumlah cert, subjek tiap cert).

Cek (semua verdict = LEAD, bukan klaim kekompakan CA):
  file-unparsed        (high)  : PEM/DER rusak, block tak tertutup, waktu
                                  tidak valid — fail-closed, tidak pernah
                                  dihitung bersih.
  chain-order          (high)  : issuer cert ke-i != subject cert sebelumnya
                                  — rantai putus.
  self-signed-tengah   (medium): issuer==subject di posisi bukan terakhir.
  kedaluwarsa          (high)  : notAfter < now (atau --now).
  belum-berlaku        (high)  : notBefore > now (atau --now).
  masa-berlaku-panjang (info)  : > 398 hari (batas CA/Browser forum —
                                  normal utk CA internal, info saja).
  ca-tanpa-bc          (high)  : cert di posisi CA (bukan terakhir) tanpa
                                  basicConstraints CA:TRUE.
  leaf-ca-true         (medium): leaf dalam rantai >= 2 masih CA:TRUE —
                                  risiko mis-issuance.
  keyusage-ca-lemah    (medium): cert CA punya keyUsage TAPI tanpa
                                  keyCertSign; CA tanpa keyUsage sama
                                  sekali -> info (RFC 5280 SHOULD).
  pathlen-langgar      (high)  : jumlah CA di bawah cert > pathLenConstraint
                                  (hanya saat rantai terhubung).
  sig-lemah            (high)  : MD2/MD5/SHA-1 pada cert yang menandatangani
                                  cert lain; self-signature SHA-1 pada root
                                  -> info (tidak divalidasi dalam jalur chain).
  rsa-pendek           (high)  : modulus RSA < 2048 bit.
  ec-kecil             (high)  : kurva EC < 256 bit (P-192/P-224).
  kunci-tak-dikenal    (info)  : tipe kunci/kurva di luar peta — butuh
                                  validasi lanjutan, bukan temuan pasti.
  serial-lemah         (medium): serial < 64 bit entropi atau negatif
                                  (RFC 5280 4.1.2.2).
  tanpa-revokasi       (info)  : leaf tanpa CRL DP maupun AIA/OCSP —
                                  pencabutan tak bisa diperiksa klien.

Fail-closed: parse error per file = lead high "file-unparsed" dan file
TIDAK dihitung bersih. Exit: 0 bersih; 1 ada lead >= --fail-on
(default high); 2 error input (sumber tidak ada / tanpa file valid).

Pemakaian:
  python tools/cert_chain_audit.py --source chain.pem
  python tools/cert_chain_audit.py --source certs/ --json hasil.json --fail-on medium
  python tools/cert_chain_audit.py --source chain.pem --now 2026-11-08T00:00:00Z
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secai.cert-chain-audit/1"
CERT_EXTS = {".pem", ".crt", ".cer", ".der"}

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}

# --- OID ---------------------------------------------------------------

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.3.14.3.2.29": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
}
# panjang bit kurva NIST/rekomendasi; kurva di luar peta -> info kunci-tak-dikenal
EC_CURVE_BITS = {
    "1.2.840.10045.3.1.1": 192,   # P-192 (secp192r1)
    "1.3.132.0.33": 224,          # P-224 (secp224r1)
    "1.2.840.10045.3.1.7": 256,   # P-256 (secp256r1)
    "1.3.132.0.10": 256,          # secp256k1
    "1.3.132.0.34": 384,          # P-384
    "1.3.132.0.35": 521,          # P-521
}
OID_BC = "2.5.29.19"
OID_KU = "2.5.29.15"
OID_CRLDP = "2.5.29.31"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_AIA_OCSP = "1.3.6.1.5.5.7.48.1"

TAG_INT = 0x02
TAG_BITSTR = 0x03
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8 = 0x0C
TAG_PRINTABLE = 0x13
TAG_T61 = 0x14
TAG_IA5 = 0x16
TAG_UTCTIME = 0x17
TAG_GENERALIZED = 0x18
TAG_BMP = 0x1E
TAG_SEQ = 0x30
TAG_SET = 0x31


class ParseError(ValueError):
    """DER/PEM tidak valid — memicu lead file-unparsed (fail-closed)."""


def _read_tlv(data: bytes, off: int) -> tuple[int, int, int]:
    """Baca satu TLV -> (tag, posisi value, panjang value)."""
    if off + 2 > len(data):
        raise ParseError("DER terpotong di header TLV")
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise ParseError("tag multi-byte tidak didukung")
    idx = off + 1
    first = data[idx]
    idx += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ParseError("panjang indefinit tidak valid di DER")
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or idx + n > len(data):
            raise ParseError("panjang long-form tidak valid")
        length = int.from_bytes(data[idx:idx + n], "big")
        idx += n
    if idx + length > len(data):
        raise ParseError("panjang value melewati ujung data")
    return tag, idx, length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """Anak-anak elemen konstruktif dalam rentang [start, end)."""
    out = []
    off = start
    while off < end:
        tag, vpos, vlen = _read_tlv(data, off)
        out.append((tag, vpos, vlen))
        off = vpos + vlen
    if off != end:
        raise ParseError("elemen konstruktif tidak pas")
    return out


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise ParseError("OID kosong")
    if raw[-1] & 0x80:
        raise ParseError("OID terpotong di tengah arc")
    if raw[0] < 40:
        parts = ["0", str(raw[0])]
    elif raw[0] < 80:
        parts = ["1", str(raw[0] - 40)]
    else:
        parts = ["2", str(raw[0] - 80)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _decode_string(tag: int, raw: bytes) -> str:
    if tag == TAG_UTF8:
        return raw.decode("utf-8", "replace")
    if tag in (TAG_PRINTABLE, TAG_IA5):
        return raw.decode("ascii", "replace")
    if tag == TAG_T61:
        return raw.decode("latin-1", "replace")
    if tag == TAG_BMP:
        return raw.decode("utf-16-be", "replace")
    if tag in (TAG_INT, TAG_BITSTR):
        return binascii.hexlify(raw).decode("ascii")
    return binascii.hexlify(raw).decode("ascii")


def _decode_name(data: bytes, start: int, end: int) -> str:
    """RDNSequence -> 'oid=value|oid=value' kanonis (urutan kemunculan)."""
    pairs = []
    for tag_set, s_start, s_len in _children(data, start, end):
        if tag_set != TAG_SET:
            raise ParseError("RDN bukan SET")
        for tag_seq, a_start, a_len in _children(data, s_start, s_start + s_len):
            if tag_seq != TAG_SEQ:
                raise ParseError("ATV bukan SEQUENCE")
            kids = _children(data, a_start, a_start + a_len)
            if len(kids) != 2:
                raise ParseError("ATV harus dua elemen")
            tag_oid, o_start, o_len = kids[0]
            if tag_oid != TAG_OID:
                raise ParseError("ATV elemen pertama bukan OID")
            oid = _decode_oid(data[o_start:o_start + o_len])
            tag_val, v_start, v_len = kids[1]
            value = _decode_string(tag_val, data[v_start:v_start + v_len])
            pairs.append(f"{oid}={value}")
    return "|".join(pairs)


def _decode_time(data: bytes, start: int, end: int) -> datetime.datetime:
    raw = data[start:end].decode("ascii", "strict")
    if len(raw) and raw[-1] not in "Zz":
        raise ParseError("waktu bukan UTC-Z")
    body = raw[:-1]
    try:
        if len(body) == 12:  # UTCTime YYMMDDHHMMSS
            yy = int(body[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime.datetime(
                year, int(body[2:4]), int(body[4:6]), int(body[6:8]),
                int(body[8:10]), int(body[10:12]), tzinfo=datetime.timezone.utc)
        if len(body) == 14:  # GeneralizedTime YYYYMMDDHHMMSS
            return datetime.datetime(
                int(body[:4]), int(body[4:6]), int(body[6:8]), int(body[8:10]),
                int(body[10:12]), int(body[12:14]), tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise ParseError(f"waktu tidak valid: {raw}") from exc
    raise ParseError(f"format waktu tidak dikenal: {raw}")


def _int_value(data: bytes, start: int, end: int) -> int:
    if start >= end:
        raise ParseError("INTEGER kosong")
    return int.from_bytes(data[start:end], "big", signed=True)


def _bitstr_payload(data: bytes, start: int, end: int) -> bytes:
    if start >= end:
        raise ParseError("BIT STRING kosong")
    unused = data[start]
    if unused > 7:
        raise ParseError("BIT STRING unused-bit tidak valid")
    return data[start + 1:end]


class Cert:
    """Model minimal satu sertifikat (field yang dipakai cek saja)."""

    def __init__(self, data: bytes, label: str):
        tag, vpos, vlen = _read_tlv(data, 0)
        if tag != TAG_SEQ:
            raise ParseError("elemen teratas bukan SEQUENCE")
        body = _children(data, vpos, vpos + vlen)
        if len(body) < 3:
            raise ParseError("Certificate < 3 elemen")
        tbs_tag, tbs_pos, tbs_len = body[0]
        if tbs_tag != TAG_SEQ:
            raise ParseError("TBSCertificate bukan SEQUENCE")
        # signatureAlgorithm + signatureValue wajib ada
        sig_alg_tag, sig_alg_pos, sig_alg_len = body[1]
        if sig_alg_tag != TAG_SEQ:
            raise ParseError("signatureAlgorithm bukan SEQUENCE")
        alg_kids = _children(data, sig_alg_pos, sig_alg_pos + sig_alg_len)
        if not alg_kids or alg_kids[0][0] != TAG_OID:
            raise ParseError("signatureAlgorithm tanpa OID")
        self.sig_oid = _decode_oid(
            data[alg_kids[0][1]:alg_kids[0][1] + alg_kids[0][2]])

        self.label = label
        kids = _children(data, tbs_pos, tbs_pos + tbs_len)
        idx = 0
        self.version = 1
        if kids and kids[idx][0] == 0xA0:  # [0] EXPLICIT version
            vk = _children(data, kids[idx][1], kids[idx][1] + kids[idx][2])
            if not vk or vk[0][0] != TAG_INT:
                raise ParseError("version bukan INTEGER")
            self.version = _int_value(data, vk[0][1], vk[0][1] + vk[0][2]) + 1
            idx += 1
        if len(kids) < idx + 6:
            raise ParseError("TBS terlalu pendek")

        serial_tag, s_pos, s_len = kids[idx]
        if serial_tag != TAG_INT:
            raise ParseError("serialNumber bukan INTEGER")
        raw_serial = data[s_pos:s_pos + s_len]
        self.serial_neg = bool(raw_serial and raw_serial[0] & 0x80)
        self.serial_bytes = len(raw_serial.lstrip(b"\x00")) or 1
        idx += 1

        alg_tag, a_pos, a_len = kids[idx]
        if alg_tag != TAG_SEQ:
            raise ParseError("signature TBS bukan SEQUENCE")
        tbs_alg = _children(data, a_pos, a_pos + a_len)
        if not tbs_alg or tbs_alg[0][0] != TAG_OID:
            raise ParseError("signature TBS tanpa OID")
        self.tbs_sig_oid = _decode_oid(
            data[tbs_alg[0][1]:tbs_alg[0][1] + tbs_alg[0][2]])
        idx += 1

        iss_tag, i_pos, i_len = kids[idx]
        if iss_tag != TAG_SEQ:
            raise ParseError("issuer bukan SEQUENCE")
        self.issuer = _decode_name(data, i_pos, i_pos + i_len)
        idx += 1

        val_tag, vv_pos, vv_len = kids[idx]
        if val_tag != TAG_SEQ:
            raise ParseError("validity bukan SEQUENCE")
        vt = _children(data, vv_pos, vv_pos + vv_len)
        if len(vt) != 2:
            raise ParseError("validity harus dua waktu")
        self.not_before = _decode_time(data, vt[0][1], vt[0][1] + vt[0][2])
        self.not_after = _decode_time(data, vt[1][1], vt[1][1] + vt[1][2])
        idx += 1

        sub_tag, su_pos, su_len = kids[idx]
        if sub_tag != TAG_SEQ:
            raise ParseError("subject bukan SEQUENCE")
        self.subject = _decode_name(data, su_pos, su_pos + su_len)
        idx += 1

        spki_tag, sp_pos, sp_len = kids[idx]
        if spki_tag != TAG_SEQ:
            raise ParseError("subjectPublicKeyInfo bukan SEQUENCE")
        spki = _children(data, sp_pos, sp_pos + sp_len)
        if len(spki) != 2:
            raise ParseError("subjectPublicKeyInfo harus 2 elemen")
        alg = _children(data, spki[0][1], spki[0][1] + spki[0][2])
        if not alg or alg[0][0] != TAG_OID:
            raise ParseError("SPKI algorithm tanpa OID")
        self.key_oid = _decode_oid(
            data[alg[0][1]:alg[0][1] + alg[0][2]])
        self.key_bits: int | None = None
        self.key_curve_bits: int | None = None
        if self.key_oid == OID_RSA:
            payload = _bitstr_payload(data, spki[1][1], spki[1][1] + spki[1][2])
            rt, rp, rl = _read_tlv(payload, 0)
            if rt != TAG_SEQ:
                raise ParseError("RSAPublicKey bukan SEQUENCE")
            ints = _children(payload, rp, rp + rl)
            if not ints or ints[0][0] != TAG_INT:
                raise ParseError("RSAPublicKey tanpa modulus")
            self.key_bits = (ints[0][2] - (1 if payload[ints[0][1]] == 0 else 0)) * 8
        elif self.key_oid == OID_EC:
            if len(alg) > 1 and alg[1][0] == TAG_OID:
                curve = _decode_oid(data[alg[1][1]:alg[1][1] + alg[1][2]])
                self.key_curve_bits = EC_CURVE_BITS.get(curve)
        idx += 1

        # extensions [3] EXPLICIT
        self.bc_present = False
        self.bc_ca: bool | None = None
        self.bc_pathlen: int | None = None
        self.ku_present = False
        self.ku_cert_sign = False
        self.has_crl_dp = False
        self.has_ocsp = False
        for ctag, cpos, clen in kids[idx:]:
            if ctag != 0xA3:
                continue
            outer = _children(data, cpos, cpos + clen)
            if not outer or outer[0][0] != TAG_SEQ:
                raise ParseError("extensions bukan SEQUENCE")
            for ext_tag, epos, elen in _children(data, outer[0][1], outer[0][1] + outer[0][2]):
                if ext_tag != TAG_SEQ:
                    raise ParseError("Extension bukan SEQUENCE")
                ek = _children(data, epos, epos + elen)
                if not ek or ek[0][0] != TAG_OID:
                    raise ParseError("Extension tanpa OID")
                ext_oid = _decode_oid(data[ek[0][1]:ek[0][1] + ek[0][2]])
                # elemen: OID, [BOOLEAN critical], OCTET STRING extnValue
                val_kid = ek[-1]
                if val_kid[0] != 0x04:
                    raise ParseError("extnValue bukan OCTET STRING")
                vs, ve = val_kid[1], val_kid[1] + val_kid[2]
                if ext_oid == OID_BC:
                    self.bc_present = True
                    bt, bp, bl = _read_tlv(data, vs)
                    if bt == TAG_SEQ:
                        for itag, ipos, ilen in _children(data, bp, bp + bl):
                            if itag == 0x01:  # BOOLEAN cA
                                self.bc_ca = bool(data[ipos])
                            elif itag == TAG_INT:
                                self.bc_pathlen = _int_value(data, ipos, ipos + ilen)
                    else:
                        raise ParseError("basicConstraints bukan SEQUENCE")
                elif ext_oid == OID_KU:
                    self.ku_present = True
                    kt, kp, kl = _read_tlv(data, vs)
                    if kt != TAG_BITSTR:
                        raise ParseError("keyUsage bukan BIT STRING")
                    payload = _bitstr_payload(data, kp, kp + kl)
                    if payload and payload[0] & 0x04:  # bit 5 = keyCertSign
                        self.ku_cert_sign = True
                elif ext_oid == OID_CRLDP:
                    self.has_crl_dp = True
                elif ext_oid == OID_AIA:
                    if _scan_for_oid(data[vs:ve], OID_AIA_OCSP):
                        self.has_ocsp = True

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer


def _oid_bytes(oid: str) -> bytes:
    """Encode string OID -> byte DER (tanpa header TLV)."""
    parts = [int(x) for x in oid.split(".")]
    arcs = [parts[0] * 40 + parts[1]]
    for n in parts[2:]:
        chunks: list[int] = []
        val = n
        while True:
            chunks.insert(0, val & 0x7F)
            val >>= 7
            if not val:
                break
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        arcs.extend(chunks)
    return bytes(arcs)


def _scan_for_oid(data: bytes, oid: str) -> bool:
    """Cari pola DER OID di blob (untuk method OCSP di AIA)."""
    enc = _oid_bytes(oid)
    marker = bytes([TAG_OID, len(enc)]) + enc
    return marker in data


PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL)


def parse_source(data: bytes, label: str) -> list[Cert]:
    """Parse file sumber -> list Cert (urutan file dipertahankan)."""
    certs: list[Cert] = []
    blocks = PEM_RE.findall(data.decode("latin-1"))
    if blocks:
        for i, b64 in enumerate(blocks):
            compact = re.sub(r"\s+", "", b64)
            if not compact:
                raise ParseError(f"PEM block {i + 1} kosong")
            try:
                der = base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ParseError(f"PEM block {i + 1} bukan base64 valid") from exc
            certs.append(Cert(der, f"{label}#{i + 1}"))
        return certs
    # bukan PEM -> coba DER mentah (walau ekstensi .pem, fail-closed ok)
    certs.append(Cert(data, f"{label}#1"))
    return certs


SEV_HIGH = "high"
SEV_MED = "medium"
SEV_INFO = "info"


def _finding(cert_label: str, check: str, sev: str, msg: str) -> dict[str, str]:
    return {"cert": cert_label, "check": check, "severity": sev, "message": msg}


def audit_chain(certs: list[Cert], now: datetime.datetime) -> list[dict[str, str]]:
    """Cek deterministik per cert + per rantai (urutan leaf -> root)."""
    out: list[dict[str, str]] = []
    n = len(certs)

    for i, c in enumerate(certs):
        lab = c.label
        if c.not_after < now:
            out.append(_finding(lab, "kedaluwarsa", SEV_HIGH,
                                f"notAfter {c.not_after.isoformat()} sudah lewat"))
        elif c.not_before > now:
            out.append(_finding(lab, "belum-berlaku", SEV_HIGH,
                                f"notBefore {c.not_before.isoformat()} belum mulai"))
        if (c.not_after - c.not_before) > datetime.timedelta(days=398):
            out.append(_finding(lab, "masa-berlaku-panjang", SEV_INFO,
                                "validitas > 398 hari (batas CA/B; normal utk CA internal)"))
        weak_sigs = {c.sig_oid, c.tbs_sig_oid} & set(WEAK_SIG_OIDS)
        if weak_sigs:
            names = sorted({WEAK_SIG_OIDS[o] for o in weak_sigs})
            if c.self_signed:
                out.append(_finding(lab, "sig-lemah", SEV_INFO,
                                    "tanda tangan self-signature lemah "
                                    f"({', '.join(names)}) — tidak divalidasi "
                                    "dalam jalur chain, info saja"))
            else:
                out.append(_finding(lab, "sig-lemah", SEV_HIGH,
                                    f"algoritma tanda tangan lemah: {', '.join(names)}"))
        if c.key_oid == OID_RSA and c.key_bits is not None and c.key_bits < 2048:
            out.append(_finding(lab, "rsa-pendek", SEV_HIGH,
                                f"modulus RSA {c.key_bits} bit < 2048"))
        if c.key_oid == OID_EC:
            if c.key_curve_bits is None:
                out.append(_finding(lab, "kunci-tak-dikenal", SEV_INFO,
                                    "kurva EC di luar peta — validasi manual"))
            elif c.key_curve_bits < 256:
                out.append(_finding(lab, "ec-kecil", SEV_HIGH,
                                    f"kurva EC {c.key_curve_bits} bit < 256"))
        elif c.key_oid not in (OID_RSA, OID_EC):
            out.append(_finding(lab, "kunci-tak-dikenal", SEV_INFO,
                                "tipe kunci di luar peta RSA/EC"))
        if c.serial_neg or c.serial_bytes < 8:
            kind = "negatif" if c.serial_neg else f"{c.serial_bytes * 8} bit < 64 bit entropi"
            out.append(_finding(lab, "serial-lemah", SEV_MED,
                                f"serial number {kind} (RFC 5280 4.1.2.2)"))

        is_signer = i > 0  # semua kecuali leaf seharusnya CA
        if is_signer:
            if c.bc_ca is not True:
                out.append(_finding(lab, "ca-tanpa-bc", SEV_HIGH,
                                    "cert CA tanpa basicConstraints CA:TRUE"))
            if c.ku_present and not c.ku_cert_sign:
                out.append(_finding(lab, "keyusage-ca-lemah", SEV_MED,
                                    "keyUsage ada TAPI tanpa keyCertSign"))
            if not c.ku_present:
                out.append(_finding(lab, "keyusage-ca-lemah", SEV_INFO,
                                    "CA tanpa keyUsage sama sekali (RFC 5280 SHOULD)"))
        if i < n - 1 and c.self_signed:
            out.append(_finding(lab, "self-signed-tengah", SEV_MED,
                                "cert self-signed di posisi bukan terakhir rantai"))

    # rantai: order (leaf dulu: issuer cert ke-i-1 = subject cert ke-i) + pathlen
    linked = [False] * n
    for i in range(1, n):
        if certs[i].subject and certs[i - 1].issuer == certs[i].subject:
            linked[i] = True
        else:
            out.append(_finding(certs[i].label, "chain-order", SEV_HIGH,
                                f"issuer {certs[i - 1].label!r} tidak sama dengan "
                                f"subject {certs[i].label!r} — rantai putus"))

    if n >= 2:
        if certs[0].bc_ca is True:
            out.append(_finding(certs[0].label, "leaf-ca-true", SEV_MED,
                                "leaf masih CA:TRUE — risiko mis-issuance"))
        if certs[0].bc_present is False:
            out.append(_finding(certs[0].label, "ca-tanpa-bc", SEV_INFO,
                                "leaf tanpa basicConstraints (CA:FALSE eksplisit dianjurkan)"))
        if not certs[0].has_crl_dp and not certs[0].has_ocsp:
            out.append(_finding(certs[0].label, "tanpa-revokasi", SEV_INFO,
                                "leaf tanpa CRL DP maupun AIA/OCSP"))

    for i in range(1, n):
        c = certs[i]
        if c.bc_pathlen is None or not linked[i]:
            continue
        below = i - 1  # jumlah CA di antara cert ini dan leaf
        if below > c.bc_pathlen:
            out.append(_finding(c.label, "pathlen-langgar", SEV_HIGH,
                                f"pathLenConstraint {c.bc_pathlen} "
                                f"terlewati ({below} CA di bawahnya)"))
    return out


def lint_source(data: bytes, label: str, now: datetime.datetime) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Lint satu file -> (findings, meta file)."""
    try:
        certs = parse_source(data, label)
        if not certs:
            raise ParseError("tidak ada sertifikat")
        fnds = audit_chain(certs, now)
    except ParseError as exc:
        return ([_finding(f"{label}#?", "file-unparsed", SEV_HIGH,
                          f"parse gagal: {exc}")],
                {"schema": SCHEMA, "source": label, "certs": 0, "unparsed": True})
    meta = {
        "schema": SCHEMA,
        "source": label,
        "certs": len(certs),
        "subjects": [c.subject.rsplit("CN=", 1)[-1] or c.subject for c in certs],
    }
    return fnds, meta


def _iter_sources(src: Path) -> list[Path]:
    if src.is_dir():
        files = sorted(p for p in src.rglob("*")
                       if p.is_file() and p.suffix.lower() in CERT_EXTS)
        if not files:
            raise FileNotFoundError(f"tidak ada file {sorted(CERT_EXTS)} di {src}")
        return files
    if not src.is_file():
        raise FileNotFoundError(f"sumber tidak ada: {src}")
    return [src]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="cert_chain_audit — auditor rantai sertifikat X.509 offline "
                    "(read-only, nol jaringan; #0341)")
    ap.add_argument("--source", required=True,
                    help="file PEM/DER rantai (leaf dulu) atau direktori")
    ap.add_argument("--json", dest="json_out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=sorted(SEV_ORDER), default="high",
                    help="threshold exit 1 (default high)")
    ap.add_argument("--now", help="override waktu sekarang ISO-8601 UTC "
                                  "(default: waktu nyata; utk test/repro)")
    args = ap.parse_args(argv)

    now = datetime.datetime.now(datetime.timezone.utc)
    if args.now:
        try:
            now = datetime.datetime.fromisoformat(
                args.now.replace("Z", "+00:00"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=datetime.timezone.utc)
        except ValueError as exc:
            print(f"ERROR --now tidak valid: {exc}", file=sys.stderr)
            return 2

    src = Path(args.source)
    try:
        files = _iter_sources(src)
    except FileNotFoundError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2

    findings: list[dict[str, str]] = []
    metas: list[dict[str, Any]] = []
    for f in files:
        fnds, meta = lint_source(f.read_bytes(), f.name, now)
        findings.extend(fnds)
        metas.append(meta)

    result = {
        "schema": SCHEMA,
        "source": str(src),
        "now": now.isoformat(),
        "files": metas,
        "findings": findings,
        "summary": {
            "files": len(files),
            "certs": sum(m["certs"] for m in metas),
            "unparsed": sum(1 for m in metas if m.get("unparsed")),
            "high": sum(1 for x in findings if x["severity"] == "high"),
            "medium": sum(1 for x in findings if x["severity"] == "medium"),
            "info": sum(1 for x in findings if x["severity"] == "info"),
        },
    }
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(text, encoding="utf-8")
    else:
        print(text)
    thr = SEV_ORDER[args.fail_on]
    hit = any(SEV_ORDER[f["severity"]] >= thr for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
