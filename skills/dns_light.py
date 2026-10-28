"""Klien DNS minimal (stdlib murni) — query read-only TXT/NS/A + AXFR.

Dibangun clean-room untuk batch 6 (konsep RFC 1035/5936, tanpa kode
dari proyek lain). Dipakai skills/spf_dmarc_posture.py (TXT) dan
skills/dns_axfr_check.py (NS + AXFR via TCP).

Disiplin fail-closed:
  - HANYA query baca (TXT/NS/A/AXFR) — bukan resolver umum.
  - NOL retry otomatis; timeout ketat per request.
  - Kegagalan network/parse = None (pemanggil wajib menulis baris
    unconfirmed, BUKAN klaim).
  - RCODE != 0 bukan exception — balik sebagai jawaban faktual
    (NXDOMAIN/NXRRSET = "tidak ada record"), pemanggil yang menilai.
"""
from __future__ import annotations

import random
import socket
import struct

DEFAULT_RESOLVER = "1.1.1.1"
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_SOA = 6
QTYPE_TXT = 16
QTYPE_AXFR = 252
CLASS_IN = 1

# pembatasan ukuran supaya parse tidak pernah loop tanpa ujung
MAX_MESSAGE = 65535
MAX_NAME_JUMPS = 16


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"label DNS tidak valid: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int) -> bytes:
    """Pesan query standar: RD=1, satu pertanyaan (RFC 1035 §4.1)."""
    ident = random.getrandbits(16)
    header = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)


def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Baca nama (dengan dekompresi pointer RFC 1035 §4.1.4).

    Return (nama, offset sesudah nama di posisi awal — pada pointer,
    offset sesudah 2 byte pointer)."""
    labels: list[str] = []
    jumps = 0
    pos = off
    end: int | None = None
    while True:
        if pos >= len(msg):
            raise ValueError("nama melewati batas pesan")
        ln = msg[pos]
        if ln == 0:
            if end is None:
                end = pos + 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError("pointer terpotong")
            if end is None:
                end = pos + 2
            pos = ((ln & 0x3F) << 8) | msg[pos + 1]
            jumps += 1
            if jumps > MAX_NAME_JUMPS:
                raise ValueError("loop pointer nama")
            continue
        labels.append(msg[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def txt_strings(rdata: bytes) -> list[str]:
    """RDATA TXT = deret character-string (len-byte + data)."""
    out: list[str] = []
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        out.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
        i += 1 + ln
    return out


def parse_message(msg: bytes) -> dict:
    """Parse pesan DNS → {"id", "rcode", "answers": [dict]}.

    answer dict: name, type, ttl, rdata (bytes), val (interpretasi:
    A = IP dotted, NS/CNAME = nama, TXT = list string, SOA = mname)."""
    if len(msg) < 12:
        raise ValueError("pesan lebih pendek dari header")
    ident, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = read_name(msg, off)
        if off + 10 > len(msg):
            raise ValueError("record terpotong")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        rd_off = off
        off += rdlen
        val: object = None
        if rtype == QTYPE_A and rdlen == 4:
            val = socket.inet_ntoa(rdata)
        elif rtype in (QTYPE_NS, 5, 12):  # NS / CNAME / PTR
            val = read_name(msg, rd_off)[0]
        elif rtype == 6:  # SOA — cukup mname (primary NS)
            val = read_name(msg, rd_off)[0]
        elif rtype == QTYPE_TXT:
            val = txt_strings(rdata)
        answers.append({"name": name, "type": rtype, "ttl": ttl,
                        "rdata": rdata, "val": val})
    return {"id": ident, "rcode": flags & 0x0F, "answers": answers}


def udp_query(server: str, name: str, qtype: int, timeout: float = 5.0,
              port: int = 53) -> dict | None:
    """Satu query UDP. Gagal network/parse = None (fail-closed).
    RCODE != 0 = jawaban faktual (answers kosong)."""
    try:
        query = build_query(name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            data, _addr = s.recvfrom(MAX_MESSAGE)
        msg = parse_message(data)
        if msg["id"] != (struct.unpack(">H", query[:2])[0]):
            return None  # id tidak cocok — buang, jangan tebak
        return msg
    except (OSError, ValueError):
        return None


def axfr(ns_ip: str, zone: str, timeout: float = 5.0,
         max_messages: int = 16, port: int = 53) -> dict | None:
    """Zone transfer TCP (RFC 5936) — read-only, satu koneksi.

    Berhenti: koneksi tutup / SOA kedua terlihat / batas pesan.
    Return None bila gagal koneksi/parse. Zona VALID ditandai caller
    via answers[0] dan answers[-1] bertipe SOA (disiplin RFC)."""
    try:
        query = build_query(zone, QTYPE_AXFR)
        records: list[dict] = []
        seen_soa = 0
        with socket.create_connection((ns_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack(">H", len(query)) + query)
            for _ in range(max_messages):
                hdr = s.recv(2)
                if len(hdr) < 2:
                    break
                (mlen,) = struct.unpack(">H", hdr)
                if mlen == 0:
                    break
                buf = b""
                while len(buf) < mlen:
                    chunk = s.recv(mlen - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                if len(buf) < mlen:
                    break
                msg = parse_message(buf)
                if msg["id"] != (struct.unpack(">H", query[:2])[0]):
                    return None
                records.extend(msg["answers"])
                seen_soa = sum(1 for r in records if r["type"] == 6)
                if seen_soa >= 2:
                    break
        return {"rcode": 0, "answers": records}
    except (OSError, ValueError):
        return None


# --- helper tingkat tinggi (dipakai skill) --------------------------------

def ns_lookup(server: str, domain: str,
              timeout: float = 5.0) -> list[str] | None:
    msg = udp_query(server, domain, QTYPE_NS, timeout)
    if msg is None:
        return None
    return [a["val"] for a in msg["answers"]
            if a["type"] == QTYPE_NS and isinstance(a["val"], str)]


def a_lookup(server: str, name: str,
             timeout: float = 5.0) -> list[str] | None:
    msg = udp_query(server, name, QTYPE_A, timeout)
    if msg is None:
        return None
    return [a["val"] for a in msg["answers"]
            if a["type"] == QTYPE_A and isinstance(a["val"], str)]


def txt_lookup(server: str, name: str,
               timeout: float = 5.0) -> list[str] | None:
    msg = udp_query(server, name, QTYPE_TXT, timeout)
    if msg is None:
        return None
    out: list[str] = []
    for a in msg["answers"]:
        if a["type"] == QTYPE_TXT and isinstance(a["val"], list):
            out.extend(a["val"])
    return out
