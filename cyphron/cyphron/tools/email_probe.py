"""email_probe — email-spoofing surface check via DNS TXT records (SPF/DMARC).
Implements a minimal DNS TXT query over UDP with the stdlib (struct/socket) —
no external dependencies. Passive; findings are definitive DNS facts."""

from __future__ import annotations

import os
import socket
import struct
from urllib.parse import urlparse

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Two-level public suffixes (ccTLD second level) — apex must NOT be computed
# onto these, or SPF/DMARC would be checked against the registry zone.
TWO_LEVEL_SUFFIXES = {"co.id", "my.id", "or.id", "web.id", "biz.id", "ac.id",
                      "sch.id", "go.id", "co.uk", "org.uk", "com.au", "net.au",
                      "co.nz", "com.br", "com.tr", "com.sg", "co.jp"}


def apex_of(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) > 2 else host


def _build_query(name: str) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    header = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + qname + b"\x00\x10\x00\x01"  # qtype=TXT, qclass=IN


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Baca nama DNS (dengan compression pointer RFC 1035). Offset yang
    dikembalikan selalu posisi SETELAH byte nama ASLI di `offset` — saat
    pointer ditemui, itu = posisi setelah 2 byte pointer, bukan setelah
    target-nya. Tanpa ini, parsing jawaban multi-record salah geser."""
    labels: list[str] = []
    next_offset: int | None = None
    end = offset
    jumped = False
    while True:
        length = packet[end]
        if length == 0:
            end += 1
            if next_offset is None:
                next_offset = end
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if not jumped:
                next_offset = end + 2
                jumped = True
            end = ((length & 0x3F) << 8) | packet[end + 1]
            continue
        labels.append(packet[end + 1:end + 1 + length].decode("ascii", "replace"))
        end += 1 + length
    return ".".join(labels), next_offset if next_offset is not None else end


def _dns_query_tcp(query: bytes, resolver: str, timeout: float) -> bytes | None:
    """Kirim query DNS via TCP (2-byte length prefix). Dipakai saat respons UDP
    ter-truncation (TC=1) — tanpa ini record besar terbaca kosong = false 'missing'."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((resolver, 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        hdr = b""
        while len(hdr) < 2:
            chunk = sock.recv(2 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        (ln,) = struct.unpack("!H", hdr)
        body = b""
        while len(body) < ln:
            chunk = sock.recv(ln - len(body))
            if not chunk:
                return None
            body += chunk
        return body
    except OSError:
        return None
    finally:
        sock.close()


def _parse_txt_answers(packet: bytes) -> list[str]:
    """Parse jawaban TXT dari respons DNS (dipakai UDP maupun TCP)."""
    if len(packet) < 12:
        return []
    ancount = struct.unpack("!H", packet[6:8])[0]
    offset = 12
    try:
        _name, offset = _read_name(packet, offset)
        offset += 4
        records: list[str] = []
        for _ in range(ancount):
            _name, offset = _read_name(packet, offset)
            rtype, _class, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata = packet[offset:offset + rdlength]
            offset += rdlength
            if rtype == 16:  # TXT: sequence of length-prefixed strings
                text, i = b"", 0
                while i < len(rdata):
                    chunk = rdata[i + 1:i + 1 + rdata[i]]
                    text += chunk
                    i += 1 + rdata[i]
                records.append(text.decode("utf-8", "replace"))
        return records
    except (IndexError, struct.error):
        return []


def _doh_txt(name: str, timeout: float = 6.0) -> list[str]:
    """Cross-check terakhir via DNS-over-HTTPS (dns.google, TCP/TLS, stdlib).

    Jaringan yang membuang DNS plaintext (UDP maupun TCP ke :53) pernah membuat
    engine melaporkan 'SPF/DMARC missing' palsu — padahal record-nya ada
    (kasus nyata 2026-09, tertolong cross-check DoH). DoH hanya
    dipanggil bila jalur UDP+TCP sama-sama kosong, jadi biaya normal nol."""
    import json as _json
    import urllib.parse
    import urllib.request

    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-_"
                       for c in name.lower()):
        return []
    url = ("https://dns.google/resolve?name="
           + urllib.parse.quote(name, safe="._-") + "&type=TXT")
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "cyphron-doh/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return []
    out: list[str] = []
    for ans in data.get("Answer") or []:
        if ans.get("type") == 16:
            out.append(str(ans.get("data", "")).strip('"'))
    return out


def dns_txt(name: str, timeout: float = 5.0) -> list[str]:
    query = _build_query(name)
    for resolver in RESOLVERS:
        packet = None
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, 53))
            packet, _addr = sock.recvfrom(4096)
        except OSError:
            packet = None
        finally:
            if sock is not None:
                sock.close()
        if packet is not None and len(packet) >= 12:
            records = _parse_txt_answers(packet)
            flags = struct.unpack("!H", packet[2:4])[0]
            if not (flags & 0x0200):  # TC=0: jawaban UDP utuh
                return records
        # UDP timeout ATAU TC=1 -> jawab via TCP (jaringan yang buang UDP/53)
        tcp_packet = _dns_query_tcp(query, resolver, timeout)
        if tcp_packet is not None:
            return _parse_txt_answers(tcp_packet)
    # Fallback terakhir: UDP+TCP sama-sama kosong BUKAN bukti record absen
    # (jaringan pembuang DNS pernah membuat 'missing' palsu). DoH menutupnya.
    return _doh_txt(name, timeout)


class EmailProbeTool(Tool):
    name = "email_probe"
    description = "Check SPF/DMARC DNS records for the target domain (email spoofing surface)."
    risk_tags = {"passive"}
    source_skill = "22"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        host = urlparse(str(args["url"])).hostname or ""
        if not host or host in ("localhost", "127.0.0.1"):
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-domain"})
        # apex domain (respect two-level public suffixes like my.id / co.uk)
        parts = host.split(".")
        apex = apex_of(host)

        findings: list[Finding] = []
        spf = [r for r in (dns_txt(apex, ctx.timeout_s) or []) if r.lower().startswith("v=spf1")]
        dmarc = [r for r in (dns_txt(f"_dmarc.{apex}", ctx.timeout_s) or []) if r.lower().startswith("v=dmarc1")]

        data = {"domain": apex, "spf": spf[:1], "dmarc": dmarc[:1]}
        if not spf:
            findings.append(Finding(
                tool=self.name, title=f"No SPF record for {apex} — email spoofing surface",
                severity="medium", cwe="CWE-290",
                description=(f"DNS TXT of {apex} contains no 'v=spf1' record. Anyone can send "
                             f"emails claiming to be from @{apex}; receiving servers that ignore "
                             f"SPF absence will deliver them."),
                recommendation=(f"Publish an SPF record, e.g. v=spf1 include:<provider> -all "
                                f"(choose the exact provider includes actually used)."),
                target_url=f"dns:{apex} TXT", request=f"DNS TXT {apex}",
                response=f"TXT records: {(dns_txt(apex, ctx.timeout_s) or ['(none)'])[:3]}",
                poc=f"nslookup -type=TXT {apex}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        if not dmarc:
            findings.append(Finding(
                tool=self.name, title=f"No DMARC policy for {apex} (_dmarc.{apex} missing)",
                severity="medium", cwe="CWE-290",
                description=(f"_dmarc.{apex} has no 'v=dmarc1' record, so spoofed mail is neither "
                             f"quarantined nor rejected, and abuse goes unreported."),
                recommendation=("Publish _dmarc TXT: v=dmarc1; p=quarantine; rua=mailto:<report@"
                                + apex + "> (start at p=none to monitor, then tighten)."),
                target_url=f"dns:_dmarc.{apex} TXT", request=f"DNS TXT _dmarc.{apex}",
                response=f"records: {(dns_txt(f'_dmarc.{apex}', ctx.timeout_s) or ['(none)'])[:3]}",
                poc=f"nslookup -type=TXT _dmarc.{apex}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        ctx.world.note(f"email_probe: SPF={'yes' if spf else 'MISSING'}, "
                       f"DMARC={'yes' if dmarc else 'MISSING'} for {apex}")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
