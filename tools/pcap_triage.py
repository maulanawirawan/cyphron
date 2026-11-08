r"""[SAFETY: read-only] pcap_triage — triase forensik OFFLINE file pcap
klasik (Ethernet/RawIP/Linux-SLL): protokol, percakapan, top talker,
kueri DNS, permintaan HTTP, kredensial cleartext (FTP/HTTP Basic),
SNI TLS, kandidat beacon & port scan. TANPA jaringan.

Mengisi antrean port SKILL-PORT-QUEUE #0855 + #0856 + #0857
(mukul975/Anthropic-Cybersecurity-Skills 'performing-network-forensics-
with-wireshark', 'performing-network-packet-capture-analysis',
'performing-network-traffic-analysis-with-tshark'; atribusi konsep,
lisensi sumber Apache-2.0). Skill sumber mengandalkan Wireshark/tshark/
scapy — alat pihak ketiga; inti deterministik yang diekstrak di sini =
parser pcap + statistik + deteksi pola dari scratch (spesifikasi publik
libpcap/IPv4/TCP/UDP/DNS/HTTP; TIDAK menyalin kode sumber skill dan
TIDAK memakai scapy/pyshark).

Pembagian ranah (TIDAK diduplikasi):
  - frame ARP poisoning -> arp_pcap_scan; deauth 802.11 ->
    deauth_pcap_scan (parser pcap-nya spesifik protokol)
  - log Zeek (conn/dns/http.log) -> zeek_beacon_scan, zeek_front_scan,
    zeek_lateral_scan
  - NetFlow -> netflow_parse
  - di sini: pcap mentah generik IPv4/TCP/UDP.

Input -> mekanisme -> output:
  - Input : file pcap CLASSIC (magic 0xa1b2c3d4 / nano 0xa1b23c4d,
            LE/BE), linktype 1 (Ethernet), 101/12 (Raw IP), 113 (SLL).
            Hasil capture lab/berizin. Read-only. PCAPNG TIDAK
            didukung (ditolak eksplisit, bukan diam-diam).
  - Mekanisme: parse tiap paket -> protokol + percakapan (pkts/bytes
            per pasangan IP) + top talker; kueri DNS (label >= 30 char
            / nama >= 52 -> kandidat tunneling); request HTTP (method,
            Host, User-Agent, Authorization: Basic -> kredensial
            cleartext dgn REDAKSI); FTP USER/PASS -> kredensial
            cleartext dgn REDAKSI; ClientHello TLS -> SNI; beacon =
            SYN-only interval reguler (jitter < --max-jitter) pada
            pasangan (src,dst,dport); port scan = banyak port tujuan
            SYN-only dari satu sumber.
  - Output: JSON {schema, stats, conversations, dns_queries, findings,
            notes}; finding = {check, severity, message, evidence}.

Cek:
  cleartext-ftp-creds    (high): USER/PASS FTP terbuka (pass diredaksi).
  cleartext-http-basic   (high): Authorization: Basic (pass diredaksi).
  dns-tunnel-candidate   (medium): >= --min-tunnel-queries kueri DNS
                         berlabel panjang per (sumber, domain dasar).
  beacon-candidate       (medium): >= --min-beacon-conns koneksi SYN
                         interval rata >= 1s dan jitter < --max-jitter.
  portscan-candidate     (medium): >= --min-scan-ports port tujuan
                         SYN-only unik dari satu sumber.
  truncated-packet       (medium): incl_len > caplen (capture rusak/
                         snaplen) — dihitung eksplisit, tak pernah
                         dianggap bersih.
  http-request / dns / sni / percakapan = inventaris di output (bukan
  temuan) — bahan baku IOC utk ioc_defang / campaign_correlate.

Fail-closed:
  - file tidak ada / bukan pcap (magic salah / PCAPNG) -> exit 2.
  - nol paket ter-parse -> exit 2.
  - record terpotong (caplen < incl_len) -> truncated-packet dihitung
    + linktype asing dihitung stats.skipped_frames (dicatat, tak dibuang
    diam-diam).

Anti-FP: --allow-ip PREFIX (boleh diulang) menyaring sumber sah;
beacon butuh >= 4 interval & rata-rata 1-3600s (ping 1x tak menyala);
port scan butuh >= ambang port unik.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium); 2 error input.

Pemakaian:
  python tools/pcap_triage.py --pcap capture.pcap --out triage.json
  python tools/pcap_triage.py --pcap c.pcap --min-beacon-conns 10 \
      --allow-ip 10.0.0.0/8
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
from pathlib import Path

SCHEMA = "secai.pcap-triage/1"
MAX_FILE_BYTES = 512 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # LE usec
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # LE nano
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),   # BE usec
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # BE nano
}
LINKTYPES = {1: "ethernet", 101: "raw-ip", 12: "raw-ip", 113: "linux-sll"}

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD

TCP_FLAGS_SYN = 0x02
TCP_FLAGS_ACK = 0x10

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                b"OPTIONS ", b"PATCH ")


def _clamp(b: bytes, off: int, n: int) -> bytes:
    return b[off:off + n]


def parse_dns_name(buf: bytes, off: int) -> "tuple[str, int] | None":
    """Nama QNAME (labels, tanpa kompresi di question — cukup)."""
    labels = []
    pos = off
    while pos < len(buf):
        ln = buf[pos]
        if ln == 0:
            pos += 1
            break
        if ln > 63 or pos + 1 + ln > len(buf):
            return None
        labels.append(buf[pos + 1:pos + 1 + ln].decode("ascii",
                                                       errors="replace"))
        pos += 1 + ln
    if not labels:
        return None
    return ".".join(labels), pos


def parse_sni(payload: bytes) -> "str | None":
    """SNI dari ClientHello TLS; None bila tak bisa diparse."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        # record header 5 byte; handshake type 0x01, len 3 byte
        if payload[5] != 0x01:
            return None
        pos = 5 + 4  # handshake header
        pos += 2 + 32  # version + random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", payload[pos:pos + 4])
            pos += 4
            data = _clamp(payload, pos, elen)
            pos += elen
            if etype == 0x0000 and len(data) >= 5:
                nl = struct.unpack(">H", data[3:5])[0]
                return data[5:5 + nl].decode("ascii", errors="replace")
        return None
    except (struct.error, IndexError):
        return None


class _PcapTriage:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.findings: "list[dict]" = []
        self.stats: "dict" = {
            "packets": 0, "ipv4": 0, "tcp": 0, "udp": 0, "icmp": 0,
            "arp": 0, "ipv6": 0, "other_frames": 0, "truncated": 0,
            "dns_queries": 0, "http_requests": 0, "tls_clienthello": 0,
            "allowed_filtered": 0,
        }
        self.conv: "dict[tuple[str, str], dict]" = {}
        self.src_bytes: "dict[str, int]" = {}
        self.dns_q: "dict[str, dict]" = {}
        self.http_hosts: "dict[str, int]" = {}
        self.http_uas: "dict[str, int]" = {}
        self.snis: "dict[str, int]" = {}
        self.syn_ts: "dict[tuple[str, str, int], list[float]]" = {}
        self.scan_ports: "dict[str, set]" = {}
        self.tunnel: "dict[tuple[str, str], int]" = {}
        self.ftp_user: "dict[str, str]" = {}

    def add(self, check: str, severity: str, message: str,
            evidence: str, source_ip: str = "") -> None:
        f = {"check": check, "severity": severity,
             "message": message, "evidence": evidence}
        if source_ip:
            f["source_ip"] = source_ip
        self.findings.append(f)

    # ------------------------------------------------------ frame
    def parse(self, data: bytes) -> None:
        if len(data) < 24:
            raise ValueError("file terlalu pendek untuk header pcap")
        magic4 = data[:4]
        if magic4 == b"\x0a\x0d\x0d\x0a":
            raise ValueError("format PCAPNG tidak didukung — konversi ke "
                             "pcap classic dulu (fail-closed)")
        if magic4 not in PCAP_MAGICS:
            raise ValueError("bukan file pcap classic (magic tidak "
                             "dikenali)")
        endian, res = PCAP_MAGICS[magic4]
        _, _, _, _, _, _, linktype = struct.unpack(
            endian + "IHHiIII", data[:24])
        self.stats["linktype"] = LINKTYPES.get(
            linktype, f"linktype-{linktype}")
        pos = 24
        while pos + 16 <= len(data):
            ts_sec, ts_sub, incl, orig = struct.unpack(
                endian + "IIII", data[pos:pos + 16])
            pos += 16
            frame = data[pos:pos + incl]
            pos += incl
            if orig > incl:  # snaplen/capture menangkap kurang dari asli
                self.stats["truncated"] += 1
                if self.stats["truncated"] == 1:
                    self.add("truncated-packet", "medium",
                             f"record terpotong (orig_len={orig} > "
                             f"caplen={incl}) — snaplen kecil/capture "
                             "rusak; payload mungkin tak utuh.",
                             f"offset={pos - 16 - incl}")
            if len(frame) < incl:
                self.stats["truncated"] += 1
            if incl == 0:
                continue
            self.stats["packets"] += 1
            self.frame(linktype, frame, ts_sec + ts_sub / res)

    def frame(self, linktype: int, frame: bytes, ts: float) -> None:
        st = self.stats
        if linktype == 1:
            if len(frame) < 14:
                st["other_frames"] += 1
                return
            ethertype = struct.unpack(">H", frame[12:14])[0]
            payload = frame[14:]
        elif linktype == 113:
            if len(frame) < 16:
                st["other_frames"] += 1
                return
            ethertype = struct.unpack(">H", frame[14:16])[0]
            payload = frame[16:]
        elif linktype in (101, 12):
            ethertype = ETH_IPV4
            payload = frame
        else:
            st["other_frames"] += 1
            return
        if ethertype == ETH_ARP:
            st["arp"] += 1
            return
        if ethertype == ETH_IPV6:
            st["ipv6"] += 1
            return
        if ethertype != ETH_IPV4:
            st["other_frames"] += 1
            return
        if len(payload) < 20:
            st["other_frames"] += 1
            return
        st["ipv4"] += 1
        self.ipv4(payload, ts)

    # ------------------------------------------------------ L3/L4
    def ipv4(self, pkt: bytes, ts: float) -> None:
        st = self.stats
        ver_ihl = pkt[0]
        if ver_ihl >> 4 != 4:
            st["other_frames"] += 1
            return
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < ihl:
            st["truncated"] += 1
            return
        proto = pkt[9]
        src = ".".join(str(b) for b in pkt[12:16])
        dst = ".".join(str(b) for b in pkt[16:20])
        l4 = pkt[ihl:]
        key = tuple(sorted((src, dst)))
        c = self.conv.setdefault(key, {"packets": 0, "bytes": 0})
        c["packets"] += 1
        c["bytes"] += len(pkt)
        self.src_bytes[src] = self.src_bytes.get(src, 0) + len(pkt)

        if proto == 1:
            st["icmp"] += 1
            return
        if proto == 6:
            st["tcp"] += 1
            self.tcp(src, dst, l4, ts)
        elif proto == 17:
            st["udp"] += 1
            self.udp(src, dst, l4)
        else:
            st["other_frames"] += 1

    def tcp(self, src: str, dst: str, l4: bytes, ts: float) -> None:
        if len(l4) < 20:
            self.stats["truncated"] += 1
            return
        sport, dport = struct.unpack(">HH", l4[:4])
        doff_flags = l4[12]
        flags = l4[13]
        doff = (doff_flags >> 4) * 4
        if doff < 20 or doff > len(l4):
            self.stats["truncated"] += 1
            return
        payload = l4[doff:]
        syn_only = bool(flags & TCP_FLAGS_SYN) and not \
            bool(flags & TCP_FLAGS_ACK)
        if syn_only:
            key = (src, dst, dport)
            self.syn_ts.setdefault(key, []).append(ts)
            self.scan_ports.setdefault(src, set()).add((dst, dport))
        # protokol berbasis port
        if dport == 21 or sport == 21:
            self.ftp(src, payload)
        if dport in (80, 8080, 8000) and any(
                payload.startswith(m) for m in HTTP_METHODS):
            self.http(src, dst, dport, payload)
        if dport == 443 and payload[:1] == b"\x16":
            sni = parse_sni(payload)
            if sni:
                self.stats["tls_clienthello"] += 1
                self.snis[sni] = self.snis.get(sni, 0) + 1

    def udp(self, src: str, dst: str, l4: bytes) -> None:
        if len(l4) < 8:
            self.stats["truncated"] += 1
            return
        sport, dport = struct.unpack(">HH", l4[:4])
        if 53 in (sport, dport):
            self.dns(src, l4[8:])

    # ------------------------------------------------------ protokol
    def dns(self, src: str, q: bytes) -> None:
        if len(q) < 12:
            self.stats["truncated"] += 1
            return
        flags = struct.unpack(">H", q[2:4])[0]
        qdcount = struct.unpack(">H", q[4:6])[0]
        if flags & 0x8000 or qdcount < 1:  # response / tanpa question
            return
        parsed = parse_dns_name(q, 12)
        if parsed is None:
            return
        name, end = parsed
        qtype = struct.unpack(">H", q[end:end + 2])[0] \
            if end + 2 <= len(q) else 0
        self.stats["dns_queries"] += 1
        d = self.dns_q.setdefault(name, {"count": 0, "sources": set(),
                                         "qtype": qtype})
        d["count"] += 1
        d["sources"].add(src)
        labels = name.split(".")
        longest = max((len(l) for l in labels), default=0)
        if longest >= 30 or len(name) >= 52:
            base = ".".join(labels[-2:]) if len(labels) >= 2 else name
            k = (src, base)
            self.tunnel[k] = self.tunnel.get(k, 0) + 1

    def http(self, src: str, dst: str, port: int, payload: bytes) -> None:
        self.stats["http_requests"] += 1
        try:
            text = payload[:4096].decode("ascii", errors="replace")
        except Exception:  # pragma: no cover
            return
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        host, ua, auth = "", "", ""
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "host":
                host = v
            elif k == "user-agent":
                ua = v[:120]
            elif k == "authorization" and v.lower().startswith("basic "):
                auth = v[6:].strip()
        if host:
            self.http_hosts[host] = self.http_hosts.get(host, 0) + 1
        if ua:
            self.http_uas[ua] = self.http_uas.get(ua, 0) + 1
        if auth:
            try:
                raw = base64.b64decode(auth, validate=True).decode(
                    "ascii", errors="replace")
            except Exception:
                raw = ""
            if ":" in raw:
                user, pwd = raw.split(":", 1)
                self.add("cleartext-http-basic", "high",
                         f"kredensial HTTP Basic dari {src} ke "
                         f"{host or dst}:{port} — user '{user}', "
                         f"password DIREDAKSI (len={len(pwd)}); kirim "
                         "cleartext = jejak log/pcap.",
                         f"{src} -> {host or dst}:{port} user={user}",
                         source_ip=src)

    def ftp(self, src: str, payload: bytes) -> None:
        if not payload:
            return
        try:
            text = payload[:2048].decode("ascii", errors="replace")
        except Exception:
            return
        # USER dan PASS kerap di paket terpisah — simpan USER per sumber
        for ln in text.split("\r\n"):
            t = ln.strip()
            if t.upper().startswith("USER ") and len(t) > 5:
                self.ftp_user[src] = t[5:].strip()
            elif t.upper().startswith("PASS ") and len(t) > 5:
                pwd = t[5:].strip()
                user = self.ftp_user.get(src, "")
                if user:
                    self.add("cleartext-ftp-creds", "high",
                             f"kredensial FTP cleartext dari {src} — user "
                             f"'{user}', password DIREDAKSI "
                             f"(len={len(pwd)}); FTP tanpa TLS bocor di "
                             "jalur.",
                             f"src={src} user={user}", source_ip=src)
                    self.ftp_user.pop(src, None)

    # ------------------------------------------------------ deteksi
    def detect(self) -> None:
        a = self.args
        # beacon: interval SYN reguler
        for (src, dst, dport), tss in sorted(self.syn_ts.items()):
            if len(tss) < max(5, a.min_beacon_conns):
                continue
            tss = sorted(tss)
            deltas = [tss[i + 1] - tss[i] for i in range(len(tss) - 1)]
            if len(deltas) < 4:
                continue
            mean = sum(deltas) / len(deltas)
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            sd = var ** 0.5
            jitter = sd / mean if mean > 0 else 9
            if 1.0 <= mean <= 3600.0 and jitter < a.max_jitter:
                self.add("beacon-candidate", "medium",
                         f"{len(tss)} koneksi SYN {src} -> {dst}:{dport} "
                         f"interval rata {mean:.1f}s jitter "
                         f"{jitter:.2f} — pola beacon C2; cf. "
                         "zeek_beacon_scan utk log Zeek.",
                         f"n={len(tss)} mean={mean:.2f}s "
                         f"jitter={jitter:.3f}", source_ip=src)
        # port scan
        for src, ports in sorted(self.scan_ports.items()):
            if len(ports) >= a.min_scan_ports:
                dsts = sorted({d for d, _ in ports})
                self.add("portscan-candidate", "medium",
                         f"{src} menyentuh {len(ports)} port tujuan unik "
                         f"(SYN-only) pada {len(dsts)} host — pola "
                         "pemindaian.",
                         f"ports={len(ports)} hosts={len(dsts)}",
                         source_ip=src)
        # dns tunnel
        for (src, base), n in sorted(self.tunnel.items()):
            if n >= a.min_tunnel_queries:
                self.add("dns-tunnel-candidate", "medium",
                         f"{n} kueri DNS berlabel panjang dari {src} ke "
                         f"'{base}' — kandidat tunneling/exfil DNS "
                         "(bandingkan baseline, cf. dns_log_triage).",
                         f"long_queries={n} base={base}", source_ip=src)

    def result(self) -> dict:
        self.detect()
        conversations = [
            {"a": k[0], "b": k[1], "packets": v["packets"],
             "bytes": v["bytes"]}
            for k, v in sorted(self.conv.items(),
                               key=lambda kv: -kv[1]["bytes"])[:20]]
        dns_queries = [
            {"name": name, "count": d["count"], "qtype": d["qtype"],
             "sources": sorted(d["sources"])}
            for name, d in sorted(self.dns_q.items(),
                                  key=lambda kv: -kv[1]["count"])[:50]]
        top_talkers = sorted(self.src_bytes.items(),
                             key=lambda kv: -kv[1])[:10]
        allow = tuple(x.strip() for x in self.args.allow_ip if x.strip())
        if allow:
            kept = []
            for f in self.findings:
                ip = str(f.get("source_ip", ""))
                if ip and any(ip == a or ip.startswith(a)
                              for a in allow):
                    self.stats["allowed_filtered"] += 1
                    continue
                kept.append(f)
            self.findings = kept
        return {
            "schema": SCHEMA,
            "stats": self.stats,
            "conversations": conversations,
            "dns_queries": dns_queries,
            "top_talkers": [{"ip": ip, "bytes": n}
                            for ip, n in top_talkers],
            "http": {"hosts": dict(sorted(self.http_hosts.items(),
                                          key=lambda kv: -kv[1])[:20]),
                     "user_agents": dict(sorted(
                         self.http_uas.items(),
                         key=lambda kv: -kv[1])[:10])},
            "tls_sni": dict(sorted(self.snis.items(),
                                   key=lambda kv: -kv[1])[:20]),
            "findings": sorted(
                self.findings,
                key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                               f["check"], f["message"])),
            "notes": [
                "triase STATIS pcap — capture diambil dulu di lab "
                "(tcpdump/tshark); alat ini TIDAK mengirim paket apa pun.",
                "HTTP hanya dicek di AWAL payload TCP port 80/8080/8000 "
                "(tanpa reassembly stream — stream terpecah tidak "
                "terdeteksi; keterbatasan tercatat).",
                "PCAPNG tidak didukung (fail-closed) — konversi dulu: "
                "tshark -F pcap -r file.pcapng -w c.pcap.",
                "IOC dari dns_queries/tls_sni/http.hosts siap dipipe ke "
                "ioc_defang; ARP/deauth punya tool spesifik masing-"
                "masing (arp_pcap_scan, deauth_pcap_scan).",
                "kredensial diredaksi: user tampil, password hanya "
                "panjangnya — tak ada nilai penuh di output.",
            ],
        }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase pcap offline (protokol, percakapan, DNS, "
                    "HTTP, kredensial cleartext, beacon, scan), nol "
                    "jaringan.")
    ap.add_argument("--pcap", required=True, help="file pcap classic")
    ap.add_argument("--min-beacon-conns", type=int, default=5)
    ap.add_argument("--max-jitter", type=float, default=0.15)
    ap.add_argument("--min-scan-ports", type=int, default=50)
    ap.add_argument("--min-tunnel-queries", type=int, default=3)
    ap.add_argument("--allow-ip", action="append", default=[],
                    metavar="IP/PREFIX",
                    help="abaikan temuan yang evidensinya memuat IP "
                         "ini (bisa diulang)")
    ap.add_argument("--fail-on", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    p = Path(args.pcap)
    try:
        if not p.is_file():
            raise ValueError(f"file tidak ada: {p}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file terlalu besar")
        data = p.read_bytes()
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    t = _PcapTriage(args)
    try:
        t.parse(data)
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2
    if t.stats["packets"] == 0:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "nol paket ter-parse (fail-closed)",
        }), file=sys.stderr)
        return 2

    report = t.result()
    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in report["findings"]
           if SEV_ORDER.get(f["severity"], 0) >= threshold]
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
