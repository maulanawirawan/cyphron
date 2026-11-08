r"""[SAFETY: read-only] arp_pcap_scan — deteksi indikasi ARP poisoning
dari capture Ethernet offline (pcap classic, stdlib murni, tanpa jaringan).

Port konsep dari antrean SKILL-PORT-QUEUE #0380 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'detecting-arp-poisoning-in-network-
traffic' — indikator MAC flip-flop, duplicate IP, gratuitous ARP flood,
lonjakan volume ARP, perubahan MAC gateway; atribusi konsep, lisensi
sumber Apache-2.0). Dibangun FROM SCRATCH: parser pcap + frame ARP
ditulis sendiri dari spesifikasi publik (Ethernet II + RFC 826), TIDAK
menyalin kode sumber skill dan tidak memakai lib pcap/scapy.

Input -> mekanisme -> output:
  - Input : file pcap classic (linktype Ethernet 0x01) hasil capture
            lab/berizin. Read-only, NOL jaringan — alat hanya membaca
            byte file dan menganalisis frame ARP di dalamnya.
  - Mekanisme: iterasi paket pcap -> Ethernet -> ethertype 0x0806 ->
            parse ARP (oper 1=request, 2=reply) -> pemetaan pengumuman
            (spa -> sha) berurutan waktu + hitungan per pengirim.
  - Output: daftar temuan {check, severity, ip, macs, evidence, message}
            + ringkasan (jumlah frame, pengumuman binding teratas).

Cek (semua verdict = LEAD indikator L2, bukan klaim kompromi — ARP sah
juga bisa memicu beberapa cek, caveat ditulis di note):
  duplicate-ip        (high)  : 1 IP diumumkan oleh >= 2 MAC berbeda.
  mac-flip-flop       (high)  : pengumuman satu IP bergantian antar MAC
                                  >= --flip-transitions kali (pola arpwatch
                                  "flip flop").
  gateway-mac-change  (high)  : MAC terikat --gateway-ip berubah dari
                                  pengamatan pertama (perlu --gateway-ip).
  gratuitous-flood    (high)  : reply ARP gratis (spa == tpa) dari MAC
                                  sama >= --flood-count dalam jendela
                                  --flood-window. Catatan FP: failover/
                                  VRRP sah juga mengirim gratuitous ARP.
  arp-volume-spike    (medium): total frame ARP >= --volume-threshold
                                  dalam jendela --volume-window detik.

Fail-closed: bukan pcap / magic tak dikenal -> error (exit 2); paket
terpotong di akhir file dicatat (truncated) dan TIDAK dihitung bersih
diam-diam; frame ARP dengan format tak wajar dicatat arp_malformed.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/arp_pcap_scan.py --pcap capture.pcap
  python tools/arp_pcap_scan.py --pcap capture.pcap --gateway-ip 10.0.0.1
  python tools/arp_pcap_scan.py --pcap capture.pcap --json --out hasil.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.arp-pcap-scan/1"

LINKTYPE_ETHERNET = 1
ETHERTYPE_ARP = 0x0806
ARP_OPER_REQUEST = 1
ARP_OPER_REPLY = 2

SEV_ORDER = {"info": 0, "medium": 1, "high": 2}


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ipv4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def iter_pcap(data: bytes):
    """Yield (ts, linktype, packet, truncated) per paket pcap classic.

    Fail-closed: magic tidak dikenal -> ValueError; paket terakhir yang
    terpotong diberi tanda truncated=True lalu iterasi berhenti.
    """
    if len(data) < 24:
        raise ValueError("file terlalu pendek untuk header pcap (24 byte)")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise ValueError(f"magic pcap tidak dikenal: {magic.hex()}")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
        endian + "HHiIII", data[4:24])
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(
            endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            yield (ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6),
                   linktype, data[off:], True)
            return
        yield (ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6),
               linktype, data[off:off + incl_len], False)
        off += incl_len


def parse_arp_frame(pkt: bytes):
    """Parse Ethernet + ARP. Return dict atau None bila bukan frame ARP.

    Return keys: oper, sha, spa, tha, tpa (byte) — atau string
    "malformed" bila ethertype ARP tetapi isi tidak lengkap.
    """
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack(">H", pkt[12:14])[0]
    if ethertype != ETHERTYPE_ARP:
        return None
    body = pkt[14:]
    if len(body) < 28:
        return "malformed"
    htype, ptype, hlen, plen, oper = struct.unpack(
        ">HHBBH", body[:8])
    sha = body[8:14]
    spa = body[14:18]
    tha = body[18:24]
    tpa = body[24:28]
    # binding hanya untuk Ethernet/IPv4 dengan panjang standar
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return {"oper": None, "sha": sha, "spa": spa, "tha": tha,
                "tpa": tpa, "standard": False}
    return {"oper": oper, "sha": sha, "spa": spa, "tha": tha,
            "tpa": tpa, "standard": True}


def _peak_window(stamps: "list[float]", window: float) -> "tuple[int, float, float] | None":
    """Jumlah maksimum timestamp dalam jendela geser + batas jendelanya."""
    stamps = sorted(stamps)
    best: "tuple[int, float, float] | None" = None
    j = 0
    for i in range(len(stamps)):
        while stamps[i] - stamps[j] > window:
            j += 1
        n = i - j + 1
        if best is None or n > best[0]:
            best = (n, stamps[j], stamps[i])
    return best


def scan(data: bytes, *, flip_transitions: int = 3, flood_count: int = 10,
         flood_window: float = 10.0, volume_threshold: int = 50,
         volume_window: float = 10.0, gateway_ip: str | None = None,
         now_hint: str | None = None) -> dict:
    """Scan penuh byte pcap -> ringkasan + daftar temuan. Tanpa jaringan."""
    del now_hint  # tidak dipakai; disediakan agar CLI konsisten
    total = 0
    truncated = False
    arp_frames = 0
    arp_malformed = 0
    non_arp = 0
    linktypes: Counter[int] = Counter()
    requests = replies = gratuitous = 0
    all_arp_ts: "list[float]" = []
    # (ts, spa, sha, oper, gratuitous) berurutan waktu — pengumuman sender
    announcements: "list[tuple[float, str, str, int]]" = []
    gratuitous_by_sender: "dict[str, list[float]]" = {}

    for ts, linktype, pkt, trunc in iter_pcap(data):
        total += 1
        linktypes[linktype] += 1
        if trunc:
            truncated = True
            break
        parsed = parse_arp_frame(pkt)
        if parsed is None:
            non_arp += 1
            continue
        arp_frames += 1
        if parsed == "malformed":
            arp_malformed += 1
            continue
        if not parsed["standard"]:
            arp_malformed += 1
            continue
        all_arp_ts.append(ts)
        sha, spa = mac_str(parsed["sha"]), ipv4_str(parsed["spa"])
        tpa = ipv4_str(parsed["tpa"])
        if parsed["oper"] == ARP_OPER_REQUEST:
            requests += 1
            announcements.append((ts, spa, sha, ARP_OPER_REQUEST))
        elif parsed["oper"] == ARP_OPER_REPLY:
            replies += 1
            announcements.append((ts, spa, sha, ARP_OPER_REPLY))
            if spa == tpa:
                gratuitous += 1
                gratuitous_by_sender.setdefault(sha, []).append(ts)
        # oper lain (mis. InARP=8) dicatat sebagai frame ARP biasa saja

    findings: "list[dict]" = []

    # binding unik per IP dari pengumuman sender (request maupun reply)
    ip_macs: "dict[str, Counter[str]]" = {}
    mac_seq: "dict[str, list[tuple[float, str]]]" = {}
    for ts, spa, sha, _oper in announcements:
        ip_macs.setdefault(spa, Counter())[sha] += 1
        seq = mac_seq.setdefault(spa, [])
        if not seq or seq[-1][1] != sha:  # transisi MAC
            seq.append((ts, sha))

    for ip, cnt in sorted(ip_macs.items()):
        if len(cnt) >= 2:
            findings.append({
                "check": "duplicate-ip",
                "severity": "high",
                "ip": ip,
                "macs": {m: c for m, c in cnt.most_common(10)},
                "message": f"{ip} diumumkan oleh {len(cnt)} MAC berbeda "
                           f"(binding bentrok di lantai 2).",
            })

    for ip, seq in sorted(mac_seq.items()):
        if len(seq) - 1 >= flip_transitions and len(
                {m for _, m in seq}) >= 2:
            findings.append({
                "check": "mac-flip-flop",
                "severity": "high",
                "ip": ip,
                "transitions": len(seq) - 1,
                "mac_sequence": [m for _, m in seq[:20]],
                "message": f"{ip} bergantian diumumkan oleh MAC berbeda "
                           f"{len(seq) - 1}x (pola flip-flop arpwatch).",
            })

    if gateway_ip:
        gw_seq = mac_seq.get(gateway_ip) or []
        if len({m for _, m in gw_seq}) >= 2:
            findings.append({
                "check": "gateway-mac-change",
                "severity": "high",
                "ip": gateway_ip,
                "mac_sequence": [m for _, m in gw_seq[:20]],
                "message": f"MAC pengumuman gateway {gateway_ip} berubah "
                           f"selama capture — cek failover sah dulu.",
            })

    for sender, stamps in sorted(gratuitous_by_sender.items()):
        peak = _peak_window(stamps, flood_window)
        if peak and peak[0] >= flood_count:
            findings.append({
                "check": "gratuitous-flood",
                "severity": "high",
                "sender": sender,
                "count": peak[0],
                "window_s": flood_window,
                "from_ts": round(peak[1], 6),
                "to_ts": round(peak[2], 6),
                "message": f"{peak[0]} gratuitous ARP reply dari {sender} "
                           f"dalam {flood_window:g}s (caveat: failover sah).",
            })

    peak_all = _peak_window(all_arp_ts, volume_window) if all_arp_ts else None
    if peak_all and peak_all[0] >= volume_threshold:
        findings.append({
            "check": "arp-volume-spike",
            "severity": "medium",
            "count": peak_all[0],
            "window_s": volume_window,
            "from_ts": round(peak_all[1], 6),
            "to_ts": round(peak_all[2], 6),
            "message": f"Lonjakan volume ARP: {peak_all[0]} frame dalam "
                       f"{volume_window:g}s.",
        })

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["check"]))

    top_bindings = {ip: c.most_common(1)[0][0]
                    for ip, c in sorted(ip_macs.items())[:25]}
    verdict = ("MALICIOUS_PATTERN_DETECTED"
               if any(f["severity"] == "high" for f in findings)
               else ("SUSPICIOUS" if findings else "CLEAN_NO_POISONING"))
    return {
        "schema": SCHEMA,
        "packets_scanned": total,
        "truncated": truncated,
        "linktypes": {str(k): v for k, v in sorted(linktypes.items())},
        "arp_frames": arp_frames,
        "arp_requests": requests,
        "arp_replies": replies,
        "gratuitous_replies": gratuitous,
        "arp_malformed": arp_malformed,
        "non_arp_frames": non_arp,
        "bindings_top": top_bindings,
        "findings": findings,
        "verdict": verdict,
        "note": "read-only DFIR L2; ARP tanpa autentikasi sehingga temuan "
                "adalah LEAD indikator — grat/failover sah (VRRP) bisa "
                "memenuhi cek flood/gateway; konfirmasi dengan owner "
                "jaringan sebelum tindakan.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="arp_pcap_scan — deteksi indikasi ARP poisoning dari "
                    "pcap Ethernet (read-only, nol jaringan).")
    ap.add_argument("--pcap", required=True, help="file pcap classic")
    ap.add_argument("--gateway-ip", help="IP gateway utk cek ganti MAC")
    ap.add_argument("--flip-transitions", type=int, default=3,
                    help="ambang transisi MAC utk flip-flop (default 3)")
    ap.add_argument("--flood-count", type=int, default=10,
                    help="ambang gratuitous reply per jendela (default 10)")
    ap.add_argument("--flood-window", type=float, default=10.0,
                    help="jendela flood detik (default 10)")
    ap.add_argument("--volume-threshold", type=int, default=50,
                    help="ambang total frame ARP per jendela (default 50)")
    ap.add_argument("--volume-window", type=float, default=10.0,
                    help="jendela volume detik (default 10)")
    ap.add_argument("--fail-on", choices=["medium", "high"], default="high",
                    help="severity minimum utk exit 1 (default high)")
    ap.add_argument("--json", action="store_true", help="keluaran JSON")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.pcap)
    if not path.is_file():
        print(f"[arp] file tidak ada: {path}", file=sys.stderr)
        return 2
    data = path.read_bytes()
    try:
        result = scan(
            data,
            flip_transitions=args.flip_transitions,
            flood_count=args.flood_count,
            flood_window=args.flood_window,
            volume_threshold=args.volume_threshold,
            volume_window=args.volume_window,
            gateway_ip=args.gateway_ip,
        )
    except ValueError as exc:
        print(f"[arp] pcap tidak valid (fail-closed): {exc}", file=sys.stderr)
        return 2

    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    if args.json or args.out:
        print(text)
    else:
        print(f"verdict          : {result['verdict']}")
        print(f"packets_scanned  : {result['packets_scanned']}"
              f" (arp={result['arp_frames']}, non_arp={result['non_arp_frames']})")
        print(f"gratuitous       : {result['gratuitous_replies']}")
        for f in result["findings"]:
            print(f"  [{f['severity']:6}] {f['check']}: {f['message']}")
        if result["truncated"]:
            print("  CATATAN: paket terakhir terpotong (truncated)")
        print(f"note             : {result['note']}")

    worst = max((SEV_ORDER[f["severity"]] for f in result["findings"]),
                default=0)
    return 1 if worst >= SEV_ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
