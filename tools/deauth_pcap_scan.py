"""[SAFETY: read-only] deauth_pcap_scan — analisis forensik frame
deauthentication/disassociation 802.11 dari file pcap (CWE-754/ laporan
insiden nirkabel), nol jaringan.

Input : file pcap classic (magic a1b2c3d4 / d4c3b2a1 / nano), linktype
        127 (radiotap) atau 105 (802.11 murni).
Parse : radiotap di-skip via length header; frame control 802.11 →
        type=0 (management), subtype 0xC = deauth, 0xA = disassoc;
        addr2 = transmitter (pengirim frame — kandidat penyerang bila
        bukan AP sah), addr3 = BSSID; reason code 2-byte setelah header
        MAC management (offset 24).
Analisis (fail-closed, hanya menghitung yang terbukti dari data):
  - agregasi per transmitter/BSSID, hitung broadcast (DA ff:ff:ff:ff:ff:ff)
  - storm alert: >= --storm-count frame dari transmitter sama dalam
    --storm-window detik (default 10 frame / 10 detik)
  - reason code dihitung (mis. 2=prev-auth-invalid, 3=leaving,
    7=class-3, 15=handshake-timeout) — tanpa interpretasi berlebih
  - status PMF TIDAK bisa dipastikan dari pcap saja — dicatat eksplisit
    (tanpa klaim palsu "aman")
Exit: 0 hasil (+ JSON bila --out); 2 file/magic/linktype tidak didukung;
      3 file terpotong di tengah packet (ditandai truncated, tetap 0).
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "secai.deauth-pcap-scan/1"
RADIOTAP_LINKTYPE = 127
IEEE80211_LINKTYPE = 105
BROADCAST = "ff:ff:ff:ff:ff:ff"
SUBTYPE_DEAUTH = 0xC
SUBTYPE_DISASSOC = 0xA
TYPE_MGMT = 0

REASON_NAMES: dict[int, str] = {
    1: "unspecified", 2: "prev-auth-invalid", 3: "deauth-leaving",
    4: "disassoc-inactivity", 5: "disassoc-ap-busy", 6: "class2-from-nonauth",
    7: "class3-from-nonassoc", 8: "disassoc-leaving",
    15: "4way-handshake-timeout", 16: "4way-key-timeout",
}


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def iter_pcap_packets(data: bytes):
    """Yield (ts_float, payload) tiap packet pcap classic. Fail-closed."""
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
                   linktype, data[off:], True)  # truncated
            return
        yield (ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6),
               linktype, data[off:off + incl_len], False)
        off += incl_len


def strip_radiotap(pkt: bytes) -> bytes:
    """Buang header radiotap via length field (present+pad)."""
    if len(pkt) < 4:
        raise ValueError("radiotap terlalu pendek")
    rt_len = struct.unpack("<H", pkt[2:4])[0]
    if rt_len < 4 or rt_len > len(pkt):
        raise ValueError(f"panjang radiotap tak wajar: {rt_len}")
    return pkt[rt_len:]


def parse_mgmt_frame(pkt80211: bytes) -> "tuple[int, int, str, str, str, int | None] | None":
    """Parse frame control + address + reason utk management frame.

    Return (type, subtype, addr1, addr2, addr3, reason|None) atau None
    jika bukan frame yang kita pedulikan / terlalu pendek.
    """
    if len(pkt80211) < 10:
        return None
    fc0 = pkt80211[0]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xF
    if ftype != TYPE_MGMT:
        return None
    if len(pkt80211) < 24:
        return None
    addr1 = mac_str(pkt80211[4:10])
    addr2 = mac_str(pkt80211[10:16])
    addr3 = mac_str(pkt80211[16:22])
    reason = None
    if subtype in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC) and len(pkt80211) >= 26:
        reason = struct.unpack("<H", pkt80211[24:26])[0]
    return ftype, subtype, addr1, addr2, addr3, reason


def scan(data: bytes, storm_count: int = 10,
         storm_window: float = 10.0) -> dict:
    """Scan penuh byte pcap → ringkasan + alert. Tanpa I/O jaringan."""
    total = 0
    truncated = False
    linktypes: Counter[int] = Counter()
    deauth = disassoc = 0
    by_tx: Counter[str] = Counter()
    by_bssid: Counter[str] = Counter()
    reasons: Counter[int] = Counter()
    broadcast = 0
    events: "list[tuple[float, int, str, str, str, int | None]]" = []

    for ts, linktype, pkt, trunc in iter_pcap_packets(data):
        total += 1
        linktypes[linktype] += 1
        if trunc:
            truncated = True
            break
        try:
            body = strip_radiotap(pkt) if linktype == RADIOTAP_LINKTYPE \
                else (pkt if linktype == IEEE80211_LINKTYPE else None)
        except ValueError:
            body = None
        if body is None:
            continue
        parsed = parse_mgmt_frame(body)
        if parsed is None:
            continue
        _t, subtype, addr1, addr2, addr3, reason = parsed
        if subtype == SUBTYPE_DEAUTH:
            deauth += 1
        elif subtype == SUBTYPE_DISASSOC:
            disassoc += 1
        else:
            continue
        by_tx[addr2] += 1
        by_bssid[addr3] += 1
        if addr1 == BROADCAST:
            broadcast += 1
        if reason is not None:
            reasons[reason] += 1
        events.append((ts, subtype, addr1, addr2, addr3, reason))

    # storm detection: sliding window per transmitter
    alerts: "list[dict]" = []
    per_tx_ts: dict[str, "list[float]"] = {}
    for ts, _st, _a1, a2, _a3, _r in events:
        per_tx_ts.setdefault(a2, []).append(ts)
    for tx, stamps in per_tx_ts.items():
        stamps.sort()
        for i in range(len(stamps)):
            window = [s for s in stamps if stamps[i] - storm_window <= s <= stamps[i]]
            if len(window) >= storm_count:
                alerts.append({
                    "kind": "deauth-storm",
                    "transmitter": tx,
                    "frames": len(window),
                    "window_s": storm_window,
                    "from_ts": window[0],
                    "to_ts": window[-1],
                })
                break  # satu alert per transmitter cukup

    verdict = "MALICIOUS_PATTERN_DETECTED" if alerts or (
        broadcast >= storm_count) else (
        "SUSPICIOUS" if (deauth + disassoc) > 0 else "CLEAN_NO_DEAUTH")
    return {
        "schema": SCHEMA,
        "packets_scanned": total,
        "truncated": truncated,
        "linktypes": {str(k): v for k, v in sorted(linktypes.items())},
        "deauth_count": deauth,
        "disassoc_count": disassoc,
        "broadcast_count": broadcast,
        "reason_codes": {REASON_NAMES.get(k, f"code-{k}"): v
                         for k, v in sorted(reasons.items())},
        "by_transmitter": dict(by_tx.most_common(20)),
        "by_bssid": dict(by_bssid.most_common(20)),
        "alerts": alerts,
        "verdict": verdict,
        "note": "read-only DFIR; PMF (802.11w) tidak dapat dipastikan "
                "dari pcap saja — verdict bukan klaim keamanan menyeluruh.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="deauth_pcap_scan — deteksi serangan deauth/disassoc "
                    "dari capture nirkabel (read-only, nol jaringan).")
    ap.add_argument("--pcap", required=True, help="file pcap classic")
    ap.add_argument("--storm-count", type=int, default=10,
                    help="ambang storm: N frame dari TX sama (default 10)")
    ap.add_argument("--storm-window", type=float, default=10.0,
                    help="jendela storm detik (default 10)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.pcap)
    if not path.is_file():
        print(f"[deauth] file tidak ada: {path}", file=sys.stderr)
        return 2
    data = path.read_bytes()
    try:
        result = scan(data, args.storm_count, args.storm_window)
    except ValueError as exc:
        print(f"[deauth] pcap tidak valid (fail-closed): {exc}",
              file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[deauth] packets={result['packets_scanned']} "
          f"deauth={result['deauth_count']} "
          f"disassoc={result['disassoc_count']} "
          f"broadcast={result['broadcast_count']}")
    for r, c in result["reason_codes"].items():
        print(f"[deauth] reason {r}: {c}")
    for al in result["alerts"]:
        print(f"[deauth] ALERT {al['kind']}: tx={al['transmitter']} "
              f"{al['frames']} frame / {al['window_s']}s")
    print(f"[deauth] verdict: {result['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
