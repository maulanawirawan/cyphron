"""[SAFETY: read-only] netflow_parse — parser NetFlow v5 + deteksi
anomali trafik (scan / exfil / beacon).

Port konsep dari antrean SKILL-PORT-QUEUE #0222 (mukul975/
Anthropic-Cybersecurity-Skills 'analyzing-network-flow-data-with-
netflow' — pustaka netflow + analisis baseline). Dibangun from
scratch dari spesifikasi NetFlow v5 Cisco yang dipublikasikan
terbuka, stdlib-only, NOL jaringan: input = file berisi datagram
NetFlow v5 mentah yang digabung (payload UDP export hasil capture
lab/berizin), TIDAK menghubungi collector apapun.

Mekanisme:
  - header 24B (version=5, count, sys_uptime, unix_secs/nsecs,
    flow_sequence, engine, sampling) + record 48B per flow
  - waktu absolut flow = unix_secs*1000 + nsecs/1e6 - (sys_uptime -
    first) — dipakai utk deteksi beacon berbasis interval
  - agregat per host sumber/tujuan: flow, host tujuan unik, port
    tujuan unik, byte keluar/masuk
  - heuristik anomali (threshold bisa diatur, bukti disertakan):
      * scan   : 1 host sumber menjangkau >= --scan-ports port tujuan
                 ATAU >= --scan-hosts host tujuan
      * exfil  : total byte keluar >= --exfil-bytes dari satu sumber
      * beacon : >= --beacon-min flow ke (src,dst,port) yang sama,
                 interval antar-mulai relatif teratur (stdev <= 2s)

Fail-closed: file kosong / bukan NetFlow v5 -> exit 2. Datagram tak
sah di tengah file TIDAK dipendam — parsing berhenti di situ, offset
dan sisa byte dicatat di output (packet_malformed_tail).

Pemakaian:
  python tools/netflow_parse.py --flows capture.netflow --out nf.json
  python tools/netflow_parse.py --flows capture.netflow --scan-ports 10
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from pathlib import Path

SCHEMA = "secai.netflow-parse/1"

HEADER_LEN = 24
RECORD_LEN = 48
VERSION = 5

HEADER = struct.Struct("!HHIIIIBBH")
RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes v5


def _ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


def parse_datagram(buf: bytes, base_flow_seq: int) -> tuple[list[dict],
                                                            int]:
    """Parse satu datagram v5 -> (flows, header_dict)."""
    if len(buf) < HEADER_LEN:
        raise ValueError("datagram lebih pendek dari header 24B")
    (version, count, uptime, secs, nsecs, seq, etype, eid,
     sampling) = HEADER.unpack_from(buf, 0)
    if version != VERSION:
        raise ValueError(f"bukan NetFlow v5 (version={version})")
    need = HEADER_LEN + count * RECORD_LEN
    if len(buf) < need:
        raise ValueError(f"datagram terpotong: butuh {need}B, ada {len(buf)}B")
    flows: list[dict] = []
    for i in range(count):
        (src, dst, nh, inp, outp, pkts, octets, first, last, sport,
         dport, _pad1, tcpf, prot, tos, sas, das, smask, dmask,
         _pad2) = RECORD.unpack_from(buf, HEADER_LEN + i * RECORD_LEN)
        start_ms = (secs * 1000 + nsecs // 1_000_000
                    - (uptime - first))
        dur_ms = max(0, last - first)
        flows.append({
            "src": _ip(src), "dst": _ip(dst), "nexthop": _ip(nh),
            "in_if": inp, "out_if": outp,
            "packets": pkts, "bytes": octets,
            "start_ms": start_ms, "duration_ms": dur_ms,
            "src_port": sport, "dst_port": dport,
            "tcp_flags": tcpf, "proto": prot,
            "src_as": sas, "dst_as": das,
            "src_mask": smask, "dst_mask": dmask,
        })
    return flows, count


def _mean_std(vals: list[float]) -> tuple[float, float]:
    if len(vals) < 2:
        return (vals[0] if vals else 0.0), 0.0
    m = sum(vals) / len(vals)
    var = sum((v - m) ** 2 for v in vals) / (len(vals) - 1)
    return m, var ** 0.5


def analyze(flows: list[dict], scan_ports: int, scan_hosts: int,
            exfil_bytes: int, beacon_min: int) -> list[dict]:
    """Heuristik anomali — setiap flag disertai bukti, fail-closed
    (tanpa bukti tidak dilaporkan)."""
    anomalies: list[dict] = []
    per_src: dict[str, dict] = {}
    for f in flows:
        s = per_src.setdefault(f["src"], {
            "flows": 0, "bytes_out": 0, "dst_hosts": set(),
            "dst_ports": set()})
        s["flows"] += 1
        s["bytes_out"] += f["bytes"]
        s["dst_hosts"].add(f["dst"])
        s["dst_ports"].add(f["dst_port"])

    for src, s in sorted(per_src.items()):
        if len(s["dst_ports"]) >= scan_ports:
            anomalies.append({
                "type": "port-scan", "src": src,
                "detail": f"{len(s['dst_ports'])} port tujuan unik "
                          "(>= ambang)", "evidence": {
                              "dst_ports_unique": len(s["dst_ports"]),
                              "sample": sorted(s["dst_ports"])[:20]}})
        if len(s["dst_hosts"]) >= scan_hosts:
            anomalies.append({
                "type": "host-sweep", "src": src,
                "detail": f"{len(s['dst_hosts'])} host tujuan unik "
                          "(>= ambang)", "evidence": {
                              "dst_hosts_unique": len(s["dst_hosts"])}})
        if s["bytes_out"] >= exfil_bytes:
            anomalies.append({
                "type": "exfil-candidate", "src": src,
                "detail": f"total {s['bytes_out']} byte keluar "
                          "(>= ambang)", "evidence": {
                              "bytes_out": s["bytes_out"],
                              "flows": s["flows"]}})

    groups: dict[tuple, list[int]] = {}
    for f in flows:
        groups.setdefault((f["src"], f["dst"], f["dst_port"]),
                          []).append(f["start_ms"])
    for (src, dst, dport), starts in sorted(groups.items()):
        if len(starts) < beacon_min:
            continue
        starts = sorted(starts)
        intervals = [b - a for a, b in zip(starts, starts[1:])
                     if b > a]
        if not intervals:
            continue
        mean, std = _mean_std([float(x) for x in intervals])
        if std <= 2000.0:  # teratur: stdev <= 2 detik
            anomalies.append({
                "type": "beacon-candidate", "src": src, "dst": dst,
                "detail": f"{len(starts)} flow ke port {dport}, "
                          f"interval rata-rata {mean/1000:.1f}s "
                          f"(stdev {std/1000:.2f}s <= 2s)",
                "evidence": {"flows": len(starts),
                             "interval_mean_ms": round(mean, 1),
                             "interval_stdev_ms": round(std, 1)}})
    return anomalies


def scan_file(path: Path, scan_ports: int = 20, scan_hosts: int = 10,
              exfil_bytes: int = 100 * 1024 * 1024,
              beacon_min: int = 5) -> dict:
    data = path.read_bytes()
    if not data:
        raise ValueError("file kosong")
    flows: list[dict] = []
    packets = 0
    off = 0
    tail_note = ""
    while off < len(data):
        if len(data) - off < HEADER_LEN:
            tail_note = f"{len(data) - off} byte sisa (kurang dari header)"
            break
        try:
            nf, count = parse_datagram(data[off:], len(flows))
        except ValueError as exc:
            if not flows:
                raise
            tail_note = (f"berhenti di offset {off}: {exc}; "
                         f"{len(data) - off} byte sisanya tak terurai")
            break
        flows.extend(nf)
        packets += 1
        off += HEADER_LEN + count * RECORD_LEN

    bytes_total = sum(f["bytes"] for f in flows)
    pkts_total = sum(f["packets"] for f in flows)
    anomalies = analyze(flows, scan_ports, scan_hosts, exfil_bytes,
                        beacon_min)
    out: dict = {
        "schema": SCHEMA,
        "file": str(path),
        "netflow_packets": packets,
        "flows": len(flows),
        "bytes_total": bytes_total,
        "packets_total": pkts_total,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "read_only": True,
    }
    if tail_note:
        out["packet_malformed_tail"] = tail_note
    if len(data) > 0 and packets == 0:
        raise ValueError("tidak ada datagram NetFlow v5 yang valid")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Parser NetFlow v5 + deteksi anomali "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--flows", required=True,
                    help="file datagram NetFlow v5 mentah (gabungan "
                         "payload UDP export)")
    ap.add_argument("--scan-ports", type=int, default=20,
                    help="ambang port tujuan unik per sumber (default 20)")
    ap.add_argument("--scan-hosts", type=int, default=10,
                    help="ambang host tujuan unik per sumber (default 10)")
    ap.add_argument("--exfil-bytes", type=int,
                    default=100 * 1024 * 1024,
                    help="ambang byte keluar per sumber (default 100MB)")
    ap.add_argument("--beacon-min", type=int, default=5,
                    help="minimum flow utk kandidat beacon (default 5)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.flows)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = scan_file(path, args.scan_ports, args.scan_hosts,
                           args.exfil_bytes, args.beacon_min)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
