"""test_netflow_parse — parser NetFlow v5 (#0222), nol jaringan.

Fixtures = datagram NetFlow v5 sintetis dibangun dari spesifikasi
header 24B + record 48B (Cisco NetFlow export format v5).
"""
from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import netflow_parse  # noqa: E402

HDR = struct.Struct("!HHIIIIBBH")
REC = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")


def _ip(s: str) -> int:
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _mk_packet(records: list[dict], uptime: int = 100_000,
               unix_secs: int = 1_700_000_000, nsecs: int = 0,
               seq: int = 1) -> bytes:
    hdr = HDR.pack(5, len(records), uptime, unix_secs, nsecs, seq,
                   0, 1, 0)
    body = b""
    for r in records:
        body += REC.pack(
            _ip(r["src"]), _ip(r["dst"]), _ip(r.get("nexthop", "0.0.0.0")),
            r.get("in_if", 1), r.get("out_if", 2),
            r.get("packets", 10), r.get("bytes", 1500),
            r.get("first", 90_000), r.get("last", 91_000),
            r.get("src_port", 44444), r["dst_port"],
            0, r.get("tcp_flags", 0x18), r.get("proto", 6),
            r.get("tos", 0),
            r.get("src_as", 0), r.get("dst_as", 0), 24, 24, 0)
    return hdr + body


def _mk_flow(**kw) -> dict:
    kw.setdefault("src", "10.0.0.5")
    kw.setdefault("dst", "192.0.2.9")
    kw.setdefault("dst_port", 80)
    return kw


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "netflow_parse.py"), "--flows",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def test_parse_basic_fields(tmp_path):
    p = tmp_path / "nf.bin"
    p.write_bytes(_mk_packet([
        _mk_flow(dst_port=443, bytes=5000, packets=5, src_port=49152,
                 proto=6),
    ]))
    rc, out = _run(p)
    assert rc == 0
    assert out["netflow_packets"] == 1 and out["flows"] == 1
    assert out["bytes_total"] == 5000 and out["packets_total"] == 5


def test_absolute_start_time(tmp_path):
    """start_ms = unix_secs*1000 - (uptime - first)."""
    p = tmp_path / "nf.bin"
    # uptime 100000ms, flow first=90000 -> mulai 10000ms sebelum export
    p.write_bytes(_mk_packet([_mk_flow(first=90_000)],
                             uptime=100_000,
                             unix_secs=1_700_000_000))
    rc, out = _run(p)
    # flows ada di anomalies-check saja; cek lewat modul langsung
    flows, _ = netflow_parse.parse_datagram(p.read_bytes(), 0)
    assert flows[0]["start_ms"] == 1_700_000_000_000 - 10_000


def test_duration_and_ports(tmp_path):
    p = tmp_path / "nf.bin"
    p.write_bytes(_mk_packet([_mk_flow(first=50_000, last=60_500,
                                       dst_port=22)]))
    flows, _ = netflow_parse.parse_datagram(p.read_bytes(), 0)
    assert flows[0]["duration_ms"] == 10_500
    assert flows[0]["dst_port"] == 22


def test_port_scan_detected(tmp_path):
    recs = [_mk_flow(dst_port=p_) for p_ in range(4000, 4020)]
    p = tmp_path / "scan.bin"
    p.write_bytes(_mk_packet(recs))
    rc, out = _run(p, "--scan-ports", "20")
    types = [a["type"] for a in out["anomalies"]]
    assert "port-scan" in types
    ev = [a for a in out["anomalies"] if a["type"] == "port-scan"][0]
    assert ev["evidence"]["dst_ports_unique"] == 20


def test_beacon_detected_regular_interval(tmp_path):
    # 6 flow, interval 60.0s teratur (stdev 0)
    recs = []
    for i in range(6):
        recs.append(_mk_flow(dst="198.51.100.7", dst_port=8443,
                             first=1_000 + i * 60_000,
                             last=1_500 + i * 60_000,
                             uptime=200_000))
    p = tmp_path / "beacon.bin"
    p.write_bytes(_mk_packet(recs))
    rc, out = _run(p)
    types = [a["type"] for a in out["anomalies"]]
    assert "beacon-candidate" in types


def test_beacon_not_flagged_irregular(tmp_path):
    recs = []
    gaps = [5_000, 61_000, 9_000, 120_000, 33_000]  # acak
    first = 1_000
    for i, g in enumerate(gaps):
        recs.append(_mk_flow(dst="198.51.100.7", dst_port=8443,
                             first=first, last=first + 500))
        first += g
    p = tmp_path / "noisy.bin"
    p.write_bytes(_mk_packet(recs))
    rc, out = _run(p)
    types = [a["type"] for a in out["anomalies"]]
    assert "beacon-candidate" not in types


def test_exfil_threshold(tmp_path):
    p = tmp_path / "exfil.bin"
    p.write_bytes(_mk_packet([_mk_flow(dst_port=443, bytes=110 *
                                       1024 * 1024)]))
    rc, out = _run(p, "--exfil-bytes", str(100 * 1024 * 1024))
    types = [a["type"] for a in out["anomalies"]]
    assert "exfil-candidate" in types


def test_clean_traffic_no_anomaly(tmp_path):
    recs = [_mk_flow(dst="192.0.2.9", dst_port=443, bytes=50_000)]
    p = tmp_path / "ok.bin"
    p.write_bytes(_mk_packet(recs))
    rc, out = _run(p)
    assert rc == 0 and out["anomaly_count"] == 0


def test_truncated_tail_reported(tmp_path):
    good = _mk_packet([_mk_flow()])
    p = tmp_path / "tail.bin"
    p.write_bytes(good + b"\x00" * 10)  # sisa < header
    rc, out = _run(p)
    assert rc == 0
    assert "packet_malformed_tail" in out
    assert out["flows"] == 1


def test_not_netflow_exit2(tmp_path):
    p = tmp_path / "bukan.bin"
    p.write_bytes(b"\x00\x09" + b"\x00" * 100)  # version=9
    rc, out = _run(p)
    assert rc == 2 and out is None


def test_empty_exit2(tmp_path):
    p = tmp_path / "kosong.bin"
    p.write_bytes(b"")
    rc, out = _run(p)
    assert rc == 2


def test_missing_file_exit2(tmp_path):
    rc, out = _run(tmp_path / "tiada.bin")
    assert rc == 2


def test_out_file(tmp_path):
    p = tmp_path / "nf.bin"
    p.write_bytes(_mk_packet([_mk_flow()]))
    rc, out = _run(p, "--out", str(tmp_path / "o.json"))
    assert rc == 0
    saved = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "secai.netflow-parse/1"


def test_two_datagrams_sequential(tmp_path):
    p = tmp_path / "dua.bin"
    p.write_bytes(_mk_packet([_mk_flow()], seq=1)
                  + _mk_packet([_mk_flow(dst_port=53)], seq=2))
    rc, out = _run(p)
    assert out["netflow_packets"] == 2 and out["flows"] == 2
