"""test_pcap_triage — triase pcap offline (#0855 #0856 #0857), nol
jaringan, tanpa capture nyata.

Fixture = bytes pcap disintesis dgn struct (writer helper di file ini)
mengikuti spesifikasi publik libpcap/Ethernet/IPv4/TCP/UDP/DNS/TLS;
bukan salinan kode alat sumber dan bukan capture pihak ketiga.
"""
from __future__ import annotations

import base64
import json
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import pcap_triage as pt  # noqa: E402


# -------------------------------------------------- fixture writer
def _pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _rec(ts: float, frame: bytes) -> bytes:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame),
                       len(frame)) + frame


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x11\x22\x33\x44\x55\x66" + b"\xaa\xbb\xcc\xdd\xee\xff" + \
        struct.pack(">H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    total = 20 + len(l4)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, 64, proto,
                      0) + bytes(int(x) for x in src.split(".")) + \
        bytes(int(x) for x in dst.split("."))
    return hdr + l4


def _tcp(sport: int, dport: int, flags: int = 0x18,
         payload: bytes = b"") -> bytes:
    # header TCP penuh 20 byte: sport dport seq ack off|res flags win cks urg
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags,
                       65535, 0, 0) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + \
        payload


def _dns_query(name: str, qtype: int = 1) -> bytes:
    q = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def _client_hello(sni: str) -> bytes:
    # server_name list: list_len(2) type(1) name_len(2) name
    data = struct.pack(">H", len(sni) + 3) + b"\x00" + \
        struct.pack(">H", len(sni)) + sni.encode()
    ext = struct.pack(">HH", 0x0000, len(data)) + data
    body = struct.pack(">H", 0x0303) + b"\x00" * 32 + \
        b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + \
        b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _write_pcap(tmp_path: Path, name: str, frames: "list[bytes]") -> Path:
    p = tmp_path / name
    p.write_bytes(_pcap_header() +
                  b"".join(_rec(1000.0 + i * 0.01, f)
                           for i, f in enumerate(frames)))
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pcap_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pcap_triage.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--pcap", str(tmp_path / "no.pcap"))
    assert rc == 2 and out is None and "tidak ada" in err


def test_not_pcap_exit2(tmp_path):
    p = tmp_path / "rand.bin"
    p.write_bytes(b"\x00" * 100)
    rc, out, err = _run("--pcap", str(p))
    assert rc == 2 and "magic" in err


def test_pcapng_rejected(tmp_path):
    p = tmp_path / "x.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    rc, out, err = _run("--pcap", str(p))
    assert rc == 2 and "PCAPNG" in err


def test_empty_pcap_exit2(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(_pcap_header())
    rc, out, err = _run("--pcap", str(p))
    assert rc == 2 and "nol paket" in err


# ------------------------------------------------------- statistik
def test_protocol_counts_and_conversations(tmp_path):
    frames = [
        _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1000, 80))),
        _eth(_ipv4("10.0.0.2", "10.0.0.1", 6, _tcp(80, 1000))),
        _eth(_ipv4("10.0.0.1", "8.8.8.8", 17,
                   _udp(53, 53, _dns_query("example.com")))),
        _eth(b"\x00\x01\x08\x00\x06\x04" + b"\x00" * 20, 0x0806),
        _eth(b"\x60\x00" + b"\x00" * 30, 0x86DD),
    ]
    p = _write_pcap(tmp_path, "stats.pcap", frames)
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 0
    st = out["stats"]
    assert st["packets"] == 5 and st["tcp"] == 2 and st["udp"] == 1
    assert st["arp"] == 1 and st["ipv6"] == 1
    conv = {(c["a"], c["b"]): c for c in out["conversations"]}
    assert conv[("10.0.0.1", "10.0.0.2")]["packets"] == 2


# ------------------------------------------------------- kredensial
def test_http_basic_creds(tmp_path):
    cred = base64.b64encode(b"admin:S3cretPw!").decode()
    req = (b"GET /admin HTTP/1.1\r\nHost: intranet.lab.corp\r\n"
           b"User-Agent: curl/8.5\r\nAuthorization: Basic " +
           cred.encode() + b"\r\n\r\n")
    p = _write_pcap(tmp_path, "http.pcap",
                    [_eth(_ipv4("10.0.0.9", "10.0.0.5", 6,
                                _tcp(40000, 80, payload=req)))])
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 1
    f = [x for x in out["findings"]
         if x["check"] == "cleartext-http-basic"]
    assert len(f) == 1 and f[0]["severity"] == "high"
    assert f[0]["source_ip"] == "10.0.0.9"
    blob = json.dumps(out)
    assert "S3cretPw!" not in blob          # nilai penuh TIDAK bocor
    assert "len=9" in f[0]["message"]       # hanya panjang
    assert out["http"]["hosts"]["intranet.lab.corp"] == 1


def test_ftp_creds_split_packets(tmp_path):
    frames = [
        _eth(_ipv4("10.0.0.9", "10.0.0.5", 6,
                   _tcp(40001, 21, payload=b"USER ftpbackup\r\n"))),
        _eth(_ipv4("10.0.0.9", "10.0.0.5", 6,
                   _tcp(40001, 21, payload=b"PASS hunter2secret\r\n"))),
    ]
    p = _write_pcap(tmp_path, "ftp.pcap", frames)
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 1
    f = [x for x in out["findings"]
         if x["check"] == "cleartext-ftp-creds"]
    assert len(f) == 1
    assert "hunter2secret" not in json.dumps(out)
    assert "len=13" in f[0]["message"]


# ------------------------------------------------------- dns / sni
def test_dns_queries_and_tunnel(tmp_path):
    frames = [
        _eth(_ipv4("10.0.0.7", "8.8.8.8", 17,
                   _udp(53, 53, _dns_query("example.com")))),
        _eth(_ipv4("10.0.0.7", "8.8.8.8", 17,
                   _udp(53, 53, _dns_query("evil.example.tk")))),
    ]
    for i in range(4):
        long_label = "a" * 40 + str(i)
        frames.append(_eth(_ipv4(
            "10.0.0.7", "8.8.8.8", 17,
            _udp(53, 53, _dns_query(f"{long_label}.tun.evil.tk",
                                    qtype=16)))))
    p = _write_pcap(tmp_path, "dns.pcap", frames)
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 1
    assert out["stats"]["dns_queries"] == 6
    names = [q["name"] for q in out["dns_queries"]]
    assert "example.com" in names
    f = [x for x in out["findings"] if x["check"] == "dns-tunnel-candidate"]
    assert len(f) == 1
    assert "evil.tk" in f[0]["message"]  # domain dasar = 2 label terakhir


def test_sni_extracted(tmp_path):
    p = _write_pcap(tmp_path, "tls.pcap", [
        _eth(_ipv4("10.0.0.9", "93.184.216.34", 6,
                   _tcp(40002, 443, payload=_client_hello(
                       "update-service.example-c2.net"))))])
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 0
    assert out["tls_sni"]["update-service.example-c2.net"] == 1
    assert out["stats"]["tls_clienthello"] == 1


# ------------------------------------------------------- beacon & scan
def test_beacon_detected(tmp_path):
    frames = []
    for i in range(6):  # SYN tiap ~60s, jitter kecil
        frames.append(_eth(_ipv4(
            "10.0.0.20", "185.53.10.9", 6,
            _tcp(50000, 443, flags=0x02))))
    p = tmp_path / "beacon.pcap"
    p.write_bytes(_pcap_header() + b"".join(
        _rec(1000.0 + i * 60.0, f) for i, f in enumerate(frames)))
    rc, out, _ = _run("--pcap", str(p))
    f = [x for x in out["findings"] if x["check"] == "beacon-candidate"]
    assert len(f) == 1
    assert "185.53.10.9" in f[0]["message"]


def test_jittery_traffic_no_beacon(tmp_path):
    frames = []
    t = 1000.0
    offsets = [0, 10, 47, 61, 118, 240, 301]  # acak
    for off in offsets:
        frames.append(_eth(_ipv4(
            "10.0.0.21", "203.0.113.80", 6, _tcp(50001, 443,
                                                 flags=0x02))))
    p = tmp_path / "jit.pcap"
    p.write_bytes(_pcap_header() + b"".join(
        _rec(1000.0 + off, f) for off, f in zip(offsets, frames)))
    rc, out, _ = _run("--pcap", str(p))
    assert "beacon-candidate" not in _checks(out)


def test_portscan_detected(tmp_path):
    frames = []
    for port in range(60, 120):  # 60 port SYN-only unik
        frames.append(_eth(_ipv4(
            "10.0.0.30", "10.0.0.99", 6,
            _tcp(50002, port, flags=0x02))))
    p = _write_pcap(tmp_path, "scan.pcap", frames)
    rc, out, _ = _run("--pcap", str(p))
    f = [x for x in out["findings"] if x["check"] == "portscan-candidate"]
    assert len(f) == 1 and f[0]["source_ip"] == "10.0.0.30"


def test_few_syns_no_scan(tmp_path):
    frames = [_eth(_ipv4("10.0.0.31", "10.0.0.99", 6,
                         _tcp(50003, port, flags=0x02)))
              for port in (22, 80, 443)]
    p = _write_pcap(tmp_path, "noscan.pcap", frames)
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- fail-closed
def test_truncated_counted(tmp_path):
    # orig_len lebih besar dari caplen -> truncated
    hdr = _pcap_header()
    frame = _eth(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1, 80)))
    rec = struct.pack("<IIII", 1000, 0, len(frame), len(frame) + 50) + \
        frame
    p = tmp_path / "trunc.pcap"
    p.write_bytes(hdr + rec)
    rc, out, _ = _run("--pcap", str(p))
    assert rc == 1
    assert "truncated-packet" in _checks(out)


# ------------------------------------------------------- anti-FP
def test_allow_ip(tmp_path):
    cred = base64.b64encode(b"svc:pw123456").decode()
    req = (b"GET / HTTP/1.1\r\nHost: h.lab\r\nAuthorization: Basic " +
           cred.encode() + b"\r\n\r\n")
    p = _write_pcap(tmp_path, "allow.pcap", [
        _eth(_ipv4("10.0.0.99", "10.0.0.5", 6,
                   _tcp(41000, 80, payload=req)))])
    rc, out, _ = _run("--pcap", str(p), "--allow-ip", "10.0.0.99")
    assert rc == 0
    assert out["findings"] == []
    assert out["stats"]["allowed_filtered"] == 1


# ------------------------------------------------------- kontrak
def test_schema_sorted_notes(tmp_path):
    frames = [
        _eth(_ipv4("10.0.0.1", "8.8.8.8", 17,
                   _udp(53, 53, _dns_query("a.com")))),
    ]
    frames += [_eth(_ipv4("10.0.0.30", "10.0.0.99", 6,
                          _tcp(50002, port, flags=0x02)))
               for port in range(60, 115)]
    p = _write_pcap(tmp_path, "contract.pcap", frames)
    _, out, _ = _run("--pcap", str(p))
    assert out["schema"] == pt.SCHEMA
    sevs = [pt.SEV_ORDER[f["severity"]] for f in out["findings"]]
    assert sevs == sorted(sevs, reverse=True)
    assert any("PCAPNG" in n for n in out["notes"])
    assert any("ioc_defang" in n for n in out["notes"])
    assert all({"check", "severity", "message", "evidence"}
               <= set(f) for f in out["findings"])


def test_fail_on_high(tmp_path):
    frames = [_eth(_ipv4("10.0.0.30", "10.0.0.99", 6,
                         _tcp(50002, port, flags=0x02)))
              for port in range(60, 120)]
    p = _write_pcap(tmp_path, "fh.pcap", frames)
    rc, out, _ = _run("--pcap", str(p), "--fail-on", "high")
    assert rc == 0  # portscan medium < high -> exit 0
    assert "portscan-candidate" in _checks(out)
