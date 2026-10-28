"""[SAFETY: 1-request] SSL/TLS analyzer — satu koneksi TLS ke host:443.

Skill v2 (produk Cyphron). Satu TCP+TLS handshake (setara satu kunjungan
browser HTTPS). Yang dianalisis dari sertifikat & sesi:
  - masa berlaku: kedaluwarsa / < 14 hari -> lead
  - protokol negosiasi: TLSv1.0/1.1 -> lead (CWE-327)
  - self-signed (issuer == subject) -> lead
  - SAN jumlah host -> info
Semua klaim membawa bukti mentah (notAfter, issuer, version) — fail-closed.

Pemakaian:
  python skills/ssl_tls_analyzer.py --host contoh.go.id --out f.json
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

UA = user_agent()


def probe_tls(host: str, port: int = 443, timeout: float = 15.0) -> dict:
    """SATU koneksi TLS. Return dict fakta; error jelas, bukan kosong."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # analisis, bukan validasi klien
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der) if der else ""
            return {
                "ok": True,
                "protocol": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
                "pem": pem,
            }


CERT_INFO = """
import ssl, sys, os, json, tempfile
pem = open(sys.argv[1]).read(262145)  # cap 256 KB — sertifikat selalu jauh di bawah ini
with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as f:
    f.write(pem); p = f.name
try:
    info = ssl._ssl._test_decode_cert(p)
    print(json.dumps({'subject': info.get('subject'),
                      'issuer': info.get('issuer'),
                      'not_after_s': ssl.cert_time_to_seconds(info['notAfter']),
                      'not_after': info.get('notAfter'),
                      'san_count': len(info.get('subjectAltName', []) or [])}))
finally:
    os.unlink(p)
"""


def parse_cert_info(pem: str) -> dict | None:
    """Ekstrak fakta sertifikat dari PEM (stdlib; satu subprocess)."""
    if not pem:
        return None
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        import subprocess
        r = subprocess.run(["python", "-c", CERT_INFO, path],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return json.loads(r.stdout)
    finally:
        Path(path).unlink(missing_ok=True)
    return None


def audit(host: str, facts: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []

    def finding(title, sev, desc, rec="", cwe=None, category="MISC",
                verdict=0, status="confirmed"):
        rows.append(make_finding(
            tool="ssl-tls-analyzer", title=title, severity=sev,
            description=desc, recommendation=rec, cwe=cwe,
            target_url=f"https://{host}", response=json.dumps(
                {k: facts.get(k) for k in ("protocol", "cipher")})[:300],
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status=status, verdict=verdict,
            extra={"category": category, "safety_class": "1-request"}))

    if not facts.get("ok"):
        finding(f"TLS handshake failed on {host}", "medium",
                str(facts.get("error"))[:300],
                verdict=1, status="unconfirmed")
        return rows, {"host": host, "error": True}

    # protokol lemah
    proto = facts.get("protocol") or ""
    if proto in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        finding(f"Weak TLS protocol negotiated on {host}: {proto}", "medium",
                f"Sesi tersambung dengan {proto} — protokol di bawah "
                "TLSv1.2 tidak lagi dianggap aman.",
                rec="Matikan TLS 1.0/1.1 di server; minimum TLSv1.2.",
                cwe="CWE-327", category="MISC", verdict=1)
    else:
        finding(f"TLS protocol OK on {host}: {proto}", "info",
                f"Sesi tersambung dengan {proto} (cipher {facts.get('cipher')}).",
                category="AMAN", verdict=0)

    # sertifikat: kedaluwarsa / self-signed
    info = facts.get("cert_info") or {}
    if info.get("not_after_s"):
        days = (info["not_after_s"] - time.time()) / 86400
        if days < 0:
            finding(f"TLS certificate EXPIRED on {host}", "high",
                    f"Sertifikat kedaluwarsa {-days:.0f} hari lalu "
                    f"({info.get('not_after')}) — browser memperingatkan "
                    "pengunjung.",
                    rec="Perbarui sertifikat segera.",
                    cwe="CWE-318", category="MISC", verdict=1)
        elif days < 14:
            finding(f"TLS certificate expires in {days:.0f} days on {host}",
                    "low", "Sertifikat mendekati kedaluwarsa.",
                    rec="Perbarui sebelum kedaluwarsa.",
                    category="MISC", verdict=1)
        else:
            finding(f"TLS certificate validity OK on {host} "
                    f"({days:.0f} days left)", "info",
                    "Masa berlaku sertifikat sehat.",
                    category="AMAN", verdict=0)

    subject = json.dumps(info.get("subject", ""))
    issuer = json.dumps(info.get("issuer", ""))
    if subject and issuer and subject == issuer:
        finding(f"Self-signed certificate on {host}", "medium",
                "Issuer sama dengan subject — sertifikat tidak ditandatangani CA publik.",
                rec="Gunakan sertifikat CA terpercaya (mis. ACME).",
                cwe="CWE-295", category="MISC", verdict=1)

    return rows, {"host": host, "protocol": proto,
                  "san_count": info.get("san_count"),
                  "requests": 1}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--out", default="ssl_findings.json")
    args = ap.parse_args()
    try:
        facts = probe_tls(args.host)
        facts["cert_info"] = parse_cert_info(facts.get("pem", ""))
    except Exception as exc:
        facts = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    rows, meta = audit(args.host, facts)
    write_findings(args.out, rows, {**meta, "safety_class": "1-request"})
    aman = sum(1 for r in rows if r.get("category") == "AMAN")
    print(f"ssl-tls-analyzer: {len(rows)} temuan ({aman} AMAN) -> {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
