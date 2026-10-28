"""[SAFETY: 1-request] tls-cipher-suites-checker — TLS cipher suites posture — 1 handshake
1 handshake TLS — tidak bruteforce, tidak spam.
"""
from __future__ import annotations
import argparse, json, sys, socket, ssl
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings

def probe(host):
    try:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((host,443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                return {"ok":True, "proto":tls.version(), "cipher":tls.cipher()[0] if tls.cipher() else ""}
    except Exception as e:
        return {"ok":False, "err":str(e)}

def audit(host, facts):
    rows=[]
    if not facts.get("ok"):
        rows.append(make_finding(tool="tls-cipher-suites-checker", title=f"TLS probe failed on {host}", severity="info", description=facts.get("err","")[:300], target_url=f"https://{host}", evidence_kind="request-response", finding_class="posture", confidence=1.0, status="unconfirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
    else:
        proto=facts.get("proto","")
        if proto in ("TLSv1","TLSv1.0","TLSv1.1"):
            rows.append(make_finding(tool="tls-cipher-suites-checker", title=f"Weak TLS on {host}: {proto}", severity="medium", description=f"Negosiasi {proto} — lemah.", cwe="CWE-326", target_url=f"https://{host}", response=proto, evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=1, extra={"category":"MISC","safety_class":"1-request"}))
        else:
            rows.append(make_finding(tool="tls-cipher-suites-checker", title=f"TLS OK on {host}: {proto}", severity="info", description=f"Proto {proto} sehat.", target_url=f"https://{host}", response=proto, evidence_kind="request-response", finding_class="posture", confidence=1.0, status="confirmed", verdict=0, extra={"category":"AMAN","safety_class":"1-request"}))
    return rows, {"host":host, "requests":1}

def main():
    ap=argparse.ArgumentParser(description="[SAFETY: 1-request] tls-cipher-suites-checker")
    ap.add_argument("--host", default=None)
    ap.add_argument("--domain", default=None)
    ap.add_argument("--out", default="tls_cipher_suites_checker_findings.json")
    args=ap.parse_args()
    host=args.host or args.domain
    if not host:
        ap.error("--host/--domain wajib")
    facts=probe(host)
    rows,meta=audit(host, facts)
    meta["safety_class"]="1-request"
    write_findings(args.out, rows, meta)
    print(f"tls-cipher-suites-checker: {len(rows)} temuan (1 handshake) -> {args.out}")
    return 0
if __name__=="__main__":
    raise SystemExit(main())
