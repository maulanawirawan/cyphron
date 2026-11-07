r"""[SAFETY: read-only] ws_handshake_audit — audit OFFLINE bukti handshake
WebSocket utk CSWSH/absennya auth/teks-terbuka (T1559.100? — ranah OWASP
A01/A05; kelas komunikasi real-time). TANPA jaringan.

Port konsep dari antrean SKILL-PORT-QUEUE #0514 (mukul975/Anthropic-
Cybersecurity-Skills 'exploiting-websocket-vulnerabilities'; atribusi
konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH: taksonomi
temuan handshake ditulis sendiri dari spesifikasi RFC 6455 + konsep
pengujian publik (differential Origin, key konforman, subprotokol).
Skill sumber = runbook live (wscat/Burp/python websockets); cyphron
menganalisis BUKTI probe handshake (export Burp/DevTools/curl -I) —
tool ini TIDAK membuka koneksi.

Input -> mekanisme -> output:
  - Input : file JSON (array) atau JSONL, satu objek per baris:
      (a) handshake: {"url": "ws(s)://...", "status": 101|403|...,
          "request_headers": {...}, "response_headers": {...}}
          (header case-insensitive; field opsional per jenis cek)
      (b) halaman: {"url": "https://...", "html": "<...>"}
          — dicari referensi ws:// di halaman HTTPS (mixed transport).
  - Mekanisme: cek deterministik per rekaman + korelasi kecil:
    Origin-evil yang dijawab 101 = CSWSH; handshake tanpa kredensial
    yang diterima = auth absen di upgrade; key/ketentuan RFC tidak
    diwapit = validasi longgar; query URL ber-token = kredensial di
    URL; referensi ws:// di halaman https = transport campuran.
  - Output: temuan {check, severity, url, message} + stats + notes
    (ranah pesan-WS — authz per pesan, rate limit, injeksi isi —
    butuh sesi live, dicatat eksplisit BUKAN disimpulkan aman).

Cek:
  cswsh-origin-unvalidated (high) : probe dgn Origin asing/evil dijawab
                                    101 Switching Protocols — hijack
                                    sesi browser via halaman musuh.
  nonconform-key-accepted  (high) : upgrade 101 tanpa Sec-WebSocket-Key
                                    di request (RFC 6455 wajib).
  anon-handshake-accepted  (medium): upgrade 101 tanpa cookie/authorization
                                    apa pun di request (endpoint mungkin
                                    memang publik — konteks review).
  ws-plaintext             (medium): endpoint ws:// (bukan wss://).
  mixed-ws-on-https-page   (medium): halaman https:// merujuk ws://.
  token-in-query           (medium): token/key/auth/secret di query URL.
  permessage-deflate       (low)   : kompresi dinegosiasikan (sisi-
                                    kanal CRIME-like bila isi rahasia).
  subprotocol-echo         (low)   : Sec-WebSocket-Protocol request
                                    di-echo utuh (negosiasi longgar).

Fail-closed:
  - Bukti tidak valid / nol rekaman ter-parse -> exit 2.
  - Status 4xx dgn Origin evil dicatat di notes (origin DITEGAKKAN —
    bukti positif, bukan kegelapan).
  - Authz level-pesan & rate limit tidak bisa dinilai dari bukti
    handshake — dicatat sebagai cakupan yang tidak dinilai.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/ws_handshake_audit.py --evidence bukti-handshake.jsonl
  python tools/ws_handshake_audit.py --evidence burp.json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.ws-handshake-audit/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

_TOKEN_QUERY = re.compile(r"[?&](token|key|auth|secret|jwt|session)=", re.I)
_RE_WS_REF = re.compile(r"""["']ws://[^"'\s]+["']""", re.I)


def _norm_headers(headers: "dict | None") -> "dict[str, str]":
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if isinstance(k, str) and isinstance(v, str):
            out[k.lower()] = v
    return out


def load_evidence(path: Path) -> "list[dict]":
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"bukti tidak terbaca: {exc}") from exc
    if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("bukti melebihi batas ukuran")
    stripped = raw.strip()
    if not stripped:
        raise ValueError("bukti kosong")
    if stripped.startswith("["):
        try:
            records = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON array tidak valid: {exc}") from exc
    else:
        records = []
        for lineno, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"JSONL baris {lineno} tidak valid: {exc}") from exc
    if not isinstance(records, list):
        raise ValueError("JSON bukan array")
    valid: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if isinstance(rec.get("url"), str) and isinstance(rec.get("html"), str):
            valid.append({"kind": "page", "url": rec["url"],
                          "html": rec["html"]})
        elif isinstance(rec.get("url"), str) and "status" in rec:
            valid.append({
                "kind": "handshake", "url": rec["url"],
                "status": rec["status"],
                "req": _norm_headers(rec.get("request_headers")),
                "resp": _norm_headers(rec.get("response_headers")),
            })
    if not valid:
        raise ValueError(
            "nol rekaman valid (butuh handshake url+status atau halaman "
            "url+html)")
    return valid


def _auth_cookie_present(req: "dict[str, str]") -> bool:
    return any(h in req for h in ("cookie", "authorization",
                                  "sec-websocket-protocol-token",
                                  "x-api-key"))


def analyze(evidence: "list[dict]") -> "dict":
    findings: "list[dict]" = []
    n_handshake = 0
    origin_enforced: "list[str]" = []

    for rec in evidence:
        if rec["kind"] == "page":
            for m in _RE_WS_REF.findall(rec["html"]):
                findings.append({
                    "check": "mixed-ws-on-https-page", "severity": "medium",
                    "url": rec["url"],
                    "message": (
                        f"Halaman HTTPS merujuk endpoint plaintext {m} — "
                        "transport campuran; frame ws:// terbaca network "
                        "observer."),
                })
            continue

        n_handshake += 1
        url = rec["url"]
        status = rec["status"]
        req, resp = rec["req"], rec["resp"]
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None

        # CSWSH: Origin asing dijawab 101.
        origin = req.get("origin", "")
        if origin and status == 101:
            # "evil"/"attacker"/domain non-target = probe sengaja asing.
            # Bukti dinyatakan probe-evil oleh pencatat; dikenali dari
            # header X-Probe-Evil: 1 ATAU origin berlabel evil/attacker.
            probe_evil = (
                req.get("x-probe-evil") == "1"
                or any(t in origin.lower() for t in ("evil", "attacker")))
            if probe_evil:
                findings.append({
                    "check": "cswsh-origin-unvalidated", "severity": "high",
                    "url": url,
                    "message": (
                        f"Upgrade 101 diterima dgn Origin '{origin}' "
                        "(probe asing) — Origin tidak divalidasi saat "
                        "handshake; halaman musuh bisa membuka WS memakai "
                        "cookie korban (CSWSH)."),
                })
            else:
                origin_enforced.append(f"{url} (origin {origin} -> {status})")
        elif origin and status in (403, 400):
            origin_enforced.append(f"{url} (origin {origin} -> {status})")

        # RFC 6455: upgrade tanpa Sec-WebSocket-Key diterima.
        if status == 101 and "sec-websocket-key" not in req:
            findings.append({
                "check": "nonconform-key-accepted", "severity": "high",
                "url": url,
                "message": (
                    "Upgrade 101 tanpa Sec-WebSocket-Key di request — "
                    "validasi handshake longgar (RFC 6455 §4.2.1 wajib "
                    "key); server menerima klien non-konforman."),
            })

        # Upgrade anonim diterima.
        if status == 101 and not _auth_cookie_present(req):
            findings.append({
                "check": "anon-handshake-accepted", "severity": "medium",
                "url": url,
                "message": (
                    "Upgrade 101 tanpa cookie/authorization — tidak ada "
                    "auth di handshake; endpoint mungkin memang publik "
                    "(tinjau konteks), bila datanya privat ini akses "
                    "tanpa identitas."),
            })

        # Transport plaintext + token di URL.
        if url.lower().startswith("ws://"):
            findings.append({
                "check": "ws-plaintext", "severity": "medium",
                "url": url,
                "message": "Endpoint ws:// (tanpa TLS) — frame terbaca "
                           "network observer.",
            })
        if _TOKEN_QUERY.search(url):
            findings.append({
                "check": "token-in-query", "severity": "medium",
                "url": url,
                "message": (
                    "Kredensial di query URL (token/key/auth=...) — URL "
                    "tersimpan di log proxy/browser/history."),
            })

        # Ekstensi & subprotokol.
        ext = resp.get("sec-websocket-extensions", "")
        if "permessage-deflate" in ext.lower():
            findings.append({
                "check": "permessage-deflate", "severity": "low",
                "url": url,
                "message": (
                    "Kompresi permessage-deflate dinegosiasikan — bila "
                    "frame memuat rahasia bersama data terkendali, "
                    "sisi-kanal kompresi (CRIME-like) mungkin; matikan "
                    "bila tak wajib."),
            })
        req_proto = req.get("sec-websocket-protocol", "")
        resp_proto = resp.get("sec-websocket-protocol", "")
        if req_proto and resp_proto and req_proto.strip() == resp_proto.strip():
            findings.append({
                "check": "subprotocol-echo", "severity": "low",
                "url": url,
                "message": (
                    f"Sec-WebSocket-Protocol '{req_proto}' di-echo utuh — "
                    "negosiasi tanpa whitelist; klien bisa memilih "
                    "subprotokol arbitrer."),
            })

    notes: "list[str]" = []
    if origin_enforced:
        notes.append(
            "origin DITEGAKKAN pada: " + "; ".join(origin_enforced))
    if n_handshake:
        notes.append(
            "authz level-pesan (IDOR/subscribe channel), rate limit, dan "
            "injeksi isi frame butuh sesi WS live — tidak dinilai dari "
            "bukti handshake, jangan disimpulkan aman dari kegelapan ini.")
    else:
        notes.append("tidak ada rekaman handshake di bukti — cek hanya "
                     "menyentuh referensi halaman.")

    return {"findings": findings, "notes": notes,
            "handshakes": n_handshake}


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit bukti handshake WebSocket (offline, nol jaringan).")
    ap.add_argument("--evidence", required=True,
                    help="bukti JSON array / JSONL (handshake url+status"
                         "+headers, atau halaman url+html)")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None,
                    help="tulis laporan JSON ke file (default stdout)")
    args = ap.parse_args(argv)

    path = Path(args.evidence)
    try:
        evidence = load_evidence(path)
    except ValueError as exc:
        print(json.dumps({
            "schema": SCHEMA, "error": str(exc), "source": str(path),
        }, ensure_ascii=False), file=sys.stderr)
        return 2

    result = analyze(evidence)
    threshold = SEVERITY_ORDER[args.fail_on]
    hit = [f for f in result["findings"]
           if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    report = {
        "schema": SCHEMA,
        "source": str(path),
        "handshakes": result["handshakes"],
        "findings": result["findings"],
        "notes": result["notes"],
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
