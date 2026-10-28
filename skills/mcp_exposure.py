"""[SAFETY: bounded-requests] mcp-exposure — deteksi server MCP
(Model Context Protocol) yang terbuka dari target URL (F62; latar:
riset AI-2026 — CSA "MCP Security Crisis" ±200rb instance rentan,
NSA CSI MCP security, agentic tool-chain attack: satu server
terkompromi menjalar ke semua agen yang terhubung).

Bounded MAKS 3 GET (TANPA POST initialize — handshake aktif tidak
dilakukan; cukup shape respons transport):
  - /sse      — transport lama HTTP+SSE: `event: endpoint` +
               `session_id` tanpa auth = signature kuat;
  - /mcp      — transport streamable HTTP: 405/4xx dgn body JSON-RPC
               ("jsonrpc"+"error") ATAU header Mcp-* = kandidat kuat;
  - /messages — endpoint pesan transport lama (GET = 405 wajar).
Deteksi zero-FP: L1 lead HANYA bila token eksplisit "mcp" (word-
boundary) / frasa "model context protocol" / shape transport di atas.
Bukan eksploitasi — deteksi postur infra AI milik sendiri/program
terotorisasi.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 3
TIMEOUT_S = 10.0
PROBES = ("/sse", "/mcp", "/messages")
ACCEPT = "text/event-stream, application/json"
# Token eksplisit: "mcp" ber-tepi kata (mcp-server, MCP, mcp_session)
# ATAU frasa penuh "model context protocol". Bukan substring buta.
_RE_TOKEN = re.compile(r"\bmcp\b|model context protocol", re.I)
# Header transport MCP (streamable HTTP): Mcp-Session-Id dsb.
_RE_HEADER = re.compile(r"^mcp-", re.I)
_RE_SESSION = re.compile(r"session_id", re.I)
_RE_SSE_EVENT = re.compile(r"^event:\s*endpoint", re.I | re.M)
_RE_JSONRPC = re.compile(r'"jsonrpc"\s*:\s*"2\.0"', re.I)


def _is_mcp_shape(path: str, body: str, headers: dict) -> bool:
    """Shape signature per transport (dipakai BERSAMA token; shape
    sendirian pada path transport yang tepat = kandidat kuat)."""
    hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    if any(_RE_HEADER.match(k) for k in headers) or \
            _RE_TOKEN.search(hdr_blob):
        return True
    if path == "/sse" and _RE_SSE_EVENT.search(body):
        return True
    if path == "/mcp" and _RE_JSONRPC.search(body):
        return True
    return False


def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): 3 GET (bounded) -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base
    probes: list[dict] = []
    for path in PROBES:
        if len(probes) >= MAX_GETS:
            break
        try:
            req = urllib.request.Request(
                base + path, method="GET",
                headers={"User-Agent": "cyphron-mcp-exposure",
                         "Accept": ACCEPT})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                body = r.read(32_000).decode("utf-8", "replace")
                headers = dict(r.headers.items())
                status = r.status
        except urllib.error.HTTPError as e:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
            headers = dict(e.headers.items()) if e.headers else {}
            status = e.code
        except Exception as exc:
            probes.append({"path": path, "status": None,
                           "error": f"{type(exc).__name__}: {exc}"[:120],
                           "marker": False})
            continue
        marker = bool(_RE_TOKEN.search(body)) or \
            _is_mcp_shape(path, body, headers)
        probes.append({"path": path, "status": status,
                       "marker": marker,
                       "body_preview": body[:200]})
    detected = [p for p in probes if p.get("marker")]
    responded = [p for p in probes if p.get("status") is not None]
    rows: list[dict] = []
    if detected:
        paths = ", ".join(p["path"] for p in detected)
        rows.append(make_finding(
            tool="mcp-exposure",
            title=f"Endpoint MCP terdeteksi di {base} ({paths})",
            severity="medium",
            description=f"Token/shape eksplisit MCP di respons {paths}. "
                        "Infra Model Context Protocol ter-expose: CSA "
                        "melaporkan ±200rb instance rentan (Mei 2026), "
                        "agentic tool-chain attack menjalar ke semua "
                        "agen terhubung (CrowdStrike), NSA terbit CSI "
                        "khusus MCP. L1 lead — inventaris transport + "
                        "autentikasi diverifikasi manual.",
            recommendation="Jangan ekspos server MCP tanpa auth ke "
                           "internet; ikuti NSA CSI MCP Security "
                           "(authN/authZ per tool, allowlist, audit "
                           "log); audit tool poisoning/schema "
                           "manipulation.",
            cwe=None, target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "AI", "safety_class": "bounded-requests",
                   "probe_paths": [p["path"] for p in detected]}))
    elif not responded:
        # Semua probe gagal jaringan — TIDAK ADA klaim AMAN (fail-closed).
        rows.append(make_finding(
            tool="mcp-exposure",
            title=f"Gagal jaringan pada {base} — tanpa klaim AMAN",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} semua "
                        "gagal jaringan; kegagalan koneksi BUKAN bukti "
                        "tidak-ada-MCP (fail-closed).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests", "network_error": True}))
    else:
        rows.append(make_finding(
            tool="mcp-exposure",
            title=f"Tidak ada marker MCP pada {base}",
            severity="info",
            description=f"{MAX_GETS} GET ke {', '.join(PROBES)} tanpa "
                        "token eksplisit 'mcp' ATAU shape transport "
                        "(SSE endpoint-event / JSON-RPC error pada "
                        "/mcp) (AMAN/inventaris, signature ketat).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))
    meta = {"url": base, "requests": len(probes),
            "detected": bool(detected)}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="mcp_exposure.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"mcp-exposure: detected={meta['detected']} "
          f"({meta['requests']} GET) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
