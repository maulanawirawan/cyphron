"""proxycore — Proxy/Intercept layer CLI-first (Fullpower B4 / CI-2).

Proxy HTTP lokal untuk engagement berotorisasi:
- mode passive: setiap request dilewatkan + dicatat ke history (JSONL);
- mode intercept: request DITAHAN di antrian berbatas sampai operator
  memutuskan (approve/drop) lewat callback — repeat untuk replay manual;
- CONNECT: tunneled passthrough (TANPA dekripsi — stdlib tidak bisa
  menegakkan CA buatan; dekripsi konten browser = jalur CDP browser_scout);
- scope: host tujuan divalidasi ke AuthorizationGate (evaluate_host) —
  host di luar scope mendapat refusal, bukan di-forward.

Fungsi inti dipisah dari I/O supaya bisa diuji tanpa jaringan nyata.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .guardrails.authorization import AuthorizationGate
from .tools.base import redact

DEFAULT_LIMIT = 25


class History:
    """Riwayat request/response (in-memory + opsional JSONL append)."""

    def __init__(self, path: Path | None = None, limit: int = DEFAULT_LIMIT):
        self.rows: list[dict] = []
        self.path = path
        self.limit = limit

    def add(self, row: dict) -> dict:
        row = {**row, "ts": datetime.now(timezone.utc).isoformat()}
        self.rows.append(row)
        if len(self.rows) > self.limit:
            self.rows.pop(0)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row

    def last(self, n: int = 5) -> list[dict]:
        return self.rows[-n:]


def forward_request(method: str, url: str, headers: dict, body: bytes | None,
                    timeout: float = 10.0) -> dict:
    """Forward satu request (http biasa) dan kembalikan ringkasannya."""
    req = Request(url, data=body, method=method,
                  headers={k: v for k, v in headers.items()
                           if k.lower() not in ("host", "proxy-connection",
                                                "connection")})
    started = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = resp.read(200_000)
            return {"status": resp.status, "headers":
                    dict(resp.headers), "body_preview":
                    payload[:2000].decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": -1, "error": f"{type(exc).__name__}",
                "elapsed": round(time.monotonic() - started, 3)}


class InterceptQueue:
    """Antrian request tertahan (intercept mode), berbatas."""

    def __init__(self, cap: int = 8):
        self.cap = cap
        self._items: list[dict] = []
        self._events: dict[str, threading.Event] = {}
        self._decisions: dict[str, str] = {}

    def hold(self, item: dict) -> str:
        rid = f"r{len(self._items) + 1}"
        item["id"] = rid
        if len(self._items) >= self.cap:
            self._decisions[rid] = "drop"  # antrian penuh: auto-drop
            return rid
        self._items.append(item)
        self._events[rid] = threading.Event()
        return rid

    def decide(self, rid: str, decision: str) -> None:
        self._decisions[rid] = decision
        ev = self._events.get(rid)
        if ev:
            ev.set()

    def wait(self, rid: str, timeout: float = 30.0) -> str:
        self._events.get(rid, threading.Event()).wait(timeout)
        return self._decisions.get(rid, "drop")

    def pending(self) -> list[dict]:
        return list(self._items)


class ProxyHandler(BaseHTTPRequestHandler):
    """Handler proxy: history + scope + intercept (class attributes diisi
    oleh serve_proxy)."""

    history: History = None          # type: ignore[assignment]
    gate: AuthorizationGate = None   # type: ignore[assignment]
    queue: InterceptQueue = None     # type: ignore[assignment]
    intercept: bool = False

    log_message = lambda self, *a: None

    def _row(self, method: str, url: str, body: bytes | None) -> dict:
        return {"method": method, "url": url,
                "body_len": len(body or b""),
                "body_preview": (body or b"")[:500].decode("utf-8", "replace")}

    def _in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if self.gate is None:
            return True
        decision = self.gate.evaluate_host(parts.hostname or "",
                                           parts.port or 80)
        return decision.allowed

    def do_CONNECT(self):  # noqa: N802 (http.server naming)
        host = self.path.split(":", 1)[0]
        row = {"kind": "connect", "host": host,
               "decision": "passthrough (no-decrypt)"}
        if self.gate is not None:
            d = self.gate.evaluate_host(host, 443)
            row["decision"] = "allowed" if d.allowed else "refused"
        self.history.add(row)
        if row["decision"] != "allowed":
            self.send_error(403, "out of scope")
            return
        # passthrough tunnel: koneksi kedua sisi diteruskan buta
        try:
            remote = socket.create_connection((host, 443), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            tunnel(self.connection, remote, timeout=30)
        except Exception:
            self.send_error(502)
        finally:
            try:
                remote.close()
            except Exception:
                pass

    def _proxy_one(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        url = self.path
        if not url.startswith("http"):
            url = f"http://localhost{self.path}"
        row = self._row(self.command, url, body)
        if not self._in_scope(url):
            row["decision"] = "refused (out of scope)"
            self.history.add(row)
            self.send_error(403, "out of scope")
            return
        if self.intercept:
            rid = self.queue.hold({k: row.get(k) for k in
                                   ("method", "url")})
            row["intercept_id"] = rid
            decision = self.queue.wait(rid, timeout=60)
            row["decision"] = decision
            if decision != "approve":
                self.history.add(row)
                self.send_error(410, "dropped by operator")
                return
        resp = forward_request(self.command, url, dict(self.headers), body)
        row["status"] = resp.get("status")
        row["response_preview"] = redact(resp.get("body_preview", ""))[:500]
        self.history.add(row)
        if resp.get("status") in (None, -1):
            self.send_error(502)
            return
        self.send_response(resp["status"])
        for k, v in (resp.get("headers") or {}).items():
            if k.lower() not in ("transfer-encoding", "content-length",
                                 "connection"):
                self.send_header(k, v)
        payload = (resp.get("body_preview") or "").encode("utf-8", "replace")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _proxy_one
    do_POST = _proxy_one
    do_PUT = _proxy_one
    do_DELETE = _proxy_one
    do_PATCH = _proxy_one


def tunnel(a, b, timeout: float = 30.0) -> None:
    """Siramlan byte dua arah sampai salah satu koneksi tutup."""
    a.settimeout(timeout)
    b.settimeout(timeout)
    done = threading.Event()

    def pump(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            done.set()

    threading.Thread(target=pump, args=(a, b), daemon=True).start()
    pump(b, a)
    done.wait(1)


def serve_proxy(listen: tuple[str, int], gate: AuthorizationGate | None,
                history: History, intercept: bool = False) -> tuple:
    """Jalankan proxy server (threading) — return (server, queue)."""
    ProxyHandler.history = history
    ProxyHandler.gate = gate
    ProxyHandler.intercept = intercept
    ProxyHandler.queue = InterceptQueue()
    server = ThreadingHTTPServer(listen, ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, ProxyHandler.queue
