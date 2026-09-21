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
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .guardrails.authorization import AuthorizationGate
from .tools.base import redact

DEFAULT_LIMIT = 25
_BODY_CAP = 200_000  # batas baca body dari origin (proxy bertingkat)
_PREVIEW = 2000


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
    """Forward satu request (http biasa) dan kembalikan ringkasannya.

    HTTP >= 400 dari origin adalah JAWABAN SAH (bukan error jaringan) —
    diteruskan apa adanya; hanya kegagalan transport yang jadi status -1.
    `body` = bytes utuh (sampai cap) untuk diteruskan ke klien;
    `body_preview` = potongan untuk history.
    """
    req = Request(url, data=body, method=method,
                  headers={k: v for k, v in headers.items()
                           if k.lower() not in ("host", "proxy-connection",
                                                "connection")})
    started = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = resp.read(_BODY_CAP)
            return {"status": resp.status, "headers": dict(resp.headers),
                    "body": payload,
                    "truncated": len(payload) >= _BODY_CAP,
                    "body_preview": payload[:_PREVIEW].decode("utf-8", "replace")}
    except urllib.error.HTTPError as http_err:
        # respons error asli dari origin: pertahankan status/headers/body
        try:
            payload = http_err.read(_BODY_CAP)
        except Exception:
            payload = b""
        return {"status": http_err.code, "headers": dict(http_err.headers or {}),
                "body": payload, "truncated": len(payload) >= _BODY_CAP,
                "body_preview": payload[:_PREVIEW].decode("utf-8", "replace")}
    except Exception as exc:
        return {"status": -1, "error": f"{type(exc).__name__}",
                "elapsed": round(time.monotonic() - started, 3)}


class InterceptQueue:
    """Antrian request tertahan (intercept mode), berbatas.

    - rid dari counter monotonik + lock (dua hold() konkuren tak mungkin
      mendapat rid sama / Event tertimpa);
    - item DIHAPUS saat didecide — antrian benar-benar kosong setelah
      operator memutuskan semua (bukan macet selamanya setelah cap);
    - keputusan tetap tersimpan untuk wait() yang datang terlambat.
    """

    def __init__(self, cap: int = 8):
        self.cap = cap
        self._lock = threading.Lock()
        self._counter = 0
        self._items: list[dict] = []
        self._events: dict[str, threading.Event] = {}
        self._decisions: dict[str, str] = {}

    def hold(self, item: dict) -> str:
        with self._lock:
            self._counter += 1
            rid = f"r{self._counter}"
            item["id"] = rid
            if len(self._items) >= self.cap:
                self._decisions[rid] = "drop"  # antrian penuh: auto-drop
                return rid
            self._items.append(item)
            self._events[rid] = threading.Event()
            return rid

    def decide(self, rid: str, decision: str) -> None:
        with self._lock:
            self._decisions[rid] = decision
            self._items = [it for it in self._items if it.get("id") != rid]
            ev = self._events.get(rid)
        if ev:
            ev.set()

    def wait(self, rid: str, timeout: float = 30.0) -> str:
        self._events.get(rid, threading.Event()).wait(timeout)
        return self._decisions.get(rid, "drop")

    def pending(self) -> list[dict]:
        with self._lock:
            return [dict(it) for it in self._items]


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
        # tanpa gate = tak ada scope untuk dicek (konsisten dengan _in_scope);
        # hanya gate eksplisit yang bisa menolak
        allowed = True
        if self.gate is not None:
            allowed = self.gate.evaluate_host(host, 443).allowed
        row = {"kind": "connect", "host": host,
               "decision": ("allowed" if allowed
                            else "refused") if self.gate is not None
               else "passthrough (no-decrypt)"}
        self.history.add(row)
        if self.gate is not None and not allowed:
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
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400, "bad Content-Length")
            return
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.send_error(411, "chunked request body not supported")
            return
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
        if resp.get("truncated"):
            row["response_truncated"] = True  # jejak jujur di history
        self.history.add(row)
        if resp.get("status") in (None, -1):
            self.send_error(502)
            return
        self.send_response(resp["status"])
        for k, v in (resp.get("headers") or {}).items():
            if k.lower() not in ("transfer-encoding", "content-length",
                                 "connection"):
                self.send_header(k, v)
        # kirim BODY UTUH yang dibaca dari origin (bukan preview 2KB);
        # Content-Length selalu cocok dengan yang dikirim — framing valid
        payload = resp.get("body") or b""
        if resp.get("truncated"):
            self.send_header("X-Cyphron-Proxy-Truncated", "true")
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
