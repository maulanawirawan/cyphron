"""roadmap_batch2 - slot ROADMAP berikutnya yang diimplementasikan LIVE:
1. header_policy  (csp-unsafe-eval / unsafe-inline - slot medium)
2. ws_probe       (WebSocket unauth handshake - slot high)
Keduanya marker definitif -> temuan TRUE by construction."""

from __future__ import annotations

import base64
import os
import socket
from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class HeaderPolicyTool(Tool):
    name = "header_policy"
    description = "Parse kualitas CSP: unsafe-inline/unsafe-eval/frame-src longgar."
    risk_tags = {"passive"}
    source_skill = "72"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        status, headers, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.observe_response(url, status, headers, body, self.name)
        csp = headers.get("content-security-policy", "")
        findings: list[Finding] = []
        if csp:
            problems = []
            if "unsafe-inline" in csp:
                problems.append("'unsafe-inline' aktif (inline script/style diizinkan)")
            if "unsafe-eval" in csp:
                problems.append("'unsafe-eval' aktif")
            if "default-src" not in csp:
                problems.append("default-src tidak didefinisikan")
            if problems:
                findings.append(Finding(
                    tool=self.name, title="CSP lemah: " + "; ".join(problems),
                    severity="medium", cwe="CWE-79",
                    description=f"CSP di {url} memiliki kelemahan: {'; '.join(problems)}.",
                    recommendation="Pergi ke nonce/hash (Skill 72); hapus unsafe-*; tetapkan default-src 'self'.",
                    target_url=url, request=f"GET {url}", response=f"CSP: {csp[:300]}",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header"))
        return ToolResult(tool=self.name, ok=True, data={"url": url}, findings=findings)


class WsProbeTool(Tool):
    name = "ws_probe"
    description = "Uji handshake WebSocket tanpa auth pada path /ws, /websocket, /socket."
    risk_tags = {"active"}
    source_skill = "16"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args["url"])
        parts = urlsplit(url)
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if parts.scheme == "https" else 80)
        findings: list[Finding] = []
        key = base64.b64encode(os.urandom(16)).decode()
        for path in ("/ws", "/websocket", "/socket.io/?EIO=4"):
            if ctx.world.request_count >= int(args.get("max_requests", 12)):
                break
            try:
                ctx.throttle()
                sock = socket.create_connection((host, port), timeout=ctx.timeout_s)
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                       f"Origin: https://{host}\r\n\r\n")
                sock.sendall(req.encode())
                resp = sock.recv(2048).decode("latin-1", "replace")
                sock.close()
            except OSError:
                continue
            ctx.world.request_count += 1
            status_line = resp.split("\r\n", 1)[0]
            ctx.world.note(f"ws_probe: {path} -> {status_line[:60]}")
            if resp.startswith("HTTP/1.1 101") or " 101 " in status_line:
                # high-06: kirim pesan JSON tanpa auth — apakah server memproses?
                try:
                    ctx.throttle()
                    sock2 = socket.create_connection((host, port), timeout=ctx.timeout_s)
                    sock2.sendall(req.encode("latin-1") if isinstance(req, str) else req)
                    _hs = sock2.recv(2048)
                    import json as _json
                    import struct as _struct
                    payload = _json.dumps({"action": "list", "probe": "cyphron"}).encode()
                    mask = os.urandom(4)
                    frame = bytearray([0x81])
                    ln = len(payload)
                    if ln < 126:
                        frame.append(0x80 | ln)
                    else:
                        frame.append(0x80 | 126)
                        frame += _struct.pack("!H", ln)
                    frame += mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                    sock2.sendall(bytes(frame))
                    reply = sock2.recv(4096)
                    sock2.close()
                except OSError:
                    reply = b""
                if reply and (reply[0] & 0x0F) in (0x1, 0x2) and len(reply) > 2:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Pesan WebSocket diproses tanpa autentikasi: {path}",
                        severity="high", cwe="CWE-306",
                        description=(f"Kanal WebSocket di {path} menerima handshake TANPA "
                                     f"kredensial DAN membalas pesan data ({len(reply)} byte) "
                                     f"untuk action 'list' dari klien anonim. API data "
                                     f"terpapar lewat WebSocket tanpa kontrol akses."),
                        recommendation="Wajibkan auth pada upgrade DAN validasi sesi per "
                                       "pesan; tolak action sensitif dari klien anonim.",
                        target_url=url + path,
                        request=f"WS {path} + frame {{action: list}}",
                        response=f"reply {len(reply)} byte (frame opcode {reply[0] & 0x0F})",
                        confidence=0.85, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="request-response"))
                findings.append(Finding(
                    tool=self.name,
                    title=f"WebSocket handshake diterima tanpa autentikasi: {path}",
                    severity="medium", cwe="CWE-306",
                    description=(f"Handshake WebSocket di {path} (HTTP {status_line.split(' ', 1)[1] if ' ' in status_line else '101'}) "
                                 f"berhasil TANPA kredensial/token. Verifikasi apakah pesan berisiko "
                                 f"dapat dikirim lewat kanal ini."),
                    recommendation="Wajibkan auth pada upgrade WebSocket (sesi/signed token) dan validasi origin.",
                    target_url=url + path, request=f"GET {path} (Upgrade: websocket)",
                    response=status_line, confidence=0.7,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="request-response"))
                continue
            # medium-25: origin bypass — handshake ulang dengan origin asing
            if resp.split(" ")[1:2] and status_line.split(" ")[1] in ("400", "403"):
                try:
                    ctx.throttle()
                    sock = socket.create_connection((host, port), timeout=ctx.timeout_s)
                    req_evil = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                                f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                                f"Origin: https://evil-cyphron.example\r\n\r\n")
                    sock.sendall(req_evil.encode())
                    resp_evil = sock.recv(2048).decode("latin-1", "replace")
                    sock.close()
                except OSError:
                    continue
                ctx.world.request_count += 1
                evil_line = resp_evil.split("\r\n", 1)[0]
                if resp_evil.startswith("HTTP/1.1 101") or " 101 " in evil_line:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"WebSocket origin bypass: {path} menerima origin arbitrer",
                        severity="medium", cwe="CWE-346",
                        description=(f"Upgrade WebSocket di {path} menolak request tanpa "
                                     f"origin valid tetapi MENERIMA Origin 'https://evil-cyphron.example' "
                                     f"(101). Validasi origin hanya kosmetik — situs mana pun "
                                     f"bisa membuka kanal ini dari browser korban."),
                        recommendation="Whitelist origin ketat (exact match) pada upgrade; "
                                       "jangan andalkan pengaturan kosong = default-allow.",
                        target_url=url + path,
                        request=f"GET {path} (Origin: https://evil-cyphron.example)",
                        response=f"same-origin: {status_line.split(' ', 1)[1] if ' ' in status_line else '?'}; "
                                 f"evil-origin: 101",
                        confidence=0.85, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
        return ToolResult(tool=self.name, ok=True, data={"host": host}, findings=findings)
