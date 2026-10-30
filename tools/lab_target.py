"""[F25] Lab target — aplikasi rentan LOKAL (127.0.0.1) untuk exploit engine.

Satusatunya tujuan: menjadi lawan uji bagi tools/exploit_engine.py.
Sengaja rentan (IDOR, role check hilang, SQLi, SSRF, JWT secret lemah)
supaya playbook bisa membuktikan PoC nyata TANPA satu pun request ke
jaringan eksternal. Semua kerentanan = kelas nyata yang dibuktikan
playbook di tools/exploit_playbooks.py.

BUKAN untuk produksi; hanya dijalankan manual atau di test (port
ephemeral, bind 127.0.0.1 saja).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pickle
import re
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# svc-canary PALING ATAS: playbook nosqli-login mengandalkan urutan ini —
# operator {"$ne": ""} selalu match akun canary dulu (deterministik)
USERS = {
    "svc-canary": {"password": "canary-pass-9f3", "role": "user",
                   "email": "canary@example.com"},
    "alice": {"password": "alicepass", "role": "user",
              "email": "alice@example.com"},
    "bob": {"password": "bobpass", "role": "user",
            "email": "bob@example.com"},
}
ORDERS = {
    "1001": {"owner": "alice", "item": "keyboard", "owner_email": "alice@example.com"},
    "1002": {"owner": "bob", "item": "monitor", "owner_email": "bob@example.com"},
}
# IDOR massal (batch 7): endpoint kedua dengan bug ownership yang sama —
# id menyengaja sama dengan ORDERS supaya playbook massal satu set id
TICKETS = {
    "1001": {"owner": "alice", "event": "conf-2026", "owner_email": "alice@example.com"},
    "1002": {"owner": "bob", "event": "conf-2026", "owner_email": "bob@example.com"},
}
ADMIN_MARKER = "admin-panel-secret-marker"

# Kerentanan sengaja: JWT secret statis yang ADA di wordlist umum (CWE-321)
JWT_SECRET = "changeme"

# Canary LFI: file DI LUAR root served — hanya terbaca via traversal (CWE-22)
LFI_CANARY = "cyphron-lfi-canary-9d1c"

# Data privat cache-deception: halaman profil auth-required yang (sengaja)
# terhidang di URL statis + header cache publik (CWE-444)
CACHE_DECEPTION_MARKER = "cyphron-private-data-7a3"

PRODUCTS = [
    (1, "keyboard", 150000),
    (2, "monitor", 1200000),
    (3, "mouse", 95000),
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict, secret: str) -> str:
    h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64url(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_verify(token: str, secret: str) -> dict | None:
    try:
        h, p, s = token.split(".")
        expect = hmac.new(secret.encode(), f"{h}.{p}".encode(),
                          hashlib.sha256).digest()
        if not hmac.compare_digest(expect, _b64url_dec(s)):
            return None
        return json.loads(_b64url_dec(p))
    except Exception:
        return None


class _Handler(BaseHTTPRequestHandler):
    # akses state lewat atribut server (bukan global) supaya test paralel aman
    @property
    def lab(self):
        return self.server

    def log_message(self, *a):  # senyap: test yang logging, bukan server
        return

    def _json(self, code: int, obj: dict, headers: dict | None = None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _session_user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return self.lab.sessions.get(v)
        return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/api/rag/query":
            # F46: retrieval naive — dokumen corpus yang memuat token q
            # dikutip utuh dalam jawaban (poisoning terlihat di sini).
            q = (qs.get("q") or [""])[0]
            if q:
                for doc_id, content in self.lab.corpus.items():
                    if q.lower() in content.lower():
                        return self._json(200, {
                            "answer": "Menurut basis pengetahuan "
                                      f"internal: {content}",
                            "doc": doc_id})
            return self._json(200, {"answer": "Tidak ada yang cocok.",
                                    "doc": None})
        if self.path == "/health":
            return self._json(200, {"status": "ok"})
        if self.path.startswith("/api/orders/"):
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            oid = self.path.rsplit("/", 1)[-1]
            order = self.lab.orders.get(oid)
            if not order:
                return self._json(404, {"error": "not found"})
            # KERENTANAN SENGAJA: tidak ada cek ownership (IDOR)
            return self._json(200, {"id": oid, **order})
        if self.path.startswith("/api/tickets/"):
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            tid = self.path.rsplit("/", 1)[-1]
            ticket = self.lab.tickets.get(tid)
            if not ticket:
                return self._json(404, {"error": "not found"})
            # KERENTANAN SENGAJA: bug ownership identik (IDOR massal)
            return self._json(200, {"id": tid, **ticket})
        if self.path == "/admin/panel":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            # KERENTANAN SENGAJA: hanya cek auth, TIDAK cek role —
            # user biasa bisa membuka panel admin (CWE-862)
            return self._json(200, {"panel": ADMIN_MARKER})
        if parsed.path == "/api/products":
            name = (qs.get("name") or [""])[0]
            if not name:
                return self._json(400, {"error": "param 'name' wajib"})
            # KERENTANAN SENGAJA: query dirangkai string (SQLi, CWE-89)
            sql = f"SELECT id, name, price FROM products WHERE name = '{name}'"
            try:
                with self.lab.db_lock:
                    rows = self.lab.db.execute(sql).fetchall()
            except Exception as exc:
                return self._json(500, {"error": str(exc)[:200]})
            return self._json(200, {"count": len(rows),
                                    "rows": [list(r) for r in rows]})
        if parsed.path == "/fetch":
            url = (qs.get("url") or [""])[0]
            if not url.startswith(("http://", "https://")):
                return self._json(400, {"error": "url tidak valid"})
            # KERENTANAN SENGAJA: fetch URL arbitrary server-side (SSRF,
            # CWE-918) — di lab ini hanya dipakai menunjuk 127.0.0.1
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    body = r.read(4096).decode("utf-8", "replace")
                return self._json(200, {"status": r.status,
                                        "head": body[:200]})
            except Exception as exc:
                return self._json(502, {"error": repr(exc)[:200]})
        if parsed.path == "/fetch-safe":
            url = (qs.get("url") or [""])[0]
            host = urllib.parse.urlparse(url).hostname or ""
            # kontrol: fetch yang MENOLAK target internal/loopback
            if (host in ("127.0.0.1", "localhost", "::1")
                    or host.startswith(("10.", "192.168.", "172."))
                    or host.endswith(".internal")):
                return self._json(403, {"error": "target internal ditolak"})
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    body = r.read(4096).decode("utf-8", "replace")
                return self._json(200, {"status": r.status,
                                        "head": body[:200]})
            except Exception as exc:
                return self._json(502, {"error": repr(exc)[:200]})
        if parsed.path == "/internal-port":
            # plumbing lab untuk playbook ssrf-chain: port service internal
            # (bind 127.0.0.1 DI DALAM proses lab — dari kontainer engine
            # TIDAK bisa dijangkau langsung; hanya via SSRF /fetch)
            return self._json(200, {"port": self.lab.internal_port})
        if parsed.path == "/api/cors-sub":
            origin = self.headers.get("Origin", "")
            # KERENTANAN SENGAJA: allowlist pakai SUFFIX subdomain
            # (CWE-942) — origin *.lab.local direfleksikan + kredensial
            if origin.endswith(".lab.local"):
                return self._json(200, {"ok": True}, headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true"})
            return self._json(200, {"ok": True})
        if parsed.path == "/api/cors-safe":
            origin = self.headers.get("Origin", "")
            # kontrol: allowlist origin eksplisit, tidak ada refleksi
            if origin == "https://app.lab.local":
                return self._json(200, {"ok": True}, headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true"})
            return self._json(200, {"ok": True})
        if parsed.path == "/api/token":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            token = jwt_encode({"sub": user["username"],
                                "role": user["role"]}, JWT_SECRET)
            return self._json(200, {"token": token})
        if parsed.path == "/api/profile-loose":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return self._json(401, {"error": "bearer wajib"})
            token = auth[len("Bearer "):]
            try:
                h64, p64, _sig = token.split(".")
                header = json.loads(_b64url_dec(h64))
                if header.get("alg") == "none":
                    # KERENTANAN SENGAJA: verifier MEMERCAYAI field alg
                    # dari token tanpa verifikasi (CWE-347) — token
                    # alg:none lolos tanpa tanda tangan
                    payload = json.loads(_b64url_dec(p64))
                    return self._json(200, {"sub": payload.get("sub"),
                                            "role": payload.get("role")})
            except Exception:
                pass
            payload = jwt_verify(token, JWT_SECRET)
            if not payload:
                return self._json(401, {"error": "token tidak valid"})
            return self._json(200, {"sub": payload.get("sub"),
                                    "role": payload.get("role")})
        if parsed.path == "/api/profile":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return self._json(401, {"error": "bearer wajib"})
            payload = jwt_verify(auth[len("Bearer "):], JWT_SECRET)
            if not payload:
                return self._json(401, {"error": "token tidak valid"})
            return self._json(200, {"sub": payload.get("sub"),
                                    "role": payload.get("role")})
        if parsed.path == "/redirect":
            to = (qs.get("to") or [""])[0]
            if not to:
                return self._json(400, {"error": "param 'to' wajib"})
            # KERENTANAN SENGAJA: redirect ke URL arbitrer tanpa
            # validasi (CWE-601) — engine TIDAK mengikuti redirect ini
            self.send_response(302)
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/uploads":
            return self._json(404, {"error": "not found"})
        if parsed.path.startswith("/uploads/"):
            name = parsed.path[len("/uploads/"):]
            data = self.lab.uploads.get(name)
            if data is None:
                return self._json(404, {"error": "not found"})
            ctype = "text/html" if name.endswith((".html", ".svg")) \
                else "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path == "/download":
            name = (qs.get("file") or [""])[0]
            if not name:
                return self._json(400, {"error": "param 'file' wajib"})
            # KERENTANAN SENGAJA: join naive tanpa normalisasi (CWE-22) —
            # "../canary-lfi.txt" keluar dari root served. Lab-only: root
            # file adalah direktori temp yang lab buat sendiri.
            fp = os.path.join(str(self.lab.files_root), name)
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    data = fh.read(4096)
            except OSError:
                return self._json(404, {"error": "file tidak ada"})
            return self._json(200, {"content": data})
        if parsed.path == "/api/render":
            tpl = (qs.get("tpl") or [""])[0]
            # KERENTANAN SENGAJA: mesin template naive yang MENGEVALUASI
            # ekspresi di {{...}} (CWE-1336). Charset dibatasi digit +
            # operator aritmetika supaya lab hanya bisa membuktikan
            # evaluasi benign ({{7*7}}), bukan eksekusi apa pun.
            m = re.fullmatch(r"\s*\{\{\s*([0-9+\-*/(). ]+?)\s*\}\}\s*", tpl)
            if m:
                try:
                    val = eval(m.group(1), {"__builtins__": {}}, {})  # noqa: S307 (lab, charset terkunci)
                except Exception:
                    val = None
                if val is not None:
                    return self._json(200, {"rendered": str(val)})
            return self._json(200, {"rendered": tpl})
        if self.path == "/api/whoami":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            return self._json(200, {"user": user["username"],
                                    "role": user["role"]})
        if parsed.path.startswith("/api/v1/orders/"):
            oid = parsed.path.rsplit("/", 1)[-1]
            order = self.lab.orders.get(oid)
            if not order:
                return self._json(404, {"error": "not found"})
            # KERENTANAN SENGAJA: versi lama TANPA auth sama sekali
            # (regresi auth antar versi, CWE-284/862)
            return self._json(200, {"id": oid, **order, "api": "v1"})
        if parsed.path.startswith("/api/v2/orders/"):
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            oid = parsed.path.rsplit("/", 1)[-1]
            order = self.lab.orders.get(oid)
            if not order:
                return self._json(404, {"error": "not found"})
            # versi baru: auth DITEGAKKAN (kontrol untuk api-version-auth)
            return self._json(200, {"id": oid, **order, "api": "v2"})
        if parsed.path == "/api/ping" or parsed.path == "/api/ping-safe":
            host = (qs.get("host") or [""])[0]
            if parsed.path == "/api/ping-safe" and any(
                    c in host for c in (";", "|", "&", "`", "$(")):
                return self._json(400, {"error": "karakter terlarang"})
            # KERENTANAN SENGAJA: host dirangkai mentah ke baris shell
            # (CWE-78). Lab TIDAK mengeksekusi apa pun — fake-shell
            # deterministik: segmen setelah ; | & dievaluasi sebagai
            # perintah echo/ping sintetis (bukti = output echo marker)
            segs = re.split(r"[;|&]", host)
            outs = []
            for seg in segs:
                seg = seg.strip().replace("$(", "").replace(")", "")
                if seg.startswith("echo "):
                    outs.append(seg[5:].strip())
                elif seg:
                    outs.append(f"PING {seg} (0% loss)")
            return self._json(200, {"output": "\n".join(outs)})
        if parsed.path == "/api/note":
            # KERENTANAN SENGAJA: nilai user masuk ke header respons TANPA
            # sanitasi CRLF (CWE-93) — respons dirakit manual (raw) agar
            # injeksi header benar-benar terjadi, bukan dibersihkan stdlib
            text = (qs.get("text") or [""])[0]
            raw = (f"HTTP/1.1 200 OK\r\n"
                   f"Content-Type: text/plain\r\n"
                   f"X-Note: {text}\r\n"
                   f"Content-Length: 2\r\n"
                   f"\r\nok").encode()
            self.wfile.write(raw)
            return
        if parsed.path == "/api/note-safe":
            # kontrol FP: versi FIXED — CRLF dibersihkan sebelum masuk header
            text = (qs.get("text") or [""])[0]
            clean = text.replace("\r", "").replace("\n", " ")
            raw = (f"HTTP/1.1 200 OK\r\n"
                   f"Content-Type: text/plain\r\n"
                   f"X-Note: {clean}\r\n"
                   f"Content-Length: 2\r\n"
                   f"\r\nok").encode()
            self.wfile.write(raw)
            return
        if parsed.path == "/search":
            q = (qs.get("q") or [""])[0]
            # KERENTANAN SENGAJA: q direfleksikan mentah ke HTML (CWE-79)
            page = (f"<html><body><h1>Cari produk</h1>"
                    f"<p>Hasil untuk: {q}</p></body></html>")
            data = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path == "/search-safe":
            q = (qs.get("q") or [""])[0]
            safe = (q.replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
            page = (f"<html><body><h1>Cari produk</h1>"
                    f"<p>Hasil untuk: {safe}</p></body></html>")
            data = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path == "/api/search-sleep":
            q = (qs.get("q") or [""])[0]
            m = re.search(r"SLEEP\((\d+)\)", q)
            if m:
                # KERENTANAN SENGAJA: SLEEP disuntikkan ke "query"
                # (CWE-89 varian time-based; dibatasi 3 detik lab)
                time.sleep(min(int(m.group(1)), 3))
                return self._json(200, {"results": [], "delayed": True})
            items = [p[1] for p in PRODUCTS if q.lower() in p[1]]
            return self._json(200, {"results": items})
        if parsed.path == "/oauth/authorize":
            # simulasi OAuth lab: code diterbitkan + state TERIKAT
            state = (qs.get("state") or [""])[0]
            code = secrets.token_hex(8)
            self.lab.oauth_codes[code] = state
            return self._json(200, {"code": code, "state": state})
        if parsed.path in ("/oauth/callback", "/oauth/callback-strict"):
            code = (qs.get("code") or [""])[0]
            state = (qs.get("state") or [""])[0]
            bound = self.lab.oauth_codes.get(code)
            if parsed.path == "/oauth/callback-strict":
                # kontrol: state WAJIB identik yang terikat pada code
                if bound is None or state != bound:
                    return self._json(400, {"error": "state mismatch"})
            else:
                # KERENTANAN SENGAJA: state TIDAK divalidasi (CWE-352) —
                # code diterima dengan state arbitrer (login CSRF)
                if bound is None:
                    return self._json(400, {"error": "code tidak dikenal"})
            if "alice" not in self.lab.users:
                return self._json(500, {"error": "akun lab hilang"})
            sid = secrets.token_hex(8)
            self.lab.sessions[sid] = {
                **self.lab.users["alice"], "username": "alice"}
            return self._json(200, {"ok": True, "user": "alice"},
                              headers={"Set-Cookie": f"sid={sid}; Path=/"})
        if parsed.path == "/api/search-sleep-safe":
            q = (qs.get("q") or [""])[0]
            _ = q  # kontrol: query disanitasi, TIDAK ada SLEEP yang jalan
            return self._json(200, {"results": []})
        if parsed.path == "/api/search-raw":
            q = (qs.get("q") or [""])[0]
            # KERENTANAN SENGAJA: query dirakit string mentah (CWE-89,
            # varian error-based) — kutip tunggal memecah query dan
            # signature error DB bocor ke klien BERSAMA fragmen payload.
            if "'" in q:
                return self._json(500, {"error":
                                        f"sqlite3.OperationalError: near "
                                        f'"{q}": syntax error'})
            items = [p[1] for p in PRODUCTS if q.lower() in p[1]]
            return self._json(200, {"results": items})
        if parsed.path == "/api/search-raw-safe":
            q = (qs.get("q") or [""])[0]
            # kontrol: query berparameter (disimulasikan) — kutip
            # di-escape, error TIDAK pernah bocor ke klien
            _ = q.replace("'", "''")
            return self._json(200, {"results": []})
        if parsed.path == "/api/reset-check":
            token = (qs.get("token") or [""])[0]
            email = self.lab.reset_tokens.get(token)
            if not email:
                return self._json(404, {"error": "token tidak valid"})
            return self._json(200, {"valid": True, "email": email})
        if parsed.path == "/api/config":
            # gadget prototype-pollution: membaca objek defaults bersama
            return self._json(200, dict(self.lab.pp_defaults))
        if parsed.path == "/api/log4j":
            msg = (qs.get("msg") or [""])[0]
            # KERENTANAN SENGAJA: resolver JNDI naive (CWE-917) — lookup
            # ${jndi:...} disimulasikan dengan callback HTTP ke host di
            # string (pola OOB sama dengan xxe/ssrf; canary benign)
            m = re.search(r"\$\{jndi:(?:ldap|rmi|dns|iiop)://([^:/}]+)"
                          r"(?::(\d+))?(/[^}]*)?\}", msg)
            if not m:
                return self._json(200, {"resolved": False})
            host, port, path = m.group(1), m.group(2) or "80", m.group(3) or "/"
            try:
                with urllib.request.urlopen(
                        f"http://{host}:{port}{path}", timeout=3) as r:
                    r.read(256)
                return self._json(200, {"resolved": True})
            except Exception as exc:
                return self._json(200, {"resolved": False,
                                        "error": repr(exc)[:120]})
        if parsed.path.startswith("/cacheable-header/") or \
                parsed.path.startswith("/cache-safe-header/"):
            # mini-cache sama (keyed by PATH SAJA): refleksi header unkeyed
            # X-Forwarded-Host ke respons ter-cache = cache poisoning
            cached = self.lab.cache.get(self.path)
            if cached is not None:
                status, hdrs, body = cached
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            xfh = self.headers.get("X-Forwarded-Host", "")
            if parsed.path.startswith("/cache-safe-header/"):
                # kontrol: konten invarian terhadap header — poison mustahil
                raw = json.dumps({"served_for": "origin",
                                  "note": "header tidak dipercaya"}).encode()
            else:
                # KERENTANAN SENGAJA: header unkeyed direfleksikan ke
                # respons yang di-cache publik (CWE-444)
                raw = json.dumps({"served_for": xfh}).encode()
            hdrs = {"Content-Type": "application/json",
                    "Cache-Control": "public, max-age=300"}
            self.lab.cache[self.path] = (200, dict(hdrs), raw)
            self.send_response(200)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if parsed.path.startswith("/cacheable/") or \
                parsed.path.startswith("/cache-safe/"):
            # mini-cache DICEK DULU (sebelum auth) — inilah esensi cache
            # deception: cache menyajikan konten privat ke user anonim
            cached = self.lab.cache.get(self.path)
            if cached is not None:
                status, hdrs, body = cached
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            name = parsed.path.rsplit("/", 1)[-1]
            if parsed.path.startswith("/cacheable/") and \
                    name.endswith(".css"):
                # KERENTANAN SENGAJA: router mengabaikan ekstensi statis —
                # halaman profil privat terhidang di URL .css dengan header
                # cache publik (CWE-444, dua-langkah tervalidasi lapangan)
                raw = json.dumps({"profile": CACHE_DECEPTION_MARKER,
                                  "user": user["username"]}).encode()
                hdrs = {"Content-Type": "application/json",
                        "Cache-Control": "public, max-age=300"}
                self.lab.cache[self.path] = (200, dict(hdrs), raw)
                self.send_response(200)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if parsed.path.startswith("/cache-safe/"):
                # kontrol FP: versi FIXED — data privat di URL statis tetap
                # ada TAPI no-store sehingga cache tidak pernah menyimpan
                raw = json.dumps({"profile": CACHE_DECEPTION_MARKER,
                                  "user": user["username"]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "private, no-store")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            return self._json(404, {"error": "not found"})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path in ("/api/llm-render", "/api/llm-render-safe"):
            # F46: simulator endpoint generatif yang outputnya DIPAKAI/
            # dirender. /api/llm-render = KERENTANAN SENGAJA — keluaran
            # "model" tidak dinetralkan sebelum render (CWE-1426):
            # konten user muncul MENTAH di dalam markup hasil generasi.
            # /api/llm-render-safe = kontrol: konten user DI-ESCAPE.
            import html as _html
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            msg = str(payload.get("message", "")) if isinstance(
                payload, dict) else ""
            body_content = msg if parsed.path == "/api/llm-render"                 else _html.escape(msg, quote=True)
            reply = ('<div class="ai-generated">Berikut badge untuk '
                     f'Anda: {body_content} - ada lagi?</div>')
            return self._json(200, {"reply": reply})
        if parsed.path in ("/api/rag/ingest", "/api/rag/ingest-review"):
            # F46: jalur ingest basis pengetahuan RAG. /api/rag/ingest =
            # KERENTANAN SENGAJA — dokumen baru LANGSUNG retrievable
            # tanpa review (poisoning corpus). /api/rag/ingest-review =
            # kontrol: dokumen masuk antrean review, TIDAK retrievable.
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            doc_id = str(payload.get("doc_id", "")) if isinstance(
                payload, dict) else ""
            content = str(payload.get("content", "")) if isinstance(
                payload, dict) else ""
            if not doc_id or not content:
                return self._json(400, {"error": "doc_id+content wajib"})
            if parsed.path == "/api/rag/ingest-review":
                self.lab.corpus_pending[doc_id] = content
                return self._json(202, {"ok": True, "status": "pending"})
            self.lab.corpus[doc_id] = content
            return self._json(201, {"ok": True, "status": "active"})
        if parsed.path == "/api/llm-chat-flaky":
            # F59: target non-deterministik - menuruti canary hanya di
            # panggilan genap (stateful counter per lab run); dipakai
            # playbook prompt-injection dgn trials>=3 (verdict cap L2)
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            msg = str(payload.get("message", "")) if isinstance(
                payload, dict) else ""
            self.lab.flaky_counter = getattr(self.lab,
                                             "flaky_counter", 0) + 1
            m = re.search(r"output\s+exactly\s+the\s+word\s+"
                          r"([A-Za-z0-9]+)", msg, re.I)
            if (m and self.lab.flaky_counter % 2 == 0
                    and re.search(r"ignore\s+(all\s+)?(previous|prior|"
                                  r"above)? ?(previous|prior|above)?.*"
                                  r"instruction", msg, re.I)):
                return self._json(200, {"reply": m.group(1)})
            return self._json(200, {"reply": "Halo! Ada yang bisa "
                                             "dibantu?"})
        if parsed.path in ("/api/llm-chat", "/api/llm-chat-safe"):
            # Batch 10/F44: simulator endpoint generasi LLM deterministik
            # (TANPA model nyata). /api/llm-chat = KERENTANAN SENGAJA —
            # instruksi user menimpa pengarah sistem (CWE-1427): pola
            # "output exactly the word X" dieksekusi. /api/llm-chat-safe
            # = kontrol: menolak instruksi pengabaian, jawaban tetap.
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            msg = str(payload.get("message", "")) if isinstance(
                payload, dict) else ""
            if parsed.path == "/api/llm-chat-safe":
                return self._json(200, {"reply": "Saya hanya menjawab "
                                                 "sesuai topik percakapan."})
            m = re.search(r"output\s+exactly\s+the\s+word\s+([A-Za-z0-9]+)",
                          msg, re.I)
            if m and re.search(r"ignore\s+(all\s+)?(previous|prior|above)"
                               r"? ?(previous|prior|above)?.*instruction",
                               msg, re.I):
                # menuruti instruksi user: marker keluar utuh
                return self._json(200, {"reply": m.group(1)})
            return self._json(200, {"reply": "Halo! Ada yang bisa "
                                             "dibantu?"})
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            fields = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            uname = fields.get("username", "")
            rec = self.lab.users.get(uname)
            if not rec or rec["password"] != fields.get("password", ""):
                return self._json(401, {"error": "bad credentials"})
            sid = secrets.token_hex(8)
            self.lab.sessions[sid] = {**rec, "username": uname}
            return self._json(200, {"ok": True, "user": uname},
                              headers={"Set-Cookie": f"sid={sid}; Path=/"})
        if parsed.path == "/api/merge":
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            if not isinstance(payload, dict):
                return self._json(400, {"error": "body JSON objek wajib"})

            # KERENTANAN SENGAJA: recursive merge TANPA filter kunci
            # __proto__ (CWE-1321) — menulis ke objek defaults bersama
            # (simulasi prototype pollution; gadget = GET /api/config)
            def _vuln_merge(dst: dict, src: dict) -> None:
                for k, v in src.items():
                    if k in ("constructor", "prototype"):
                        continue  # di luar simulasi lab
                    if k == "__proto__":
                        if isinstance(v, dict):
                            _vuln_merge(dst, v)  # tanpa guard: menulis ke prototipe
                        continue
                    if isinstance(v, dict):
                        node = dst.get(k)
                        if not isinstance(node, dict):
                            node = {}
                            dst[k] = node
                        _vuln_merge(node, v)
                    else:
                        dst[k] = v

            _vuln_merge(self.lab.pp_defaults, payload)
            return self._json(200, {"merged": True})
        if parsed.path in ("/api/forgot", "/api/forgot-safe"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                fields = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            email = str(fields.get("email", ""))
            known = any(r["email"] == email for r in self.lab.users.values())
            if not known:
                # respons generik: keberadaan akun TIDAK dibocorkan
                return self._json(200, {"sent": True, "preview_link": None})
            token = secrets.token_hex(8)
            self.lab.reset_tokens[token] = email
            if self.path == "/api/forgot":
                # KERENTANAN SENGAJA: link reset dibangun dari header Host
                # tanpa allowlist (CWE-444/639) — host terpoison menerima
                # token reset; lab menyimpan token (tanpa email nyata)
                base = f"http://{self.headers.get('Host', 'localhost')}"
            else:
                # kontrol FP: versi FIXED — base dari konfigurasi server,
                # header Host diabaikan
                base = self.lab.own_base
            return self._json(200, {"sent": True,
                                    "preview_link": f"{base}/reset?token={token}"})
        if parsed.path == "/api/nosqli-login":
            length = int(self.headers.get("Content-Length", 0))
            try:
                fields = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            if not isinstance(fields, dict):
                return self._json(400, {"error": "body JSON objek wajib"})

            # KERENTANAN SENGAJA: matcher "mongo-like" yang menerima
            # operator $ne/$regex pada field login (CWE-943) — playbook
            # hanya membuktikan bypass sesi ke akun canary
            def _match(cond, stored) -> bool:
                if isinstance(cond, dict):
                    for op, val in cond.items():
                        if op == "$ne":
                            if stored == val:
                                return False
                        elif op == "$regex":
                            if not re.search(str(val), str(stored)):
                                return False
                        else:
                            return False  # operator tak dikenal = tidak match
                    return True
                return stored == cond

            for uname, rec in self.lab.users.items():
                if _match(fields.get("username", ""), uname) and \
                        _match(fields.get("password", ""), rec["password"]):
                    sid = secrets.token_hex(8)
                    self.lab.sessions[sid] = {**rec, "username": uname}
                    return self._json(200, {"ok": True, "user": uname},
                                      headers={"Set-Cookie": f"sid={sid}; Path=/"})
            return self._json(401, {"error": "bad credentials"})
        if parsed.path == "/api/upload":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            filename = (qs.get("filename") or [""])[0]
            # KERENTANAN SENGAJA: klaim "hanya PNG" tapi cek substring —
            # payload.png.html lolos (CWE-434)
            if ".png" not in filename:
                return self._json(400, {"error": "hanya .png diizinkan"})
            data = self.rfile.read(
                min(int(self.headers.get("Content-Length", 0)), 8192))
            self.lab.uploads[filename] = data
            return self._json(201, {"stored": filename})
        if parsed.path == "/api/coupon":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            code = "CANARY-" + secrets.token_hex(4)
            self.lab.coupons[code] = {"uses": 1}
            return self._json(201, {"code": code, "uses": 1})
        if parsed.path == "/api/coupon/redeem":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            length = int(self.headers.get("Content-Length", 0))
            try:
                code = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))["code"]
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            coupon = self.lab.coupons.get(code)
            if not coupon:
                return self._json(404, {"error": "coupon tidak ada"})
            # KERENTANAN SENGAJA: check-then-act TIDAK atomik (CWE-362) —
            # redeem konkuren pada kupon uses=1 lolos lebih dari sekali
            if coupon["uses"] > 0:
                time.sleep(0.05)
                coupon["uses"] -= 1
                return self._json(200, {"redeemed": True,
                                        "remaining": coupon["uses"]})
            return self._json(409, {"error": "sudah terpakai"})
        if parsed.path == "/api/profile/update":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            length = int(self.headers.get("Content-Length", 0))
            try:
                fields = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            # KERENTANAN SENGAJA: mass assignment — field apa pun dari
            # body diterima, termasuk "role" (CWE-915)
            for k in ("email", "role"):
                if k in fields:
                    user[k] = fields[k]
            return self._json(200, {"ok": True, "role": user.get("role")})
        if parsed.path == "/api/xml":
            body = self.rfile.read(
                min(int(self.headers.get("Content-Length", 0)), 8192)
            ).decode("utf-8", "replace")
            # KERENTANAN SENGAJA: parser XML naive yang MENYELESAIKAN
            # entity eksternal (CWE-611) — termasuk fetch http://
            m = re.search(r'SYSTEM\s+"(https?://[^"]+)"', body)
            ent = ""
            if m:
                try:
                    with urllib.request.urlopen(m.group(1), timeout=3) as r:
                        ent = r.read(512).decode("utf-8", "replace")
                except Exception as exc:
                    ent = f"[resolve gagal: {exc!r}]"
            doc = body.replace("&xxe;", ent)
            return self._json(200, {"parsed": "<doc>" in doc,
                                    "content": doc[:300]})
        if parsed.path == "/api/deser":
            raw = self.rfile.read(
                min(int(self.headers.get("Content-Length", 0)), 8192))
            # KERENTANAN SENGAJA: unpickle data tidak tepercaya (CWE-502)
            # — di lab ini, payload playbook hanya menjalankan perintah
            # marker benign (bukti RCE), tanpa destruktif apa pun
            obj = pickle.loads(base64.b64decode(raw))
            return self._json(200, {"imported": str(type(obj))})
        if parsed.path in ("/api/xml2", "/api/xml2-safe"):
            length = int(self.headers.get("Content-Length", 0))
            xml = self.rfile.read(length).decode("utf-8", "replace")
            if parsed.path == "/api/xml2-safe":
                # kontrol: parser aman — DOCTYPE/entity DITOLAK total
                if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
                    return self._json(400, {"error":
                                            "DOCTYPE/entity ditolak"})
                content = re.sub(r"<[^>]+>", "", xml)
                return self._json(200, {"parsed": content[:2000]})
            # KERENTANAN SENGAJA: parser naive yang MENYELESAIKAN external
            # entity file:// (CWE-611 varian in-band). Dibatasi file DI
            # DALAM dir lab (path relatif) — lab tidak boleh jadi pintu
            # baca file host sembarangan.
            ents = re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', xml)
            content = re.sub(r"<!DOCTYPE[^>[]*(\[[^\]]*\])?>", "", xml,
                             flags=re.S)
            for name, sysid in ents:
                if not sysid.startswith("file://"):
                    return self._json(400, {"error":
                                            "hanya file:// (lab)"})
                rel = sysid[len("file://"):].lstrip("/")
                if ".." in rel or ":" in rel or rel.startswith("\\"):
                    return self._json(400, {"error": "path file lab saja"})
                fp = os.path.join(self.lab.files_base, rel)
                try:
                    with open(fp, encoding="utf-8", errors="replace") as fh:
                        data = fh.read(4096)
                except OSError:
                    data = ""
                content = content.replace(f"&{name};", data)
            return self._json(200, {"parsed": content[:2000]})
        if self.path == "/login-locked":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            fields = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            uname = fields.get("username", "")
            rec = self.lab.users.get(uname)
            fails = self.lab.lockout.get(uname, 0)
            # kontrol CWE-307: setelah 5 gagal, login BENAR pun ditolak
            if rec and rec["password"] == fields.get("password", "") \
                    and fails < 5:
                self.lab.lockout.pop(uname, None)
                sid = secrets.token_hex(8)
                self.lab.sessions[sid] = {**rec, "username": uname}
                return self._json(200, {"ok": True, "user": uname},
                                  headers={"Set-Cookie": f"sid={sid}; Path=/"})
            self.lab.lockout[uname] = fails + 1
            if self.lab.lockout[uname] >= 5:
                return self._json(429, {"error": "account locked"})
            return self._json(401, {"error": "bad credentials"})
        if self.path == "/login-fixated":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            fields = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            uname = fields.get("username", "")
            rec = self.lab.users.get(uname)
            if not rec or rec["password"] != fields.get("password", ""):
                return self._json(401, {"error": "bad credentials"})
            # KERENTANAN SENGAJA: session id TIDAK diregenerasi saat auth
            # (CWE-384) — sid yang dipaksa sebelum login tetap dipakai
            sid = None
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "sid" and v:
                    sid = v
            if not sid:
                sid = secrets.token_hex(8)
            self.lab.sessions[sid] = {**rec, "username": uname}
            return self._json(200, {"ok": True, "user": uname},
                              headers={"Set-Cookie": f"sid={sid}; Path=/"})
        if self.path == "/logout":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            # KERENTANAN SENGAJA: sesi TIDAK dibatalkan setelah logout
            # (CWE-613) — sid lama tetap hidup di server
            return self._json(200, {"ok": True, "msg": "logged out"})
        if self.path == "/logout-secure":
            user = self._session_user()
            if not user:
                return self._json(401, {"error": "unauthenticated"})
            # kontrol: sesi benar-benar dibatalkan di server
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "sid" and v:
                    self.lab.sessions.pop(v, None)
            return self._json(200, {"ok": True, "msg": "logged out"},
                              headers={"Set-Cookie": "sid=; Path=/; "
                                                      "Max-Age=0"})
        if parsed.path in ("/api/register", "/api/register-safe"):
            length = int(self.headers.get("Content-Length", 0))
            try:
                email = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace")
                )["email"]
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            generic = {"status": "pending",
                       "msg": "verifikasi dikirim bila email valid"}
            if parsed.path == "/api/register-safe":
                # kontrol: respons uniform TANPA sinyal keberadaan
                return self._json(200, dict(generic))
            # KERENTANAN SENGAJA: keberadaan akun terkonfirmasi EKSPLISIT
            # via 409 (CWE-204, sisi registrasi). TIDAK ada akun dibuat —
            # differential respons saja (disiplin reset-enum).
            known = any(u["email"] == email for u in self.lab.users.values())
            if known:
                return self._json(409, {"error": "email already registered"})
            return self._json(200, dict(generic))
        if parsed.path == "/api/reset":
            length = int(self.headers.get("Content-Length", 0))
            try:
                email = json.loads(
                    self.rfile.read(length).decode("utf-8", "replace")
                )["email"]
            except Exception:
                return self._json(400, {"error": "body JSON wajib"})
            # KERENTANAN SENGAJA: respons BERBEDA untuk email terdaftar vs
            # tidak (CWE-204) — enumerasi user terbukti dari differential
            known = any(u["email"] == email for u in self.lab.users.values())
            if known:
                # catatan: di lab TIDAK ada email sungguhan yang dikirim —
                # tier-1 playbook hanya membaca differential respons
                return self._json(200, {"status": "sent",
                                        "msg": "tautan reset dikirim"})
            return self._json(404, {"status": "unknown",
                                    "error": "email tidak terdaftar"})
        return self._json(404, {"error": "not found"})

    def do_PATCH(self):
        return self.do_POST()

    def do_DELETE(self):
        # evict mini-cache untuk cleanup playbook cache-poison — plumbing
        # lab (di luar gate auth supaya cleanup engine selalu berhasil)
        if self.path.startswith("/cacheable-header/"):
            self.lab.cache.pop(self.path, None)
            return self._json(200, {"evicted": self.path})
        if self.path.startswith("/api/rag/doc/"):
            # F46: cleanup canary RAG (dipanggil engine via
            # register_cleanup - terjamin walau playbook crash)
            doc_id = self.path.rsplit("/", 1)[-1]
            removed = self.lab.corpus.pop(doc_id, None)
            self.lab.corpus_pending.pop(doc_id, None)
            return self._json(200, {"ok": True, "removed": bool(removed)})
        user = self._session_user()
        if not user:
            return self._json(401, {"error": "unauthenticated"})
        name = self.path.rsplit("/", 1)[-1]
        if self.path.startswith("/api/upload/"):
            if self.lab.uploads.pop(name, None) is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, {"deleted": name})
        if self.path.startswith("/api/coupon/"):
            if self.lab.coupons.pop(name, None) is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, {"deleted": name})
        return self._json(404, {"error": "not found"})


class _InternalHandler(BaseHTTPRequestHandler):
    """Service INTERNAL lab (bind 127.0.0.1 di dalam proses lab): dasar
    bukti ssrf-chain — endpoint yang tidak terhidang di port publik lab.
    Echo marker unik per-run (zero-FP: bukti terikat request kita)."""
    def log_message(self, *a):
        return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        marker = (qs.get("marker") or [""])[0]
        body = json.dumps({"service": "inventory-internal",
                           "echo": marker}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _InternalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind: str = "127.0.0.1", port: int = 0):
        super().__init__((bind, port), _Handler)
        self.users = {k: dict(v) for k, v in USERS.items()}
        self.orders = {k: dict(v) for k, v in ORDERS.items()}
        self.tickets = {k: dict(v) for k, v in TICKETS.items()}
        self.sessions: dict[str, dict] = {}
        # F46: corpus RAG (dokumen aktif) + antrean review (kontrol)
        self.corpus: dict[str, str] = {
            'faq-1': 'Jam layanan 09.00-17.00 WIB hari kerja.',
            'faq-2': 'Refund diajukan maksimal 7 hari setelah'
                     ' transaksi.',
        }
        self.corpus_pending: dict[str, str] = {}
        self.uploads: dict[str, bytes] = {}
        self.coupons: dict[str, dict] = {}
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db_lock = threading.Lock()
        self.db.execute("CREATE TABLE products (id INT, name TEXT, price INT)")
        self.db.executemany("INSERT INTO products VALUES (?,?,?)", PRODUCTS)
        self.db.commit()
        # LFI lab: root served + canary DI LUARNYA (satu direktori temp
        # milik lab sendiri; dihapus stop_lab)
        self.files_base = tempfile.mkdtemp(prefix="cyphron-lab-files-")
        self.files_root = os.path.join(self.files_base, "files")
        os.makedirs(self.files_root)
        with open(os.path.join(self.files_root, "report.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("hello from lab report")
        with open(os.path.join(self.files_base, "canary-lfi.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(LFI_CANARY)
        # proto-pollution lab: objek "defaults" bersama (simulasi prototipe)
        self.pp_defaults: dict = {"theme": "light"}
        # mini-cache: url -> (status, headers, body) — mensimulasikan cache
        # bersama untuk bukti cache deception dua-langkah
        self.cache: dict[str, tuple[int, dict, bytes]] = {}
        # password-reset lab: token -> email (bukan pengirim email nyata)
        self.reset_tokens: dict[str, str] = {}
        # oauth-state lab: code -> state terikat (simulasi OAuth)
        self.oauth_codes: dict[str, str] = {}
        # lockout lab: username -> jumlah login gagal (kontrol CWE-307)
        self.lockout: dict[str, int] = {}
        # ssrf-chain lab: service internal bind 127.0.0.1 DI DALAM proses
        # lab — dari luar proses/kontainer lain tidak terjangkau langsung
        self.internal_srv = _InternalServer(("127.0.0.1", 0),
                                            _InternalHandler)
        threading.Thread(target=self.internal_srv.serve_forever,
                         daemon=True).start()
        self.internal_port = self.internal_srv.server_address[1]
        self.own_base = (f"http://{self.server_address[0]}:"
                         f"{self.server_address[1]}")


def start_lab() -> tuple[LabServer, str]:
    """Start lab pada port ephemeral 127.0.0.1. Return (server, base_url)."""
    server = LabServer()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def stop_lab(server: LabServer) -> None:
    server.internal_srv.shutdown()
    server.internal_srv.server_close()
    server.shutdown()
    server.server_close()
    shutil.rmtree(server.files_base, ignore_errors=True)


if __name__ == "__main__":
    import os
    # dukungan lab-in-docker: bind/port lewat env (sandbox menaruh lab di
    # jaringan internal Docker dan engine mengakses via nama kontainer)
    port = int(os.environ.get("CYPHRON_LAB_PORT", "0") or 0)
    bind = os.environ.get("CYPHRON_LAB_BIND", "127.0.0.1")
    server = LabServer(bind=bind, port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"lab target aktif: http://{bind}:{server.server_address[1]}")
    try:
        threading.Event().wait()
    finally:
        stop_lab(server)
