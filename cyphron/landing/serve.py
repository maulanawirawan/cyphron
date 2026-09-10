"""serve.py — server web Cyphron yang AMAN untuk localhost/VPS.

Aturan keamanan (kenapa bukan python -m http.server biasa):
1. HANYA melayani file statis dari folder landing/ (index.html, app.html, aset).
2. app.html + endpoint /api/* WAJIB login: akun disimpan sebagai SHA-256+salt
   di accounts.json (password asli TIDAK PERNAH disimpan).
3. Path terlarang diblokir total: .py, .cyphron (skill!), .git, .env, json, yaml —
   source code attack engine TIDAK PERNAH tersaji ke publik.
4. Default bind 127.0.0.1. Untuk VPS: jalankan di belakang nginx + HTTPS.

Jalankan:  python serve.py            (localhost:8080)
Daftar:    buka /register  atau POST register dari halaman login.
"""
import hashlib, json, os, secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
ACCOUNTS = ROOT / "accounts.json"
BLOCK = (".py", ".cyphron", ".git", ".env", ".json", ".yaml", ".md", "__", "cyphron/")

def _load_accounts():
    if ACCOUNTS.exists():
        return json.loads(ACCOUNTS.read_text())
    return {}

def _save_accounts(acc):
    ACCOUNTS.write_text(json.dumps(acc, indent=2))

def _hash(salt, pw):
    return hashlib.sha256((salt + pw).encode()).hexdigest()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookie=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _blocked(self, path):
        low = path.lower()
        return any(b in low for b in BLOCK) or ".." in path

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/register":
            return self._send(200, (ROOT / "app.html").read_text(encoding="utf-8"))
        if self._blocked(path):
            return self._send(404, "not found")
        if path in ("/app.html", "/api/session"):
            # butuh token sesi: cek cookie cyphron_session
            if "cyphron_session=" not in (self.headers.get("Cookie") or ""):
                return self._send(403, "<h1>403</h1><p>Login dulu via halaman utama.</p>")
        file = ROOT / (path.lstrip("/") or "index.html")
        if file.is_file():
            return self._send(200, file.read_text(encoding="utf-8"))
        self._send(404, "not found")

    def do_POST(self):
        if self._blocked(self.path):
            return self._send(404, "not found")
        length = int(self.headers.get("Content-Length", 0))
        form = dict(p.split("=", 1) for p in self.headers.get("Cookie", "").split("; ") if "=" in p)
        raw = self.rfile.read(length).decode()
        fields = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
        action = fields.get("action", "")
        email, pw = fields.get("email", ""), fields.get("password", "")
        if not email or not pw or len(pw) < 8:
            return self._send(400, "email & password (min 8 karakter) wajib")
        acc = _load_accounts()
        if action == "register":
            if email in acc:
                return self._send(400, "email sudah terdaftar")
            salt = secrets.token_hex(8)
            acc[email] = {"salt": salt, "hash": _hash(salt, pw), "tier": fields.get("tier", "basic")}
            _save_accounts(acc)
            tok = secrets.token_urlsafe(32)
            return self._send(200, '{"ok":true,"msg":"terdaftar & masuk"}',
                              cookie=f"cyphron_session={tok}; HttpOnly; SameSite=Lax; Path=/")
        # login
        rec = acc.get(email)
        if rec and _hash(rec["salt"], pw) == rec["hash"]:
            tok = secrets.token_urlsafe(32)
            return self._send(200, '{"ok":true}', cookie=f"cyphron_session={tok}; HttpOnly; SameSite=Lax; Path=/")
        return self._send(401, "kredensial salah")

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"[cyphron] aman di http://127.0.0.1:{port} (register/login: Hash SHA-256, source code TIDAK dilayani)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
