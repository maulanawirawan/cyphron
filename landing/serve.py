"""serve.py — server web Cyphron yang AMAN untuk localhost/VPS.

Aturan keamanan (kenapa bukan python -m http.server biasa):
1. HANYA melayani file statis dari folder landing/ (index.html, app.html, aset).
2. app.html + endpoint /api/* WAJIB login: akun disimpan sebagai SHA-256+salt
   di accounts.json (password asli TIDAK PERNAH disimpan).
3. Path terlarang diblokir total: .py, .cyphron (skill!), .git, .env, json, yaml —
   source code attack engine TIDAK PERNAH tersaji ke publik.
4. Default bind 127.0.0.1. Untuk VPS: jalankan di belakang nginx + HTTPS.
5. /api/scan menjalankan engine sebagai subprocess TANPA shell, satu job
   sekaligus per klik, target wajib http(s)://, kerja di folder jobs/<id>/.

Alur user (wizard minimal-klik di app.html):
  masukkan URL -> klik 1 kartu mode -> MULAI -> polling progress -> unduh PDF.

Jalankan:  python serve.py            (localhost:8080)
Daftar:    buka /register  atau POST register dari halaman login.
"""
import hashlib, json, os, secrets, subprocess, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
REPO = ROOT.parent
ACCOUNTS = ROOT / "accounts.json"
JOBS = ROOT / "jobs"
SESSIONS = ROOT / "sessions.json"   # {token: {"email":..., "exp": epoch}}
SESSION_TTL_S = 12 * 3600
MAX_BODY = 1_000_000                # cap body request (1 MB)
BLOCK = (".py", ".cyphron", ".git", ".env", ".json", ".yaml", "__", "cyphron/")

# mode wizard -> profil dast + kebutuhan otorisasi + lisensi otomatis
MODES = {
    "trial":    {"profile": "dev-cicd", "auth_required": False, "kind": "trial",
                 "tier": "basic", "days": 7, "token_limit": 30},
    "standard": {"profile": "standard", "auth_required": True, "kind": "standard",
                 "tier": None, "days": 30, "token_limit": None},
    "full":     {"profile": "full", "auth_required": True, "kind": "standard",
                 "tier": None, "days": 30, "token_limit": None},
}


def _load_sessions() -> dict:
    if SESSIONS.exists():
        try:
            return json.loads(SESSIONS.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def _save_sessions(s):
    SESSIONS.write_text(json.dumps(s, indent=2), encoding="utf-8")


def _session_email(token: str | None) -> str | None:
    """Validasi token terhadap store + TTL — dulu cookie random cuma dipercaya
    begitu saja (siapa pun yang menebak/memegang token masuk tanpa batas)."""
    if not token:
        return None
    s = _load_sessions()
    rec = s.get(token)
    if not rec or rec.get("exp", 0) < time.time():
        if rec:
            s.pop(token, None)
            _save_sessions(s)
        return None
    return rec.get("email")


def _scans_today(email: str) -> int:
    """Jumlah scan milik satu email pada hari UTC ini (dari job.json)."""
    today = time.strftime("%Y-%m-%d", time.gmtime())
    n = 0
    if JOBS.is_dir():
        for j in JOBS.iterdir():
            meta = j / "job.json"
            if meta.is_file():
                try:
                    m = json.loads(meta.read_text(encoding="utf-8"))
                    if m.get("user") == email and m.get("day") == today:
                        n += 1
                except (OSError, ValueError):
                    pass
    return n


_LOGIN_FAILS: dict[str, list[float]] = {}  # kunci email -> timestamp gagal
LOGIN_WINDOW_S = 900     # 15 menit
LOGIN_MAX_FAILS = 5


def _login_blocked(email: str) -> tuple[bool, int]:
    """Anti brute-force: >=5 gagal dalam 15 menit = tolak sementara."""
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(email, []) if now - t < LOGIN_WINDOW_S]
    _LOGIN_FAILS[email] = fails
    return len(fails) >= LOGIN_MAX_FAILS, LOGIN_MAX_FAILS - len(fails)


def _load_accounts():
    if ACCOUNTS.exists():
        return json.loads(ACCOUNTS.read_text())
    return {}


def _save_accounts(acc):
    ACCOUNTS.write_text(json.dumps(acc, indent=2))


def _hash(salt, pw):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


class Job:
    def __init__(self, jid: str):
        self.dir = JOBS / jid
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "log.txt"

    def append(self, line: str):
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line.rstrip() + "\n")

    def tail(self, n: int = 12) -> list:
        if not self.log_path.exists():
            return []
        return self.log_path.read_text(
            encoding="utf-8", errors="replace").splitlines()[-n:]

    @property
    def done(self) -> bool:
        return (self.dir / "out" / "report.md").exists()


def _run_job(jid: str, meta: dict):
    """Worker: spawn engine sebagai subprocess (tanpa shell), catat log."""
    job = Job(jid)
    job.append(f"[job] mode={meta['mode']} target={meta['target']}")
    cmd = [sys.executable, "-m", "cyphron", "dast",
           "--target", meta["target"],
           "--profile", meta["profile"],
           "--out", str(job.dir / "out")]
    if meta.get("license_path"):
        cmd += ["--license", meta["license_path"]]
    if meta.get("auth_path"):
        cmd += ["--auth", meta["auth_path"]]
    job.append("[job] " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, cwd=REPO, capture_output=True, text=True, timeout=60 * 60,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        for line in (proc.stdout or "").splitlines():
            job.append(line)
        if proc.returncode not in (0, 2):
            job.append(f"[job] engine keluar dengan kode {proc.returncode}")
            if proc.stderr:
                job.append(proc.stderr[-500:])
    except subprocess.TimeoutExpired:
        job.append("[job] WAKTU HABIS (60 menit) — scan dihentikan")
    except Exception as exc:  # jangan biarkan job zombie
        job.append(f"[job] gagal: {type(exc).__name__}: {exc}")
    job.append("[job] SELESAI" if job.done else "[job] SELESAI tanpa laporan")


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

    def _raw(self, data: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _blocked(self, path):
        low = path.lower()
        return any(b in low for b in BLOCK) or ".." in path

    def _session_email(self):
        cookie = self.headers.get("Cookie", "")
        token = (cookie.split("cyphron_session=", 1)[1].split(";", 1)[0]
                 if "cyphron_session=" in cookie else None)
        return _session_email(token)

    def _owns_job(self, email: str | None, jdir: Path) -> bool:
        meta = jdir / "job.json"
        if not email or not meta.is_file():
            return False
        try:
            return json.loads(meta.read_text(encoding="utf-8")).get("user") == email
        except (OSError, ValueError):
            return False

    def do_GET(self):
        path, _, _q = self.path.partition("?")
        if path == "/register":
            return self._send(200, (ROOT / "app.html").read_text(encoding="utf-8"))
        if self._blocked(path):
            return self._send(404, "not found")
        if path.startswith("/api/"):
            if not self._session_email():
                return self._send(403, '{"error":"login dulu"}')
            if path == "/api/session":
                email = self._session_email()
                tier = _load_accounts().get(email, {}).get("tier", "basic")
                from cyphron.pricing import PLANS
                plan = PLANS.get(tier) or PLANS["basic"]
                return self._send(200, json.dumps({
                    "email": email, "tier": tier,
                    "scans_today": _scans_today(email),
                    "scans_per_day": plan.get("scans_per_day", 4)}))
            if path == "/api/my-jobs":
                email = self._session_email()
                mine = []
                if JOBS.is_dir():
                    for j in sorted(JOBS.iterdir()):
                        meta = j / "job.json"
                        if not meta.is_file():
                            continue
                        try:
                            m = json.loads(meta.read_text(encoding="utf-8"))
                        except (OSError, ValueError):
                            continue
                        if m.get("user") != email:
                            continue  # laporan orang lain bukan urusan kita
                        pdf = (j / "out" / "report.pdf").exists()
                        mine.append({"id": j.name, "mode": m.get("mode"),
                                     "day": m.get("day", ""),
                                     "done": (j / "out" / "report.md").exists(),
                                     "has_pdf": pdf})
                return self._send(200, json.dumps({"jobs": mine[:20]}))
            if path.startswith("/api/job/"):
                jid = path.rsplit("/", 1)[-1]
                jdir = JOBS / jid
                if not jdir.is_dir():
                    return self._send(404, '{"error":"job tidak ditemukan"}')
                if not self._owns_job(email=self._session_email(), jdir=jdir):
                    return self._send(403, '{"error":"bukan job kamu"}')
                job = Job(jid)
                pdf = jdir / "out" / "report.pdf"
                md = jdir / "out" / "report.md"
                return self._send(200, json.dumps({
                    "id": jid, "done": job.done, "lines": job.tail(12),
                    "report": {"pdf": "report.pdf" if pdf.exists() else None,
                               "md": "report.md" if md.exists() else None}}))
            if path.startswith("/api/report/"):
                rest = path.partition("/api/report/")[2]
                jid, _, fname = rest.partition("/")
                if not self._owns_job(email=self._session_email(),
                                      jdir=JOBS / jid):
                    return self._send(403, "bukan job kamu")
                f = JOBS / jid / "out" / (fname or "report.pdf")
                if not f.is_file() or f.suffix not in (".pdf", ".md"):
                    return self._send(404, "laporan belum siap")
                ctype = ("application/pdf" if f.suffix == ".pdf"
                         else "text/markdown; charset=utf-8")
                return self._raw(f.read_bytes(), ctype)
        file = ROOT / (path.lstrip("/") or "index.html")
        if file.is_file():
            return self._send(200, file.read_text(encoding="utf-8"))
        self._send(404, "not found")

    def do_POST(self):
        if self._blocked(self.path):
            return self._send(404, "not found")
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            return self._send(413, "body terlalu besar")
        raw = self.rfile.read(length).decode()
        fields = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
        fields = {k: urllib.parse.unquote_plus(v) for k, v in fields.items()}
        cookie_fields = dict(p.split("=", 1)
                             for p in self.headers.get("Cookie", "").split("; ")
                             if "=" in p)

        if self.path == "/api/scan":
            email = cookie_fields.get("cyphron_session")
            if not email:
                return self._send(403, '{"error":"login dulu"}')
            target = fields.get("target", "").strip()
            mode = fields.get("mode", "trial")
            if mode not in MODES:
                return self._send(400, '{"error":"mode tidak dikenal"}')
            if not target.startswith(("http://", "https://")):
                return self._send(400, '{"error":"target wajib http(s)://"}')
            m = MODES[mode]
            auth_text = (fields.get("auth_doc") or "").strip()
            if m["auth_required"] and not auth_text:
                return self._send(400, '{"error":"mode ini butuh dokumen otorisasi"}')
            # kuota scan harian per akun (PLANS.scans_per_day) — anti-abuse
            # trial spam; dulu dideklarasikan tapi tidak pernah ditegakkan
            from cyphron.pricing import PLANS
            tier = m["tier"] or _load_accounts().get(email, {}).get("tier", "basic")
            quota = (PLANS.get(tier) or PLANS["basic"]).get("scans_per_day", 4)
            if _scans_today(email) >= quota:
                return self._send(429, json.dumps({
                    "error": f"kuota scan harian habis ({quota}/hari pada paket {tier})"}))
            jid = secrets.token_urlsafe(12)
            job = Job(jid)
            job.append(f"[job] user={email}")
            (job.dir / "job.json").write_text(json.dumps({
                "user": email, "day": time.strftime("%Y-%m-%d", time.gmtime()),
                "mode": mode, "ts": time.time()}), encoding="utf-8")
            meta = {"target": target, "mode": mode, "profile": m["profile"]}
            if auth_text:
                try:
                    json.loads(auth_text)  # validasi sebelum dipercaya
                except json.JSONDecodeError as exc:
                    return self._send(400, f'{{"error":"dokumen otorisasi bukan JSON valid: {exc}"}}')
                auth_path = job.dir / "auth-doc.json"
                auth_path.write_text(auth_text, encoding="utf-8")
                meta["auth_path"] = str(auth_path)
            # lisensi: trial di-issue otomatis; tier lain dari akun
            sys.path.insert(0, str(REPO))
            from cyphron.licensing import issue_license
            lic_path = job.dir / "license.json"
            issue_license(lic_path, licensee=email, tier=tier, kind=m["kind"],
                          days=m["days"], token_limit=m["token_limit"],
                          bind_device=False)  # scan jalan di server, bukan klien
            meta["license_path"] = str(lic_path)
            threading.Thread(target=_run_job, args=(jid, meta), daemon=True).start()
            return self._send(200, json.dumps({"ok": True, "id": jid}))

        action = fields.get("action", "")
        email, pw = fields.get("email", ""), fields.get("password", "")
        if not email or not pw or len(pw) < 8:
            return self._send(400, "email & password (min 8 karakter) wajib")
        if action != "register" and _login_blocked(email):
            return self._send(429, "terlalu banyak percobaan gagal — coba lagi 15 menit")
        acc = _load_accounts()
        if action == "register":
            if email in acc:
                return self._send(400, "email sudah terdaftar")
            salt = secrets.token_hex(8)
            acc[email] = {"salt": salt, "hash": _hash(salt, pw), "tier": fields.get("tier", "basic")}
            _save_accounts(acc)
            tok = secrets.token_urlsafe(32)
            s = _load_sessions()
            s[tok] = {"email": email, "exp": time.time() + SESSION_TTL_S}
            _save_sessions(s)
            return self._send(200, '{"ok":true,"msg":"terdaftar & masuk"}',
                              cookie=f"cyphron_session={tok}; HttpOnly; SameSite=Lax; Path=/")
        # login
        rec = acc.get(email)
        if rec and _hash(rec["salt"], pw) == rec["hash"]:
            _LOGIN_FAILS.pop(email, None)
            tok = secrets.token_urlsafe(32)
            s = _load_sessions()
            s[tok] = {"email": email, "exp": time.time() + SESSION_TTL_S}
            _save_sessions(s)
            return self._send(200, '{"ok":true}', cookie=f"cyphron_session={tok}; HttpOnly; SameSite=Lax; Path=/")
        _LOGIN_FAILS.setdefault(email, []).append(time.time())
        return self._send(401, "kredensial salah")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"[cyphron] aman di http://127.0.0.1:{port} (register/login: Hash SHA-256, source code TIDAK dilayani)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
