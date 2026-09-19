"""tierpack — 100 attack/audit skills organized into 4 severity tiers
(25 each: LOW -> MEDIUM -> HIGH -> CRITICAL), matching the CVSS bands.

Each skill = (name, technique, fp_guard, verify, engine).
- engine "live:<tool>"  -> runnable TODAY by the named Cyphron engine
- engine "road:<name>"  -> designed slot; implement via the same
  test-gated pipeline (unit test + FP-guard) before it can report TRUE.

`build(kimchi_dir)` emits .kimchi/skills-tiers/<tier>/NN-*.md + INDEX.md."""

from __future__ import annotations

from pathlib import Path

LOW = [
    ("robots-disclosure", "robots.txt membocorkan path privat", "hit = 200 + konten, bandingkan baseline 404", "crawler"),
    ("sitemap-paths", "sitemap.xml mengungkap rute tersembunyi", "hit = <loc> resolved same-host", "crawler"),
    ("securitytxt-missing", "security.txt (RFC 9116) tidak ada", "hit = 404 pada /.well-known/security.txt", "crawler"),
    ("humans-changelog", "humans.txt/CHANGELOG membocorkan versi", "hit = 200 + marker", "dir_probe"),
    ("readme-exposed", "README/dokumentasi internal terekspos", "hit = 200 beda dari baseline 404", "dir_probe"),
    ("packagejson-deps", "package.json/composer.json membocorkan dependensi", "hit = 200 + JSON valid", "dir_probe"),
    ("server-header", "Header Server/X-Powered-By membocorkan teknologi", "definitif: header ada", "http_probe"),
    ("generator-meta", "Meta generator membocorkan versi CMS/framework", "definitif: tag meta ada", "http_probe"),
    ("referrer-policy", "Referrer-Policy tidak diatur", "definitif: header absen", "security_headers"),
    ("permissions-policy", "Permissions-Policy tidak diatur", "definitif: header absen", "security_headers"),
    ("xcto-missing", "X-Content-Type-Options: nosniff tidak ada", "definitif: header absen", "security_headers"),
    ("xfo-missing", "X-Frame-Options/frame-ancestors tidak ada", "definitif: header absen", "security_headers"),
    ("cookie-httponly", "Cookie tanpa HttpOnly", "definitif: atribut di Set-Cookie", "security_headers"),
    ("cookie-samesite", "Cookie tanpa SameSite", "definitif: atribut di Set-Cookie", "security_headers"),
    ("open-registration", "Registrasi publik terbuka (inventaris permukaan)", "hit = 200 + form password", "auth_probe"),
    ("login-discovery", "Endpoint login teridentifikasi", "hit = form password di HTML", "auth_probe"),
    ("options-allow", "Header Allow membocorkan metode", "definitif: header Allow", "method_audit"),
    ("html-comments", "Komentar HTML membocorkan info internal", "hit = komentar >8 char", "crawler"),
    ("email-in-page", "Alamat email terekspos di halaman", "definitif: regex email", "crawler"),
    ("asset-fingerprint", "Fingerprint aset/versi statis", "hit = path _next/static dkk.", "crawler"),
    ("session-cookie-name", "Nama cookie sesi terungkap", "definitif: Set-Cookie", "session_probe"),
    ("error-tech-disclosure", "Pesan error membocorkan framework (mis. NextAuth)", "definitif: teks error spesifik", "auth_probe"),
    ("sitemap-hidden-paths", "sitemap memuat path non-publik", "hit = loc non-marketing", "crawler"),
    ("cors-no-cred", "CORS refleksi Origin tanpa kredensial", "hit = ACAO == Origin, ACAC != true", "deep_probe"),
    ("options-permissive", "OPTIONS mengizinkan metode berisiko rendah", "definitif: header Allow", "method_audit"),
]

MEDIUM = [
    ("csp-missing", "CSP tidak ada sama sekali", "definitif: header absen", "security_headers"),
    ("csp-report-only", "CSP baru Report-Only (belum enforcing)", "definitif: header report-only tanpa enforcing", "security_headers"),
    ("hsts-missing", "HSTS tidak dikirim di HTTPS", "definitif: header absen", "security_headers"),
    ("spf-missing", "SPF tidak dipublikasikan (spoofing email)", "fakta DNS TXT", "email_probe"),
    ("dmarc-missing", "DMARC tidak dipublikasikan", "fakta DNS TXT _dmarc", "email_probe"),
    ("dkim-missing", "Selector DKIM standar tidak dipublikasikan", "fakta DNS TXT selector", "road:dkim_probe"),
    ("lockout-absent", "Tidak ada lockout/rate-limit di login", "6 gagal beruntun tanpa 429", "auth_probe"),
    ("user-enum", "Username enumeration via respons berbeda", "hit = dua respons tak-kenal berbeda material", "auth_probe"),
    ("login-error-diff", "Pesan error login berbeda per kasus", "hit = marker error berbeda", "auth_probe"),
    ("csrf-form-missing", "Form POST tanpa token CSRF terlihat", "info: SPA bisa via header; wajib verifikasi", "deep_probe"),
    ("cookie-samesite-session", "Cookie sesi tanpa SameSite", "definitif: atribut absen", "security_headers"),
    ("jwt-exp-missing", "JWT tanpa klaim exp", "definitif: decode payload", "session_probe"),
    ("session-entropy-low", "Entropi token sesi < 100 bit", "hit = perhitungan entropi", "session_probe"),
    ("dir-listing", "Directory listing (autoindex) aktif", "definitif: marker 'Index of /'", "dir_probe"),
    ("verbose-errors", "Halaman error verbose membocorkan stack/path", "hit = stack trace di body", "road:err_probe"),
    ("open-redirect-reflected", "Open redirect terpantul via parameter", "hit = Location ke canary host", "redirect_probe"),
    ("trace-enabled", "Metode TRACE aktif (XST)", "hit = body echo probe", "method_audit"),
    ("debug-path", "Path /debug terbuka", "hit = 200 beda dari baseline", "dir_probe"),
    ("phpinfo", "phpinfo terekspos", "definitif: marker phpinfo()", "dir_probe"),
    ("actuator-exposed", "Spring actuator terekspos", "hit = 200 pada /actuator/*", "dir_probe"),
    ("swagger-public", "Swagger/OpenAPI publik tanpa auth", "hit = 200 + JSON spec", "dir_probe"),
    ("graphiql-exposed", "GraphiQL IDE terbuka", "hit = 200 + HTML IDE", "deep_probe"),
    ("mixed-content", "HTTPS memuat aset http://", "definitif: marker src/href http://", "deep_probe"),
    ("load-5xx", "5xx muncul di bawah beban terukur", "hit = 5xx > 0 dalam ladder", "load_probe"),
    ("load-latency", "p95 melonjak > 2x baseline stage", "hit = rasio p95 antar stage", "load_probe"),
]

HIGH = [
    ("xss-reflected", "Reflected XSS terkonfirmasi (marker markup mentah)", "hit = tag script payload terpantul utuh", "xss_probe"),
    ("open-redirect-confirmed", "Open redirect ke canary host", "hit = 3xx Location canary", "redirect_probe"),
    ("crlf-injection", "CRLF menyuntikkan header respons", "definitif: header X-Cyphron-Probe muncul", "deep_probe"),
    ("hostheader-reflect", "X-Forwarded-Host terpantul di respons", "definitif: nilai canary di body", "deep_probe"),
    ("jwt-algnone-accepted", "JWT alg:none diterima server", "hit = tampered 200 vs baseline denied", "session_probe"),
    ("api-unauth-data", "Endpoint /api/* mengembalikan data tanpa auth", "hit = 200 + JSON >200 byte", "deep_probe"),
    ("traversal-verified", "Path traversal membaca file sistem", "hit = marker root:/win.ini, absen di baseline", "deep_probe"),
    ("sqli-boolean", "Boolean-based blind SQLi (pasangan diverifikasi)", "hit = divergensi terukur pasangan TRUE/FALSE", "sqli_probe"),
    ("cors-credentialed", "CORS refleksi Origin + kredensial", "hit = ACAO==Origin & ACAC=true", "deep_probe"),
    ("graphql-introspection", "GraphQL introspection terbuka", "hit = __schema hadir", "deep_probe"),
    ("sast-shell", "shell=True / os.system di kode", "SAST file:line", "code_audit"),
    ("sast-eval", "eval()/exec() pada input", "SAST file:line", "code_audit"),
    ("sast-deserialization", "pickle.loads / yaml.load tanpa Loader", "SAST file:line", "code_audit"),
    ("sast-tls-verify-off", "Verifikasi TLS dimatikan", "SAST file:line", "code_audit"),
    ("hardcoded-secrets", "Kredensial ter-hardcode di repositori", "SAST file:line + redaksi", "secret_scan"),
    ("sast-sql-fstring", "SQL dibangun via f-string/konkatenasi", "SAST file:line", "code_audit"),
    ("sast-dom-write", "innerHTML/dangerouslySetInnerHTML langsung", "SAST file:line", "code_audit"),
    ("admin-weak-cred", "Kredensial lemah diterima (diferensial terverifikasi)", "hit = respons != respons password-salah", "auth_probe"),
    ("route-no-authz", "Rute sensitif identik tanpa sesi", "hit = 200+len identik unauth vs auth", "session_probe"),
    ("dirlisting-sensitive", "Listing direktori sensitif", "definitif: marker Index of /", "dir_probe"),
    ("admin-default-creds", "Kredensial default panel admin", "hit = diferensial + marker panel", "auth_probe"),
    ("subdomain-takeover", "Subdomain takeover terkonfirmasi", "hit = CNAME ke layanan unclaimed + fingerprint", "road:ct_takeover"),
    ("ratelimit-bypass", "Bypass rate-limit API (terautentikasi)", "hit = 429 dihindari via trik header", "road:rate_bypass"),
    ("mass-assignment", "Mass assignment pada API", "hit = field tambahan tersimpan", "road:mass_assign"),
    ("param-pollution-authbypass", "Parameter pollution mem-bypass auth", "hit = dua nilai mengubah keputusan", "road:param_pol"),
]

CRITICAL = [
    ("ssti-verified", "SSTI dual-payload terverifikasi (potensi RCE)", "hit = 49 DAN 998001 muncul, absen di baseline, payload tak ter-echo", "deep_probe"),
    ("sqli-error-confirmed", "SQLi error-based terkonfirmasi", "hit = signature DB error muncul hanya dengan payload", "sqli_probe"),
    ("cmdi-time-confirmed", "Command injection time-based (wajib konfirmasi manual)", "hit = delay >= 2.5s vs baseline", "deep_probe"),
    ("authbypass-algnone", "Bypass autentikasi via alg:none", "hit = tampered 200 vs baseline denied", "session_probe"),
    ("unauth-admin-access", "Akses panel admin tanpa autentikasi", "hit = 200 + marker admin tanpa kredensial", "session_probe"),
    ("unauth-api-data", "Data pengguna via API tanpa kredensial", "hit = 200 + data JSON terproteksi seharusnya", "deep_probe"),
    ("arbitrary-file-read", "Pembacaan file arbitrer terkonfirmasi", "hit = isi /etc/passwd terverifikasi vs baseline", "deep_probe"),
    ("real-account-weak-cred", "Kredensial lemah pada akun produksi nyata", "hit = diferensial + sesi terbentuk", "auth_probe"),
    ("jwt-signature-bypass", "Rantai bypass signature JWT (key confusion)", "hit = token ditempa diverifikasi server", "road:jwt_chain"),
    ("deserialization-rce", "Deserialization -> eksekusi kode", "hit = canary eksekusi terverifikasi", "road:deser_rce"),
    ("upload-webshell", "Upload file -> webshell dieksekusi", "hit = canary dieksekusi server", "road:upload_webshell"),
    ("ssrf-internal-rce", "SSRF sampai kompromi layanan internal", "hit = respons metadata/internal terbaca", "road:ssrf_chain"),
    ("chain-secret-access", "Rantai: secret bocor -> akses internal", "hit = graf chain di world model", "road:chain_secret"),
    ("chain-xss-admin", "Rantai: XSS -> sesi admin", "hit = chain terverifikasi dua akun", "road:chain_xss"),
    ("chain-sqli-data", "Rantai: SQLi -> data sensitif (tanpa eksfiltrasi)", "hit = schema terbaca, contoh 1 baris", "road:chain_sqli"),
    ("prod-admin-default-creds", "Kredensial default panel admin produksi", "hit = login sukses + marker panel", "auth_probe"),
    ("rfi-confirmed", "Remote File Inclusion terkonfirmasi", "hit = canary dieksekusi", "road:rfi"),
    ("git-source-recovery", ".git terekspos sampai sumber penuh pulih", "hit = checkout log tanpa kerusakan", "road:git_recover"),
    ("db-dump-exposed", "Dump database dengan tabel pengguna terekspos", "hit = header tabel user terbaca", "dir_probe"),
    ("dns-takeover", "Domain/subdomain takeover via DNS menggantung", "hit = NXDOMAIN + fingerprint layanan", "road:dns_takeover"),
    ("gql-mutation-unauth", "GraphQL mutation tanpa autentikasi", "hit = mutation dieksekusi (test object)", "road:gql_mutation"),
    ("reset-token-reuse", "Token reset dipakai ulang/fixation", "hit = token lama masih valid", "road:reset_reuse"),
    ("ato-chain", "Rantai pengambilalihan akun penuh", "hit = akses akun kedua via celah terverifikasi", "road:ato_chain"),
    ("payment-bypass", "Bypass pembayaran/logika order", "hit = entitlement tanpa pembayaran di staging", "road:pay_bypass"),
    ("race-double-effect", "Race condition -> efek ganda (opt-in flag)", "hit = dua transisi dari satu event", "road:race"),
]

TIERS = {"low": LOW, "medium": MEDIUM, "high": HIGH, "critical": CRITICAL}
ORDER = ["low", "medium", "high", "critical"]
CVSS = {"low": "0.1 - 3.9", "medium": "4.0 - 6.9", "high": "7.0 - 8.9", "critical": "9.0 - 10.0"}


def _render(tier: str, idx: int, name: str, technique: str, guard: str, engine: str) -> str:
    status = "LIVE" if engine.startswith(("live:",)) or ":" not in engine else "ROADMAP"
    engine_name = engine.replace("live:", "").replace("road:", "")
    return "\n".join([
        f"# [{tier.upper()}-{idx:02d}] {name.replace('-', ' ').title()}",
        "",
        f"> Tingkat: **{tier.upper()}** (estimasi CVSS v3.1: {CVSS[tier]}) | "
        f"Engine: **{engine_name}** ({status})",
        "",
        "## TEKNIK",
        technique + ".",
        "",
        "## FP-GUARD (syarat temuan TRUE)",
        guard + ". Temuan tanpa memenuhi guard ini TIDAK BOLEH dilaporkan.",
        "",
        "## VERIFIKASI",
        "Jalankan engine terkait; temuan dikonfirmasi hanya jika bukti memenuhi FP-guard,",
        "dengan request/response tercatat dan early-stop-on-hit aktif.",
        "",
        f"## SCRIPT/ENGINE",
        f"`cyphron` engine: {engine_name}"
        + (" — siap pakai hari ini." if status == "LIVE"
           else " — slot terdesain; implementasi lewat pipeline yang sama (unit test + FP-guard) sebelum boleh TRUE."),
        "",
        "## CVSS",
        f"Band: {CVSS[tier]} ({tier}).",
    ])


def build(kimchi_dir: Path) -> dict:
    out_root = kimchi_dir / "skills-tiers"
    stats = {}
    for tier in ORDER:
        tdir = out_root / tier
        tdir.mkdir(parents=True, exist_ok=True)
        for i, (name, technique, guard, engine) in enumerate(TIERS[tier], start=1):
            (tdir / f"{tier}-{i:02d}-{name}.md").write_text(
                _render(tier, i, name, technique, guard, engine), encoding="utf-8")
        stats[tier] = len(TIERS[tier])
    index = ["# Cyphron Tier Pack — 100 Skills (25 x 4 severity tiers)", "",
             "Matriks skill serangan/audit per tingkat CVSS. Setiap skill memuat teknik,",
             "FP-GUARD wajib (syarat temuan TRUE), verifikasi, dan pemetaan script/engine.",
             "Engine LIVE bisa dijalankan hari ini; ROADMAP adalah slot terdesain yang", 
             "wajib melewati pipeline test+FP-guard yang sama sebelum boleh melapor.", ""]
    for tier in ORDER:
        index.append(f"## {tier.upper()} — 25 skills (CVSS {CVSS[tier]})")
        for i, (name, technique, _g, engine) in enumerate(TIERS[tier], start=1):
            tag = "LIVE" if "road" not in engine else "ROADMAP"
            index.append(f"- {tier}-{i:02d} [{tag}] {name} -> {engine.replace('road:', '')}")
        index.append("")
    (out_root / "INDEX.md").write_text("\n".join(index), encoding="utf-8")
    return {"root": str(out_root), "stats": stats}
