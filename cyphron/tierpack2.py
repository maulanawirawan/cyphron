"""tierpack2 — 120 skill BARU (30 x 4 severity tier), teknik yang BELUM ada di
pack pertama. Mengadopsi pelajaran repo populer: frontmatter ringkas (30-token
scan) + body on-demand + FP-guard wajib + framework tag. Format file:
frontmatter YAML mini lalu metodologi ringkas."""

from __future__ import annotations

from pathlib import Path

from .tierpack import CVSS

# (name, technique, fp_guard, engine)  — engine "live:" = jalan hari ini
NEW_LOW = [
    ("favicon-fingerprint", "Fingerprint via hash favicon (identifikasi stack)", "hash dihitung deterministik", "live:crawler"),
    ("wayback-diff", "Bandingkan rute historis vs sekarang (rute hilang = lead)", "hit = rute lama 404 kini", "road:wayback"),
    ("sourcemap-exposure", "File .map terbuka (source asli bocor)", "hit = 200 + JSON sourceMap valid", "live:dir_probe"),
    ("js-secret-extraction", "Kunci/endpoint ter-hardcode di bundle JS", "hit = pola kunci di JS publik", "live:crawler"),
    ("csp-report-uri-wrong", "Report-uri CSP mengarah keluar/mati", "hit = domain report tak dikenal", "live:security_headers"),
    ("hsts-short-age", "HSTS ada tapi max-age terlalu pendek", "definitif: parse max-age < 15552000", "live:security_headers"),
    ("cookie-secure-prefix", "Cookie __Secure- tanpa flag Secure", "definitif: nama vs atribut", "live:security_headers"),
    ("cert-san-audit", "SAN sertifikat memuat nama internal", "definitif: decode SAN", "live:tls_audit"),
    ("cert-chain-incomplete", "Rantai sertifikat tidak lengkap", "hit = verify warning", "live:tls_audit"),
    ("ocsp-stapling-absent", "OCSP stapling tidak aktif", "hit = stapled None", "live:tls_audit"),
    ("svn-hg-exposed", ".svn/.hg metadata terbuka", "definitif: marker format", "live:dir_probe"),
    ("ide-files-exposed", ".idea/.vscode terekspos", "definitif: 200 + marker", "live:dir_probe"),
    ("backup-archive-7z", "Arsip .7z/.rar terekspos", "definitif: 200 + magic byte", "live:dir_probe"),
    ("registry-hints", " jejak container registry di halaman", "hit = referensi registry", "live:crawler"),
    ("ci-badge-leak", "Badge CI membocorkan pipeline internal", "hit = URL badge internal", "live:crawler"),
    ("admin-email-pattern", "Pola email admin terdeduksi dari halaman", "hit = regex email peran", "live:crawler"),
    ("sequential-user-id", "ID pengguna terlihat sekuensial", "hit = dua id beda 1", "road:id_seq"),
    ("response-time-fingerprint", "Fingerprint stack dari pola waktu respons", "statistik multi-request", "live:load_probe"),
    ("private-ip-leak", "IP privat bocor di header/body", "definitif: regex RFC1918", "live:deep_probe"),
    ("localhost-url-leak", "URL localhost bocor di produksi", "definitif: regex localhost", "live:deep_probe"),
    ("home-path-leak", "Path home OS bocor (/home/x, C:\\Users)", "definitif: regex path", "live:deep_probe"),
    ("internal-hostname-leak", "Hostname internal bocor", "definitif: pola hostname", "live:deep_probe"),
    ("altsvc-port-disclosure", "alt-svc/link membocorkan port layanan", "definitif: header alt-svc", "live:security_headers"),
    ("draft-env-exposed", "Draft/preview environment terindeks", "hit = 200 + marker draft", "live:dir_probe"),
    ("nuxt-meta-leak", "Metadata framework Nuxt/Vite bocor versi", "definitif: marker build", "live:crawler"),
    ("git-branch-names", "Nama branch bocor via .git/HEAD", "definitif: isi ref", "live:dir_probe"),
    ("npm-audit-summary", "Ringkasan audit dependensi terekspos", "hit = 200 + marker audit", "live:dir_probe"),
    ("cors-preflight-wide", "Preflight mengizinkan method berbahaya", "definitif: Allow-Methods", "live:deep_probe"),
    ("subdomain-ct-audit", "Sertifikat CT membocorkan nama subdomain", "hit = CT log entry", "road:ct_log"),
    ("mx-provider-map", "Provider email terpetakan dari MX", "definitif: MX record", "live:email_probe"),
]

NEW_MEDIUM = [
    ("smuggling-clue", "Ketidakselarasan CL/TE (detektor aman)", "hit = divergensi timeout terkontrol", "road:smuggle"),
    ("cache-deception", "Web cache deception (path .js pada data akun)", "hit = cache menyimpan respons akun", "road:cache_dec"),
    ("oauth-state-missing", "State OAuth tidak divalidasi (CSRF login)", "hit = login tanpa state tetap sukses", "road:oauth"),
    ("oauth-redirect-lax", "redirect_uri tidak ketat", "hit = subdomain/path diterima", "road:oauth"),
    ("oidc-nonce-missing", "Nonce OIDC tidak divalidasi", "hit = replay id_token sukses", "road:oauth"),
    ("session-puzzling", "Kebingungan tipe sesi (string vs array)", "hit = auth lolos via tipe", "road:puzzle"),
    ("json-injection", "Injeksi JSON ke body terstruktur", "hit = struktur berubah terverifikasi", "road:json_inj"),
    ("content-type-confusion", "Endpoint menerima content-type tak sesuai", "hit = respons berubah", "road:ct_conf"),
    ("verb-override", "X-HTTP-Method-Override dilewati tanpa cek", "hit = DELETE via override dijalankan", "road:verb_over"),
    ("csp-unsafe-eval", "CSP mengizinkan unsafe-eval", "definitif: parse policy", "live:security_headers"),
    ("csp-frame-src-missing", "frame-src tidak dibatasi", "definitif: parse policy", "live:security_headers"),
    ("dns-caa-missing", "CAA tidak dipublikasikan", "fakta DNS", "live:email_probe"),
    ("bimi-missing", "BIMI tidak dipublikasikan (brand protection)", "fakta DNS", "live:email_probe"),
    ("smtp-starttls-missing", "SMTP tanpa STARTTLS", "hit = EHLO tanpa STARTTLS", "road:smtp_probe"),
    ("dkim-weak-key", "Kunci DKIM < 1024 bit", "definitif: panjang kunci publik", "road:dkim_probe"),
    ("api-version-downgrade", "Versi API lama auth-nya lebih longgar", "hit = v1 200 vs v2 401 data sama", "road:api_ver"),
    ("graphql-batching", "Batching/array query untuk bypass rate-limit", "hit = N query dalam 1 request", "road:gql_batch"),
    ("graphql-depth-unbounded", "Depth/cost query tak dibatasi", "hit = deep query sukses", "road:gql_depth"),
    ("rest-aliasing", "Aliasing menduplikasi data sensitif dalam 1 request", "hit = field ganda terbaca", "road:gql_alias"),
    ("pagination-unbounded", "limit/first tak dibatasi (dump massal)", "hit = limit 10000 diterima", "road:pagin"),
    ("sort-filter-injection", "Injeksi pada sort/filter ORM", "hit = error/urutan berubah", "road:sort_inj"),
    ("jwt-jku-injection", "Header jku diambil dari URL penyerang", "hit = token ditempa valid", "road:jwt_jku"),
    ("jwt-x5u-injection", "Header x5u diambil dari URL penyerang", "hit = token ditempa valid", "road:jwt_x5u"),
    ("jwt-weak-hmac", "Secret HMAC JWT lemah (wordlist kecil)", "hit = signature cocok wordlist", "road:jwt_crack"),
    ("ws-origin-bypass", "WebSocket menerima origin arbitrer", "hit = handshake origin asing sukses", "road:ws_probe"),
    ("postmessage-wildcard", "postMessage target '*' dengan data sensitif", "definitif: di source JS", "live:crawler"),
    ("proto-pollution-client", "Prototype pollution via query (__proto__)", "hit = objek global berubah di DOM", "road:proto_c"),
    ("proto-pollution-server", "Prototype pollution server-side (merge)", "hit = status berubah via __proto__", "road:proto_s"),
    ("dom-clobbering", "DOM clobbering menimpa variabel", "hit = named element menimpa JS", "road:clobber"),
    ("css-injection", "CSS injection mengekstrak nilai atribut", "hit = callback CSS terpicu", "road:css_inj"),
]

NEW_HIGH = [
    ("idor-seq-probe", "IDOR sekuensial pada objek milik sendiri", "hit = objek lain terbaca (auth sama)", "road:idor_seq"),
    ("bola-object-probe", "BOLA pada endpoint terautentikasi", "hit = objek tenant lain terbaca", "road:bola"),
    ("privilege-matrix", "Matriks peran vs rute admin (low-priv access)", "hit = 200 + marker admin", "road:priv_matrix"),
    ("oauth-token-replay", "Token OAuth diputar ulang lintas flow", "hit = token lama masih valid", "road:oauth_replay"),
    ("oauth-code-intercept", "Kode otorisasi terpakai ulang", "hit = code dipakai 2x sukses", "road:oauth_code"),
    ("ws-unauth-message", "Pesan WebSocket tanpa auth diproses", "hit = server jawab data", "road:ws_probe"),
    ("proto-pollution-auth", "Prototype pollution mengubah flag auth", "hit = isAdmin true", "road:proto_auth"),
    ("css-exfiltration", "CSS injection mengekstrak token CSRF", "hit = request exfil tercatat", "road:css_exfil"),
    ("cache-key-normalization", "Normalisasi key cache membuat lintas-user", "hit = cache user A dibaca user B", "road:cache_key"),
    ("cache-poisoning-unkeyed", "Header unkeyed terpantul dan ter-cache", "hit = cache menyimpan versi beracun", "road:cache_poison"),
    ("smuggle-confirmed", "Request smuggling terkonfirmasi (dua arah)", "hit = front/back-end berbeda interpretasi", "road:smuggle2"),
    ("h2-rapid-reset-signal", "Signal rapid reset HTTP/2 (bounded)", "hit = reset storm terlihat", "road:h2_rr"),
    ("dns-rebinding-confirmed", "DNS rebinding terkonfirmasi (pin gagal)", "hit = private IP tercapai", "road:rebind2"),
    ("imds-v1-reachable", "IMDSv1 reachable via SSRF", "hit = kredensial metadata terbaca", "road:imds"),
    ("grpc-reflection", "gRPC reflection terbuka", "hit = daftar service terbaca", "road:grpc"),
    ("mq-mgmt-exposed", "Konsol RabbitMQ/Kafka mgmt terbuka", "hit = 200 + marker panel", "dir_probe"),
    ("sourcemap-full-recover", "Source penuh pulih dari .map", "hit = source asli terbaca", "road:sourcemap2"),
    ("map-secrets", ".map memuat kredensial", "hit = pola kunci di sources", "road:sourcemap2"),
    ("dom-xss-sink", "DOM XSS (sink client-side)", "hit = sink dieksekusi di browser", "road:dom_xss"),
    ("csp-bypass-trusted", "Bypass CSP via domain trusted (cdn abuse)", "hit = payload lewat domain allowlist", "road:csp_bypass"),
    ("clickjacking-action", "Clickjacking pada aksi sensitif", "hit = frame-ancestors longgar + aksi", "road:clickj"),
    ("reset-poisoning-xfh", "Poisoning link reset via X-Forwarded-Host", "hit = email/link memuat host penyerang", "road:reset_poison"),
    ("reset-token-url", "Token reset terkirim via URL query (leak ke log)", "definitif: dari source/policy", "road:reset_url"),
    ("2fa-missing-sensitive", "Operasi sensitif tanpa 2FA", "hit = aksi sukses tanpa OTP", "road:2fa"),
    ("otp-brute-bounded", "OTP brute-force terbatas (5 percobaan)", "hit = tidak ada 429 dalam 5", "road:otp_brute"),
    ("invite-abuse", "Kode invite dapat ditebak/loop", "hit = invite dibuat massal", "road:invite"),
    ("price-tamper-staging", "Manipulasi harga di staging", "hit = order sukses harga diubah", "road:price_t"),
    ("tenant-cross-two-acct", "Lintas tenant dengan dua akun", "hit = A baca data B", "road:tenant2"),
    ("admin-impersonate-massassign", "Impersonasi admin via mass-assignment", "hit = role berubah via PATCH", "road:massassign2"),
    ("sqli-os-file", "SQLi membaca file (os_file/LOAD_FILE)", "hit = isi file di respons", "road:sqli_file"),
]

NEW_CRITICAL = [
    ("ssrf-metadata-creds", "SSRF -> kredensial cloud metadata", "hit = AccessKeyId terbaca", "road:imds2"),
    ("smuggle-hijack", "Smuggling -> pembajakan sesi tetangga", "hit = sesi korban tercapta", "road:smuggle3"),
    ("sqli-stacked", "Stacked queries dieksekusi (dengan izin)", "hit = perubahan state test", "road:sqli_stack"),
    ("jndi-rce-probe", "JNDI lookup (log4j-class) canary", "hit = canary DNS terpicu", "road:jndi"),
    ("xxe-oob", "XXE out-of-band ke listener sendiri", "hit = file direspons/listener terpicu", "road:xxe_oob"),
    ("deserialization-rce-confirmed", "Deserialization RCE terkonfirmasi (canary)", "hit = perintah canary jalan", "road:deser2"),
    ("ssti-full-rce", "SSTI sampai eksekusi perintah (canary echo)", "hit = output canary", "road:ssti_rce"),
    ("webshell-confirmed", "Webshell terpasang & mengeksekusi", "hit = respons canary", "road:webshell"),
    ("container-escape-signals", "Container privileged/cap-add berisiko", "audit compose/runtime", "road:container"),
    ("k8s-api-unauth", "Kubernetes API tanpa auth", "hit = API 200 + node list", "road:k8s"),
    ("cloud-iam-wildcard", "IAM policy wildcard Action/Resource", "definitif: parse policy", "road:iam"),
    ("public-bucket-named", "Bucket publik dengan nama target", "hit = listing anonim", "road:bucket"),
    ("git-history-secrets", "Riwayat git memuat kredensial lama", "hit = secret di commit lama", "road:git_hist"),
    ("ci-secrets-exposed", "Log CI memuat secret", "hit = pola secret di log", "road:ci_log"),
    ("takeover-payload-confirmed", "Takeover dengan konten terpasang", "hit = halaman canary di subdomain", "road:takeover2"),
    ("oauth-account-takeover", "Pengambilalihan akun via OAuth flow", "hit = login sebagai korban", "road:oat"),
    ("jwt-kid-traversal", "kid traversal membaca kunci terkontrol", "hit = token valid dengan kid file", "road:jwt_kid"),
    ("jwk-header-injection", "JWK injection diterima", "hit = token ditempa valid", "road:jwt_jwk2"),
    ("rs256-hs256-confusion", "Confusion RS256->HS256 (kunci publik sbg HMAC)", "hit = token ditempa valid", "road:alg_conf"),
    ("reset-takeover-chain", "Rantai takeover via reset poisoning + host header", "hit = reset akun korban", "road:reset_chain"),
    ("2fa-bypass-response", "Bypass 2FA via manipulasi respons", "hit = status sukses tanpa OTP", "road:2fa_bypass"),
    ("otp-brute-full", "OTP ditebak penuh (staging, berizin)", "hit = OTP terverifikasi", "road:otp2"),
    ("tenant-cross-critical", "Lintas tenant kritis (data B utuh dibaca)", "hit = data B direspons ke A", "road:tenant3"),
    ("admin-impersonation-live", "Impersonasi admin di produksi (berizin)", "hit = panel admin peran rendah", "road:impersonate"),
    ("sqli-file-read-confirmed", "SQLi membaca file server terkonfirmasi", "hit = isi file vs baseline", "road:sqli_file2"),
    ("ssti-rce-confirmed", "SSTI RCE penuh terkonfirmasi (canary)", "hit = output perintah canary", "road:ssti_rce2"),
    ("webshell-live", "Webshell hidup di server produksi", "hit = canary dieksekusi", "road:webshell2"),
    ("supply-chain-install-abuse", "Skrip instal paket melakukan eksekusi", "audit manifest + lock", "road:supply"),
    ("historic-breach-reuse", "Kredensial kebocoran historis dipakai ulang", "hit = combo list cocok (staging)", "road:combo"),
    ("zero-day-hunt-fuzz", "Zero-day di sistem sendiri: fuzzing differential", "hit = crash/anomali direproduksi", "road:fuzzer"),
]

NEW_TIERS = {"low": NEW_LOW, "medium": NEW_MEDIUM, "high": NEW_HIGH, "critical": NEW_CRITICAL}


def build2(kimchi_dir: Path) -> dict:
    from .tierpack import _render
    out_root = kimchi_dir / "skills-tiers2"
    stats = {}
    for tier, rows in NEW_TIERS.items():
        tdir = out_root / tier
        tdir.mkdir(parents=True, exist_ok=True)
        for i, (name, technique, guard, engine) in enumerate(rows, start=1):
            (tdir / f"{tier}-{i:02d}-{name}.md").write_text(
                _render(tier, i, name, technique, guard, engine), encoding="utf-8")
        stats[tier] = len(rows)
    live = sum(1 for rows in NEW_TIERS.values() for r in rows if r[3].startswith("live"))
    index = ["# Cyphron Tier Pack 2 — 120 Skill BARU (30 x 4 tier)", "",
             "Semua teknik ini TIDAK ada di pack pertama maupun di 74 skill inti.",
             "FP-guard wajib per skill; engine live = jalan hari ini, road = slot terdesain.", "",
             f"Coverage: {live} LIVE / {sum(stats.values()) - live} ROADMAP (terdesain, wajib lewat pipeline test+FP-guard)", ""]
    for tier, rows in NEW_TIERS.items():
        index.append(f"## {tier.upper()} — {len(rows)} skills (CVSS {CVSS[tier]})")
        for i, (name, _t, _g, engine) in enumerate(rows, start=1):
            tag = "LIVE" if engine.startswith("live") else "ROADMAP"
            index.append(f"- {tier}-{i:02d} [{tag}] {name} -> {engine.replace('live:', '').replace('road:', '')}")
        index.append("")
    (out_root / "INDEX.md").write_text("\n".join(index), encoding="utf-8")
    return {"root": str(out_root), "stats": stats, "live": live}
