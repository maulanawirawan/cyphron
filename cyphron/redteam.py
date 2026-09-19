"""redteam — Red-team pack: katalog tradecraft berotorisasi (Unity U9).

Tiga bagian:

1. MITRE-LITE TAG per engine: taksonomi fase ringan (RECON, INITIAL_ACCESS,
   ..., IMPACT) yang menyatakan "fase ofensif yang disimulasikan engine ini
   pada engagement berotorisasi". Bukan pemetaan teknik ATT&CK penuh —
   cukup untuk coverage matrix dan komunikasi dengan tim biru.
2. COVERAGE MATRIX: fase x engine dari registry aktif — apa yang diuji,
   apa yang tidak (jujur soal lubang cakupan).
3. DETECTION-HINT per temuan + ENGAGEMENT REPORT: setiap temuan dilengkapi
   petunjuk deteksi untuk tim biru (log apa yang harusnya memicu alarm),
   laporan engagement ringkas: scope, fase yang dieksekusi, temuan +
   hints, dan checklist pembersihan (tanpa persistence).

Semua deterministik dari data run (findings.json + audit) — tanpa LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

PHASES = (
    "RECON", "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIV_ESC",
    "DEFENSE_EVASION", "CRED_ACCESS", "DISCOVERY", "LATERAL", "COLLECTION",
    "C2", "EXFIL", "IMPACT",
)

# -------------------------------------------------- tabel MITRE-lite engine
ENGINE_MITRE: dict[str, dict] = {
    # RECON / DISCOVERY pasif
    "http_probe": {"phases": ["RECON"], "hint": "Log akses: GET berulang ke / "
                   "dari satu IP dalam window pendek; UA konsisten scanner."},
    "ct_log": {"phases": ["RECON"], "hint": "CT log publik tidak menyentuh "
               "infra; mitigasi bermakna: kurangi subdomain bocor via sertifikat."},
    "wayback": {"phases": ["RECON"], "hint": "Arsip historis publik; tanggalkan "
                "route lama yang masih hidup dan meta arsip sensitif."},
    "subdomain_brute": {"phases": ["RECON", "DISCOVERY"],
                        "hint": "DNS query volume anomali per resolver; NXDOMAIN "
                        "burst dari satu sumber."},
    "passive_dns": {"phases": ["RECON"], "hint": "Data DNS pasif publik; "
                    "periksa record lama yang mengarah ke host tak terkelola."},
    "email_probe": {"phases": ["RECON"], "hint": "Query TXT SPF/DMARC; perketat "
                    "DMARC p=reject agar spoofing gagal."},
    "dkim_probe": {"phases": ["RECON"], "hint": "Selector DKIM lemah/ganda — "
                   "rotasi kunci dan terbitkan record lengkap."},
    "smtp_probe": {"phases": ["RECON"], "hint": "EHLO ke MX: STARTTLS wajib; "
                   "log koneksi TLS gagal dari IP asing."},
    "github_osint": {"phases": ["RECON", "CRED_ACCESS"],
                     "hint": "Pantau commit publik organisasi dengan secret "
                     "scanning + push protection."},
    "crawler": {"phases": ["DISCOVERY"],
                "hint": "Log akses: crawl pattern (urutan link diikuti "
                "sistematis, robots.txt dibaca dulu)."},
    "browser_engine": {"phases": ["DISCOVERY"],
                       "hint": "UA headless di log akses; blokir/boomerang bila "
                       "tidak diperlukan."},
    "browser_scout": {"phases": ["DISCOVERY", "COLLECTION"],
                      "hint": "Render headless + fetch API internal dari DOM: "
                      "log fetch /api/* yang biasanya hanya dipanggil UI."},
    # INITIAL ACCESS / auth
    "auth_probe": {"phases": ["INITIAL_ACCESS", "CRED_ACCESS"],
                   "hint": "Percobaan login gagal berulang dengan pola akun "
                   "berbeda; alarm pada rasio gagal/sukses."},
    "auth_login": {"phases": ["INITIAL_ACCESS"],
                   "hint": "Login sesi uji: catat IP sumber + waktu di auth log."},
    "lockout": {"phases": ["INITIAL_ACCESS"],
                "hint": "Tidak ada lockout = alarm keamanan ANDA yang mati; "
                "tambahkan rate-limit per akun+IP dan alarm rasio gagal."},
    "register": {"phases": ["INITIAL_ACCESS"],
                 "hint": "Pendaftaran akun uji massal: audit log registrasi "
                 "per IP + verifikasi email."},
    "reset_enum": {"phases": ["INITIAL_ACCESS", "CRED_ACCESS"],
                   "hint": "Respons reset password berbeda utk email ada/tidak: "
                   "samakan respons (user enumeration)."},
    "auth_bypass_matrix": {"phases": ["INITIAL_ACCESS", "DEFENSE_EVASION"],
                           "hint": "403 yang bisa ditembus path-trick: log "
                           "URL anomali (%2e, //, ;) di WAF/reverse proxy."},
    "oauth": {"phases": ["INITIAL_ACCESS"],
              "hint": "state/redirect_uri invalid di log OAuth provider = "
              "percobaan bypass; alarm."},
    "oauth_state_bypass": {"phases": ["INITIAL_ACCESS"],
                           "hint": "CSRF pada callback OAuth: log state kosong/"
                           "replay dan tolak di gateway."},
    "session_probe": {"phases": ["CRED_ACCESS", "PRIV_ESC"],
                      "hint": "Cookie entropy rendah / tamper JWT diterima: "
                      "validasi tanda tangan di middleware, bukan di client."},
    "jwt_jku": {"phases": ["PRIV_ESC", "DEFENSE_EVASION"],
                "hint": "Outbound fetch ke jwk eksternal di auth log = indikasi "
                "jku injection; whitelist keystore."},
    "jwt_crack": {"phases": ["CRED_ACCESS"],
                  "hint": "HMAC lemah: rotasi secret + algoritma asimetris; "
                  "offline crack tidak menyisakan log (deteksi = audit kode)."},
    # DISCOVERY / surface
    "dir_probe": {"phases": ["DISCOVERY"],
                  "hint": "404 burst ke path sensitif (.env/.git/backup): "
                  "rate-limit + tarpit; jangan hanya 404-kan."},
    "deep_probe": {"phases": ["DISCOVERY", "INITIAL_ACCESS"],
                   "hint": "Kombinasi path anomali di access log; WAF learning "
                   "mode harus menandai traversal/SSRF pattern."},
    "sourcemap_probe": {"phases": ["DISCOVERY"],
                        "hint": "Request .map: blokir di produksi; isi "
                        "sourcemap membongkar struktur kode."},
    "sourcemap2": {"phases": ["DISCOVERY", "CRED_ACCESS"],
                   "hint": "Source recovery + secret di sourcemap: blokir *.map, "
                   "audit pipeline build."},
    "js_cred_sweep": {"phases": ["CRED_ACCESS"],
                      "hint": "Kredensial di aset JS publik: rotate SEGERA "
                      "bila ketemu; deteksi = diff bundle CI."},
    "template_probe": {"phases": ["DISCOVERY"],
                       "hint": "Request ke file template/backup: blokir "
                       "ekstensi sensitif di edge."},
    "api_surface_probe": {"phases": ["DISCOVERY"],
                          "hint": "Endpoint API terbuka tanpa dokumentasi: "
                          "inventaris + auth wajib."},
    "api_version_diff": {"phases": ["INITIAL_ACCESS", "PRIV_ESC"],
                         "hint": "v1 terbuka vs v2 terlindungi: matikan "
                         "versi lama, alarm request version-mixing."},
    "method_audit": {"phases": ["DISCOVERY"],
                     "hint": "OPTIONS/TRACE/PUT diaktifkan: matikan method "
                     "tak terpakai di server/gateway."},
    "verb_over": {"phases": ["DEFENSE_EVASION"],
                  "hint": "X-HTTP-Method-Override menembus ACL berbasis "
                  "method: strip header di edge."},
    "ct_conf": {"phases": ["DEFENSE_EVASION"],
                "hint": "Content-type confusion di auth log: validasi "
                "Content-Type ketat di framework."},
    "smuggle": {"phases": ["DEFENSE_EVASION", "LATERAL"],
                "hint": "Timing divergen CL/TE: seragamkan parsing front-back; "
                "deteksi = error log proxy 400/502 anomali."},
    "host_header_poison": {"phases": ["DEFENSE_EVASION", "C2"],
                           "hint": "Link reset memakai host penyerang: kunci "
                           "ALLOWED_HOSTS; deteksi = header Host tak dikenal."},
    "cache_poison": {"phases": ["PERSISTENCE", "DEFENSE_EVASION"],
                     "hint": "Response cache berubah oleh header/query eksotis: "
                     "normalisasi cache-key + alarm cache hit berisi payload."},
    "cache_dec": {"phases": ["CRED_ACCESS"],
                  "hint": "Cache menyimpan respons ter-autentikasi: purge "
                  "cache pada logout; monitor hit pada path .css dinamis."},
    "mq_mgmt": {"phases": ["DISCOVERY", "LATERAL"],
                "hint": "Konsol MQ terekspos: isolasi di management network; "
                "alarm akses ke /mq/ dari DMZ."},
    "actuator": {"phases": ["DISCOVERY", "LATERAL"],
                 "hint": "Spring actuator /env /heapdump: wajib auth + "
                 "network policy; heapdump = kebocoran memori."},
    "admin_panel": {"phases": ["DISCOVERY", "PRIV_ESC"],
                    "hint": "Panel admin terjangkau anonim: wajibkan VPN/"
                    "IP allowlist; alarm GET /admin dari IP luar."},
    "laravel_panel": {"phases": ["DISCOVERY", "PRIV_ESC"],
                      "hint": "telescope/nova/horizon terekspos: blokir route "
                      "debug di produksi."},
    "debug_page": {"phases": ["DISCOVERY", "COLLECTION"],
                   "hint": "Error page verbose (Ignition/Whoops): matikan "
                   "debug di produksi; stack trace = peta kode untuk penyerang."},
    "error_oracle": {"phases": ["DISCOVERY"],
                     "hint": "Pesan error berbeda per input: samakan respons "
                     "error; alarm error-rate naik per endpoint."},
    "server_banner_soft": {"phases": ["RECON"],
                           "hint": "Banner versi di header: hilangkan "
                           "ServerTokens/X-Powered-By."},
    "favicon_hash": {"phases": ["RECON"],
                     "hint": "Hash favicon mengidentifikasi stack: informatif "
                     "bagi recon penyerang; tak ada mitigasi teknis selain "
                     "kesadaran."},
    # exploitation
    "sqli_probe": {"phases": ["INITIAL_ACCESS", "COLLECTION"],
                   "hint": "Pola quote/error di access log + WAF: parameterized "
                   "query; alarm error DB 500 naik."},
    "sqli_extract": {"phases": ["COLLECTION", "EXFIL"],
                     "hint": "Blind SQLi boolean-based: query identik berulang "
                     "dengan param biner — alarm ongkos query anomali."},
    "nosqli_probe": {"phases": ["INITIAL_ACCESS", "COLLECTION"],
                     "hint": "Operator $gt/$ne di payload: validasi tipe ketat "
                     "di layer ORM."},
    "xss_probe": {"phases": ["EXECUTION", "COLLECTION"],
                  "hint": "Marker refleksi tak terenkode: context-aware "
                  "escaping; CSP report-only dulu untuk mapping."},
    "dom_xss": {"phases": ["EXECUTION"],
                "hint": "location.hash menuju sink: audit kode sink DOM; "
                "CSP strict-dynamic mempersempit."},
    "ssti_rce": {"phases": ["EXECUTION", "IMPACT"],
                 "hint": "Aritmetika template {{7*7}} terrefleksi: jangan "
                 "render input user sebagai template."},
    "rce_proof": {"phases": ["EXECUTION", "IMPACT"],
                  "hint": "Marker aritmetika/uniq pada respons = eksekusi: "
                  "isolasi proses, audit fungsi exec/eval/serialize."},
    "cmdi": {"phases": ["EXECUTION", "IMPACT"],
             "hint": "Command separator di param: gunakan API subprocess tanpa "
             "shell; log exec tak terduga via EDR."},
    "traversal": {"phases": ["COLLECTION"],
                  "hint": "../ berulang di param file: normalisasi path + "
                  "chroot/allowlist; alarm 404 dengan ../ di log."},
    "lfi_read": {"phases": ["COLLECTION"],
                 "hint": "Baca /etc/passwd via param: allowlist include; "
                 "open_basedir / container read-only."},
    "xxe_probe": {"phases": ["COLLECTION", "DISCOVERY"],
                  "hint": "ENTITY DOCTYPE diterima parser: matikan external "
                  "entities (disallow-doctype-decl)."},
    "deser_probe": {"phases": ["EXECUTION", "IMPACT"],
                    "hint": "Objek serialisasi tak dipercaya: ganti format "
                    "data (JSON), audit gadget di classpath."},
    "ssrf_oob": {"phases": ["DISCOVERY", "C2"],
                 "hint": "DNS/HTTP keluar dari server ke domain oob: egress "
                 "filtering wajib; log resolusi aneh dari app host."},
    "ssrf_chain": {"phases": ["LATERAL", "C2"],
                   "hint": "SSRF internal -> metadata/cloud API: blokir "
                   "169.254.0.0/16 dari app; IMDSv2 token-required."},
    "redirect_probe": {"phases": ["INITIAL_ACCESS"],
                       "hint": "Open redirect memfasilitasi phishing "
                       "kredibel: allowlist tujuan redirect."},
    "proto_c": {"phases": ["EXECUTION"],
                "hint": "Prototype pollution client: kunci Object.prototype "
                "di bundler; payload __proto__ di log = indikasi."},
    "proto_s": {"phases": ["EXECUTION", "PRIV_ESC"],
                "hint": "Merge JSON rekursif server: validasi kunci "
                "__proto__/constructor sebelum merge."},
    "clobber": {"phases": ["EXECUTION"],
                "hint": "DOM clobbering: sanitasi id/name global; CSP "
                "membantu membatasi dampak."},
    "css_inj": {"phases": ["EXECUTION", "COLLECTION"],
                "hint": "Attribute exfiltration via CSS: CSP style-src "
                "ketat."},
    "jndi_probe": {"phases": ["EXECUTION", "IMPACT"],
                   "hint": "Lookup JNDI keluar: patch log4shell-equivalent; "
                   "egress DNS dari app = alarm."},
    "gql_introspect": {"phases": ["DISCOVERY"],
                       "hint": "Introspection di produksi membongkar skema: "
                       "matikan bila tidak dipakai; alarm __schema query."},
    "graphql_field_suggest": {"phases": ["DISCOVERY"],
                              "hint": "Field suggestion mengizinkan "
                              "enumerasi skema: matikan suggestions."},
    "gql_batch": {"phases": ["DISCOVERY", "IMPACT"],
                  "hint": "Query array berulang: batasi batch size + "
                  "complexity budget."},
    "gql_depth": {"phases": ["IMPACT"],
                  "hint": "Depth/alias 500 = resource exhaustion: depth "
                  "limit di server."},
    "gql_alias": {"phases": ["IMPACT"],
                  "hint": "Alias duplikat memperbanyak query per request: "
                  "batasi alias count."},
    # authz / business
    "bola": {"phases": ["PRIV_ESC", "COLLECTION"],
             "hint": "Akses lintas akun: object-level authorization check; "
             "alarm pola akses objek lintas pemilik."},
    "idor_mass_endpoint": {"phases": ["COLLECTION"],
                           "hint": "Iterasi ID berurutan 200 OK: randomize "
                           "identifier + ownership check."},
    "id_seq": {"phases": ["DISCOVERY"],
               "hint": "ID dapat ditebak: UUID/gap-resistant; alarm "
               "enumerasi pada param id."},
    "authz_bypass": {"phases": ["PRIV_ESC", "DEFENSE_EVASION"],
                     "hint": "Header X-Original-URL menembus ACL: strip "
                     "header tak dikenal di edge; uji ulang ACL."},
    "priv_matrix": {"phases": ["PRIV_ESC"],
                    "hint": "User melihat panel admin: RBAC server-side "
                    "pada route + render; alarm akses role-mismatch."},
    "identity_matrix": {"phases": ["PRIV_ESC", "COLLECTION"],
                        "hint": "Konten identik lintas identitas: cek "
                        "kepemilikan objek di server tiap request."},
    "business_logic": {"phases": ["IMPACT"],
                       "hint": "Transisi ilegal/repeat terminal: tegakkan "
                       "state machine + idempotency-key di server."},
    "mass_assign": {"phases": ["PRIV_ESC"],
                    "hint": "Field role/is_admin diterima dari input: "
                    "allowlist field bindable."},
    "pagin": {"phases": ["COLLECTION"],
              "hint": "limit=10000 diterima: hard-cap page size; alarm "
              "query massal."},
    "sort_inj": {"phases": ["INITIAL_ACCESS", "COLLECTION"],
                 "hint": "Sort/ORDER BY injectable: allowlist kolom sort."},
    # posture lain
    "cors_probe": {"phases": ["DISCOVERY"],
                   "hint": "ACAO reflektif dengan credentials: kunci origin "
                   "allowlist."},
    "cors_wildcard_subdomain": {"phases": ["DEFENSE_EVASION"],
                                "hint": "Wildcard subdomain di CORS: kejahatan "
                                "takeover subdomain = bypass CORS."},
    "csp_analyzer": {"phases": ["DEFENSE_EVASION"],
                     "hint": "CSP permissive (unsafe-inline): strict-dynamic "
                     "+ nonce."},
    "cookie_scope": {"phases": ["CRED_ACCESS"],
                     "hint": "Cookie tanpa HttpOnly/Secure/SameSite: set "
                     "atribut penuh; alarm cookie session baru tanpa flag."},
    "cookie_prefix_insecure": {"phases": ["CRED_ACCESS"],
                               "hint": "Prefix __Host-/__Secure- melanggar "
                               "syarat: patuhi RFC agar browser memaksa secure."},
    "cookie_prefix": {"phases": ["CRED_ACCESS"],
                      "hint": "Prefix __Host-/__Secure- melanggar syarat: "
                      "patuhi RFC agar browser memaksa secure."},
    "tls_audit": {"phases": ["DISCOVERY"],
                  "hint": "TLS lama/sertifikat lemah: enforce TLS1.2+ dan "
                  "HSTS; monitor report expiring certs."},
    "tls_mismatch_leak": {"phases": ["RECON"],
                          "hint": "CT log menyingkap hostname internal: "
                          "jangan terbitkan sertifikat untuk host internal."},
    "hsts_short_maxage": {"phases": ["DEFENSE_EVASION"],
                          "hint": "max-age HSTS pendek: naikkan ke >= 31536000 "
                          "+ preload."},
    "clickj": {"phases": ["EXECUTION"],
               "hint": "Framing tanpa X-Frame-Options: set frame-ancestors "
               "'none' pada halaman beraksi."},
    "wp_probe": {"phases": ["DISCOVERY", "INITIAL_ACCESS"],
                 "hint": "REST /wp/v2/users membocorkan login: blokir "
                 "enumerasi user; xmlrpc dibatasi."},
    "wp_dataexp": {"phases": ["COLLECTION"],
                   "hint": "Comments/media membocorkan PII: batasi REST "
                   "media/comments untuk anonim."},
    "xmlrpc_probe": {"phases": ["INITIAL_ACCESS", "IMPACT"],
                     "hint": "system.multicall = amplifikasi brute force: "
                     "matikan xmlrpc bila tidak dipakai."},
    "llm_probe": {"phases": ["EXECUTION", "IMPACT"],
                  "hint": "Endpoint AI menerima instruksi bermusuhan: "
                  "policy layer + output filter; log prompt tak wajar."},
    "takeover": {"phases": ["PERSISTENCE", "DEFENSE_EVASION"],
                 "hint": "CNAME dangling = persistence bagi penyerang: "
                 "hapus DNS yatim; alarm CNAME ke service mati."},
    "cloud_bucket_probe": {"phases": ["COLLECTION", "DISCOVERY"],
                           "hint": "Bucket publik listable: matikan ACL "
                           "publik; alarm ListObjects anonim."},
    "rate_limit_graceful": {"phases": ["DISCOVERY"],
                            "hint": "429 dengan sisa-quota bocor: "
                            "generikkan pesan rate-limit."},
    "archive_diff": {"phases": ["RECON"],
                     "hint": "Route historis hidup lagi: tanggalkan "
                     "arsip usang."},
    "username_osint": {"phases": ["RECON"],
                     "hint": "permukaan profil publik: periksa akun " 
                     "resmi brand utk antisipasi impersonasi."},
    "ip_intel": {"phases": ["RECON"],
                 "hint": "konteks geo/ASN pasif utk dossier; " 
                 "bukan bukti identitas."},
    "email_intel": {"phases": ["RECON"],
                    "hint": "header email menunjukkan impersonasi/"
                            "spoofing: karantina sejenis + verifikasi "
                            "kanal kedua."},
    "robots_sensitive_entry": {"phases": ["RECON"],
                               "hint": "robots.txt memuat path rahasia: "
                               "hapus entri sensitif (bukan disallow)."},
    "security_txt": {"phases": ["RECON"],
                     "hint": "security.txt membantu pelaporan: sediakan "
                     "kontak + policy."},
    "security_txt_quality": {"phases": ["RECON"],
                             "hint": "security.txt usang/kosong: jaga "
                             "record tetap hidup."},
    "sri_subresource": {"phases": ["DEFENSE_EVASION"],
                        "hint": "Skrip pihak ketiga tanpa SRI: tambah "
                        "integrity hash + CSP script-src allowlist."},
    "security_headers": {"phases": ["DEFENSE_EVASION"],
                         "hint": "Header keamanan hilang: set baseline "
                         "di edge (CSP/HSTS/XFO/RP/Referrer-Policy)."},
    "header_reflection": {"phases": ["EXECUTION"],
                          "hint": "Header terrefleksi ke body: encode "
                          "output; alarm respons berisi payload header."},
    "cache_control_missing": {"phases": ["COLLECTION"],
                              "hint": "Respons sensitif tanpa no-store: "
                              "set Cache-Control di proxy + app."},
    "referrer_policy_loose": {"phases": ["CRED_ACCESS"],
                              "hint": "URL internal bocor lewat Referer: "
                              "strict-origin-when-cross-origin."},
    "email_pattern": {"phases": ["RECON"],
                      "hint": "Pola email tebakable: konsisten + dmarc "
                      "reject; alarm mailing massal gagal."},
    "liveness_probe": {"phases": ["DISCOVERY"],
                       "hint": "Host stale menjalankan aplikasi lama: "
                       "lepas dari DNS/matikan — permukaan yatim."},
    "load_probe": {"phases": ["IMPACT"],
                   "hint": "Resilience test terjadwal bounded: alarm ongkos "
                   "rps tanpa berkas otorisasi (semua load test wajib berizin)."},
    "code_audit": {"phases": ["DISCOVERY"],
                   "hint": "SAST: temuan di kode = patch di CI; blokir "
                   "merge bila critical baru."},
    "sca_probe": {"phases": ["DISCOVERY"],
                  "hint": "Dependensi rentan: patch + SBOM; alarm CVE "
                  "baru pada manifest."},
    "secret_scan": {"phases": ["CRED_ACCESS"],
                    "hint": "Secret di repo: rotate + history purge; "
                    "push protection wajib."},
    "apk_surface_probe": {"phases": ["DISCOVERY", "RECON"],
                          "hint": "APK membocorkan endpoint/secret: "
                          "obfuscation + jangan hardcode; alarm API tanpa "
                          "attestation."},
    "fingerprint_to_cpe": {"phases": ["RECON"],
                           "hint": "Fingerprint akurat membantu penyerang "
                           "memilih CVE: minimalkan banner versi."},
    "cve_matcher": {"phases": ["RECON", "DISCOVERY"],
                    "hint": "CVE exposure = prioritas patch; alarm "
                    "versi rentan di CMDB."},
    "edb_reference": {"phases": ["RECON"],
                      "hint": "Exploit publik tersedia = patch SEGERA; "
                      "monitor referensi baru."},
    "nuclei_bridge": {"phases": ["INITIAL_ACCESS", "DISCOVERY"],
                      "hint": "Template komunitas di access log: UA "
                      "scanner dikenali; hanya jalankan subset aman."},
    "exploitability": {"phases": ["IMPACT"],
                       "hint": "Primitive tanpa CSP = eksploit nyata: "
                       "perbaiki header + sink bersamaan."},
    "param_miner": {"phases": ["DISCOVERY"],
                    "hint": "Param hidden terdeteksi via diff: dokumentasikan "
                    "param internal + hapus debug param."},
    "fuzz_engine": {"phases": ["DISCOVERY", "EXECUTION"],
                    "hint": "Payload diferensial di log: respons 500 massal "
                    "= fuzzer aktif; tangani error dengan rapi."},
    "drift": {"phases": ["RECON"],
              "hint": "Perubahan permukaan tiba-tiba: inventory + alarm "
              "endpoint baru di produksi."},
}

# fallback heuristik utk engine yang belum terdaftar di tabel
_FALLBACK_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("wp", ("DISCOVERY", "INITIAL_ACCESS")),
    ("jwt", ("CRED_ACCESS", "PRIV_ESC")),
    ("ssrf", ("DISCOVERY", "C2")),
    ("sqli", ("INITIAL_ACCESS", "COLLECTION")),
    ("xss", ("EXECUTION",)),
    ("redirect", ("INITIAL_ACCESS",)),
    ("traversal", ("COLLECTION",)),
    ("lfi", ("COLLECTION",)),
    ("rce", ("EXECUTION", "IMPACT")),
    ("ssti", ("EXECUTION", "IMPACT")),
    ("deser", ("EXECUTION",)),
    ("xxe", ("COLLECTION",)),
    ("cors", ("DISCOVERY",)),
    ("cookie", ("CRED_ACCESS",)),
    ("tls", ("DISCOVERY",)),
    ("oauth", ("INITIAL_ACCESS",)),
    ("admin", ("DISCOVERY", "PRIV_ESC")),
    ("idor", ("COLLECTION", "PRIV_ESC")),
    ("authz", ("PRIV_ESC",)),
    ("priv", ("PRIV_ESC",)),
    ("bola", ("PRIV_ESC", "COLLECTION")),
    ("session", ("CRED_ACCESS",)),
    ("secret", ("CRED_ACCESS",)),
    ("sca", ("DISCOVERY",)),
    ("apk", ("DISCOVERY",)),
    ("gql", ("DISCOVERY", "IMPACT")),
    ("cache", ("PERSISTENCE", "DEFENSE_EVASION")),
    ("header", ("DEFENSE_EVASION",)),
    ("hsts", ("DEFENSE_EVASION",)),
    ("email", ("RECON",)),
    ("dns", ("RECON",)),
    ("subdomain", ("RECON",)),
    ("probe", ("DISCOVERY",)),
    ("audit", ("DISCOVERY",)),
    ("matrix", ("PRIV_ESC",)),
    ("load", ("IMPACT",)),
)


def phases_for(engine: str) -> list[str]:
    ent = ENGINE_MITRE.get(engine)
    if ent:
        return list(ent["phases"])
    name = engine.lower()
    for key, phases in _FALLBACK_RULES:
        if key in name:
            return list(phases)
    return ["DISCOVERY"]


def hint_for(engine: str) -> str:
    ent = ENGINE_MITRE.get(engine)
    if ent and ent.get("hint"):
        return ent["hint"]
    return ("Deteksi generik: anomali access log (frekuensi, urutan, payload "
            "khas) dari engine ini; tinjau audit.jsonl untuk pola request.")


# --------------------------------------------------------- coverage matrix
def coverage_matrix(engine_names: list[str]) -> dict:
    """fase -> engine tercakup + fase tanpa cakupan (jujur soal gap)."""
    matrix: dict[str, list[str]] = {p: [] for p in PHASES}
    for name in sorted(engine_names):
        for phase in phases_for(name):
            if phase in matrix:
                matrix[phase].append(name)
    gaps = sorted(p for p, v in matrix.items() if not v)
    return {"coverage": matrix, "uncovered_phases": gaps,
            "engines": len(engine_names),
            "tagged": sum(1 for e in engine_names if e in ENGINE_MITRE)}


def detection_hints(findings: list[dict]) -> list[dict]:
    """Deteksi-hint per temuan utk tim biru (dari tool penemunya)."""
    out = []
    seen: set[str] = set()
    for f in findings or []:
        tool = str(f.get("tool", ""))
        key = str(f.get("id") or f.get("title") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "finding_id": key,
            "title": str(f.get("title", "")),
            "tool": tool,
            "phases": phases_for(tool),
            "hint": hint_for(tool),
        })
    return out


# ------------------------------------------------------- engagement report
def engagement_report(scan_dir: Path) -> dict:
    """Susun laporan engagement (markdown) dari folder hasil scan."""
    data = json.loads((Path(scan_dir) / "findings.json").read_text(
        encoding="utf-8"))
    confirmed = data.get("confirmed", [])
    unconfirmed = data.get("unconfirmed", [])
    world = data.get("world", {})
    executed = sorted({
        e.get("tool") for e in _read_audit(scan_dir)
        if e.get("kind") == "tool-run" and e.get("tool")})
    matrix = coverage_matrix(executed)
    hints = detection_hints(confirmed + unconfirmed)
    md: list[str] = [
        "# Engagement Report (red-team berotorisasi)", "",
        f"**Target**: {data.get('target', '-')}  ",
        f"**Mode**: {data.get('mode', '-')}  ",
        f"**Otorisasi**: {data.get('authorization') or 'tidak ada (read-only)'}  ",
        f"**Langkah**: {data.get('steps', 0)} | request: "
        f"{world.get('request_count', 0)}", "",
        "## 1. Fase yang dieksekusi (coverage)",
        ""]
    for phase in PHASES:
        engines = matrix["coverage"][phase]
        md.append(f"- **{phase}**: "
                  + (", ".join(engines) if engines else "_tidak diuji run ini_"))
    md += ["", f"Fase tanpa cakupan: "
           + (", ".join(matrix["uncovered_phases"]) or "-")
           + f" ({matrix['tagged']}/{matrix['engines']} engine ter-tag "
           "MITRE-lite eksplisit)", "",
           "## 2. Temuan + deteksi-hint (untuk tim biru)", ""]
    if hints:
        md.append("| Temuan | Engine | Fase | Deteksi-hint |")
        md.append("|---|---|---|---|")
        for h in hints:
            md.append(f"| {h['title']} | {h['tool']} | "
                      f"{', '.join(h['phases'])} | {h['hint']} |")
    else:
        md.append("_Tidak ada temuan pada run ini._")
    md += ["", "## 3. Checklist pembersihan engagement", "",
           "- [ ] Tidak ada persistence: akun uji dihapus, file uji dihapus",
           "- [ ] Tidak ada data target yang disalin keluar (redaksi tetap)",
           "- [ ] Sesi/cookie uji dicabut; kredensial disposable dinonaktifkan",
           "- [ ] Audit tamper-evident diserahkan bersama laporan",
           "- [ ] Eksekusi limited pada jendela waktu otorisasi", ""]
    return {"markdown": "\n".join(md),
            "matrix": matrix, "hints": hints,
            "executed_engines": executed}


def _read_audit(scan_dir: Path) -> list[dict]:
    p = Path(scan_dir) / "audit.jsonl"
    rows: list[dict] = []
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows
