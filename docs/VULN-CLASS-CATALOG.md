# CYPHRON — KATALOG KELAS KERENTANAN WEB (Low → Critical)
> Referensi teknik untuk penambahan engine/skill. Sumber taksonomi: OWASP
> Top 10 2021 / WSTG, statistik HackerOne (XSS ±35% volume laporan; top
> impactful: XSS, Improper Authentication, Information Disclosure,
> Privilege Escalation, SQLi, Code Injection), dan pelajaran lapangan.
> Status kolom ENGINE: ✅ = sudah ada di registry; ❌ = GAP (kandidat baru).
> Aturan yang berlaku untuk semua: bukti diferensial, cease-on-data,
> bounded & benign, zero-FP (quorum menilai, bukan klaim).

## CRITICAL
| Kelas | CWE | Engine | Catatan deteksi |
|---|---|---|---|
| SQL Injection (dump data) | CWE-89 | ✅ sqli_probe | diferensial payload + marker |
| Command Injection | CWE-78 | ✅ (code_audit statis; runtime ❌) | gap runtime: blind via delay/marker OOB |
| Deserialization → RCE | CWE-502 | ❌ | Java/PHP/Python gadget probe; butuh fingerprint lib dulu |
| File Upload → Webshell | CWE-434 | ❌ | bounded: upload benign polyglot ke endpoint upload akun sendiri; cek eksekusi |
| SSTI → RCE | CWE-1336 | ✅ template_probe | marker matematis diferensial |
| Auth bypass total / default cred | CWE-287 | ✅ auth_probe, authz_bypass | matrix identitas |
| XXE (file read / SSRF) | CWE-611 | ❌ | XML endpoint + OOB callback (pola pingback) |
| SSRF → metadata cloud (kredensial) | CWE-918 | ⚠️ parsial (next_image_proxy, xmlrpc pingback) | GAP: generic ssrf_oob via param URL + webhook capture |
| JWT forgery (none/weak key/kid) | CWE-347 | ✅ jwt_header, jwt_crack | |

## HIGH
| Kelas | CWE | Engine | Catatan |
|---|---|---|---|
| Stored XSS (halaman sensitif) | CWE-79 | ✅ xss_probe, dom_xss | |
| IDOR / BOLA | CWE-639 | ✅ bola, id_seq, authz_bypass | |
| Privilege Escalation | CWE-269 | ✅ priv_matrix | |
| SSRF internal | CWE-918 | ⚠️ parsial → lihat gap ssrf_oob | |
| Password Reset Poisoning (Host header) | CWE-640 | ❌ host_header_probe | reset ke akun sendiri, cek domain link (pola BB-003) |
| Web Cache Poisoning | CWE-444 | ⚠️ cache_dec (deception); poisoning ❌ | header unkeyed + marker OOB |
| Subdomain Takeover | CWE-350 | ✅ takeover | |
| Backup/.git/.env/.env terexpos | CWE-538/540 | ✅ dir_probe, deep_probe | |
| Exposed admin/panel internal | CWE-1236-ish | ✅ liveness_probe + census classify | pelajaran UMS (Keycloak/Gitea/UniFi) |
| Open registration di tool internal | CWE-284 | ✅ register (BARU) | form password+identitas, FP-guard halaman login; field-driven dari gitea UMS |
| Race condition (payment/state) | CWE-367 | ❌ | butuh endpoint transaksional grey-box; last-N same-request |
| CORS misconfig (reflect Origin + cred) | CWE-942 | ✅ cors (BARU) | exact-reflection guard; wildcard tidak dilaporkan |
| Secrets di source/sourcemap | CWE-540/798 | ✅ js_cred_sweep, sourcemap2, secret_scan | |

## MEDIUM
| Kelas | CWE | Engine | Catatan |
|---|---|---|---|
| Reflected XSS | CWE-79 | ✅ xss_probe | |
| CSRF state-changing | CWE-352 | ❌ csrf_probe | cek SameSite + token per-form; butuh akun uji |
| Clickjacking | CWE-1021 | ✅ clickj | terbukti BINUS BB-006 |
| User enumeration (login/reset diff) | CWE-204/200 | ✅ reset_enum (BARU) | field-proven BINUS BB-003; 3 putaran konsisten wajib; email fiktif .invalid |
| No lockout/rate limit | CWE-307 | ✅ lockout | terbukti BINUS BB-005 |
| Verbose debug/error page | CWE-209 | ✅ debug_page | terbukti BINUS BB-003 |
| User enum WP fleet | CWE-200 | ✅ wp_probe, wp_dataexp | terbukti BINUS BB-001 |
| Open redirect | CWE-601 | ✅ redirect_probe | |
| Missing security headers | CWE-693 | ✅ header_policy | |
| Cookie flags (Secure/HttpOnly/SameSite) | CWE-1004 | ✅ cookie_audit | |
| Versi software tua/EOL | CWE-1104 | ✅ (banner di census; sca untuk repo) | inflasi dilarang: banner saja = info |
| Info disclosure (email/PII di koleksi publik) | CWE-359 | ✅ wp_dataexp | terbukti BB-001 |
| TLS: cert kedaluwarsa/hostname mismatch | CWE-295 | ✅ tls_audit (sudah ada!) | handshake-only; pelajaran portal.binus.edu |
| security.txt hilang | — | ✅ security_txt (BARU) | RFC 9116; pelajaran UMS; info→posisi VDP |
| Path traversal (file param) | CWE-22 | ❌ path_traversal | bounded depth, marker file publik (robots.txt dkk) |
| CRLF injection | CWE-93 | ❌ crlf_probe | header split marker |

## LOW
| Kelas | CWE | Engine | Catatan |
|---|---|---|---|
| Directory listing tanpa konten sensitif | CWE-548 | ✅ dir_probe | pelajaran ops.developeracademy = info saja |
| TLS cipher lemah | CWE-326/327 | ❌ masuk tls_audit | |
| Cookie autocomplete / Secure off | CWE-525 | ⚠️ cookie_audit | |
| SPF/DMARC lemah | CWE-— | ✅ email_probe, dkim | terbukti BINUS BB-002 |
| Banner/version disclosure | CWE-200 | ✅ (census) | info |
| Host certificate mismatch | CWE-295 | ❌ masuk tls_audit | |

## ANTREAN ENGINE BERIKUTNYA (urutan prioritas — semua field-driven)
Batch 2026-09-12 (malam): security_txt, cors, register, reset_enum,
**admin_panel** (exposure konsol manajemen — pelajaran UMS), **laravel_panel**
(Telescope/Horizon/Ignition — FP-guard: fingerprint title-tag ketat + no-
redirect, pelajaran GitLab catch-all), **actuator** (Spring env/heapdump,
header-only) — **79 engine, suite 270/270**. Sisa antrean:
1. **host_header_probe** — reset-poisoning & cache-key: Host/X-Forwarded-Host domain kontrol (hanya bila reset flow milik akun sendiri).
7. **path_traversal** — param file/PATH dengan ../../ marker file publik; diferensial content.
8. **ssrf_oob** — param URL-ish + webhook capture (pola BB-004); tanpa OOB = UNCONFIRMED lead.
9. **file_upload_probe** — upload benign polyglot ke fitur upload akun sendiri; cek served-as/executed.
10. **xxe_probe** — XML endpoint + entity OOB/callback; content-blind sampai capture.

## Disiplin implementasi (dari doktrin docs/ROADMAP-CAPABILITIES.md)
Tiap engine baru: research loop (hipotesis→eksperimen→observasi→konfirmasi),
FP-guard eksplisit (marker statis ≠ dinamis, atribusi redirect, filename
lookalike), cease-on-data, redaksi PII, test offline (HTTPServer lokal)
wajib, suite hijau sebelum push.
