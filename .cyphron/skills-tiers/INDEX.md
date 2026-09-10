# Cyphron Tier Pack — 100 Skills (25 x 4 severity tiers)

Matriks skill serangan/audit per tingkat CVSS. Setiap skill memuat teknik,
FP-GUARD wajib (syarat temuan TRUE), verifikasi, dan pemetaan script/engine.
Engine LIVE bisa dijalankan hari ini; ROADMAP adalah slot terdesain yang
wajib melewati pipeline test+FP-guard yang sama sebelum boleh melapor.

## LOW — 25 skills (CVSS 0.1 - 3.9)
- low-01 [LIVE] robots-disclosure -> crawler
- low-02 [LIVE] sitemap-paths -> crawler
- low-03 [LIVE] securitytxt-missing -> crawler
- low-04 [LIVE] humans-changelog -> dir_probe
- low-05 [LIVE] readme-exposed -> dir_probe
- low-06 [LIVE] packagejson-deps -> dir_probe
- low-07 [LIVE] server-header -> http_probe
- low-08 [LIVE] generator-meta -> http_probe
- low-09 [LIVE] referrer-policy -> security_headers
- low-10 [LIVE] permissions-policy -> security_headers
- low-11 [LIVE] xcto-missing -> security_headers
- low-12 [LIVE] xfo-missing -> security_headers
- low-13 [LIVE] cookie-httponly -> security_headers
- low-14 [LIVE] cookie-samesite -> security_headers
- low-15 [LIVE] open-registration -> auth_probe
- low-16 [LIVE] login-discovery -> auth_probe
- low-17 [LIVE] options-allow -> method_audit
- low-18 [LIVE] html-comments -> crawler
- low-19 [LIVE] email-in-page -> crawler
- low-20 [LIVE] asset-fingerprint -> crawler
- low-21 [LIVE] session-cookie-name -> session_probe
- low-22 [LIVE] error-tech-disclosure -> auth_probe
- low-23 [LIVE] sitemap-hidden-paths -> crawler
- low-24 [LIVE] cors-no-cred -> deep_probe
- low-25 [LIVE] options-permissive -> method_audit

## MEDIUM — 25 skills (CVSS 4.0 - 6.9)
- medium-01 [LIVE] csp-missing -> security_headers
- medium-02 [LIVE] csp-report-only -> security_headers
- medium-03 [LIVE] hsts-missing -> security_headers
- medium-04 [LIVE] spf-missing -> email_probe
- medium-05 [LIVE] dmarc-missing -> email_probe
- medium-06 [ROADMAP] dkim-missing -> dkim_probe
- medium-07 [LIVE] lockout-absent -> auth_probe
- medium-08 [LIVE] user-enum -> auth_probe
- medium-09 [LIVE] login-error-diff -> auth_probe
- medium-10 [LIVE] csrf-form-missing -> deep_probe
- medium-11 [LIVE] cookie-samesite-session -> security_headers
- medium-12 [LIVE] jwt-exp-missing -> session_probe
- medium-13 [LIVE] session-entropy-low -> session_probe
- medium-14 [LIVE] dir-listing -> dir_probe
- medium-15 [ROADMAP] verbose-errors -> err_probe
- medium-16 [LIVE] open-redirect-reflected -> redirect_probe
- medium-17 [LIVE] trace-enabled -> method_audit
- medium-18 [LIVE] debug-path -> dir_probe
- medium-19 [LIVE] phpinfo -> dir_probe
- medium-20 [LIVE] actuator-exposed -> dir_probe
- medium-21 [LIVE] swagger-public -> dir_probe
- medium-22 [LIVE] graphiql-exposed -> deep_probe
- medium-23 [LIVE] mixed-content -> deep_probe
- medium-24 [LIVE] load-5xx -> load_probe
- medium-25 [LIVE] load-latency -> load_probe

## HIGH — 25 skills (CVSS 7.0 - 8.9)
- high-01 [LIVE] xss-reflected -> xss_probe
- high-02 [LIVE] open-redirect-confirmed -> redirect_probe
- high-03 [LIVE] crlf-injection -> deep_probe
- high-04 [LIVE] hostheader-reflect -> deep_probe
- high-05 [LIVE] jwt-algnone-accepted -> session_probe
- high-06 [LIVE] api-unauth-data -> deep_probe
- high-07 [LIVE] traversal-verified -> deep_probe
- high-08 [LIVE] sqli-boolean -> sqli_probe
- high-09 [LIVE] cors-credentialed -> deep_probe
- high-10 [LIVE] graphql-introspection -> deep_probe
- high-11 [LIVE] sast-shell -> code_audit
- high-12 [LIVE] sast-eval -> code_audit
- high-13 [LIVE] sast-deserialization -> code_audit
- high-14 [LIVE] sast-tls-verify-off -> code_audit
- high-15 [LIVE] hardcoded-secrets -> secret_scan
- high-16 [LIVE] sast-sql-fstring -> code_audit
- high-17 [LIVE] sast-dom-write -> code_audit
- high-18 [LIVE] admin-weak-cred -> auth_probe
- high-19 [LIVE] route-no-authz -> session_probe
- high-20 [LIVE] dirlisting-sensitive -> dir_probe
- high-21 [LIVE] admin-default-creds -> auth_probe
- high-22 [ROADMAP] subdomain-takeover -> ct_takeover
- high-23 [ROADMAP] ratelimit-bypass -> rate_bypass
- high-24 [ROADMAP] mass-assignment -> mass_assign
- high-25 [ROADMAP] param-pollution-authbypass -> param_pol

## CRITICAL — 25 skills (CVSS 9.0 - 10.0)
- critical-01 [LIVE] ssti-verified -> deep_probe
- critical-02 [LIVE] sqli-error-confirmed -> sqli_probe
- critical-03 [LIVE] cmdi-time-confirmed -> deep_probe
- critical-04 [LIVE] authbypass-algnone -> session_probe
- critical-05 [LIVE] unauth-admin-access -> session_probe
- critical-06 [LIVE] unauth-api-data -> deep_probe
- critical-07 [LIVE] arbitrary-file-read -> deep_probe
- critical-08 [LIVE] real-account-weak-cred -> auth_probe
- critical-09 [ROADMAP] jwt-signature-bypass -> jwt_chain
- critical-10 [ROADMAP] deserialization-rce -> deser_rce
- critical-11 [ROADMAP] upload-webshell -> upload_webshell
- critical-12 [ROADMAP] ssrf-internal-rce -> ssrf_chain
- critical-13 [ROADMAP] chain-secret-access -> chain_secret
- critical-14 [ROADMAP] chain-xss-admin -> chain_xss
- critical-15 [ROADMAP] chain-sqli-data -> chain_sqli
- critical-16 [LIVE] prod-admin-default-creds -> auth_probe
- critical-17 [ROADMAP] rfi-confirmed -> rfi
- critical-18 [ROADMAP] git-source-recovery -> git_recover
- critical-19 [LIVE] db-dump-exposed -> dir_probe
- critical-20 [ROADMAP] dns-takeover -> dns_takeover
- critical-21 [ROADMAP] gql-mutation-unauth -> gql_mutation
- critical-22 [ROADMAP] reset-token-reuse -> reset_reuse
- critical-23 [ROADMAP] ato-chain -> ato_chain
- critical-24 [ROADMAP] payment-bypass -> pay_bypass
- critical-25 [ROADMAP] race-double-effect -> race
