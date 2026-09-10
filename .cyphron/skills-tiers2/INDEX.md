# Cyphron Tier Pack 2 — 120 Skill BARU (30 x 4 tier)

Semua teknik ini TIDAK ada di pack pertama maupun di 74 skill inti.
FP-guard wajib per skill; engine live = jalan hari ini, road = slot terdesain.

Coverage: 70 LIVE / 50 ROADMAP (b3: low-02/17/29+medium-01..07; b4: medium-08/09/14..21; b5: medium-22..25+27..30; b6: high-16..19+21; b7: high-01/02/03/06/28 via multi-account god mode) (terdesain, wajib lewat pipeline test+FP-guard)

## LOW — 30 skills (CVSS 0.1 - 3.9)
- low-01 [LIVE] favicon-fingerprint -> crawler
- low-02 [LIVE] wayback-diff -> wayback
- low-03 [LIVE] sourcemap-exposure -> dir_probe
- low-04 [LIVE] js-secret-extraction -> crawler
- low-05 [LIVE] csp-report-uri-wrong -> security_headers
- low-06 [LIVE] hsts-short-age -> security_headers
- low-07 [LIVE] cookie-secure-prefix -> security_headers
- low-08 [LIVE] cert-san-audit -> tls_audit
- low-09 [LIVE] cert-chain-incomplete -> tls_audit
- low-10 [LIVE] ocsp-stapling-absent -> tls_audit
- low-11 [LIVE] svn-hg-exposed -> dir_probe
- low-12 [LIVE] ide-files-exposed -> dir_probe
- low-13 [LIVE] backup-archive-7z -> dir_probe
- low-14 [LIVE] registry-hints -> crawler
- low-15 [LIVE] ci-badge-leak -> crawler
- low-16 [LIVE] admin-email-pattern -> crawler
- low-17 [LIVE] sequential-user-id -> id_seq
- low-18 [LIVE] response-time-fingerprint -> load_probe
- low-19 [LIVE] private-ip-leak -> deep_probe
- low-20 [LIVE] localhost-url-leak -> deep_probe
- low-21 [LIVE] home-path-leak -> deep_probe
- low-22 [LIVE] internal-hostname-leak -> deep_probe
- low-23 [LIVE] altsvc-port-disclosure -> security_headers
- low-24 [LIVE] draft-env-exposed -> dir_probe
- low-25 [LIVE] nuxt-meta-leak -> crawler
- low-26 [LIVE] git-branch-names -> dir_probe
- low-27 [LIVE] npm-audit-summary -> dir_probe
- low-28 [LIVE] cors-preflight-wide -> deep_probe
- low-29 [LIVE] subdomain-ct-audit -> ct_log
- low-30 [LIVE] mx-provider-map -> email_probe

## MEDIUM — 30 skills (CVSS 4.0 - 6.9)
- medium-01 [LIVE] smuggling-clue -> smuggle
- medium-02 [LIVE] cache-deception -> cache_dec
- medium-03 [LIVE] oauth-state-missing -> oauth
- medium-04 [LIVE] oauth-redirect-lax -> oauth
- medium-05 [LIVE] oidc-nonce-missing -> oauth
- medium-06 [LIVE] session-puzzling -> puzzle
- medium-07 [LIVE] json-injection -> json_inj
- medium-08 [LIVE] content-type-confusion -> ct_conf
- medium-09 [LIVE] verb-override -> verb_over
- medium-10 [LIVE] csp-unsafe-eval -> security_headers
- medium-11 [LIVE] csp-frame-src-missing -> security_headers
- medium-12 [LIVE] dns-caa-missing -> email_probe
- medium-13 [LIVE] bimi-missing -> email_probe
- medium-14 [LIVE] smtp-starttls-missing -> smtp_probe
- medium-15 [LIVE] dkim-weak-key -> dkim_probe
- medium-16 [LIVE] api-version-downgrade -> api_ver
- medium-17 [LIVE] graphql-batching -> gql_batch
- medium-18 [LIVE] graphql-depth-unbounded -> gql_depth
- medium-19 [LIVE] rest-aliasing -> gql_alias
- medium-20 [LIVE] pagination-unbounded -> pagin
- medium-21 [LIVE] sort-filter-injection -> sort_inj
- medium-22 [LIVE] jwt-jku-injection -> jwt_jku
- medium-23 [LIVE] jwt-x5u-injection -> jwt_x5u (jwt_jku)
- medium-24 [LIVE] jwt-weak-hmac -> jwt_crack
- medium-25 [LIVE] ws-origin-bypass -> ws_probe
- medium-26 [LIVE] postmessage-wildcard -> crawler
- medium-27 [LIVE] proto-pollution-client -> proto_c
- medium-28 [LIVE] proto-pollution-server -> proto_s
- medium-29 [LIVE] dom-clobbering -> clobber
- medium-30 [LIVE] css-injection -> css_inj

## HIGH — 30 skills (CVSS 7.0 - 8.9)
- high-01 [LIVE] idor-seq-probe -> bola (+id_seq)
- high-02 [LIVE] bola-object-probe -> bola
- high-03 [LIVE] privilege-matrix -> priv_matrix
- high-04 [ROADMAP] oauth-token-replay -> oauth_replay
- high-05 [ROADMAP] oauth-code-intercept -> oauth_code
- high-06 [LIVE] ws-unauth-message -> ws_probe
- high-07 [ROADMAP] proto-pollution-auth -> proto_auth
- high-08 [ROADMAP] css-exfiltration -> css_exfil
- high-09 [ROADMAP] cache-key-normalization -> cache_key
- high-10 [ROADMAP] cache-poisoning-unkeyed -> cache_poison
- high-11 [ROADMAP] smuggle-confirmed -> smuggle2
- high-12 [ROADMAP] h2-rapid-reset-signal -> h2_rr
- high-13 [ROADMAP] dns-rebinding-confirmed -> rebind2
- high-14 [ROADMAP] imds-v1-reachable -> imds
- high-15 [ROADMAP] grpc-reflection -> grpc
- high-16 [LIVE] mq-mgmt-exposed -> mq_mgmt
- high-17 [LIVE] sourcemap-full-recover -> sourcemap2
- high-18 [LIVE] map-secrets -> sourcemap2
- high-19 [LIVE] dom-xss-sink -> dom_xss
- high-20 [ROADMAP] csp-bypass-trusted -> csp_bypass
- high-21 [LIVE] clickjacking-action -> clickj
- high-22 [ROADMAP] reset-poisoning-xfh -> reset_poison
- high-23 [ROADMAP] reset-token-url -> reset_url
- high-24 [ROADMAP] 2fa-missing-sensitive -> 2fa
- high-25 [ROADMAP] otp-brute-bounded -> otp_brute
- high-26 [ROADMAP] invite-abuse -> invite
- high-27 [ROADMAP] price-tamper-staging -> price_t
- high-28 [LIVE] tenant-cross-two-acct -> bola
- high-29 [ROADMAP] admin-impersonate-massassign -> massassign2
- high-30 [ROADMAP] sqli-os-file -> sqli_file

## CRITICAL — 30 skills (CVSS 9.0 - 10.0)
- critical-01 [ROADMAP] ssrf-metadata-creds -> imds2
- critical-02 [ROADMAP] smuggle-hijack -> smuggle3
- critical-03 [ROADMAP] sqli-stacked -> sqli_stack
- critical-04 [ROADMAP] jndi-rce-probe -> jndi
- critical-05 [ROADMAP] xxe-oob -> xxe_oob
- critical-06 [ROADMAP] deserialization-rce-confirmed -> deser2
- critical-07 [ROADMAP] ssti-full-rce -> ssti_rce
- critical-08 [ROADMAP] webshell-confirmed -> webshell
- critical-09 [ROADMAP] container-escape-signals -> container
- critical-10 [ROADMAP] k8s-api-unauth -> k8s
- critical-11 [ROADMAP] cloud-iam-wildcard -> iam
- critical-12 [ROADMAP] public-bucket-named -> bucket
- critical-13 [ROADMAP] git-history-secrets -> git_hist
- critical-14 [ROADMAP] ci-secrets-exposed -> ci_log
- critical-15 [ROADMAP] takeover-payload-confirmed -> takeover2
- critical-16 [ROADMAP] oauth-account-takeover -> oat
- critical-17 [ROADMAP] jwt-kid-traversal -> jwt_kid
- critical-18 [ROADMAP] jwk-header-injection -> jwt_jwk2
- critical-19 [ROADMAP] rs256-hs256-confusion -> alg_conf
- critical-20 [ROADMAP] reset-takeover-chain -> reset_chain
- critical-21 [ROADMAP] 2fa-bypass-response -> 2fa_bypass
- critical-22 [ROADMAP] otp-brute-full -> otp2
- critical-23 [ROADMAP] tenant-cross-critical -> tenant3
- critical-24 [ROADMAP] admin-impersonation-live -> impersonate
- critical-25 [ROADMAP] sqli-file-read-confirmed -> sqli_file2
- critical-26 [ROADMAP] ssti-rce-confirmed -> ssti_rce2
- critical-27 [ROADMAP] webshell-live -> webshell2
- critical-28 [ROADMAP] supply-chain-install-abuse -> supply
- critical-29 [ROADMAP] historic-breach-reuse -> combo
- critical-30 [ROADMAP] zero-day-hunt-fuzz -> fuzzer
