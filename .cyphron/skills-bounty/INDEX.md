# Cyphron Bug Bounty Pack - HARVEST 6 sumber (2026-09-06)

Sumber: yaklang/hack-skills (101 skill), matty69v/Bug-Bounty-Agents
(43 agen), skraft9/vulnerability-research, patientzerosecurity.com,
owlshield.ai, Rise The Ranger 2 (Satsiber TNI). Skill BARU di luar
skills-tiers2/3. FP-guard + truth-guarantee per skill.

## LOW - 8 skills (CVSS 0.1 - 3.9)
- low-01 [LIVE] param-miner-basic -> param_miner
- low-02 [ROADMAP] csv-formula-injection -> csv_inj
- low-03 [ROADMAP] dangling-markup-injection -> dangle
- low-04 [ROADMAP] hpp-parameter-pollution -> hpp
- low-05 [ROADMAP] sri-missing-cdn -> sri
- low-06 [ROADMAP] cookie-attrs-audit -> cookie_audit
- low-07 [ROADMAP] meta-refresh-redirect -> meta_redir
- low-08 [ROADMAP] response-timing-oracle -> timing_oracle

## MEDIUM - 10 skills (CVSS 4.0 - 6.9)
- medium-01 [ROADMAP] nosql-operator-injection -> nosql
- medium-02 [ROADMAP] gql-field-suggestion -> gql_suggest
- medium-03 [ROADMAP] password-reset-enumeration -> reset_enum
- medium-04 [ROADMAP] signup-mass-assignment -> massassign
- medium-05 [LIVE] prompt-injection-ai-endpoint -> llm_probe
- medium-06 [ROADMAP] waf-fingerprint-evasion-matrix -> waf_matrix
- medium-07 [ROADMAP] open-redirect-meta-chain -> redir_chain
- medium-08 [ROADMAP] api-mass-docs-drift -> drift_bounty
- medium-09 [ROADMAP] subdomain-permute-dns -> sub_permute
- medium-10 [ROADMAP] cors-reflect-strict -> cors_strict

## HIGH - 8 skills (CVSS 7.0 - 8.9)
- high-01 [LIVE] authz-bypass-401-403 -> authz_bypass
- high-02 [LIVE] subdomain-takeover-fingerprint -> takeover
- high-03 [ROADMAP] race-condition-bounded -> race
- high-04 [ROADMAP] http2-content-based-smuggle -> h2_crlf
- high-05 [ROADMAP] js-analysis-endpoint-harvest -> js_harvest
- high-06 [ROADMAP] cache-key-normalization-bounty -> cache_norm
- high-07 [ROADMAP] csrf-token-not-bound -> csrf_bind
- high-08 [ROADMAP] jwt-null-signature -> jwt_null

## CRITICAL - 7 skills (CVSS 9.0 - 10.0)
- critical-01 [ROADMAP] takeover-payload-provider -> takeover2
- critical-02 [ROADMAP] sso-saml-assertion-tamper -> saml
- critical-03 [ROADMAP] webhook-secret-bypass -> wh_sig
- critical-04 [ROADMAP] graphql-dataloader-leak -> gql_dataloader
- critical-05 [ROADMAP] llm-agent-tool-abuse -> llm_tool
- critical-06 [ROADMAP] payment-amount-tamper-race -> pay_race
- critical-07 [ROADMAP] cloud-bucket-takeover-signal -> bucket_sig

Coverage: 4 LIVE / 29 ROADMAP