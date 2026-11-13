# Changelog

All notable changes to secai are documented here. Dates are UTC.
The format follows [Keep a Changelog](https://keepachangelog.com); the
project has not adopted semver yet — treat the badge numbers (tests)
as the compatibility signal.

## [Unreleased]

### Added — F66 queue completion: 2 banner skills + MCP prompt-injection playbook + net-guard runner (2 new skills, 93 -> 95)

Antrian eksplisit F66 dibereskan (3 dari 4; sisanya HOLD kebijakan):

- `banner_oracle_ebs` + `banner_plex` — dua skill deteksi banner/versi (maks 2 GET, token ketat anti-FP, versi tak terekspos = pemetaan CVE TIDAK diklaim); melengkapi seed watchlist Oracle EBS & Plex2Shell; terkurasi di verdict-audit (rantai E via cve-matcher). 16 test.
- `McpPromptInjectionPlaybook` (`mcp-prompt-injection`, tier-1 proof) — playbook prompt-injection untuk server MCP nyata via JSON-RPC 2.0 (`initialize` wajib hidup, `tools/call` canary instruksi benign, tool kontrol `-safe` wajib menolak); ditambah simulator server MCP di `tools/lab_target.py` (`/mcp`). 3 test differential (L3 terbukti / not-proven fail-closed / kontrol imun).
- net-guard runner Rust (Fase 2-B lanjutan, docs/CONTROLLED-NETWORK.md §3) — `core-rs/src/runner.rs::run_skill_guarded`: env guard diinjeksi + budget file milik runner + verifikasi audit log fail-closed (wajib ada, wajib baris `guard-install` dari `core/net_guard.auto_install_from_env`, semua baris JSON valid, `used <= limit`); CLI `secai run --net-budget N`. 7 test Rust.
- agent-shield: verifikator kini ikut ter-lock (`tools/agent_shield.py` masuk WATCHED_FILES — memodifikasi verifier merusak seal); batas TOCTOU/hash-tanpa-tanda-tangan didokumentasikan jujur di docs/AGENT-SAFETY.md.
- Docs: status antrian F66/CONTROLLED-NETWORK/CVE-MATCHER diperbarui; PORT-AGENT-METHODS diberi header "bukan antrian tugas" (55 titik ekstraksi tool sudah jadi; checklist = langkah kerja agent).


### Added — intel & DFIR reference batch (7 new tools, 189 -> 196)

A batch of 7 new offline triage tools under `tools/`, each closing a gap
mapped against popular reference catalogs (A-poc/RedTeam-Tools and
A-poc/BlueTeam-Tools — *concept* references only; all code written from
scratch, stdlib-only, zero-network, fail-closed, emitting the triage
`findings.json` shape, each with a false-positive control test).

- `dmarc_report_triage` — DMARC aggregate report (xml/gz/zip) triage: spoof-candidate (SPF+DKIM fail volume), forwarder-mixed, unaligned sources, soft policy (p=none/pct<100), new-source vs known-ips list. *(gap: parsedmarc)*
- `cryptojack_log_triage` — proxy/DNS log triage for cryptojacking: known pool keys, stratum ports/scheme, JSON-RPC mining tokens, long-uniform beacons. *(gap: "Detect Cryptojacking Malware with Proxy Logs")*
- `vbs_decode_triage` — VBE/JScript.Encode decoder (format constants embedded; verified against the documented sample -> `MsgBox "Hello"`) + static triage of the decoded text (exec/download/obfuscation/persistence indicators). No execution. *(gap: decode-vbe)*
- `bh_ingest_triage` — BloodHound JSON/ZIP ingest (legacy list & 4.x collections): AS-REP roastable, password-not-required, password-never-expires, unconstrained delegation, GPP Groups.xml candidates, DCSync-capable non-admins, kerberoastable SPNs. *(gap: BloodHound/PingCastle passives)*
- `misp_event_ingest` — MISP event JSON ingest: IOC catalog, in-scope matching (ips/domains/emails scope file), notable-tag escalation. Mirror of `stix_bundle_audit`. *(gap: MISP)*
- `qr_payload_triage` — weighted scoring of decoded QR payloads (credential lure, IP literal, shorteners, embedded-redirect, userinfo trick, punycode, non-HTTP schemes). *(gap: SquarePhish/evilqr counterpoint)*
- `canary_alert_triage` — Canarytoken alert (.eml/JSON webhook) triage: trigger + source context + memo, unparseable files reported for audit. *(gap: Canary Tokens)*



### Added — offensive capability expansion (13 new tools, 176 -> 189)

A batch of 13 new offline tools under `tools/` (11 red-team + 2 detection-
bridge). All stdlib-only, zero-network, deterministic, fail-closed, emitting
the single-door `findings.json` contract, each with a false-positive control
test. NO NEVER-LIST techniques (no DoS/persistence/worms/ransomware/mass-
exfil), no Docker, no new skills. 101 new tests; secrets/PoCs are redacted and
benign-marker-only.

- `jwt_crypto_attack` — offline JWT HS256 crack (L3 arithmetic) + RS->HS confusion + alg:none lead; recovered secret redacted.
- `bola_bfla_prover` — prove BOLA/BFLA from two-role captures (2xx + owner marker => L2; 403 => L0).
- `nosql_injection_analyzer` — NoSQL operator injection; differential bypass => L2, operator present => L1.
- `proto_pollution_scan` — static JS prototype-pollution sinks with real line numbers (L2/L1).
- `cors_poc_gen` — CORS exploit PoC-HTML from a confirmed finding (reflection+creds => L1; wildcard+creds => L0).
- `smuggling_desync_analyzer` — HTTP request-smuggling classifier (CL/TE ambiguity => L1; front/back divergence => L2).
- `ssrf_metadata_map` — SSRF -> cloud IMDS mapper, capability-gated (reachable => L1, else L0).
- `lfi_rce_playbook` — LFI->RCE ladder generator, benign markers only (lab-only L1).
- `ssti_exploit_plan` — engine-specific SSTI ladder generator, benign markers (lab-only L1).
- `iam_assume_chain` — AWS IAM multi-hop assume-role escalation to admin (>=2 hops => L2).
- `ai_redteam_score` — LLM jailbreak/indirect-injection corpus + transcript scorer (canary echo => L2; refused => L0; redacted).
- `detection_rule_gen` — generate Sigma + YARA rules from a finding (blue bridge).
- `attack_navigator_export` — export a MITRE ATT&CK Navigator layer (blue bridge).

### Repo hygiene

- Added community health files: `.github/SECURITY.md` (vulnerability
  reporting policy for secai itself), `.github/CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), `.github/PULL_REQUEST_TEMPLATE.md`
  (house rules as a checklist), `.github/ISSUE_TEMPLATE/` (bug report,
  feature request, and a first-class **false positive report** form —
  FP reports tighten every detector's anti-FP floor).
- Added this `CHANGELOG.md`.
- **G6 delta-port wave opened** (source repos grew; 113 unported
  concepts found via a 3-tier evidence diff). Block 1 (#1001-#1030):
  `broken_link_scan` (#1010 — 23 tests, live-verified with real DoH +
  RDAP double evidence) + 6 METHODS sections (257-262). Suite
  3254 → 3277; badges follow the tool count.
- **Project renamed: `cyphron` → `secai`** (SECurity + Agentic/AI —
  short and searchable). Mechanical rename across 298 files: the CLI,
  binary, MCP tool names, findings-contract schema strings, docs, and
  community files. Old repo URLs redirect after the GitHub-side
  rename. Presentation is now English-first (`README.id.md` removed).
- Added `## Roadmap` and `install.sh` (one-command build + link).

- `README.md` (+ es/id/zh): capability map (what the port program
  built, grouped by domain), commands cheat-sheet, community section.
- **ABH mini-program** (concept source: awarexone/Agentic-Bug-Hunter,
  MIT): 8 new offline tools — `scope_gate`, `scope_aggregate`,
  `solidity_static_audit`, `token_rug_scan`, `hunt_pattern_db`,
  `submission_report` (worker wave) + `chain_planner`,
  `submission_gate` (coordinator). Web3 is a brand-new domain for the
  repo. Suite 3090 → 3254 (+31 subtests).
- `README.md`: added a capability map (what the port program built,
  grouped by domain) and a community section.

## [v0.1.0] — 2026-11-08

The detection-tooling milestone: a one-day, five-wave port program
processed **995 skill concepts** from four public GitHub security-skill
collections, triaged one by one (build from scratch / distill
methodology / out-of-domain). Result: **112 ported tools** (stdlib-only,
zero-network, fail-closed, concept attribution per tool), **250
methodology sections** in `docs/PORT-AGENT-METHODS.md`, and a test
suite that grew **2015 → 3093**.

### Capability map added by the port program (by domain)

| Domain | Tools (examples) |
|:---|:---|
| Log & event triage (Windows) | `sysmon_triage`, `win_logon_triage`, `win_auth_triage`, `win_persist_triage`, `account_manip_triage`, `dcsync_triage`, `kerberos_log_triage`, `ps_scriptlog_triage`, `applocker_policy_audit` |
| Log & event triage (Linux/K8s/Cloud) | `linux_auth_triage`, `linux_persist_scan`, `linux_cis_audit`, `linux_privesc_audit`, `aide_change_triage`, `k8s_audit_triage`, `k8s_podsec_audit`, `netpol_audit`, `psa_ns_audit`, `aws_config_audit`, `gcp_fw_audit`, `gcp_orgpolicy_audit`, `lambda_config_audit`, `etcd_config_audit`, `kubebench_ingest` |
| Network & PCAP | `zeek_beacon_scan`, `zeek_lateral_scan`, `zeek_front_scan`, `dns_log_triage`, `pcap_triage`, `netflow_parse`, `arp_pcap_scan`, `deauth_pcap_scan`, `pcap_triage` |
| Web, API & OAuth | `web_log_intrusion`, `waf_sqli_triage`, `webshell_triage`, `openapi_spec_audit`, `shadow_api_diff`, `graphql_depth_audit`, `oauth_redirect_audit`, `oauth_grant_audit`, `jwt_token_audit`, `brand_lookalike_scan`, `type_juggling_scan` |
| Malware & binary | `pe_import_scan`, `pe_mitigation_scan`, `elf_checksec`, `rust_binary_triage`, `crypto_constant_scan`, `rat_config_scan`, `maldoc_triage`, `pdf_triage`, `packer_scan`, `stego_triage`, `carve_scan`, `sqlite_forensics`, `killswitch_triage`, `ransom_artifact_triage` |
| Secrets & data | `secret_history_scan`, `secret_report_ingest`, `paste_triage`, `data_class_scan`, `browser_history_triage`, `zeroize_scan` |
| Supply chain & CI/CD | `supplychain_check`, `dep_confusion_check`, `pkg_typosquat_check`, `gha_workflow_audit`, `sarif_ingest`, `cspm_finding_ingest`, `stix_bundle_audit`, `slsa_provenance_audit`, `crypto_inventory_scan` |
| Vulnerability management | `vuln_sla_aging`, `vuln_exception_check`, `kev_gap`, `cvss_score`, `owasp_risk_rating`, `ssvc_triage`, `attack_coverage`, `asset_criticality_score`, `ioc_lifecycle_score` |
| Validation & reporting | `brocards_triage`, `triage_advisor`, `verify_gate`, `ingest_gate`, `log_chain_verify`, `report_pack`, `report_pdf` |

*(full list: `tools/` — every tool is a standalone CLI with a JSON
contract and an anti-FP floor; `docs/PORT-AGENT-METHODS.md` carries the
methodology distilled from the 800+ concepts that were not tool-shaped)*

### Program discipline (kept in `docs/PORT-AGENT-METHODS.md` + addenda)

- Anti-collision entry numbering across 33 parallel workers.
- Coordinator-only badge/README writes; full suite green before every
  push; CI verified by the coordinator (a wave-4 red CI — SQLite 3.46
  free-page behavior + POSIX-only tests — was reproduced via WSL and
  fixed with version-deterministic fixtures).
- GitHub Push Protection lesson codified: test fixtures containing
  secret-shaped strings are built at runtime, never as literals.

[Unreleased]: https://github.com/maulanawirawan/secai/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/maulanawirawan/secai/releases/tag/v0.1.0
