# Changelog

All notable changes to cyphron are documented here. Dates are UTC.
The format follows [Keep a Changelog](https://keepachangelog.com); the
project has not adopted semver yet — treat the badge numbers (tests)
as the compatibility signal.

## [Unreleased]

### Repo hygiene

- Added community health files: `.github/SECURITY.md` (vulnerability
  reporting policy for cyphron itself), `.github/CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), `.github/PULL_REQUEST_TEMPLATE.md`
  (house rules as a checklist), `.github/ISSUE_TEMPLATE/` (bug report,
  feature request, and a first-class **false positive report** form —
  FP reports tighten every detector's anti-FP floor).
- Added this `CHANGELOG.md`.
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

[Unreleased]: https://github.com/maulanawirawan/cyphron/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/maulanawirawan/cyphron/releases/tag/v0.1.0
