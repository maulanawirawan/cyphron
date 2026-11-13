# AGENTS.md — guidance for AI coding agents (and humans who read code)

secai is an evidence-first security assessment engine: skills collect
evidence, a quorum (FAO) verifies it, and the engine refuses to report
anything it cannot prove. "No proof, no report" is the contract — the
proof tier builds gated PoCs to turn a lead into evidence, but a lead
that cannot be proven never ships.

## Repo map

- `secai.py` — one-command mode board (`scan | validate | scout | night
  | intel | fresh | contrib | ledger | report | mcp | skills | lab |
  guard | shield | gate`);
  every mode has its own `--help`. Start here.
- `SKILL.md` — the agent manual: safe playbook + guardrails (also mounted
  as `.claude/skills/secai/`).
- `skills/` — 95 standalone Python CLIs, one detection skill each
  (`--url` / `--target` ... `--out result.json`). This is what users run.
- `core-rs/` — native Rust core (`secai validate | scan ...`).
  Build: `cargo build --release --manifest-path core-rs/Cargo.toml`
- `tools/` — helpers: lab target (`tools/lab_target.py`), planner,
  benchmarks, self-update, MCP server (`tools/mcp_server.py`), scout,
  session ledger, contribution pipeline (`cve_sweep`, `antidup_check`),
  agent-safety (`injection_guard`, `agent_shield`), audit engines
  (`audit_phases` multi-phase fail-closed, `insecure_defaults` config
  scanner), verify gate (`verify_gate` — claims need fresh evidence), leak-claim triage (`leak_triage`), parallel job dispatch (`fleet_dispatch`), skill vetting gate (`skill_vet`), CVSS v3.1 calculator (`cvss_score`), DFIR, config & intel triage (28+ tools hasil program port SKILL-PORT-QUEUE: maldoc/pdf/mft/netflow/deauth/dpapi/packer/web-log/dns-log/eml/k8s/cloudtrail/IAM/sysmon/win-logon/waf/lolbin/CT-baseline/IOC-defang/SARIF-ingest/dsb. — lihat git log).
- `tests/` — pytest suite (3449 tests + 31 subtests; 3 test POSIX skip otomatis di Windows). Run: `python -m pytest tests/ -q`
- `docs/` — policies: exploit tier, egress, install, nightrun, legion
  method (`docs/LEGION-METHOD.md`).

## Ground rules (non-negotiable)

1. Authorized targets only — own assets, explicit written permission, or
   a local lab. This is a tool for learning and for sanctioned testing,
   not for hitting systems you have no right to touch.
2. Evidence is the product. A finding only counts when it carries
   verifiable evidence; if it cannot be proven, the verdict stays quiet
   (fail-closed). "No proof, no report."
3. The proof tier (`tools/exploit_*`) builds reproducible PoCs to turn a
   lead into proof — but only under its gates: `exploit_allowed` per
   target, lab/staging by default, three keys for anything destructive.
   The NEVER-LIST (DoS, persistence/backdoor, worms, ransomware-sim,
   mass exfiltration) is refused no matter what flags are passed — do
   not add techniques from it, and do not weaken the gates.
4. License is PolyForm NC: free for noncommercial use, commercial use by
   arrangement with the owner. Contributions follow the same license.

## Commands

- run all tests: `python -m pytest tests/ -q`
- run one skill: `python skills/banner_posture.py --url https://example.com --out banner.json`
- validate an output: `core-rs/target/release/secai validate banner.json`
- local playground: `python tools/lab_target.py` (safe target for skills)

## Adding a skill (the most common contribution)

1. Copy the reference shape: `skills/banner_posture.py` (small, argparse,
   evidence dict out).
2. Your output must satisfy the contract (`secai validate` decides).
3. Add a unit test under `tests/` mirroring the naming scheme.
4. Run the full suite — green before the PR. Small and focused PRs win.

## Style

- Python: stdlib-first, match the surrounding code, type hints where
  already present.
- Docs/messages: plain and honest. English or Indonesian, both fine.
- PRs: include before/after evidence for any behavior change.
