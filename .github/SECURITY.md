# Security Policy

## Supported versions

Only the latest `main` and the latest tagged release receive security
fixes. If you are pinned to an older release, upgrade first — the
project moves fast and the test suite is the compatibility contract.

## Reporting a vulnerability in cyphron itself

cyphron is a security tool, so a bug in cyphron is itself a potential
security issue (for example: a gated proof-tier technique that fires
outside `exploit_allowed`, evidence redaction that leaks a secret, a
tool that talks to the network when it must not).

**Please do not open a public issue for that.**

1. Use GitHub's *Report a vulnerability* (Security → Advisories) on this
   repository, or contact the maintainer privately.
2. Include: affected tool/skill, commit hash, minimal reproduction, and
   the contract/output that misbehaved.
3. You will get an initial response within 7 days. We aim to ship a fix
   or a mitigation within 30 days for confirmed issues.

## What we care about most

- **Network calls from tools/skills that must be offline.** The test
  suite enforces zero-network for the triage family; a bypass matters.
- **Redaction escapes.** Findings and carve outputs must never emit
  full credential values (see `paste_triage`, `sqlite_forensics`).
- **Gate bypasses.** The exploit proof tier (`tools/exploit_*`) and the
  request budget must fail closed; anything that turns a gate into a
  rubber stamp is a security bug.
- **Scope/Safety-class violations.** A `read-only` skill that can reach
  `state-changing` behavior through its flags.

## Safe harbor

Good-faith research against your own instance of cyphron, following
this policy, is welcome and will not be met with legal action under the
repository license. Findings in *targeted* systems are out of scope for
this policy — always test targets you are authorized to test.

## Scope note

This policy covers the cyphron codebase and its distributions. It does
not cover the systems you point cyphron at.
