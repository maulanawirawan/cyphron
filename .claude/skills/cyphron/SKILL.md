---
name: cyphron
description: Evidence-first security assessment via CLI (scan, scout,
  night-run, ledger, validate). Use when the user wants authorized-target
  security checks with verifiable evidence — no proof, no report.
---

# cyphron

This repo IS the tool. The full agent manual — modes table, safe
playbook, guardrails, MCP setup — lives at the repo root:
[`SKILL.md`](../../../SKILL.md). Read it before running anything.

Fast lane (from the repo root):

```bash
python cyphron.py            # mode board
python cyphron.py <mode> --help
```

Hard rules that never bend: authorized targets only; lab-only classes
stay behind their gates; a findings.json that fails `python cyphron.py
validate` is not a report.
