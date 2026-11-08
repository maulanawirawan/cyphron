<!--
Thanks for the PR! secai has a few house rules that keep the suite
trustworthy. Tick them off — the CI and the guard tests will also check
several of them, but honest boxes save a review round.
-->

## What does this PR do?

<!-- One paragraph. If it adds a tool/skill, say which entry/concept it
     ports and link the source. -->

## House rules checklist

- [ ] **Full suite green**: `python -m pytest tests/ -q` passes locally
      before every push (this includes the FP regression + guard tests).
- [ ] **Zero network in tests** for anything in `tools/` / `skills/`
      triage family — no sockets, no `urlopen`, no HTTP clients.
- [ ] **Fail closed**: new tools exit `2` (not "clean") on unreadable /
      unknown / partial input, and darkness (absent telemetry) is
      reported, never interpreted as "no findings".
- [ ] **No-FP discipline**: verdicts are evidence-based, not verdicts
      from vibes; probabilistic detections cap at evidence level
      (see docs/ — the evidence ladder).
- [ ] **From scratch**: no copied source code; concept attribution and
      source license noted in the docstring.
- [ ] **NEVER-LIST respected**: no DoS / persistence / worm /
      ransomware / mass-exfiltration capabilities.
- [ ] **README / AGENTS.md untouched** unless this PR *is* a docs
      consolidation (badge numbers are maintained by the maintainer).
- [ ] `findings.json` contract unchanged — or, if changed, both the
      Python and Rust implementations + cross-tests are updated.

## Evidence

<!-- Paste the live-verify output of the new/changed tool on a
     realistic fixture (fail-closed cases included), or the test run
     summary for refactors. -->

```
(paste output here)
```

## How was it tested?

<!-- Which test files cover the change; any fixture notes. -->
