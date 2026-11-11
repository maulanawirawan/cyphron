# Announcement drafts

Honest copy you can paste when you want to share secai. Nothing here
overstates what the tool does. Swap in real numbers before posting, and
only post where self-promotion is allowed (read each community's rules —
r/netsec in particular is strict about it).

---

## Show HN

**Title:**
Show HN: SecAI – a security scanner that refuses to report what it can't prove

**Body:**

I got tired of scanners that hand you a few hundred "possible" findings
and leave the triage to you. So I built the opposite: an engine where a
finding only lands in the report if it's actually proven.

Every result sits on an explicit evidence ladder — from L0 ("checked,
found nothing") up to L5 ("confirmed by a third party"). Only L3 and
above, where there's a reproducible proof, ever reach a report.
Everything below that is kept as internal bookkeeping instead of being
dressed up as a finding, because that's where false positives come from.

A few things that make it different:

- One strict output contract (`findings.json`) implemented in both
  Python and Rust, and the two are cross-tested against each other.
- A false-positive regression battery in CI — if a control endpoint
  "fails" the same way the target did, the claim gets cancelled, not
  confirmed.
- Self-updating CVE intel from CISA KEV, NVD, and OSV.
- A gated proof tier for turning a lead into a reproducible PoC, off by
  default and meant for labs and systems you're authorized to test.

It's Python skills driven by a native Rust core. Authorized testing
only. PolyForm Noncommercial license.

Repo: https://github.com/maulanawirawan/secai

Happy to answer anything about the design — especially the evidence
ladder and why I went fail-closed on malformed output.

---

## r/netsec (self-post)

> r/netsec only allows self-promotion under specific conditions and a
> flair. Check the current rules and the "Project / Tool" guidance
> before posting — if in doubt, let someone else submit it, or share it
> in a weekly thread instead.

**Title:**
SecAI: evidence-first scanning with an explicit L0–L5 verdict ladder (Python + Rust, open source)

**Body:**

Sharing a tool I've been building. The core idea: a finding you can't
prove is a lead, not a claim. SecAI puts every result on an evidence
ladder and only lets L3+ (a reproducible proof) into a report.

Technical bits that might interest this crowd:

- `findings.json` is one contract, implemented in Python and Rust and
  cross-tested, so the two halves can't quietly drift apart.
- Malformed tool output fails the run (fail-closed) instead of being
  silently dropped — silent skips are how false positives get born.
- FP regression battery (FP1–FP16) plus per-class guards in the suite:
  a control endpoint that "fails" the same way cancels the claim.
- Cross-tool correlation (what I call FAO quorum) only promotes a lead
  when independent sources agree.
- Honest egress by default — no evasion features, on purpose.

Authorized targets only, and the active proof tier is gated behind an
explicit per-target opt-in. PolyForm NC license.

https://github.com/maulanawirawan/secai

Feedback on the verdict model and the zero-FP guards is very welcome.

---

## One-liner (Twitter/X, Mastodon, LinkedIn, Discord)

Built SecAI: a security scanner that refuses to report anything it
can't prove. Every finding sits on an L0–L5 evidence ladder; only
reproducible proof (L3+) makes the report. Python + Rust, open source,
authorized testing only. https://github.com/maulanawirawan/secai

---

## Posting checklist

- [ ] Replace any rounded numbers with the current real ones (skills,
      tests). As of now: 93 registered skills, 176 tools, 3,315 Python tests.
- [ ] Confirm the repo README demo/GIF renders before you post the link.
- [ ] Read the target community's self-promotion rules first.
- [ ] Reply to early comments quickly — the first hour sets the tone.
- [ ] Don't ask for stars directly. Let the idea do the work.
