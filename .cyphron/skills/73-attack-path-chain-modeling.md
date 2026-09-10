# Skill 73 — Attack Path Chain Modeling & Validation

> Cyphron's methodology for reasoning in CHAINS, not isolated findings: entry →
> impact sentences (forgery → funds, spoofing → rate-limit collapse), each hop
> mapped to an owning test and owner. Chains are covered by composing existing
> controls — they never become separate backlog items of their own.

---

## WHEN TO ACTIVATE

- User asks "what's the worst case if X and Y combine?" / skenario berantai
- User wants attack-path analysis beyond single-vulnerability findings
- User adds a new public endpoint/exemption and wants to know which chains it touches
- Pentest reporting needs a worst-case scenario section

---

## METHODOLOGY

### Step 1: Express chains as entry→impact sentences
Each chain is one sentence: how an attacker gets in, and what they end up with.
Example taxonomy (harvested verbatim from a real plan):

| ID | Entry and impact |
|---|---|
| AP1 | OAuth identity/linking or seed-admin rule reaches an unintended admin account |
| AP2 | Unauthenticated legacy webhook selects a tenant and invokes bot behavior |
| AP3 | Crafted inbound message reaches a money-moving tool |
| AP4 | Attacker-authored memory persists as future prompt authority |
| AP5 | Static-file matcher gap reaches a sensitive dynamic route |
| AP6 | Forged forwarding header defeats registration/rate limits |
| AP7 | Wildcard trusted-proxy configuration defeats IP controls |
| AP8 | A rushed public-API exemption removes tenant binding |
| AP9 | Leaked signed media URL is replayed within its validity window |
| AP10 | Direct origin bypasses the intended TLS/proxy boundary |

### Step 2: Map every hop to a closure
For each chain, list which existing test sections/controls close each hop
(e.g. AP6 closes at the proxy contract + rate-limit identity; AP7 closes at
boot-time wildcard rejection). A hop with no owning test is a **gap** — feed it
to Skills 66–72 or create a new test; it is never left as prose.

### Step 3: Control-oriented coverage, chain-oriented reporting
One control usually closes many chains (signature verification closes webhook
forgery AND tenant selection). Optimize the test suite by **control**, but
report risk by **chain** — executives think in chains.

### Step 4: No separate backlog
Combinatorial chains are covered by the same tests that cover their hops.
Chains do not create separate backlog items; they create **review obligations**
whenever a hop's control changes.

### Step 5: Trigger re-validation
Re-walk the chain table when: a new public API exemption is added, the proxy or
tenant model changes, a new money-moving path appears, or an AI/tool capability
is granted. Ask for each chain: "did any hop's control get weaker?"

### Step 6: World-model integration
In agent runs, a chain = ordered edges over findings/controls in the world
model. Use chains to compute the worst-case scenario section of reports, and to
prioritize which findings to verify first (those that unlock a chain matter
more than isolated ones).

---

## SECURE PATTERNS

- Entry→impact sentence format with a stable ID (AP1, AP2, ...)
- Closure mapping per hop to a named test section + owner
- Chains re-validated on every architecture/exemption change
- Worst-case narrative in reports derived from the chain table, not invented ad hoc

---

## AUDIT CHECKLIST

- [ ] Chain table exists, verbatim, with stable IDs and closure sections
- [ ] Every hop has an owning test (no prose-only hops)
- [ ] Every chain has an owner
- [ ] New exemptions/endpoints checked against the chain table at review time
- [ ] Re-validation performed after control changes
- [ ] Report worst-case section derived from chains
- [ ] AI/tool capabilities (memory, spend) treated as chain hops (AP3/AP4 class)

> Provenance: harvested verbatim from an attack-path plan table (AP1–AP10 with
> closure sections 5.x/6.x) and its governing rule that combinatorial chains are
> covered by the same tests — they do not create separate backlog items.
