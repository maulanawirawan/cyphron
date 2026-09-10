# Skill 72 — CSP Engineering & Migration

> Cyphron's methodology for auditing and migrating Content-Security-Policy:
> eliminating 'unsafe-inline' via nonce/hash without breaking hydration, OAuth,
> or dark/light/mobile rendering — with report-only rollout and the hard rule
> that no directive is ever removed mechanically.

---

## WHEN TO ACTIVATE

- User asks "is my CSP safe?" / "cara ilangin unsafe-inline"
- User plans a CSP nonce/hash migration for a framework app (Next.js, etc.)
- User asks why XSS protection headers matter or how to lock down script/style sources
- ZAP/scanner flags weak CSP and the user wants a fix path

---

## METHODOLOGY

### Step 1: Baseline audit
Parse the current CSP verbatim and flag:
- `'unsafe-inline'` / `'unsafe-eval'` in script-src or style-src
- missing `default-src 'self'`, `object-src`, `base-uri`, `frame-ancestors`,
  `form-action` (these four must be locked regardless)
- wildcard `*` sources or overly broad hosts
- `connect-src` enumerating hosts that should not be there (or missing ones the
  app actually calls — which will break after tightening)

### Step 2: Migration design (nonce at one layer)
Issue a fresh nonce **per response at a single middleware/proxy layer** and
propagate it to the document. Replace:
`script-src 'self' 'unsafe-inline'` → `script-src 'self' 'nonce-<random>'`
(+ `'strict-dynamic'` where the loader supports it);
`style-src` follows the same path (hash-based for static inline styles is
acceptable where nonces are impractical).

### Step 3: Inline-dependency census
List every legitimate inline script/style: framework hydration bootstrap, OAuth
popup/callback glue, static chunks, theme (light/dark/mobile) inline styles,
telemetry snippet. Each must be converted to nonce/hash or removed — none may
stay as `unsafe-inline`.

### Step 4: THE HARD RULE
**Never remove a directive mechanically.** Every removal is preceded by proof
that all legitimate pages still render and interact. Breaking hydration or OAuth
in production is a worse outcome than a weaker CSP shipped temporarily.

### Step 5: Report-only rollout
1. Add the new policy as `Content-Security-Policy-Report-Only` with a reporting
   endpoint.
2. Fix violations until the report is clean across all pages and flows.
3. Flip to enforcing only after a clean window.
4. Run full browser regression (every page, light/dark/mobile) plus the OAuth
   round-trip, and re-run the passive scanner to confirm the alert is gone.

### Step 6: Keep the always-on set
Regardless of migration state, these must already be present:
`default-src 'self'; base-uri 'self'; object-src 'none';
frame-ancestors 'none'; form-action 'self'` — plus `Strict-Transport-Security`
in production.

---

## SECURE PATTERNS

- Nonce per response, generated at exactly one layer (no per-page ad-hoc nonces)
- `strict-dynamic` for script loaders that inject dependencies
- Report-only first; enforcing after a clean report window
- Enumerated `connect-src` (explicit hosts only, no wildcards)

---

## AUDIT CHECKLIST

- [ ] Baseline CSP parsed and weak directives listed with line references
- [ ] Nonce generated per request at a single middleware/proxy layer
- [ ] Inline-dependency census complete (hydration, OAuth, themes, telemetry)
- [ ] No directive removed without proof of legitimate function
- [ ] Report-Only phase ran clean before enforcement
- [ ] Browser regression across all pages + OAuth round-trip passed
- [ ] `object-src`, `base-uri`, `frame-ancestors`, `form-action` locked
- [ ] HSTS present in production; scanner alert cleared

> Provenance: harvested from a CSP migration design (H14) including the current
> policy verbatim (unsafe-inline in script-src/style-src, enumerated
> connect-src) and the planned nonce-at-proxy approach with report-only
> rollout. Implementation detail (exact nonce mechanism, framework propagation)
> was not yet designed — treat this skill as the migration recipe, not a record
> of a completed migration.
