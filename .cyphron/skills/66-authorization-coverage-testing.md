# Skill 66 — Authorization Coverage Testing (Route Matrix & Tenant Isolation)

> Cyphron's methodology for proving that EVERY API route carries the correct
> authorization guard, and that multi-tenant boundaries actually hold — using a
> static route-inventory matrix plus behavioral cross-tenant tests. This is the
> executable answer to "are we sure no endpoint is unprotected?"

---

## WHEN TO ACTIVATE

- User asks "are all my API routes protected?" / "audit semua endpoint"
- User asks about route authorization matrix or endpoint guard inventory
- User asks "tenant A could access tenant B data?" / multi-tenant isolation testing
- User asks about IDOR at route/resource level, or missing auth on new endpoints
- User adds a new public API exemption and wants to verify it does not remove tenant binding

---

## METHODOLOGY

### Step 1: Build the route inventory (static)
Walk the filesystem for route definitions (e.g. `src/app/api/**/route.ts`) and
produce the complete endpoint list. Do not trust documentation — the filesystem
is the source of truth.

### Step 2: Classify the caller model per route
Classify every route into exactly one class, ideally codified in a single policy
module (single source of truth):
- **public-exact** — webhook/health/media/registration endpoints, exact-match only
- **public-prefix** — e.g. `/api/auth`
- **self-authenticated** — API-key callers, e.g. prefix `/api/v1`
- **admin** — prefix plus an explicit non-prefix exception list
- **session-gated** — everything else (default)

### Step 3: Two-way inventory assertion
Assert `inventory == filesystem` in both directions: `unexpected` and `missing`
must both be empty. A new route without a classification breaks the check.

### Step 4: Assert in-source guards per class
For each route, grep its source for the expected guard markers:
- webhook class → signature verifier calls (`isValidMetaSignature`,
  `verifyWebhookToken`, `timingSafeEqual`, source-IP allowlist, webhook secret)
- self-authenticated → API-key validation call
- admin → `auth()` + role predicate `"admin"`
- session → `requireAuth(` / `auth()` **plus a tenant predicate**
  (`userId` / `parentTenantId`) on every dynamic resource route
- custom → explicit rate limiting
Record violations as `{route, expected_guard, actual}`.

### Step 5: Behavioral cross-tenant tests
For every resource-bearing route, run a matrix of callers against resources of
two tenants (A and B):

| Caller | Own resource (A) | Other tenant (B) | Anonymous |
|---|---|---|---|
| owner A | 200 + correct body | **404** + B untouched | — |
| operator A (has parentTenantId) | policy-decided (e.g. 403 on delete) | **404/403** | — |
| tenant B | — | 200 | — |
| anonymous | — | — | **401** |

Assert **store state, not just status codes**: after every mutation attempt
against B, verify B's rows still exist and are unchanged (handler fields,
assigned operator, team membership). Status-code-only assertions hide silent
writes.

### Step 6: Include provenance/legacy filters
Legacy or provider-specific data (e.g. records with
`sourceProvider:"legacy"`) may be intentionally invisible even to their owner —
assert this as expected 404 behavior, not as a bug.

### Step 7: Lifecycle edge assertions
- admin role transitions: grant (`make_admin`), revoke on self (400), non-admin
  → 403, anonymous → 401
- scoped-key replay across tenants: a key belonging to tenant A must create/act
  only inside A, never touch B — even with identical business payloads

---

## SECURE PATTERNS

- **Policy-as-code**: one policy module classifies all routes; tests import it,
  never re-implement it.
- **Two-way inventory test** in CI — a route added without a guard fails the
  build before merge.
- **Store-level assertions** after every cross-tenant mutation attempt.
- **Distinct fixtures** per role (owner / operator / admin / anonymous) with
  fixed tenant UUIDs for determinism.
- **Reviewed exceptions list**: proxy-only routes and non-prefix admin routes
  live in explicit, commented allowlists.

---

## AUDIT CHECKLIST

- [ ] Every route classified, both inventory directions asserted empty
- [ ] Tenant predicate asserted on every dynamic resource route
- [ ] Cross-tenant mutation asserted at the store level (rows unchanged)
- [ ] Provenance/legacy filter behavior asserted explicitly
- [ ] Admin role transitions tested (grant / revoke-self / non-admin / anon)
- [ ] Scoped-key replay tested across tenant boundaries
- [ ] Route-inventory test wired into CI as a merge gate
- [ ] Every allowlisted exception has a review note

> Provenance: harvested from a real authorization-matrix suite (103 routes,
> two-way assert) and a 15-scenario cross-tenant isolation suite; see
> `.kimchi/pentest/offensive-skills.md` §6 and cyphron ROADMAP R1
> (assisted route-inventory mode).
