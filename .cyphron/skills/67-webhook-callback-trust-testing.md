# Skill 67 — Webhook & Callback Trust Testing

> Cyphron's methodology for testing inbound webhook/callback trust: authenticity
> before lookup, credential-bound tenant resolution, vendor allowlisting, and
> idempotency/replay suppression that makes duplicate deliveries harmless.

---

## WHEN TO ACTIVATE

- User asks about webhook signature verification or forged callbacks
- User asks "duplicate webhook delivery / replay" or idempotency-key design
- User integrates a messaging/payment vendor (WhatsApp gateways, Xendit, Midtrans,
  Telegram, Meta) and wants the callback path tested
- User asks about fail-closed behavior on ambiguous callbacks
- User asks "provider called twice?" / double-delivery safety

---

## METHODOLOGY

### Step 1: Authenticity BEFORE any lookup
The very first action on an inbound callback is signature/HMAC/token
verification using `timingSafeEqual`. Unsigned or forged requests are rejected
at the gate — **before** any tenant lookup, before any store read, before any
queue enqueue. Log the rejection with the source IP.

### Step 2: Credential-bound tenant resolution
The tenant must be resolved from trusted, stored data — the verified signature
payload or an internal record (e.g. resolve via `payments.externalId`), **never**
from caller-supplied fields such as body `tenantId`, `phone`, or headers.
Ambiguity (two providers/tenants could match) must **fail closed**: reject or
ignore, never guess, never 500-crash into retries.

### Step 3: Vendor source allowlisting
Known provider hops get an explicit source-IP allowlist (CIDR). Forwarded
headers from the vendor are treated as untrusted unless the proxy trust config
(see Skill 69) matches real infrastructure.

### Step 4: Idempotency & replay suppression
- Key: business-supplied `Idempotency-Key`; validate format server-side
  (length bounds, no CR/LF).
- Storage: **tenant-scoped digest** — `sha256(tenantId + "\n" + rawKey)` —
  stored on the business row itself. The raw key is never persisted. No TTL
  unless the business demands expiry (key stays valid as long as the row exists).
- Flow: lookup before dispatch → insert-first as a reservation state →
  race fallback re-select → respond `replayed:true` with the original result;
  reservation failure → 409.
- **A unique index on the digest column is mandatory** — an error-catching
  pattern around insert is NOT a substitute; confirm the index in the schema.

### Step 5: The nine-callback matrix
Test every class and assert **single side effect**:

| Callback class | Expected |
|---|---|
| unsigned / wrong signature | rejected at gate, 0 side effects |
| wrong amount/value | rejected against canonical record |
| wrong tenant | rejected (tenant from ledger, not caller) |
| duplicate | `replayed:true` / `alreadyProcessed:true`, provider called exactly once |
| out-of-order / late / expired | rejected by state machine, not timestamps alone |
| reversal | correct compensating transition, no double credit |
| concurrent | exactly one transition wins |

### Step 6: Duplicate-job suppression
Duplicate vendor deliveries must yield the **identical job id** — dedup at
enqueue, not at processing.

---

## SECURE PATTERNS

- Verify-then-resolve: signature check precedes every other action.
- Tenant-scoped digests; raw keys never stored.
- Insert-first reservation with race fallback; unique index under it.
- Exact-match CIDR allowlists per vendor; ambiguity fails closed.
- Replay responses are logged — replay monitoring is free evidence.

---

## AUDIT CHECKLIST

- [ ] Unsigned/forged rejected before any lookup or enqueue
- [ ] Tenant resolved from stored/verified data only
- [ ] Ambiguous callback fails closed (never guessed)
- [ ] Idempotency digest is tenant-scoped and schema has the unique index
- [ ] Duplicate delivery → same job id, provider called exactly once
- [ ] All nine callback classes tested on staging (or unit-mocked)
- [ ] Reversal and expiry paths have explicit state transitions
- [ ] Same idempotency pattern applied to every new money-moving path

> Provenance: harvested from webhook-authenticity, idempotency/replay, and
> provider-readiness suites (tenant-scoped SHA-256 digest, no TTL, insert-first
> reservation) plus a payment-abuse plan §5.7. DIUSULKAN items carry
> `success_criteria`, not executed evidence — label test results accordingly.
