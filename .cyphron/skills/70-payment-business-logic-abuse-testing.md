# Skill 70 — Payment & Business-Logic Abuse Testing

> Cyphron's methodology for testing money-moving paths: forged/duplicate/
> out-of-order/reversal callbacks must never create duplicate commercial side
> effects. Built on canonical ledgers, atomic row-locked idempotency, and
> tenant binding from stored records — never caller data.

---

## WHEN TO ACTIVATE

- User builds/tests payment webhooks (Xendit, Midtrans, Stripe, ...) or order flows
- User asks "can someone get entitlement without paying?" / double-spend / replay
- User asks about price manipulation, concurrent callbacks, or reversal abuse
- User grants automated/AI tools any spending capability

---

## METHODOLOGY

### Step 1: The nine-callback abuse matrix
On staging (or mocked handlers), fire every class and assert **no duplicate
orders/invoices, no unearned entitlements**:
wrong signature · wrong amount · wrong tenant · duplicate · out-of-order ·
late · expired · reversal · concurrent.
Each must resolve to a single, correct ledger transition.

### Step 2: Canonical ledger + immutable idempotency
Payment state must bind to a canonical order/payment record. Idempotency is an
immutable record checked **inside the same atomic transaction** that performs
the effect (row-lock): `alreadyProcessed:true` must mean the store proves it —
not an in-memory flag that dies on restart.

### Step 3: Tenant binding from the ledger
Resolve the tenant from the stored payment row (e.g. `payments.externalId` —
the record created when the order was made), never from caller-supplied fields
in the callback body. A callback that references another tenant's order must be
rejected by that binding alone.

### Step 4: Amount/value verification server-side
The callback amount is a claim, not truth. Verify against the canonical order's
expected amount/currency before granting anything; mismatches are rejected and
logged.

### Step 5: Retry/timeout safety
Timeout-and-retry by the vendor must be harmless: replayed deliveries hit the
idempotency record and return the original outcome. Concurrent delivery of the
same event → exactly one transition wins (row-lock decides, not timestamps).

### Step 6: Reversal & expiry as explicit states
Refunds/void/expiry are modeled as state-machine transitions with allowed
predecessors — late or out-of-order events are rejected by the machine, not by
clock comparison.

### Step 7: Automated spend gating
Inbound AI/automated tools must not be able to spend merchant balance unless an
explicitly approved, gated capability is enabled. Treat tool-mediated spend as a
separate authorization surface from webhook spend.

---

## SECURE PATTERNS

- Webhook token + HMAC signature verification with `timingSafeEqual` before lookup
- Atomic transaction with row-locked idempotency check (`alreadyProcessed`)
- Tenant from `externalId` ledger binding; caller fields are claims, not facts
- Explicit state machine with allowed transitions; timestamps are not authorization
- Gated capability flags for any tool/AI-initiated spend

---

## AUDIT CHECKLIST

- [ ] All nine abuse classes tested (mocked or staging), single transition each
- [ ] Concurrent duplicate delivery → one effect, decided by row-lock
- [ ] Amount verified server-side against the canonical order
- [ ] Tenant resolved from ledger, immune to caller payload
- [ ] Reversal/expiry are explicit transitions; no clock-only logic
- [ ] Vendor retry storm produces zero second effects
- [ ] AI/tool spend paths are behind explicit gates
- [ ] Findings labeled honestly: design-level (DIUSULKAN) results are
      `success_criteria`, not executed evidence, until staged

> Provenance: harvested from a payment/order abuse replay plan (§5.7 verbatim)
> plus source-verified controls (webhook token + Midtrans signature, atomic
> row-locked idempotency at billing/webhook route, tenant-from-externalId).
> Status of the end-to-end staging run: DIUSULKAN — methodology is real,
> execution evidence pending.
