# Skill 69 — Proxy & Origin Trust Verification

> Cyphron's methodology for testing client-IP trust: a single resolver with
> right-to-left trusted-proxy walking, fail-closed behavior without config,
> header-overwrite contracts at the reverse proxy, direct-origin bypass
> resistance, and the DNS-rebinding window.

---

## WHEN TO ACTIVATE

- User asks "can someone spoof their IP with X-Forwarded-For?" / "client ip aman?"
- User configures TRUSTED_PROXIES, nginx, Cloudflare, or any reverse proxy
- User asks about rate-limit bypass via forged headers
- User asks about direct-origin access or DNS rebinding on a VPS deployment

---

## METHODOLOGY

### Step 1: One resolver, socket-first
There must be exactly one `resolveClientIp` function used everywhere. Semantics:
1. Take the socket peer address as ground truth (`request.ip` → `socket` →
   `connection`).
2. If the socket peer is in TRUSTED_PROXIES → walk `X-Forwarded-For`
   **right-to-left** and return the first hop that is NOT trusted.
3. If the socket exists but is not trusted → use the socket; **ignore headers**.
4. Header-only contexts (e.g. middleware without socket) may walk XFF only when
   TRUSTED_PROXIES is configured.
5. Non-production-only fallbacks (`x-real-ip`, `cf-connecting-ip`,
   `fly-client-ip`, `true-client-ip`) are disabled in production.
6. Production without valid config → `null` → callers map to one shared bucket
   (`"unknown"`). **Fail-closed**: better one shared rate-limit bucket than an
   attacker-controlled identity.

### Step 2: Wildcard rejection
`TRUSTED_PROXIES: *` means "all hops trusted" — reject it at boot in production
via environment validation, before any request is served.

### Step 3: Forged-chain test set
Assert resolver behavior against these chains (documentation ranges):

| Input | Config | Expected result |
|---|---|---|
| `X-Forwarded-For: 1.2.3.4, 5.6.7.8` | none | `null` (headers ignored) |
| `X-Forwarded-For: 203.0.113.7, 10.1.2.3, 10.1.2.4` | `10.0.0.0/8` | `203.0.113.7` (rightmost non-trusted) |
| `X-Forwarded-For: 6.6.6.6, 7.7.7.7` | trusted proxy present | `7.7.7.7` (proves not-leftmost) |
| fake headers + socket `192.0.2.9` | peer not trusted | socket wins |

### Step 4: Reverse-proxy overwrite contract
nginx (or any edge) must **overwrite**, never append/echo, caller-supplied
`X-Real-IP`, `X-Forwarded-For`, and `CF-Connecting-IP`. Test by sending forged
chains (e.g. `X-Forwarded-For: 203.0.113.10, 10.0.0.5`) with `curl` directly to
the origin IP versus through the domain: the origin must never see attacker
values, and the vendor allowlist hop (source-IP check) must observe the real hop.

### Step 5: Direct-origin bypass resistance
The origin accepts traffic only from the proxy (host firewall / security group).
Direct `curl` to origin IP must fail. TLS termination, HSTS, request/body
limits, SSE/WebSocket behavior, and certificate renewal must still work after a
restart.

### Step 6: DNS rebinding (TOCTOU)
Resolve immediately before connect; pin the connect-time IP where the runtime
allows. If pinning is not portable (some runtimes), document a measured
compensating control: egress firewall on the app container denying private
ranges. Optionally measure the window with an alternating public→private DNS
answer — as a **measurement**, not an attack on others.

### Step 7: Rate-limit collapse check
Without valid proxy config, all clients share the `"unknown"` bucket — verify
this is an explicit, accepted behavior (fail-closed), and that no consumer
computes IP identity outside the single resolver.

---

## SECURE PATTERNS

- Right-to-left walk; leftmost header is never trusted
- Boot-time env validation rejecting wildcards in production
- Fail-closed shared bucket; spoofing must never mint new identity buckets
- Proxy `set` (overwrite) semantics for all forwarding headers
- Origin firewall: proxy-only ingress; vendor allowlist sees the real hop

---

## AUDIT CHECKLIST

- [ ] One `resolveClientIp` used by every consumer (no ad-hoc header reads)
- [ ] Leftmost-XFF never returned; right-to-left walk asserted by tests
- [ ] Wildcard TRUSTED_PROXIES rejected at boot in production
- [ ] All three forwarding headers overwritten at the edge (not appended)
- [ ] Direct-origin connections refused; survives restart
- [ ] Vendor source-IP allowlist checks see the intended hop
- [ ] DNS-rebinding window closed (pinning) or compensated (egress firewall) and documented
- [ ] Rate-limit identity cannot be minted by attacker headers

> Provenance: harvested from trusted-proxy/XFF spoof suites (resolver semantics,
> forged chain vectors, boot-time wildcard rejection), the planned reverse-proxy
> verification (nginx overwrite contract), and the DNS-rebinding measurement
> design (H9). Reverse-proxy parts are design-level (DIUSULKAN) — label as
> unverified until executed on the VPS.
