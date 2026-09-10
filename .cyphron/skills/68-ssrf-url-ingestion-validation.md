# Skill 68 — SSRF & URL Ingestion Validation Testing

> Cyphron's methodology for testing any feature that fetches a user-supplied URL:
> a single deny-by-default validator, all DNS answers checked, automatic
> redirects disabled, and the TOCTOU (DNS-rebinding) window measured and closed.

---

## WHEN TO ACTIVATE

- User asks "is my URL fetch safe from SSRF?" / "url validation aman gak"
- User builds media/document ingestion by URL (image proxy, importer, webhook media)
- User asks about cloud metadata endpoints, loopback/internal access via fetch
- User asks about DNS rebinding or redirect-based SSRF bypass

---

## METHODOLOGY

### Step 1: One choke point
Every external fetch must pass through a single validator module. Find all
fetch/http call-sites; any fetch that bypasses the choke point is a finding.

### Step 2: Deny-by-default URL grammar
Reject at the string layer before any network activity:
- non-HTTP(S) schemes
- `localhost` and its variants (`*.localhost`, `*.local`, `*.internal`,
  `metadata.google.internal`)
- embedded credentials (`https://user:pass@host/...`)
- IPv4 literals in blocked ranges: loopback `127.0.0.0/8`, RFC1918
  `10/8, 172.16/12, 192.168/16`, link-local `169.254/16` (cloud metadata),
  `0.0.0.0`, CGNAT `100.64/10`, broadcast
- IPv6: normalize bracketed forms first, then check `::1`, `fc00::/7`,
  `fe80::/10`, `::ffff:` mapped IPv4
- non-standard encodings: decimal/octal/hex integer IPs, short-form IPs

### Step 3: Validate ALL DNS answers
Resolve the hostname with **all** address records (A + AAAA, e.g.
`dns.lookup(host, {all: true, verbatim: true})`) and validate every returned
address — not just the first. One poisoned answer must fail the whole request.

### Step 4: Disable automatic redirects
Redirects are followed **manually** only: each hop re-enters the validator.
Rationale (mechanism, not style): automatic redirect following can land on a
host that was never validated — the initial URL check is bypassed by the second
hop. `redirect: "manual"` makes the second hop never happen without approval.

### Step 5: Shrink the TOCTOU window
Resolve named hosts **immediately before connecting** so the validated name and
the connected address are the same observation. If the runtime cannot pin the
connect-time IP, compensate at the network layer (egress firewall on the app
container that denies private ranges) and document the residual window.

### Step 6: Resource limits
Byte-limit the response **before** reading it into memory (`arrayBuffer()` /
`resp.read()`); parse media in an isolated context with its own timeout.
Require HTTPS per call-site where the provider supports it.

### Step 7: Corpus
Test at minimum: `http://localhost/x`, `http://[::1]/x`,
`http://metadata.google.internal/computeMetadata/v1/`, `https://svc.internal/x`,
`https://user:pass@example.test/x`, `http://2130706433/` (decimal IP),
`http://0x7f000001/` (hex), `http://169.254.169.254/latest/meta-data/`,
`http://[::ffff:127.0.0.1]/x`. Expected: every one rejected by the validator.

---

## SECURE PATTERNS

- Deny-by-default range set; normalize → check → resolve → connect, in that order
- All-DNS-answers validation (`all: true`), never first-answer-only
- Manual redirect handling; per-hop re-validation
- `requireHttps` option per call-site for provider integrations
- One validator module + unit-test corpus in CI; byte limits before buffering

---

## AUDIT CHECKLIST

- [ ] All fetch call-sites route through the single validator
- [ ] IPv6, mapped-IPv4, and integer encodings covered (not just dotted quad)
- [ ] All DNS answers validated, not only the first record
- [ ] Automatic redirects disabled; hops re-validated
- [ ] Cloud metadata + internal suffixes rejected
- [ ] DNS-rebinding window: measured, then closed (pinning) or compensated (egress firewall)
- [ ] Byte/pixel limits applied before buffering; parser isolated
- [ ] Validator corpus runs in CI (offline, no real DNS in unit mode)

> Provenance: harvested from SSRF validation unit suites (offline rejection
> corpus, all-DNS-answers via verbatim lookup, manual redirects with the
> documented TOCTOU rationale) — see also cyphron ROADMAP R1 engine
> `ssrf_probe` (stdlib urlparse + ipaddress + socket).
