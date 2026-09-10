# Skill 12 — OWASP Top 10 Hardening

> Cyphron's methodology for hardening applications against the OWASP Top 10. Cyphron knows each vulnerability class in depth — every variant, every bypass — so it produces hardening guides that close every known attack path, not just the obvious ones.

---

## WHEN TO ACTIVATE

- User asks about OWASP Top 10 (2021 or 2017)
- User asks to harden against a specific OWASP category (A01-A10)
- User asks "how do I prevent [vulnerability class]?"
- User asks for a security hardening checklist
- User asks about a specific vulnerability class broadly

---

## OWASP TOP 10 (2021) — HARDENING GUIDE

### A01:2021 — Broken Access Control

**Attack mechanism:** Users access resources or perform actions beyond their authorized level — viewing other users' data (IDOR), accessing admin functions, bypassing API restrictions.

**Hardening checklist:**
- [ ] Implement object-level authorization (check ownership on every object access)
- [ ] Default-deny: deny access unless explicitly granted
- [ ] Validate every request through authorization middleware (not just at login)
- [ ] Use indirect references (map user-facing IDs to internal IDs per session)
- [ ] Enforce authorization on both client and server (server is authoritative)
- [ ] Invalidate JWT/session on logout and password change
- [ ] Implement rate limiting on API endpoints
- [ ] Log all access control failures
- [ ] Test for IDOR: user A cannot access user B's resources
- [ ] Test for privilege escalation: regular user cannot access admin endpoints

```javascript
// Object-level authorization on every access
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await db.getOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (order.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});
```

---

### A02:2021 — Cryptographic Failures

**Attack mechanism:** Sensitive data exposed due to weak or missing encryption — plaintext passwords, weak hashing, no TLS, hardcoded keys.

**Hardening checklist:**
- [ ] Classify data by sensitivity; encrypt sensitive data at rest and in transit
- [ ] Use TLS 1.2+ everywhere; disable TLS 1.0/1.1, SSLv3
- [ ] Use strong ciphers; disable weak ciphers (RC4, 3DES, CBC without MAC)
- [ ] Hash passwords with Argon2id/bcrypt/scrypt (never MD5/SHA1/plaintext)
- [ ] Use AEAD for encryption (AES-GCM, ChaCha20-Poly1305); never ECB
- [ ] Generate keys with CSPRNG; store in KMS/vault (never in code)
- [ ] Rotate keys periodically
- [ ] Disable caching for sensitive responses (`Cache-Control: no-store`)
- [ ] Don't return sensitive data in API responses unless needed
- [ ] Use HSTS header

---

### A03:2021 — Injection

**Attack mechanism:** Untrusted data sent to an interpreter as part of a command or query — SQLi, NoSQLi, command injection, LDAP injection, XPath injection, SSTI.

**Hardening checklist:**
- [ ] Use parameterized queries / prepared statements (ALL database access)
- [ ] Use ORM with parameterization (verify it doesn't allow raw queries with concatenation)
- [ ] For NoSQL: enforce type checking on inputs (prevent operator injection)
- [ ] For commands: use argument arrays, never shell=True with user input
- [ ] Validate input with allowlists (type, length, format, range)
- [ ] For template engines: never concatenate user input into template strings
- [ ] For LDAP: use parameterized LDAP queries
- [ ] For XPath: use parameterized XPath
- [ ] Deploy WAF as defense-in-depth (not primary defense)
- [ ] Test with injection payloads in CI/CD

---

### A04:2021 — Insecure Design

**Attack mechanism:** Security flaws built into the architecture — missing rate limiting, no threat modeling, insecure business logic.

**Hardening checklist:**
- [ ] Threat model every new feature before implementation
- [ ] Implement rate limiting on all entry points
- [ ] Design for fail-safe defaults (deny on error)
- [ ] Implement separation of duties for sensitive operations
- [ ] Design logging and monitoring from the start
- [ ] Use security user stories in requirements
- [ ] Implement business logic limits (max transfer amount, max items per order)
- [ ] Design for defense in depth
- [ ] Plan for abuse cases, not just use cases

---

### A05:2021 — Security Misconfiguration

**Attack mechanism:** Systems configured insecurely — default credentials, verbose errors, unnecessary features enabled, missing security headers.

**Hardening checklist:**
- [ ] Disable default accounts and change default passwords
- [ ] Disable unnecessary features, ports, services, accounts
- [ ] Remove default/unused framework pages and documentation
- [ ] Set secure headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] Disable directory listing
- [ ] Use generic error messages in production (no stack traces)
- [ ] Disable debug mode in production
- [ ] Secure cloud storage (no public S3 buckets unless intended)
- [ ] Use Infrastructure as Code with security policies
- [ ] Regularly scan for misconfigurations (Scout Suite, Prowler)

```nginx
# Nginx security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "0" always;  # deprecated, use CSP instead
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

### A06:2021 — Vulnerable and Outdated Components

**Attack mechanism:** Known vulnerabilities in dependencies exploited for access or RCE.

**Hardening checklist:**
- [ ] Inventory all dependencies (SBOM)
- [ ] Monitor for CVEs in dependencies (Dependabot, Snyk, npm audit)
- [ ] Remove unused dependencies
- [ ] Pin dependency versions (no `*` or `latest`)
- [ ] Verify dependencies (checksums, signatures)
- [ ] Update dependencies regularly (scheduled, not ad-hoc)
- [ ] Use vendored/private package registry for critical dependencies
- [ ] Scan container images for vulnerabilities (Trivy, Grype)
- [ ] Review transitive dependencies
- [ ] Subscribe to security advisories for critical libraries

---

### A07:2021 — Identification and Authentication Failures

**Attack mechanism:** Weak authentication allows attackers to compromise accounts — brute force, credential stuffing, session hijacking, weak password policies.

**Hardening checklist:**
- [ ] Implement MFA for all accounts (especially admin)
- [ ] Enforce strong password policy (length > complexity, check against breached passwords)
- [ ] Rate limit login attempts (per account AND per IP)
- [ ] Use generic error messages ("Invalid credentials" not "User not found")
- [ ] Regenerate session ID after login (prevent fixation)
- [ ] Set secure cookie flags: HttpOnly, Secure, SameSite
- [ ] Short session timeout; sliding only with activity
- [ ] Implement account lockout with secure unlock
- [ ] Check passwords against breach databases (HIBP API)
- [ ] Secure password reset: random tokens, short expiry, one-time use
- [ ] Log all authentication events

---

### A08:2021 — Software and Data Integrity Failures

**Attack mechanism:** Code or data whose integrity isn't verified — unsigned updates, untrusted CI/CD, insecure deserialization.

**Hardening checklist:**
- [ ] Sign all software releases (Cosign, GPG)
- [ ] Verify signatures before deployment
- [ ] Use signed dependencies (verify checksums)
- [ ] Secure CI/CD pipeline (separate build/deploy permissions, signed commits)
- [ ] Never deserialize untrusted data (use JSON, not native serialization)
- [ ] If deserialization is unavoidable, use allowlists of allowed classes
- [ ] Implement integrity checks on critical data (HMAC)
- [ ] Use Subresource Integrity (SRI) for external scripts
- [ ] Verify Docker image digests, not just tags

---

### A09:2021 — Security Logging and Monitoring Failures

**Attack mechanism:** Attacks go undetected because logging and monitoring are insufficient.

**Hardening checklist:**
- [ ] Log all security events: auth, authz, access, changes, errors
- [ ] Include sufficient context: who, what, when, where, source IP
- [ ] Send logs to centralized, tamper-proof storage
- [ ] Set up alerts for: failed logins, privilege escalation, data access anomalies
- [ ] Monitor for impossible travel, unusual access patterns
- [ ] Implement SIEM or log analysis pipeline
- [ ] Test alerting (inject test events, verify alerts fire)
- [ ] Retain logs per compliance requirements
- [ ] Don't log sensitive data (passwords, tokens, PII)
- [ ] Ensure logs have timestamps (UTC, synchronized)

---

### A10:2021 — Server-Side Request Forgery (SSRF)

**Attack mechanism:** Server makes requests to attacker-specified URLs — accessing internal services, cloud metadata, or internal network.

**Hardening checklist:**
- [ ] Validate and allowlist URLs (scheme, host, port)
- [ ] Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
- [ ] Block cloud metadata endpoints (169.254.169.254)
- [ ] Block non-HTTP schemes (file://, gopher://, ftp://, dict://)
- [ ] Use a network allowlist (egress firewall) for outbound requests
- [ ] Don't follow redirects when fetching user-specified URLs
- [ ] Use a dedicated egress proxy with allowlist
- [ ] Disable DNS rebinding (resolve once, use resolved IP)
- [ ] Log all outbound requests made by the server

```python
# SSRF protection — URL validation
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_PORTS = {80, 443}

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme {parsed.scheme} not allowed")
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise ValueError(f"Port {parsed.port} not allowed")

    # Resolve hostname and check it's not internal
    ip = socket.gethostbyname(parsed.hostname)
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError("Internal IP addresses are not allowed")

    return url
```

---

## OUTPUT FORMAT

When hardening against a specific OWASP category:

```markdown
## 🛡️ Hardening Guide: [OWASP Category]

### Attack Mechanism
[How this vulnerability class works — mechanistically]

### Hardening Checklist
- [ ] [control 1]
- [ ] [control 2]
...

### Implementation
```lang
[code implementing the controls]
```

### Verification
```lang
[test proving the hardening works]
```

### Detection
```lang
[detection rule for this attack class]
```
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — detailed attack mechanisms per class
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — secure implementations
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — fix recipes
