# Attack Encyclopedia

> Cyphron's reference catalog of attack techniques. This knowledge is used to build precise defenses — understanding exactly how an attack works allows Cyphron to create targeted mitigations, detection rules, and secure implementations. **This is reference knowledge for defense, not an attack manual.**

---

## HOW TO USE THIS DOCUMENT

When Cyphron needs to explain an attack mechanism, build a detection rule, or design a mitigation, it references this catalog. Each entry contains:
- **Mechanism**: How the attack works (the "why")
- **Indicators**: What the attack looks like (for detection)
- **Root cause**: What mistake makes it possible
- **Defense**: How to prevent it

---

## 1. INJECTION ATTACKS

### 1.1 SQL Injection (SQLi)

**Mechanism:** User input concatenated into a SQL query string alters the query's structure, allowing an attacker to execute arbitrary SQL.

**Variants:**
| Variant | How It Works | Detection Indicator |
|---|---|---|
| Union-based | `UNION SELECT` appends results from other tables | `UNION SELECT` in parameters |
| Boolean-blind | No data returned, but true/false responses reveal data | Repeated requests with boolean logic |
| Time-blind | `SLEEP()` or `BENCHMARK()` delays response | Slow responses to specific payloads |
| Error-based | DB error messages leak data | DB errors in HTTP responses |
| Second-order | Input stored safely, used unsafely in later query | Stored data appearing in queries |
| Stacked | `;` allows executing multiple statements | `;` followed by SQL keywords |

**Root cause:** String concatenation of user input into SQL queries.

**Defense:** Parameterized queries / prepared statements. The database separates code (query structure) from data (user values), making injection impossible.

---

### 1.2 NoSQL Injection

**Mechanism:** In MongoDB and similar, passing objects like `{"$ne": null}` as query values can match all documents, bypassing authentication.

**Example:** `db.users.find({ email: req.body.email })` where `req.body.email = {"$ne": null}` matches all users.

**Root cause:** Not enforcing type on input; accepting objects where strings expected.

**Defense:** Enforce type (`String(req.body.email)`), use schema validation, sanitize operators.

---

### 1.3 Command Injection

**Mechanism:** User input concatenated into an OS command allows an attacker to execute arbitrary commands via shell metacharacters (`;`, `|`, `&&`, backticks, `$()`).

**Root cause:** Using `shell=True` / `exec()` with user input instead of argument arrays.

**Defense:** Use argument arrays (`execFile(['cmd', arg])`), never `shell=True` with user input.

---

### 1.4 LDAP Injection

**Mechanism:** User input in LDAP queries allows altering the query logic, similar to SQLi but with LDAP syntax (`*)(uid=*`).

**Defense:** Parameterized LDAP queries, input validation (allowlist characters).

---

### 1.5 XPath Injection

**Mechanism:** User input in XPath queries alters the query to extract data.

**Defense:** Parameterized XPath, input validation.

---

### 1.6 Template Injection (SSTI)

**Mechanism:** User input concatenated into a template string is evaluated by the template engine, allowing code execution.

**Example:** `render_template_string("Hello " + user_input)` where `user_input = {{7*7}}` renders as `49`. More advanced payloads achieve RCE.

**Root cause:** Concatenating user input into template strings instead of passing as variables.

**Defense:** Never concatenate user input into template strings. Pass as variables: `render_template_string("Hello {{name}}", name=user_input)`.

---

### 1.7 Expression Language Injection

**Mechanism:** User input in expression language (Spring SpEL, OGNL, JBoss EL) is evaluated, allowing code execution.

**Notable:** CVE-2017-5638 (Equifax breach) — Struts2 OGNL injection.

**Defense:** Never pass user input to expression evaluators. Disable expression evaluation where not needed.

---

## 2. CROSS-SITE SCRIPTING (XSS)

### 2.1 Reflected XSS

**Mechanism:** User input in URL is reflected in the HTTP response without encoding, executing in the victim's browser.

**Example:** `https://site.com/search?q=<script>alert(1)</script>`

**Defense:** Output encoding (context-appropriate), CSP.

---

### 2.2 Stored XSS

**Mechanism:** Attacker stores malicious payload in the database (e.g., in a comment). When other users view the page, the payload executes.

**Impact:** Much higher than reflected — affects all viewers, no user interaction needed beyond visiting the page.

**Defense:** Output encoding on render, input validation (reduce attack surface), CSP.

---

### 2.3 DOM-Based XSS

**Mechanism:** Client-side JavaScript writes user-controlled data to the DOM without encoding. The payload never touches the server.

**Example:** `document.getElementById('out').innerHTML = location.hash.substring(1)`

**Defense:** Use `textContent` instead of `innerHTML`, DOMPurify for HTML, CSP with `nonce` or `hash`.

---

### 2.4 Mutation XSS (mXSS)

**Mechanism:** Browser HTML parsing "mutates" the input in ways that bypass server-side sanitization, creating valid XSS after the browser re-parses.

**Defense:** Use well-tested sanitization libraries (DOMPurify) that account for mutation behavior, not custom regex.

---

### 2.5 XSS Context Variants

The payload form depends on where input lands:
| Context | Example Payload Pattern | Defense |
|---|---|---|
| HTML body | `<script>alert(1)</script>` | HTML entity encoding |
| HTML attribute | `" onfocus="alert(1)` | Attribute encoding + quotes |
| JavaScript string | `';alert(1)//` | JS string encoding |
| URL | `javascript:alert(1)` | URL scheme validation |
| CSS | `expression(alert(1))` | Don't allow user input in CSS |
| SVG | `<svg onload=alert(1)>` | Sanitize SVG, encode |

---

## 3. AUTHENTICATION ATTACKS

### 3.1 Brute Force

**Mechanism:** Systematically trying all possible passwords for a known username.

**Defense:** Rate limiting (per account AND per IP), account lockout, MFA, progressive delays.

---

### 3.2 Credential Stuffing

**Mechanism:** Using username/password pairs from one breach to log into other services (users reuse passwords).

**Defense:** Breached password checking (HIBP API), MFA, anomaly detection (impossible travel), CAPTCHA.

---

### 3.3 Password Spraying

**Mechanism:** Trying one common password against many usernames (avoids per-account lockout).

**Defense:** Per-IP rate limiting, account-level monitoring, CAPTCHA, MFA.

---

### 3.4 Session Fixation

**Mechanism:** Attacker sets the victim's session ID to a known value, then waits for them to authenticate. The session ID isn't regenerated after login, so the attacker shares the authenticated session.

**Defense:** Regenerate session ID after login (`req.session.regenerate()`).

---

### 3.5 Session Hijacking

**Mechanism:** Stealing a valid session token (via XSS, network sniffing, predictable IDs).

**Defense:** HttpOnly + Secure + SameSite cookies, TLS, CSP (prevent XSS), sufficient session ID entropy (128+ bits from CSPRNG).

---

### 3.6 JWT Attacks

| Attack | Mechanism | Defense |
|---|---|---|
| Algorithm confusion | Attacker changes `alg` to `none` or switches RS256→HS256 | Explicit `algorithms: ['RS256']` allowlist |
| Signature stripping | Remove signature, set `alg: none` | Reject `none` algorithm |
| Key confusion | Use public key as HMAC secret | Don't mix symmetric/asymmetric |
| Weak secret | Brute-force HMAC secret | Use 256-bit random secrets |
| Claim manipulation | Modify payload, re-sign if key known | Verify signature + all claims |

---

### 3.7 OAuth Attacks

| Attack | Mechanism | Defense |
|---|---|---|
| Redirect hijack | Attacker intercepts redirect with auth code | Exact redirect URI matching, state parameter |
| Token theft | Steal access/refresh token | PKCE, short-lived tokens, secure storage |
| Scope escalation | Request more scopes than granted | Server-side scope validation |
| Account linking abuse | Link attacker's account to victim's identity | Verify email ownership before linking |

---

## 4. ACCESS CONTROL ATTACKS

### 4.1 IDOR (Insecure Direct Object Reference)

**Mechanism:** Application uses user-supplied object IDs without checking ownership. User A accesses User B's data by changing the ID.

**Example:** `/api/orders/123` → change to `/api/orders/124` → see someone else's order.

**Defense:** Object-level authorization on every access: verify the requesting user owns (or is authorized for) the object.

---

### 4.2 Privilege Escalation

**Mechanism:** User accesses functionality above their privilege level — either vertical (user→admin) or horizontal (user→another user).

**Vertical:** Accessing `/admin/deleteUser` as a regular user.
**Horizontal:** Accessing another user's account settings.

**Defense:** Authorization checks on every request, default-deny, role-based access control.

---

### 4.3 Forced Browsing

**Mechanism:** Accessing pages/resources by guessing URLs, bypassing navigation-based access control.

**Defense:** Default-deny authorization (check on every request, not just navigation), server-side access control.

---

### 4.4 Path Traversal

**Mechanism:** User input in file paths allows escaping the intended directory (`../../../etc/passwd`).

**Variants:** `../`, `..\`, `%2e%2e%2f`, `....//`, double encoding, null bytes.

**Defense:** Canonicalize path, verify it's within the allowed base directory. Use `path.resolve()` + prefix check.

---

## 5. SERVER-SIDE ATTACKS

### 5.1 SSRF (Server-Side Request Forgery)

**Mechanism:** Server makes HTTP requests to attacker-specified URLs, allowing access to internal services, cloud metadata, or localhost.

**High-value targets:** Cloud metadata endpoints (`169.254.169.254`), internal admin panels, localhost services.

**Defense:** URL allowlist (scheme, host, port), block private/internal IPs, block metadata endpoints, egress firewall, don't follow redirects.

---

### 5.2 XXE (XML External Entity)

**Mechanism:** XML parser processes external entity definitions, allowing file read, SSRF, or DoS.

**Example:** `<!ENTITY xxe SYSTEM "file:///etc/passwd">`

**Defense:** Disable external entity processing in XML parsers. Use `libxml2` with `NOENT` disabled, or JSON instead of XML.

---

### 5.3 Deserialization Attacks

**Mechanism:** Deserializing untrusted data allows code execution (language-specific: Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter`).

**Defense:** Never deserialize untrusted data. Use JSON. If unavoidable, use allowlists of permitted classes.

---

### 5.4 Race Conditions (TOCTOU)

**Mechanism:** Time-of-check to time-of-use gap allows an attacker to modify state between a check and its use.

**Example:** Balance check → transfer (attacker sends multiple transfers simultaneously before balance updates).

**Defense:** Atomic operations, database transactions with proper isolation, locks, idempotency.

---

### 5.5 Request Smuggling

**Mechanism:** Discrepancy in how frontend and backend parse HTTP requests allows an attacker to "smuggle" a request that the backend interprets as a new request.

**Defense:** Use HTTP/2 end-to-end, disable HTTP/1.1 keep-alive, consistent parsing, reject ambiguous requests.

---

### 5.6 Host Header Injection

**Mechanism:** Application trusts the `Host` header for generating links, password reset emails, etc. Attacker injects a malicious host.

**Defense:** Validate Host header against allowlist, don't use Host header for generating URLs.

---

## 6. CLIENT-SIDE ATTACKS

### 6.1 CSRF (Cross-Site Request Forgery)

**Mechanism:** Attacker's site causes victim's browser to make a request to the target site, using the victim's session cookie.

**Defense:** Anti-CSRF tokens, SameSite cookie attribute, require re-authentication for sensitive actions.

---

### 6.2 Clickjacking

**Mechanism:** Attacker embeds the target site in an iframe and tricks the user into clicking (invisible button overlay).

**Defense:** `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`.

---

### 6.3 Open Redirect

**Mechanism:** Application redirects to user-supplied URL without validation, enabling phishing (looks like legitimate domain).

**Defense:** Validate redirect URLs against allowlist, use indirect references, don't redirect to absolute URLs.

---

### 6.4 Prototype Pollution (JavaScript)

**Mechanism:** Attacker pollutes `Object.prototype` via recursive merge, affecting all objects. Can lead to XSS, RCE, or auth bypass.

**Defense:** Use `Object.create(null)`, validate merge inputs, use `Map` instead of objects for key-value storage.

---

## 7. CRYPTOGRAPHIC ATTACKS

### 7.1 Padding Oracle

**Mechanism:** CBC mode + error oracle (server reveals if padding is valid) allows decryption without the key.

**Defense:** Use AEAD (GCM, ChaCha20-Poly1305) instead of CBC. Never reveal decryption errors distinctly.

---

### 7.2 Timing Attack

**Mechanism:** Comparing secrets with `===` leaks information via response time (early exit on first mismatch).

**Defense:** Constant-time comparison (`crypto.timingSafeEqual()`).

---

### 7.3 Birthday Attack

**Mechanism:** With short hashes, collisions can be found in ~2^(n/2) operations instead of 2^n.

**Defense:** Use 256-bit hashes (SHA-256). Don't use MD5 (128-bit) or SHA-1 (160-bit) for security.

---

### 7.4 Downgrade Attack

**Mechanism:** Force use of weaker protocol/version/cipher (SSL→TLS1.0, strong cipher→weak).

**Defense:** Enforce minimum version (TLS 1.2+), disable weak ciphers, HSTS.

---

### 7.5 IV/Nonce Reuse

**Mechanism:** Reusing IV/nonce with same key in stream ciphers (CTR, GCM) allows plaintext recovery.

**Defense:** Generate unique IV/nonce per encryption (CSPRNG, 96 bits for GCM). Never reuse.

---

## 8. INFRASTRUCTURE ATTACKS

### 8.1 Container Escape

**Mechanism:** Exploiting misconfigurations or kernel vulnerabilities to escape container isolation.

**Defense:** Non-root user, read-only filesystem, drop capabilities, seccomp, AppArmor/SELinux, keep kernel patched.

---

### 8.2 Cloud Misconfiguration Exploitation

**Mechanism:** Public S3 buckets, over-permissive IAM roles, exposed management ports.

**Defense:** Least privilege IAM, private subnets, security groups, config scanning (Scout Suite, Prowler).

---

### 8.3 Supply Chain Attack

**Mechanism:** Compromising a dependency or build pipeline to inject malicious code.

**Defense:** Dependency pinning, SBOM, artifact signing (Cosign), isolated build environments, dependency review.

---

### 8.4 DNS Rebinding

**Mechanism:** DNS resolves to attacker IP first, then to internal IP, bypassing same-origin policy for internal services.

**Defense:** Validate Host header, don't expose management interfaces to all origins, use DNS rebinding protection.

---

## 9. BUSINESS LOGIC ATTACKS

### 9.1 Price Manipulation

**Mechanism:** Modifying price in request (client-side) to pay less.

**Defense:** Server-side price validation, never trust client-provided prices.

---

### 9.2 Race Condition on Coupons/Referrals

**Mechanism:** Using a one-time coupon multiple times by sending simultaneous requests.

**Defense:** Database constraints (unique), atomic operations, idempotency keys.

---

### 9.3 Negative Quantity

**Mechanism:** Ordering negative quantity to get credit or bypass minimums.

**Defense:** Validate input ranges server-side (quantity > 0).

---

## 10. INFORMATION DISCLOSURE

### 10.1 Verbose Error Messages

**Mechanism:** Stack traces reveal framework, versions, file paths, SQL queries.

**Defense:** Generic error messages in production, log details server-side only.

---

### 10.2 Directory Listing

**Mechanism:** Web server lists directory contents, revealing files.

**Defense:** Disable directory listing (`autoindex off` in Nginx).

---

### 10.3 Backup Files

**Mechanism:** `.bak`, `.old`, `.swp` files accessible on web server.

**Defense:** Block sensitive extensions in web server config, clean up backup files.

---

### 10.4 Source Code Disclosure

**Mechanism:** `.git` directory, `.env` file, source maps accessible.

**Defense:** Block hidden files (`location ~ /\.` in Nginx), don't deploy `.git` to production.

---

### 10.5 API Documentation Exposure

**Mechanism:** Swagger/OpenAPI docs accessible in production.

**Defense:** Disable or password-protect API docs in production.

---

## CROSS-REFERENCE

| Attack Class | OWASP 2021 | CWE | Primary Defense |
|---|---|---|---|
| SQL Injection | A03 | CWE-89 | Parameterized queries |
| XSS | A03 | CWE-79 | Output encoding |
| Command Injection | A03 | CWE-78 | Argument arrays |
| SSTI | A03 | CWE-94 | No input in template strings |
| IDOR | A01 | CWE-639 | Object-level authz |
| Privilege Escalation | A01 | CWE-269 | Per-request authz |
| SSRF | A10 | CWE-918 | URL allowlist |
| XXE | A05 | CWE-611 | Disable entities |
| Deserialization | A08 | CWE-502 | Don't deserialize untrusted |
| CSRF | A01 | CWE-352 | Anti-CSRF tokens |
| Open Redirect | A01 | CWE-601 | Redirect allowlist |
| Path Traversal | A01 | CWE-22 | Path canonicalization |
| Brute Force | A07 | CWE-307 | Rate limiting + MFA |
| Session Fixation | A07 | CWE-384 | Regenerate session ID |
| Padding Oracle | A02 | CWE-209 | Use AEAD |
| Timing Attack | A02 | CWE-208 | Constant-time comparison |
| Information Disclosure | A05 | CWE-200 | Generic errors, block files |
