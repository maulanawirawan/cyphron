# Remediation Playbook

> Cyphron's fix recipes for every vulnerability class. When Cyphron identifies a vulnerability, it references this playbook to produce the correct, complete remediation.

---

## HOW TO USE

Each entry follows this structure:
1. **Identify** — how to confirm the vulnerability exists
2. **Root Cause** — what mistake created it
3. **Fix** — the correct implementation (complete code)
4. **Verify** — how to confirm the fix works
5. **Prevent** — how to prevent recurrence (CI/CD, linting, etc.)

---

## 1. SQL INJECTION

### Identify
- Input reaches SQL query via string concatenation
- DB errors when input contains `'`, `"`, `;`, `--`
- Response changes with boolean payloads (`' OR '1'='1`)

### Root Cause
User input concatenated into SQL query string instead of parameterized.

### Fix
```python
# BEFORE (vulnerable)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# AFTER (fixed)
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

### Verify
```python
# Test: SQLi payloads should not authenticate
def test_sqli_prevention():
    payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT 1--"]
    for payload in payloads:
        response = login(payload, payload)
        assert response.status_code == 401
```

### Prevent
- SAST rule: flag string concatenation in queries (Semgrep)
- Code review checklist: verify all DB access uses parameterization
- ORM usage (reduces raw query risk)

---

## 2. CROSS-SITE SCRIPTING (XSS)

### Identify
- User input rendered in HTML without encoding
- `<script>alert(1)</script>` executes when rendered
- `innerHTML` used with user data

### Root Cause
User input output to HTML without context-appropriate encoding.

### Fix
```javascript
// BEFORE (vulnerable)
element.innerHTML = userInput;

// AFTER (fixed)
element.textContent = userInput;

// BEFORE (vulnerable — template)
res.send(`<div>Hello ${userInput}</div>`);

// AFTER (fixed — encode)
const encoded = userInput
  .replace(/&/g, '&')
  .replace(/</g, '<')
  .replace(/>/g, '>')
  .replace(/"/g, '"')
  .replace(/'/g, '&#x27;');
res.send(`<div>Hello ${encoded}</div>`);

// BEST — use framework auto-escaping (React, Django, etc.)
```

### Verify
```javascript
// Test: XSS payloads should be encoded, not executed
const xssPayloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'];
xssPayloads.forEach(payload => {
  const output = render(payload);
  assert(!output.includes('<script>'));
  assert(!output.includes('onerror='));
});
```

### Prevent
- Use frameworks with auto-escaping
- CSP header (defense in depth)
- ESLint rule: flag `innerHTML`, `dangerouslySetInnerHTML`
- Code review: verify all output is encoded

---

## 3. COMMAND INJECTION

### Identify
- `exec()`, `system()`, `subprocess.call(shell=True)` with user input
- Shell metacharacters (`;`, `|`, `&&`) in input affect execution

### Root Cause
User input passed to shell execution instead of argument array.

### Fix
```python
# BEFORE (vulnerable)
import subprocess
subprocess.run(f"ping -c 4 {host}", shell=True)

# AFTER (fixed)
subprocess.run(["ping", "-c", "4", host], shell=False)
```

### Verify
```python
def test_command_injection_prevention():
    # These should be treated as literal arguments, not shell commands
    payloads = ["; rm -rf /", "| cat /etc/passwd", "&& whoami"]
    for payload in payloads:
        result = run_command(payload)
        # Should ping the literal string, not execute the injected command
        assert "rm" not in result.stderr
        assert "passwd" not in result.stdout
```

### Prevent
- SAST rule: flag `shell=True`, `exec()` with variables
- Code review: verify all command execution uses argument arrays

---

## 4. PATH TRAVERSAL

### Identify
- File operations with user-controlled paths
- `../` in input allows accessing files outside intended directory

### Root Cause
User input in file path without canonicalization and boundary check.

### Fix
```javascript
// BEFORE (vulnerable)
const filePath = path.join(baseDir, userInput);
const content = fs.readFileSync(filePath);

// AFTER (fixed)
function safeFilePath(baseDir, userInput) {
  const resolved = path.resolve(baseDir, userInput);
  const normalizedBase = path.resolve(baseDir);
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    throw new Error('Path traversal detected');
  }
  return resolved;
}
const filePath = safeFilePath(baseDir, userInput);
const content = fs.readFileSync(filePath);
```

### Verify
```javascript
const traversalPayloads = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\win.ini',
  '....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
];
traversalPayloads.forEach(payload => {
  assert.throws(() => safeFilePath(baseDir, payload));
});
```

### Prevent
- Centralized file path validation function
- SAST rule: flag `fs.readFile`, `path.join` with user input
- Use indirect file references (map IDs to paths server-side)

---

## 5. IDOR (BROKEN ACCESS CONTROL)

### Identify
- Object ID in URL/parameter without ownership check
- Changing ID returns another user's data

### Root Cause
Missing object-level authorization check.

### Fix
```javascript
// BEFORE (vulnerable)
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await db.getOrder(req.params.id);
  res.json(order);  // No ownership check!
});

// AFTER (fixed)
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await db.getOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (order.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});
```

### Verify
```javascript
// Test: User A cannot access User B's order
async function test_idor_prevention() {
  const tokenA = await login('userA@test.com', 'pass');
  const tokenB = await login('userB@test.com', 'pass');
  const orderA = await createOrder(tokenA, { items: [...] });

  const response = await request(app)
    .get(`/api/orders/${orderA.id}`)
    .set('Authorization', `Bearer ${tokenB}`);

  assert.equal(response.status, 403);
}
```

### Prevent
- Authorization middleware on every object access
- Code review: verify ownership check on every route with `:id`
- Integration tests: IDOR tests in CI/CD

---

## 6. SSRF

### Identify
- Server makes HTTP request to user-specified URL
- Internal IPs or metadata endpoints accessible

### Root Cause
No validation on user-supplied URLs before server-side request.

### Fix
```python
# BEFORE (vulnerable)
import requests
response = requests.get(user_url)

# AFTER (fixed)
import ipaddress
import socket
from urllib.parse import urlparse

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Invalid scheme')
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        raise ValueError('Invalid port')

    ip = socket.gethostbyname(parsed.hostname)
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError('Internal IP blocked')

    return requests.get(url, allow_redirects=False, timeout=10)

response = safe_fetch(user_url)
```

### Verify
```python
def test_ssrf_prevention():
    malicious_urls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:8080/admin',
        'http://10.0.0.1/internal',
        'file:///etc/passwd',
        'gopher://localhost:25/',
    ]
    for url in malicious_urls:
        with pytest.raises(ValueError):
            safe_fetch(url)
```

### Prevent
- Centralized URL validation function
- Egress firewall (network-level defense)
- SAST rule: flag `requests.get`, `fetch` with user-controlled URLs

---

## 7. AUTHENTICATION BYPASS

### Identify
- Login succeeds with malformed input
- Default/weak credentials work
- JWT accepted with `alg: none`

### Root Cause
Weak authentication logic, missing checks, or insecure token handling.

### Fix
```javascript
// BEFORE (vulnerable — JWT without algorithm check)
const payload = jwt.verify(token, secret);  // accepts any algorithm

// AFTER (fixed)
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // explicit allowlist
  issuer: 'app',
  audience: 'app-users',
});
```

### Verify
```javascript
// Test: alg:none should be rejected
async function test_jwt_alg_none_rejected() {
  const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
  const payload = Buffer.from('{"sub":"admin","role":"admin"}').toString('base64url');
  const forgedToken = `${header}.${payload}.`;

  const response = await request(app)
    .get('/api/admin')
    .set('Authorization', `Bearer ${forgedToken}`);

  assert.equal(response.status, 401);
}
```

### Prevent
- Always specify algorithm allowlist in JWT verification
- Use asymmetric algorithms (RS256) over symmetric (HS256)
- Security tests for auth bypass in CI/CD

---

## 8. INSECURE DESERIALIZATION

### Identify
- `pickle.loads()`, `unserialize()`, `ObjectInputStream` with untrusted data
- RCE possible through crafted serialized objects

### Root Cause
Deserializing untrusted data with native serialization.

### Fix
```python
# BEFORE (vulnerable)
import pickle
data = pickle.loads(user_input)

# AFTER (fixed)
import json
data = json.loads(user_input)
```

### Verify
```python
# Test: malicious pickle should not execute
def test_deserialization_safety():
    # Crafted pickle that would execute os.system
    malicious = b"\x80\x04\x95\x25\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94."
    with pytest.raises(Exception):
        safe_deserialize(malicious)
```

### Prevent
- Never use native serialization for untrusted data
- Use JSON
- SAST rule: flag `pickle.loads`, `unserialize`, `ObjectInputStream`

---

## 9. XXE

### Identify
- XML parser processes external entities
- `<!DOCTYPE` with `ENTITY` and `SYSTEM` in input

### Root Cause
XML parser with external entity processing enabled.

### Fix
```python
# BEFORE (vulnerable)
import xml.etree.ElementTree as ET
tree = ET.parse(xml_input)

# AFTER (fixed)
from defusedxml import ElementTree
tree = ElementTree.parse(xml_input)
```

### Verify
```python
def test_xxe_prevention():
    xxe_payload = '''<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root>&xxe;</root>'''
    with pytest.raises(Exception):
        parse_xml(xxe_payload)
```

### Prevent
- Use `defusedxml` (Python) or disable entities in parser config
- Use JSON instead of XML where possible
- SAST rule: flag XML parsing without entity disabling

---

## 10. CSRF

### Identify
- State-changing operations without anti-CSRF tokens
- Cookies without SameSite attribute

### Root Cause
Missing CSRF protection on state-changing endpoints.

### Fix
```javascript
// Add CSRF middleware
const csrf = require('csurf');
app.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } }));

// Set SameSite on session cookie
app.use(session({
  cookie: { sameSite: 'strict', secure: true, httpOnly: true }
}));
```

### Verify
```javascript
// Test: request without CSRF token should be rejected
async function test_csrf_protection() {
  const response = await request(app)
    .post('/api/profile')
    .set('Cookie', sessionCookie)
    .send({ name: 'attacker' });
  // Without CSRF token
  assert.equal(response.status, 403);
}
```

### Prevent
- CSRF middleware on all state-changing routes
- SameSite cookie attribute
- Security tests for CSRF in CI/CD

---

## 11. WEAK CRYPTOGRAPHY

### Identify
- MD5, SHA1 used for security purposes
- ECB mode encryption
- `Math.random()` for security tokens
- Hardcoded keys

### Root Cause
Using weak algorithms or insecure patterns.

### Fix
```python
# BEFORE (vulnerable)
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# AFTER (fixed)
import argon2
ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
```

### Verify
```python
def test_password_hashing_strength():
    hashed = hash_password("test123")
    # Should be Argon2 format
    assert hashed.startswith("$argon2id$")
    # Should take significant time (not instant like MD5)
    import time
    start = time.time()
    verify_password(hashed, "test123")
    elapsed = time.time() - start
    assert elapsed > 0.1  # at least 100ms
```

### Prevent
- SAST rule: flag MD5, SHA1, ECB, Math.random
- Use audited crypto libraries
- Code review: verify crypto choices

---

## 12. SENSITIVE DATA EXPOSURE

### Identify
- Sensitive data in plaintext (DB, logs, responses)
- Missing TLS
- Verbose error messages

### Root Cause
Not encrypting sensitive data or exposing it unnecessarily.

### Fix
```javascript
// BEFORE (vulnerable — logging passwords)
console.log(`Login attempt: ${email} / ${password}`);

// AFTER (fixed)
console.log(`Login attempt: ${email}`);

// BEFORE (vulnerable — API returns password hash)
res.json({ user: { ...user, passwordHash: user.passwordHash } });

// AFTER (fixed)
const { passwordHash, ...safeUser } = user;
res.json({ user: safeUser });
```

### Verify
```javascript
// Test: API should not return sensitive fields
async function test_no_sensitive_data() {
  const response = await request(app).get('/api/users/me').set('Authorization', token);
  assert(!response.body.user.passwordHash);
  assert(!response.body.user.ssn);
  assert(!response.body.user.creditCard);
}
```

### Prevent
- DTO/serializer pattern (explicitly define what fields to return)
- Log sanitization (never log passwords, tokens, PII)
- Encryption at rest for sensitive data
- TLS everywhere

---

## REMEDIATION PRIORITY MATRIX

| Severity | Examples | Timeline |
|---|---|---|
| **Critical** | RCE, auth bypass, SQLi with data access | Immediate (within hours) |
| **High** | Privilege escalation, SSRF, sensitive data exposure | Within days |
| **Medium** | Stored XSS, CSRF, IDOR with limited data | Within weeks |
| **Low** | Reflected XSS (self), info disclosure, missing headers | Next release |
