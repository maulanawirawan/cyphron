# Skill 11 — Defensive Security Testing

> Cyphron's methodology for building security test suites — SAST configurations, DAST setups, unit tests for security, and integration tests that verify defenses work. Cyphron builds tests that *prove* security controls function correctly, not tests that exploit.

---

## WHEN TO ACTIVATE

- User asks to build a security test suite
- User asks to configure SAST/DAST tools
- User asks to write security unit tests
- User asks to set up security testing in CI/CD
- User asks "how do I test that my security controls work?"
- User asks to verify a fix actually prevents the vulnerability

---

## METHODOLOGY

### Step 1: Identify What to Test
Map security controls to testable assertions:

| Control | Test Assertion |
|---|---|
| Parameterized queries | SQL injection payload doesn't alter query structure |
| Output encoding | XSS payload is encoded, not executed |
| Authorization check | User A can't access User B's resources |
| Rate limiting | N+1th request is blocked |
| Password hashing | Hash is slow (Argon2), not fast (MD5) |
| Session invalidation | Old session token doesn't work after logout |
| Input validation | Invalid input is rejected, valid input accepted |
| CSRF token | Request without token is rejected |
| File upload | Malicious file type is rejected |
| JWT verification | Tampered token is rejected |

### Step 2: Choose Test Type

| Test Type | What It Does | Tools |
|---|---|---|
| **Unit test** | Tests a single function's security behavior | Jest, pytest, JUnit |
| **Integration test** | Tests component interaction security | Supertest, requests |
| **SAST** | Static analysis of source code | Semgrep, CodeQL, ESLint security |
| **DAST** | Dynamic testing of running app | OWASP ZAP, Nikto |
| **Fuzz test** | Random/malformed input testing | go-fuzz, AFL, Jazzer |
| **Property test** | Test invariants hold for all inputs | fast-check, hypothesis |
| **Mutation test** | Verify tests catch code mutations | Stryker, mutmut |

### Step 3: Build Tests
Write tests that:
1. **Prove the vulnerability exists** (red test — should fail on vulnerable code)
2. **Prove the fix works** (green test — should pass on fixed code)
3. **Don't false-positive** on secure code
4. **Don't false-negative** on vulnerable code

---

## OUTPUT FORMAT

```markdown
## 🧪 Security Test Suite: [Component]

### Test Plan
| Control | Test Type | Assertion |
|---|---|---|
| [control] | [type] | [what it verifies] |

### Test Code
```lang
[complete test suite]
```

### SAST Configuration
```yaml
[SAST config — Semgrep, CodeQL, etc.]
```

### DAST Configuration
```yaml
[DAST config — ZAP, Nikto]
```

### CI/CD Integration
```yaml
[CI pipeline config with security tests]
```

### Running the Tests
```bash
[commands to run each test type]
```
```

---

## TEST PATTERNS BY VULNERABILITY CLASS

### SQL Injection Tests
```javascript
// Test: SQL injection payloads don't alter query results
describe('SQL Injection Prevention', () => {
  const payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT * FROM admin--",
    "admin'--",
    "1' OR '1'='1",
    "' OR ''='",
    "1; SELECT * FROM users",
  ];

  payloads.forEach((payload) => {
    it(`should not authenticate with SQLi payload: ${payload}`, async () => {
      const res = await request(app)
        .post('/login')
        .send({ email: payload, password: payload });
      expect(res.status).toBe(401);
      expect(res.body.token).toBeUndefined();
    });
  });

  it('should authenticate with valid credentials', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'user@test.com', password: 'ValidPass123!' });
    expect(res.status).toBe(200);
  });
});
```

### XSS Tests
```javascript
describe('XSS Prevention', () => {
  const xssPayloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg onload=alert(1)>',
    "';alert(1)//",
    '<iframe src=javascript:alert(1)>',
    '"><img src=x onerror=alert(1)>',
  ];

  xssPayloads.forEach((payload) => {
    it(`should encode XSS payload: ${payload}`, async () => {
      const res = await request(app)
        .post('/comment')
        .send({ text: payload });
      // The response should contain the ENCODED payload, not raw
      expect(res.text).not.toContain('<script>');
      expect(res.text).not.toContain('onerror=');
      expect(res.text).not.toContain('javascript:alert');
    });
  });
});
```

### Authorization (IDOR) Tests
```javascript
describe('Authorization / IDOR Prevention', () => {
  it('should not allow user to access other users orders', async () => {
    const userAToken = await login('userA@test.com', 'pass');
    const userBToken = await login('userB@test.com', 'pass');

    // User A creates an order
    const order = await createOrder(userAToken, { items: [...] });
    const orderId = order.id;

    // User B tries to access User A's order
    const res = await request(app)
      .get(`/api/orders/${orderId}`)
      .set('Authorization', `Bearer ${userBToken}`);

    expect(res.status).toBe(403);  // Forbidden, not 200
  });

  it('should allow user to access their own orders', async () => {
    const token = await login('user@test.com', 'pass');
    const order = await createOrder(token, { items: [...] });

    const res = await request(app)
      .get(`/api/orders/${order.id}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
  });
});
```

### Rate Limiting Tests
```javascript
describe('Rate Limiting', () => {
  it('should block after too many login attempts', async () => {
    // Make 5 failed attempts
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/login')
        .send({ email: 'test@test.com', password: 'wrong' });
    }

    // 6th attempt should be rate limited
    const res = await request(app)
      .post('/login')
      .send({ email: 'test@test.com', password: 'wrong' });

    expect(res.status).toBe(429);  // Too Many Requests
  });
});
```

### JWT Tampering Tests
```javascript
describe('JWT Security', () => {
  it('should reject token with alg:none', async () => {
    // Craft a token with algorithm set to none
    const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
    const payload = Buffer.from('{"sub":"admin","role":"admin"}').toString('base64url');
    const forgedToken = `${header}.${payload}.`;  // no signature

    const res = await request(app)
      .get('/api/admin')
      .set('Authorization', `Bearer ${forgedToken}`);

    expect(res.status).toBe(401);  // should be rejected
  });

  it('should reject tampered payload', async () => {
    const token = await getValidToken('user');
    // Tamper with the payload
    const [header, payload, sig] = token.split('.');
    const tamperedPayload = Buffer.from(
      JSON.stringify({ sub: 'user', role: 'admin' })
    ).toString('base64url');
    const tamperedToken = `${header}.${tamperedPayload}.${sig}`;

    const res = await request(app)
      .get('/api/admin')
      .set('Authorization', `Bearer ${tamperedToken}`);

    expect(res.status).toBe(401);
  });
});
```

### Path Traversal Tests
```javascript
describe('Path Traversal Prevention', () => {
  const traversalPayloads = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '....\/....\/....\/etc/passwd',
    '/etc/passwd',
    'file:///etc/passwd',
  ];

  traversalPayloads.forEach((payload) => {
    it(`should block path traversal: ${payload}`, async () => {
      const res = await request(app)
        .get(`/api/files/${encodeURIComponent(payload)}`);
      expect(res.status).not.toBe(200);
      expect(res.text).not.toContain('root:');  // no passwd content
    });
  });
});
```

---

## SAST CONFIGURATION

### Semgrep Configuration
```yaml
# .semgrep.yml
rules:
  - id: sql-injection-string-concat
    pattern-either:
      - pattern: $DB.execute("..." + $INPUT + "...")
      - pattern: $DB.query(f"SELECT ... {$INPUT} ...")
      - pattern: $DB.query("SELECT ... {}".format($INPUT))
    message: "Possible SQL injection via string concatenation"
    languages: [python, javascript]
    severity: ERROR

  - id: xss-innerhtml
    pattern: $EL.innerHTML = $INPUT
    message: "Possible XSS via innerHTML"
    languages: [javascript]
    severity: WARNING

  - id: hardcoded-secret
    pattern-regex: '(password|secret|api_key|token)\s*=\s*["\x27][^"\x27]{8,}["\x27]'
    message: "Hardcoded secret detected"
    languages: [python, javascript, java, go]
    severity: ERROR

  - id: weak-crypto
    pattern-either:
      - pattern: hashlib.md5($DATA)
      - pattern: hashlib.sha1($DATA)
      - pattern: crypto.createHash("md5")
    message: "Weak hash algorithm"
    languages: [python, javascript]
    severity: WARNING
```

### ESLint Security Plugin
```javascript
// .eslintrc.js
module.exports = {
  extends: ['eslint:recommended', 'plugin:security/recommended'],
  plugins: ['security'],
  rules: {
    'security/detect-object-injection': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-child-process': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-pseudoRandomBytes': 'error',
    'security/detect-new-buffer': 'error',
  },
};
```

---

## DAST CONFIGURATION

### OWASP ZAP Baseline Scan
```yaml
# zap-baseline.yml (for CI/CD)
name: OWASP ZAP Baseline Scan
on: [push, pull_request]
jobs:
  zap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start app
        run: |
          npm install
          npm start &
          sleep 10
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          cmd_options: '-a -j'
```

---

## CI/CD SECURITY PIPELINE

```yaml
# .github/workflows/security.yml
name: Security Pipeline
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: .semgrep.yml

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: npm audit
        run: npm audit --audit-level=high

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install
      - name: Run security tests
        run: npm test -- --grep "Security|XSS|SQL|Auth|IDOR"
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — what payloads to test with
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — what correct behavior looks like
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — what to verify after fixing
