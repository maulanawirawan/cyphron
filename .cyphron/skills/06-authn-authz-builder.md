# Skill 06 — Authentication & Authorization Builder

> Cyphron's methodology for building secure authentication (AuthN) and authorization (AuthZ) systems. Cyphron knows every auth attack — session hijacking, fixation, JWT manipulation, OAuth flaws, brute force, credential stuffing — so it builds auth that resists them all.

---

## WHEN TO ACTIVATE

- User asks to build a login/authentication system
- User asks about session management, JWT, OAuth, SSO
- User asks about authorization, RBAC, ABAC, access control
- User asks "is my auth implementation secure?"
- User asks to fix an authentication/authorization vulnerability
- User asks about MFA, password policies, or token management

---

## METHODOLOGY

### Step 1: Identify the AuthN/AuthZ Requirements
- **Authentication** — who is the user? (identity verification)
- **Authorization** — what can they do? (permission enforcement)
- **Session management** — how do we maintain state across requests?
- **Federation** — do we need SSO, OAuth, or third-party identity?

### Step 2: Attack Surface Mapping
Check the design against auth attack classes:

| Attack Class | What to Verify |
|---|---|
| **Brute force** | Rate limiting, account lockout, progressive delays |
| **Credential stuffing** | Breached password checking, MFA, anomaly detection |
| **Password spraying** | Account-level rate limits (not just IP), CAPTCHA |
| **Session fixation** | Regenerate session ID after login |
| **Session hijacking** | Secure, HttpOnly, SameSite cookies; TLS |
| **Session prediction** | CSPRNG session IDs, sufficient entropy (128+ bits) |
| **JWT alg confusion** | Explicit algorithm allowlist, reject `none` |
| **JWT tampering** | Verify signature, validate all claims |
| **JWT exfiltration** | Don't store JWT in localStorage (use HttpOnly cookie) |
| **OAuth redirect hijack** | Exact redirect URI matching, state parameter |
| **OAuth token theft** | PKCE, short-lived tokens, secure storage |
| **IDOR** | Object-level authorization checks |
| **Privilege escalation** | Vertical authz checks on every request |
| **Forced browsing** | Default-deny authorization, explicit allowlists |
| **Password reset poisoning** | Random reset tokens, short expiry, one-time use |
| **Timing attacks on login** | Constant-time comparison, generic error messages |

### Step 3: Secure Implementation
Build complete, working auth systems following secure patterns.

---

## OUTPUT FORMAT

```markdown
## 🔑 AuthN/AuthZ Review: [Component]

### Requirements
- AuthN: [what identity verification is needed]
- AuthZ: [what permission model is needed]
- Session: [how state is maintained]

### Attack Surface
[Table of attack classes checked]

### Issues Found
#### Issue 1: [Problem] — [Severity]
[mechanistic explanation + fix]

### Secure Implementation
```lang
[complete, working auth code]
```

### Authorization Model
[RBAC/ABAC design with enforcement points]

### Test Cases
```lang
[tests proving auth works — positive and negative cases]
```
```

---

## SECURE AUTHENTICATION PATTERNS

### Password Storage
```python
# CORRECT — Argon2id
import argon2
ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, password)  # raises VerifyMismatchError if wrong

# WRONG — any of these:
# hashlib.sha256(password.encode()).hexdigest()
# hashlib.md5(password.encode()).hexdigest()
# base64.b64encode(password.encode())
# password + salt with SHA256 (too fast for GPU brute force)
```

### Login with Rate Limiting
```javascript
// Express — secure login with rate limiting and generic errors
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 attempts per window
  message: 'Too many login attempts, try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  // Always run the hash verification, even if user doesn't exist
  // (prevents timing-based user enumeration)
  const user = await db.findUser(username);
  const hash = user?.passwordHash || DUMMY_HASH;  // constant-time path
  const valid = await argon2.verify(hash, password);

  if (!user || !valid) {
    // Generic error — don't reveal which part failed
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Regenerate session ID (prevents session fixation)
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.role = user.role;
    res.json({ message: 'Logged in' });
  });
});
```

### Session Management (Secure Cookies)
```javascript
// CORRECT — secure session cookie
app.use(session({
  secret: process.env.SESSION_SECRET,  // 256-bit random
  name: '__Host-session',              // __Host- prefix forces Secure+Path=/
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,          // HTTPS only
    httpOnly: true,         // no JS access (prevents XSS theft)
    sameSite: 'strict',     // prevents CSRF
    maxAge: 30 * 60 * 1000,  // 30 minutes
    path: '/',
  },
  store: new RedisStore({   // server-side store, not memory
    client: redisClient,
  }),
}));
```

### JWT (Secure)
```javascript
// Signing — asymmetric, short-lived
const accessToken = jwt.sign(
  { sub: user.id, role: user.role },
  privateKey,
  { algorithm: 'RS256', expiresIn: '15m', issuer: 'app', audience: 'app-users' }
);

// Verification — explicit algorithm, all claims
jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // CRITICAL: prevents alg confusion attack
  issuer: 'app',
  audience: 'app-users',
});

// Refresh token — longer lived, stored in HttpOnly cookie, revocable
const refreshToken = crypto.randomBytes(48).toString('hex');
// Store hash of refresh token in DB (so DB leak doesn't expose tokens)
await db.storeRefreshToken(user.id, hash(refreshToken), expiresAt);
```

### Authorization (Object-Level / IDOR Prevention)
```javascript
// CORRECT — check ownership on every object access
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await db.getOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });

  // Object-level authorization — prevents IDOR
  if (order.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(order);
});

// WRONG — no ownership check:
// app.get('/api/orders/:id', auth, async (req, res) => {
//   const order = await db.getOrder(req.params.id);
//   res.json(order);  // anyone authenticated can read any order
// });
```

### RBAC Implementation
```javascript
// Centralized authorization middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// Usage — explicit, per-route
app.delete('/api/users/:id', auth, requireRole('admin'), deleteUser);
app.get('/api/orders', auth, requireRole('user', 'admin'), listOrders);
```

### Password Reset (Secure)
```javascript
// 1. Generate random, one-time, short-lived token
const resetToken = crypto.randomBytes(32).toString('hex');
const expiresAt = Date.now() + 15 * 60 * 1000;  // 15 minutes
await db.storeResetToken(user.id, hash(resetToken), expiresAt);

// 2. Send token via email (not in URL that leaks via Referer)
// 3. On reset — verify token, check expiry, check one-time use
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const resetRecord = await db.findResetToken(hash(token));

  if (!resetRecord) return res.status(400).json({ error: 'Invalid or expired token' });
  if (resetRecord.used) return res.status(400).json({ error: 'Token already used' });
  if (resetRecord.expiresAt < Date.now()) return res.status(400).json({ error: 'Token expired' });

  // Invalidate token (one-time use)
  await db.markTokenUsed(resetRecord.id);
  // Invalidate all existing sessions (force re-login everywhere)
  await db.invalidateAllSessions(resetRecord.userId);
  // Update password
  await db.updatePassword(resetRecord.userId, await argon2.hash(newPassword));

  res.json({ message: 'Password reset successful' });
});
```

### MFA (TOTP)
```javascript
// Setup — generate secret, show QR
const speakeasy = require('speakeasy');
const secret = speakeasy.generateSecret({ length: 32 });
// Store secret encrypted in DB, show QR to user

// Verify — on login, after password check
const valid = speakeasy.totp.verify({
  secret: user.totpSecret,
  encoding: 'base32',
  token: req.body.totpCode,
  window: 1,  // allow 1 step drift (±30s)
});
```

---

## AUTHORIZATION MODEL SELECTION

| Model | When to Use | Enforcement |
|---|---|---|
| **RBAC** | Fixed roles (admin, user, editor) | Role check per route |
| **ABAC** | Attribute-based (department, clearance) | Policy engine evaluation |
| **ReBAC** | Relationship-based (owner, member) | Relationship graph check |
| **ACL** | Per-object permissions | Object-level permission check |

**Default-deny principle:** Start with "no access" and explicitly grant. Never start with "allow all" and try to restrict.

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — auth attack mechanisms
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — secure auth patterns
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — auth fix recipes
