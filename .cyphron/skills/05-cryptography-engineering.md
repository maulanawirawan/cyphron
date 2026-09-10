# Skill 05 — Cryptography Engineering

> Cyphron's methodology for building secure cryptographic implementations, reviewing crypto code, and fixing cryptographic vulnerabilities. Cyphron knows how crypto attacks work (padding oracle, timing, downgrade, birthday) so it can build crypto that resists them.

---

## WHEN TO ACTIVATE

- User asks about encryption, hashing, signing, or crypto
- User asks to implement JWT, TLS, password hashing, or token systems
- User asks "is this crypto implementation secure?"
- User asks about key management, certificate handling, or PKI
- User asks to fix a crypto-related vulnerability
- User asks about random number generation, nonce handling, or IV reuse

---

## METHODOLOGY

### Step 1: Identify the Cryptographic Goal
What is the crypto trying to achieve?

| Goal | Correct Primitive | Common Mistakes |
|---|---|---|
| Confidentiality (data at rest) | AES-256-GCM, ChaCha20-Poly1305 | ECB mode, CBC without MAC, DES, 3DES |
| Confidentiality (data in transit) | TLS 1.3, TLS 1.2 with modern ciphers | SSLv3, TLS 1.0/1.1, weak ciphers |
| Integrity | HMAC-SHA256, Poly1305 | CRC32 (not crypto), MD5, SHA1 |
| Authentication | HMAC, digital signatures (Ed25519, RSA-PSS) | MD5 signatures, no signature verification |
| Password storage | Argon2id, bcrypt, scrypt | MD5, SHA256 (even salted), plaintext |
| Token generation | CSPRNG (crypto.randomBytes) | Math.random(), time-based, sequential |
| Key exchange | X25519, ECDH with P-256 | RSA without forward secrecy, DH with small groups |

### Step 2: Attack Surface Analysis
Check the implementation against known crypto attacks:

| Attack | What to Check |
|---|---|
| **Padding oracle** | CBC mode + error oracle → use AEAD (GCM/ChaCha20-Poly1305) |
| **Timing attack** | String comparison on secrets → use constant-time comparison |
| **Birthday attack** | Hash collision risk with short hashes → use 256-bit hashes |
| **IV/nonce reuse** | Same IV/nonce with same key → catastrophic for stream ciphers |
| **Downgrade attack** | Protocol negotiation → enforce minimum version, disable old |
| **Weak PRNG** | `Math.random()`, `random.random()` for security → use CSPRNG |
| **Key management** | Hardcoded keys, keys in code, keys in logs → use KMS/vault |
| **ECB mode** | Identical plaintext blocks → identical ciphertext blocks → use GCM/CBC+MAC |
| **Hash length extension** | MD5/SHA1/SHA256 as MAC → use HMAC |
| **Small subgroup** | DH with small groups → use validated curves |

### Step 3: Implementation Review
Verify the implementation follows crypto best practices:

- [ ] Uses standard, audited libraries (not custom crypto)
- [ ] Correct algorithm for the purpose
- [ ] Correct mode (AEAD for encryption, HMAC for MAC)
- [ ] Unique IV/nonce per encryption (never reused)
- [ ] Keys generated with CSPRNG
- [ ] Keys stored securely (KMS, vault, env — never in code)
- [ ] Constant-time comparison for secrets
- [ ] Proper error handling (no oracle leaks)
- [ ] Key rotation mechanism
- [ ] Forward secrecy where applicable

### Step 4: Secure Implementation
Produce complete, working secure crypto code using audited libraries.

---

## OUTPUT FORMAT

```markdown
## 🔐 Cryptography Review: [Component]

### Goal
[What the crypto is trying to achieve]

### Current Implementation
```lang
[user's code]
```

### Issues Found

#### Issue 1: [Problem] — [Severity]
**What's wrong:** [mechanistic explanation]
**Attack:** [how this could be broken — abstractly]
**Fix:** [correct approach]

### Secure Implementation
```lang
[complete, working secure code using audited libraries]
```

### Why This Is Secure
[Explanation of each security property]

### Key Management
[How keys should be generated, stored, rotated]

### Test Cases
```lang
[tests proving encryption/decryption/signing works correctly]
```
```

---

## SECURE PATTERNS BY USE CASE

### Password Hashing
```python
# Python — use argon2-cffi or bcrypt
import argon2

ph = argon2.PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
hashed = ph.hash(password)
# Verify: ph.verify(hashed, password) — raises if invalid
```

```javascript
// Node.js — use bcrypt or argon2
const argon2 = require('argon2');
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
});
const valid = await argon2.verify(hash, password);
```

### Symmetric Encryption (AEAD)
```python
# Python — AES-256-GCM
from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)  # store securely
nonce = os.urandom(12)  # unique per encryption, 96 bits
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
# Decrypt: plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

### JWT (Secure Implementation)
```javascript
// Node.js — secure JWT
const jwt = require('jsonwebtoken');

// Signing — use strong algorithm, short expiry, store secret in vault
const token = jwt.sign(
  { userId: user.id, role: user.role },
  process.env.JWT_SECRET,  // 256-bit random, from vault
  {
    algorithm: 'RS256',        // asymmetric, not HS256 with weak secret
    expiresIn: '15m',          // short-lived access token
    issuer: 'myapp',
    audience: 'myapp-users',
  }
);

// Verification — verify ALL claims, reject 'none' algorithm
try {
  const payload = jwt.verify(token, publicKey, {
    algorithms: ['RS256'],      // explicit allowlist — prevents alg confusion
    issuer: 'myapp',
    audience: 'myapp-users',
  });
} catch (err) {
  // invalid token
}
```

### Random Token Generation
```javascript
// CORRECT — CSPRNG
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');  // 256-bit token

// WRONG — predictable
// const token = Math.random().toString(36).substring(2);
// const token = Date.now().toString();
```

### Constant-Time Comparison
```javascript
// CORRECT — constant-time
const crypto = require('crypto');
const valid = crypto.timingSafeEqual(
  Buffer.from(receivedToken),
  Buffer.from(expectedToken)
);

// WRONG — timing-vulnerable
// const valid = receivedToken === expectedToken;
```

---

## COMMON CRYPTO VULNERABILITIES & FIXES

| Vulnerability | Wrong | Right |
|---|---|---|
| ECB mode | `AES.new(key, AES.MODE_ECB)` | `AESGCM(key)` or `AES.new(key, AES.MODE_GCM)` |
| MD5 for integrity | `hashlib.md5(data)` | `hashlib.sha256(data)` or HMAC |
| SHA1 for signatures | RSA with SHA1 | RSA-PSS with SHA256, or Ed25519 |
| Math.random for tokens | `Math.random()` | `crypto.randomBytes()` |
| Timing comparison | `===` on secrets | `crypto.timingSafeEqual()` |
| Hardcoded keys | `const KEY = "secret123"` | `process.env.KEY` from vault |
| JWT alg confusion | Accept any algorithm | `algorithms: ['RS256']` allowlist |
| IV reuse | Static IV | Random IV per encryption |
| Password as SHA256 | `sha256(password+salt)` | `argon2id(password, salt)` |
| No forward secrecy | RSA key exchange | ECDHE key exchange (TLS 1.3) |

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — crypto attack mechanisms
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — secure crypto patterns by language
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — crypto fix recipes
