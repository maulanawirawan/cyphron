# Secure Coding Patterns

> Cyphron's reference catalog of secure implementations by language and use case. When Cyphron builds or patches code, it uses these patterns as the correct baseline.

---

## 1. DATABASE ACCESS (SQL INJECTION PREVENTION)

### Node.js (pg / PostgreSQL)
```javascript
// ✅ CORRECT — parameterized query
const result = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND active = $2',
  [email, true]
);

// ✅ CORRECT — parameterized with IN clause
const result = await pool.query(
  'SELECT * FROM products WHERE id = ANY($1::int[])',
  [productIds]
);

// ❌ WRONG — string concatenation
// const result = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
```

### Node.js (mysql2)
```javascript
// ✅ CORRECT — use execute (prepared statements)
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = ? AND status = ?',
  [email, 'active']
);

// ✅ CORRECT — named placeholders
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = :email',
  { email }
);
```

### Python
```python
# ✅ CORRECT — parameterized
cursor.execute('SELECT * FROM users WHERE email = %s AND status = %s', (email, 'active'))

# ✅ CORRECT — SQLAlchemy ORM
user = session.query(User).filter_by(email=email).first()

# ✅ CORRECT — SQLAlchemy with text
result = session.execute(text('SELECT * FROM users WHERE email = :email'), {'email': email})

# ❌ WRONG
# cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
# cursor.execute("SELECT * FROM users WHERE email = '%s'" % email)
# cursor.execute("SELECT * FROM users WHERE email = {}".format(email))
```

### Java
```java
// ✅ CORRECT — PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ? AND status = ?");
ps.setString(1, email);
ps.setString(2, "active");
ResultSet rs = ps.executeQuery();

// ✅ CORRECT — JPA/Hibernate
TypedQuery<User> query = em.createQuery("SELECT u FROM User u WHERE u.email = :email", User.class);
query.setParameter("email", email);

// ❌ WRONG
// Statement stmt = conn.createStatement();
// ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE email = '" + email + "'");
```

### Go
```go
// ✅ CORRECT — parameterized
rows, err := db.Query("SELECT * FROM users WHERE email = $1 AND status = $2", email, "active")

// ✅ CORRECT — named parameters (sqlx)
rows, err := db.NamedQuery("SELECT * FROM users WHERE email = :email", map[string]interface{}{"email": email})
```

---

## 2. OUTPUT ENCODING (XSS PREVENTION)

### HTML Body Context
```javascript
// ✅ CORRECT — manual encoding
function encodeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ✅ CORRECT — library (DOMPurify for HTML sanitization)
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);

// ✅ CORRECT — framework auto-escaping
// React: {userInput} — auto-escaped
// Angular: {{userInput}} — auto-escaped
// Django: {{ user_input }} — auto-escaped
// Jinja2: {{ user_input }} — auto-escaped
```

### HTML Attribute Context
```javascript
// ✅ CORRECT — always quote attributes, encode quotes
function encodeAttribute(str) {
  return str.replace(/[^a-zA-Z0-9]/g, (c) => `&#x${c.charCodeAt(0).toString(16)};`);
}
// Usage: <input value="${encodeAttribute(userInput)}">
```

### JavaScript String Context
```javascript
// ✅ CORRECT — encode for JS string context
function encodeJSString(str) {
  return str.replace(/[^a-zA-Z0-9]/g, (c) => {
    return `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`;
  });
}
// Better: avoid putting user data in JS — use data attributes
```

### URL Context
```javascript
// ✅ CORRECT — validate scheme, then encode
function safeURL(url) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Invalid URL scheme');
  }
  return parsed.href;
}
```

### Python (Jinja2)
```python
# ✅ CORRECT — Jinja2 auto-escapes by default
# {{ user_input }} — auto-escaped for HTML

# ✅ CORRECT — explicit encoding for other contexts
from markupsafe import escape
html_output = escape(user_input)

# ❌ WRONG — |safe filter disables escaping
# {{ user_input | safe }}
```

---

## 3. COMMAND EXECUTION (COMMAND INJECTION PREVENTION)

### Node.js
```javascript
const { execFile } = require('child_process');

// ✅ CORRECT — argument array, no shell
execFile('ping', ['-c', '4', host], (error, stdout) => { ... });

// ✅ CORRECT — spawn with args
const { spawn } = require('child_process');
const child = spawn('convert', [inputFile, '-resize', '100x100', outputFile]);

// ❌ WRONG — exec with shell
// exec(`ping -c 4 ${host}`, callback);
// exec(`convert ${inputFile} -resize 100x100 ${outputFile}`, callback);
```

### Python
```python
import subprocess

# ✅ CORRECT — argument list, shell=False (default)
result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)

# ✅ CORRECT — with explicit shell=False
result = subprocess.run(['convert', inputFile, '-resize', '100x100', outputFile], shell=False)

# ❌ WRONG — shell=True with user input
# subprocess.run(f'ping -c 4 {host}', shell=True)
```

### Go
```go
// ✅ CORRECT — argument list
cmd := exec.Command("ping", "-c", "4", host)
output, err := cmd.Output()

// ❌ WRONG
// cmd := exec.Command("sh", "-c", "ping -c 4 " + host)
```

---

## 4. PATH TRAVERSAL PREVENTION

### Node.js
```javascript
const path = require('path');

function safeFilePath(baseDir, userInput) {
  const resolved = path.resolve(baseDir, userInput);
  const normalizedBase = path.resolve(baseDir);
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    throw new Error('Path traversal detected');
  }
  return resolved;
}
```

### Python
```python
import os

def safe_file_path(base_dir, user_input):
    resolved = os.path.realpath(os.path.join(base_dir, user_input))
    normalized_base = os.path.realpath(base_dir)
    if not resolved.startswith(normalized_base + os.sep) and resolved != normalized_base:
        raise ValueError('Path traversal detected')
    return resolved
```

---

## 5. AUTHENTICATION PATTERNS

### Password Hashing
```python
# Python — Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, password)  # raises if invalid
```

```javascript
// Node.js — Argon2id
const argon2 = require('argon2');
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
});
const valid = await argon2.verify(hash, password);
```

### Session Management
```javascript
// ✅ CORRECT — secure session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: '__Host-session',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000,
    path: '/',
  },
  store: new RedisStore({ client: redisClient }),
}));

// Regenerate session after login (prevent fixation)
app.post('/login', async (req, res) => {
  // ... verify credentials ...
  req.session.regenerate((err) => {
    req.session.userId = user.id;
    res.json({ message: 'Logged in' });
  });
});
```

### JWT (Secure)
```javascript
// ✅ CORRECT — asymmetric, short-lived, explicit algorithm
const accessToken = jwt.sign(
  { sub: user.id, role: user.role },
  privateKey,
  { algorithm: 'RS256', expiresIn: '15m', issuer: 'app', audience: 'app-users' }
);

// Verification with explicit algorithm allowlist
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // CRITICAL: prevents alg confusion
  issuer: 'app',
  audience: 'app-users',
});
```

---

## 6. AUTHORIZATION PATTERNS

### Object-Level Authorization (IDOR Prevention)
```javascript
// ✅ CORRECT — check ownership on every access
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await db.getOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (order.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});
```

### Role-Based Access Control
```javascript
// ✅ CORRECT — centralized authorization middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.delete('/api/users/:id', auth, requireRole('admin'), deleteUser);
```

### Attribute-Based Access Control
```javascript
// ✅ CORRECT — policy-based authorization
const policies = {
  'order:read': (user, resource) => {
    return user.id === resource.userId || user.role === 'admin';
  },
  'order:delete': (user, resource) => {
    return user.role === 'admin';
  },
};

function authorize(action, getResource) {
  return async (req, res, next) => {
    const resource = await getResource(req);
    const allowed = policies[action](req.user, resource);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });
    req.resource = resource;
    next();
  };
}

app.get('/api/orders/:id', auth, authorize('order:read', (req) => db.getOrder(req.params.id)), getOrder);
```

---

## 7. INPUT VALIDATION PATTERNS

### Schema Validation (Zod)
```javascript
const { z } = require('zod');

const userSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).regex(/^[a-zA-Z\s'-]+$/),
  age: z.number().int().min(13).max(150).optional(),
  role: z.enum(['user', 'editor']).default('user'),
});

app.post('/users', (req, res) => {
  const result = userSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ errors: result.error.flatten() });
  }
  // result.data is fully validated and typed
});
```

### Allowlist Validation
```javascript
// ✅ CORRECT — allowlist
const allowedSortFields = ['name', 'date', 'price', 'rating'];
const allowedSortOrders = ['asc', 'desc'];

if (!allowedSortFields.includes(req.query.sort)) {
  return res.status(400).json({ error: 'Invalid sort field' });
}
if (!allowedSortOrders.includes(req.query.order)) {
  return res.status(400).json({ error: 'Invalid sort order' });
}

// ❌ WRONG — blocklist (always incomplete)
// if (req.query.sort.includes(';') || req.query.sort.includes("'")) { ... }
```

### File Upload Validation
```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const upload = multer({
  storage: multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(16).toString('hex') + ext);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'));
    }
    cb(null, true);
  },
});
```

---

## 8. CRYPTOGRAPHIC PATTERNS

### Symmetric Encryption (AEAD)
```python
# Python — AES-256-GCM
from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

### HMAC (Integrity)
```python
import hmac
import hashlib

# ✅ CORRECT — HMAC for integrity
mac = hmac.new(key, message, hashlib.sha256).hexdigest()

# Verify — constant-time
hmac.compare_digest(received_mac, expected_mac)
```

### Random Token Generation
```javascript
// ✅ CORRECT — CSPRNG
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');

// ❌ WRONG — predictable
// const token = Math.random().toString(36).substring(2);
// const token = Date.now().toString();
```

### Constant-Time Comparison
```javascript
// ✅ CORRECT
const valid = crypto.timingSafeEqual(
  Buffer.from(receivedToken),
  Buffer.from(expectedToken)
);

// ❌ WRONG — timing-vulnerable
// const valid = receivedToken === expectedToken;
```

---

## 9. SSRF PREVENTION PATTERN

```python
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_PORTS = {80, 443, 8080, 8443}

def validate_url(url):
    """Validate URL to prevent SSRF."""
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme {parsed.scheme} not allowed")

    # Check port
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise ValueError(f"Port {parsed.port} not allowed")

    # Resolve and check IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        raise ValueError("Cannot resolve hostname")

    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError("Internal IP addresses are not allowed")

    # Block cloud metadata
    if ip == '169.254.169.254':
        raise ValueError("Metadata endpoint access blocked")

    return url
```

---

## 10. XML PARSING (XXE PREVENTION)

### Python
```python
# ✅ CORRECT — defusedxml
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)

# ✅ CORRECT — disable entities in lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_file, parser)

# ❌ WRONG — standard xml.etree (vulnerable to XXE)
# import xml.etree.ElementTree as ET
# tree = ET.parse(xml_file)
```

### Java
```java
// ✅ CORRECT — disable external entities
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

---

## 11. DESERIALIZATION SAFETY

### Python
```python
# ✅ CORRECT — use JSON
import json
data = json.loads(user_input)

# ❌ WRONG — pickle with untrusted data
# import pickle
# data = pickle.loads(user_input)  # RCE!

# ✅ If YAML needed — use safe_load
import yaml
data = yaml.safe_load(user_input)  # not yaml.load()
```

### Java
```java
// ✅ CORRECT — use JSON (Jackson/Gson)
ObjectMapper mapper = new ObjectMapper();
MyObject obj = mapper.readValue(json, MyObject.class);

// ❌ WRONG — ObjectInputStream with untrusted data
// ObjectInputStream ois = new ObjectInputStream(inputStream);
// Object obj = ois.readObject();  // RCE!
```

---

## 12. SECURITY HEADERS

```nginx
# ✅ Complete security header set
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
```

---

## 13. CSRF PREVENTION

```javascript
// ✅ CORRECT — double-submit cookie pattern
const csrf = require('csurf');
app.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } }));

// Send CSRF token to client
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Client includes token in header
// X-CSRF-Token: <token>
```

```javascript
// ✅ CORRECT — SameSite cookie (primary defense)
app.use(session({
  cookie: { sameSite: 'strict', secure: true, httpOnly: true }
}));
```
