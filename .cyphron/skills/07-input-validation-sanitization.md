# Skill 07 — Input Validation & Sanitization

> Cyphron's methodology for building robust input validation and output sanitization pipelines. Cyphron knows every injection variant — XSS in a thousand contexts, SQLi families, command injection, path traversal, SSTI — so it builds validation that defeats them all.

---

## WHEN TO ACTIVATE

- User asks about input validation, sanitization, or encoding
- User asks how to prevent XSS, SQLi, command injection, or path traversal
- User asks to "sanitize input" or "validate user data"
- User asks to build a validation library or middleware
- User asks "is this validation secure?"
- User asks about Content Security Policy (CSP) or output encoding

---

## CORE PRINCIPLE

```
NEVER trust input. ALWAYS validate at the boundary.
ALWAYS encode at the output. Defense in depth.
```

**The three layers of input defense:**

1. **Validation** (at input) — Is the data the right type, format, length, range?
2. **Sanitization** (at processing) — Remove or neutralize dangerous content.
3. **Encoding** (at output) — Context-appropriate encoding before rendering.

**Never rely on just one layer.** Validation alone can miss edge cases. Encoding alone can be bypassed. Use all three.

---

## METHODOLOGY

### Step 1: Identify Input Sources
Map every entry point where untrusted data enters:
- HTTP query parameters, path variables, headers, cookies
- Request body (JSON, form, multipart)
- File uploads
- WebSocket messages
- Third-party API responses
- Database results (second-order injection)
- Environment variables (if user-influenced)

### Step 2: Define Expected Input
For each input, define:
- **Type** (string, int, UUID, email, URL, etc.)
- **Format** (regex pattern, structure)
- **Length** (min, max)
- **Range** (for numbers)
- **Allowed values** (enum/allowlist)
- **Character set** (which characters are valid)

### Step 3: Validate (Allowlist Approach)
**Always use allowlist validation** (what IS allowed), not blocklist (what's NOT allowed). Blocklists are always incomplete.

```javascript
// CORRECT — allowlist
const allowedSortFields = ['name', 'date', 'price'];
if (!allowedSortFields.includes(req.query.sort)) {
  return res.status(400).json({ error: 'Invalid sort field' });
}

// WRONG — blocklist (always bypassable)
// if (req.query.sort.includes(';') || req.query.sort.includes('--')) {
//   return res.status(400).json({ error: 'Invalid' });
// }
```

### Step 4: Sanitize (If Needed)
For inputs that legitimately contain rich content (HTML, etc.), use **well-tested sanitization libraries**, never custom regex.

### Step 5: Encode at Output (Context-Aware)
**The most critical step.** Encoding must match the output context:

| Output Context | Encoding Method |
|---|---|
| HTML body | HTML entity encoding (`<` → `<`) |
| HTML attribute | Attribute encoding (quote-aware) |
| JavaScript string | JavaScript string encoding (`\xHH`) |
| URL | URL encoding (`%HH`) |
| CSS | CSS encoding (`\HHHH`) |
| SQL query | Parameterized queries (NOT encoding — binding) |
| OS command | Avoid entirely — use argument arrays |

---

## OUTPUT FORMAT

```markdown
## 🛡️ Input Validation Review: [Component]

### Input Sources Identified
| Source | Field | Expected Type | Current Validation |
|---|---|---|---|
| [source] | [field] | [type] | [what exists] |

### Issues Found
#### Issue 1: [Problem] — [Severity]
[mechanistic explanation of bypass + fix]

### Secure Validation Pipeline
```lang
[complete validation code]
```

### Output Encoding
```lang
[context-appropriate encoding code]
```

### Test Cases
```lang
[tests with attack payloads proving validation works]
```
```

---

## XSS PREVENTION — THE THOUSAND CONTEXTS

Cyphron knows XSS has many variants based on **where** user input lands in the page. The defense depends on context:

### Context 1: HTML Body
```javascript
// User input between tags: <div>USER_INPUT</div>
// Defense: HTML entity encoding
function encodeHTML(str) {
  return str
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#x27;');
}
// Or use framework auto-escaping (React, Angular, Django templates)
```

### Context 2: HTML Attribute
```javascript
// User input in attribute: <input value="USER_INPUT">
// Defense: Attribute encoding + always quote attributes
// <input value="${encodeAttr(userInput)}">
// Encode: " ' < > & and all non-alphanumeric
```

### Context 3: JavaScript String
```javascript
// User input in JS: <script>var x = 'USER_INPUT';</script>
// Defense: JavaScript string encoding (or avoid putting user data in JS)
// Use \xHH for characters < 256, \uHHHH for others
// CRITICAL: also encode </script> to prevent breaking out
```

### Context 4: URL
```javascript
// User input in href: <a href="USER_INPUT">
// Defense: Validate URL scheme (allowlist http/https), then URL-encode
// CRITICAL: prevent javascript: URLs
const url = new URL(userInput);
if (!['http:', 'https:'].includes(url.protocol)) {
  throw new Error('Invalid URL scheme');
}
```

### Context 5: CSS
```javascript
// User input in style: <div style="color: USER_INPUT">
// Defense: CSS encoding, or better — don't allow user input in CSS
// Encode non-alphanumeric as \HHHH
```

### Context 6: Template Injection (SSTI)
```python
# User input in template: render_template_string("Hello " + user_input)
# Defense: NEVER concatenate user input into template strings
# CORRECT: pass as variable
render_template_string("Hello {{name}}", name=user_input)
```

### DOM-Based XSS
```javascript
// WRONG — DOM XSS
document.getElementById('output').innerHTML = location.hash.substring(1);

// CORRECT — use textContent or safe DOM API
document.getElementById('output').textContent = location.hash.substring(1);
```

### Content Security Policy (CSP)
```http
# Defense in depth — even if XSS occurs, CSP limits damage
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random}';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
```

---

## SQL INJECTION PREVENTION

```javascript
// CORRECT — parameterized queries (ALL languages)
// Node.js (pg)
db.query('SELECT * FROM users WHERE email = $1', [email]);

// Node.js (mysql2)
db.execute('SELECT * FROM users WHERE email = ?', [email]);

// Python
cursor.execute('SELECT * FROM users WHERE email = %s', (email,))

// Java
PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE email = ?');
ps.setString(1, email);

// Go
db.Query('SELECT * FROM users WHERE email = $1', email)

// WRONG — string concatenation (any language)
// db.query('SELECT * FROM users WHERE email = "' + email + '"')
// db.query(`SELECT * FROM users WHERE email = '${email}'`)
```

### NoSQL Injection Prevention
```javascript
// MongoDB — prevent operator injection
// WRONG: db.collection.find({ email: req.body.email })
// If req.body.email is { "$ne": null }, it matches all!

// CORRECT — sanitize or enforce type
const email = String(req.body.email);  // force to string
db.collection.find({ email: email });

// Or use a schema validator that rejects objects
```

---

## COMMAND INJECTION PREVENTION

```javascript
// CORRECT — argument array (no shell interpretation)
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', host]);  // host is an argument, not shell

// WRONG — shell execution with concatenation
// exec(`ping -c 4 ${host}`);
// If host = "; rm -rf /", command becomes: ping -c 4 ; rm -rf /
```

```python
# CORRECT — argument list
import subprocess
subprocess.run(['ping', '-c', '4', host], shell=False)

# WRONG
# subprocess.run(f'ping -c 4 {host}', shell=True)
```

---

## PATH TRAVERSAL PREVENTION

```javascript
// CORRECT — canonicalize and validate
const path = require('path');

function safeFilePath(baseDir, userInput) {
  const resolved = path.resolve(baseDir, userInput);
  const normalizedBase = path.resolve(baseDir);
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    throw new Error('Path traversal detected');
  }
  return resolved;
}

// WRONG — direct concatenation
// fs.readFile(baseDir + '/' + userInput)
// If userInput = '../../../etc/passwd', escapes baseDir
```

---

## FILE UPLOAD VALIDATION

```javascript
// CORRECT — multi-layer validation
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const upload = multer({
  storage: multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      // Generate random filename — don't use user-provided name
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(16).toString('hex') + ext);
    },
  }),
  limits: {
    fileSize: 5 * 1024 * 1024,  // 5 MB max
  },
  fileFilter: (req, file, cb) => {
    // Allowlist MIME types
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'));
    }
    // Also verify magic bytes (MIME type can be spoofed)
    cb(null, true);
  },
});
```

---

## VALIDATION LIBRARY PATTERNS

```javascript
// Reusable validation using a schema library (e.g., Zod, Joi)
const { z } = require('zod');

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
  rememberMe: z.boolean().optional().default(false),
});

app.post('/login', (req, res) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ errors: result.error.flatten() });
  }
  const { email, password, rememberMe } = result.data;
  // ... proceed with validated data
});
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — injection attack variants
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — validation patterns by language
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — injection fix recipes
