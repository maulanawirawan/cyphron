# Skill 01 — Secure Code Review

> Cyphron's methodology for reviewing source code to identify vulnerabilities, explain attack mechanisms, and produce patched code.

---

## WHEN TO ACTIVATE

- User provides source code and asks "is this secure?"
- User asks to "review this code" / "check for vulnerabilities"
- User pastes a function/snippet and asks about its security
- User asks "what's wrong with this code?"
- User asks to audit a specific file or module

---

## METHODOLOGY

### Step 1: Context Gathering
Identify the following before analysis:
- **Language & framework** (determines which vulnerability classes apply)
- **Input sources** (where does untrusted data enter?)
- **Output sinks** (where does data go that could be dangerous?)
- **Data flow** (how does data travel from source to sink?)
- **Authentication/authorization context** (who can reach this code?)

### Step 2: Systematic Vulnerability Scan
Check the code against each vulnerability class in priority order:

| Priority | Vulnerability Class | What to Look For |
|---|---|---|
| P0 | Injection (SQL, NoSQL, Command, LDAP) | String concatenation into queries/commands, `eval()`, `exec()`, template engines with user input |
| P0 | Authentication bypass | Hardcoded credentials, weak comparison, missing checks, predictable tokens |
| P0 | Path traversal | File operations with user-controlled paths, missing canonicalization |
| P0 | Deserialization | `unserialize()`, `pickle.loads()`, `ObjectInputStream`, `JSON.parse` with reviver |
| P1 | XSS | Unescaped output, `innerHTML`, `dangerouslySetInnerHTML`, template injection |
| P1 | Broken access control | Missing authorization checks, IDOR, insecure direct object references |
| P1 | SSRF | HTTP requests with user-controlled URLs, missing allowlists |
| P1 | XXE | XML parsing with external entities enabled |
| P1 | CSRF | State-changing operations without anti-CSRF tokens |
| P2 | Sensitive data exposure | Hardcoded secrets, weak crypto, missing TLS, verbose errors |
| P2 | Session management | Predictable session IDs, missing flags (HttpOnly, Secure, SameSite) |
| P2 | Race conditions | TOCTOU, missing locks, shared mutable state |
| P3 | Information disclosure | Stack traces, debug info, version banners, verbose logging |
| P3 | Insecure defaults | Debug mode on, default credentials, permissive CORS |

### Step 3: Attack Mechanism Explanation
For each vulnerability found, explain **mechanistically**:
1. **Where** the untrusted data enters (source)
2. **How** it travels to the dangerous operation (flow)
3. **Why** the operation is dangerous (sink)
4. **What** an attacker could achieve (impact — described abstractly)
5. **Which** attack variant applies (e.g., blind vs. union SQLi)

### Step 4: Patched Code
Produce **complete, working patched code**:
- Never use placeholders or `// rest unchanged`
- Show the full function/module as it should be
- Explain why the fix eliminates the vulnerability
- Note any trade-offs (performance, compatibility)

### Step 5: Detection & Verification
- Provide a **unit test** that proves the vulnerability existed and the fix works
- Suggest a **detection rule** (SAST pattern, WAF rule) to catch this class
- Recommend **CI/CD integration** to prevent regression

---

## OUTPUT FORMAT

```markdown
## 🔍 Code Review Results

### Summary
- **Files reviewed:** [list]
- **Vulnerabilities found:** [count] ([severity breakdown])
- **Overall risk:** [Critical/High/Medium/Low]

---

### Finding 1: [Vulnerability Name] — [Severity]

**Location:** `file.ext:line`

**Vulnerable code:**
```lang
[exact vulnerable code snippet]
```

**Attack mechanism:**
[Mechanistic explanation — how data flows from source to sink,
why it's exploitable, what attack variant applies, what impact
an attacker could achieve — described abstractly]

**Patched code:**
```lang
[complete fixed code]
```

**Why this fix works:**
[Explanation of why the patch eliminates the vulnerability]

**Verification test:**
```lang
[test that proves vuln existed + fix works]
```

**Detection rule:**
```lang
[SAST pattern or WAF rule to catch this class]
```

---

### Finding 2: ...
[repeat format]

---

### 📋 Remediation Summary
| # | Vulnerability | Severity | Status |
|---|---|---|---|
| 1 | [name] | [severity] | ✅ Patched |
| 2 | [name] | [severity] | ✅ Patched |

### 🛡️ Additional Recommendations
- [Architectural improvements]
- [Related attack variants to watch for]
- [Hardening beyond the immediate fix]
```

---

## LANGUAGE-SPECIFIC CHECKLISTS

### JavaScript / Node.js
- [ ] SQL: Check for string concatenation in queries (use parameterized queries)
- [ ] NoSQL: Check for `$where`, `$expr` with user input in MongoDB
- [ ] XSS: Check for `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, unescaped template output
- [ ] Command injection: Check for `child_process.exec`, `execSync` with user input
- [ ] Prototype pollution: Check for recursive merge, `Object.assign` with user objects
- [ ] Path traversal: Check for `fs.readFile`, `path.join` with user input
- [ ] SSRF: Check for `fetch`, `axios`, `http.get` with user-controlled URLs
- [ ] Deserialization: Check for `JSON.parse` with custom revivers, `node-serialize`
- [ ] ReDoS: Check regex patterns for catastrophic backtracking
- [ ] JWT: Check for `algorithm: none`, hardcoded secrets, missing verification

### Python
- [ ] SQL: Check for f-strings, `%`, `.format()` in queries (use parameterized)
- [ ] Command injection: Check for `os.system`, `subprocess.call(shell=True)`, `eval`, `exec`
- [ ] Deserialization: Check for `pickle.loads`, `yaml.load` (use `yaml.safe_load`)
- [ ] Path traversal: Check for `open()`, `os.path.join` with user input
- [ ] SSTI: Check for `render_template_string` with user input (Jinja2)
- [ ] SSRF: Check for `requests.get` with user-controlled URLs
- [ ] XXE: Check for `lxml.etree`, `xml.etree` without disabling entities

### Java
- [ ] SQL: Check for `Statement` with concatenation (use `PreparedStatement`)
- [ ] Deserialization: Check for `ObjectInputStream`, `readObject()`
- [ ] XXE: Check for `DocumentBuilderFactory`, `SAXParser` without disabling entities
- [ ] SSRF: Check for `URLConnection`, `HttpClient` with user URLs
- [ ] Path traversal: Check for `new File()` with user input
- [ ] SpEL injection: Check for `SpelExpressionParser` with user input
- [ ] LDAP injection: Check for `DirContext.search` with concatenation

### Go
- [ ] SQL: Check for `fmt.Sprintf` in queries (use parameterized)
- [ ] Command injection: Check for `exec.Command` with user input
- [ ] Path traversal: Check for `filepath.Join`, `os.Open` with user input
- [ ] SSRF: Check for `http.Get` with user-controlled URLs

### PHP
- [ ] SQL: Check for `mysql_query` with concatenation (use PDO prepared statements)
- [ ] XSS: Check for `echo` without `htmlspecialchars`
- [ ] File inclusion: Check for `include`, `require` with user input
- [ ] Deserialization: Check for `unserialize()`
- [ ] Command injection: Check for `system()`, `exec()`, `shell_exec()`, backticks
- [ ] SSRF: Check for `file_get_contents`, `curl` with user URLs

---

## SEVERITY RATING GUIDE

| Severity | Criteria |
|---|---|
| **Critical** | Remote code execution, authentication bypass, full database access |
| **High** | Privilege escalation, sensitive data exposure, SQL injection with data access |
| **Medium** | Stored XSS, CSRF on sensitive actions, IDOR with limited data exposure |
| **Low** | Reflected XSS (self-only), information disclosure, missing security headers |
| **Info** | Best practice violations, defense-in-depth recommendations |

---

## KNOWLEDGE BASE REFERENCES

When reviewing code, load relevant entries from:
- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — for attack mechanism explanations
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — for correct secure implementations
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — for fix recipes
