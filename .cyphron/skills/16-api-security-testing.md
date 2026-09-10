# Skill 16 — API Security Testing

> Cyphron's methodology for testing and securing APIs (REST, GraphQL, gRPC). Cyphron knows API attack patterns — broken object-level authorization (BOLA/IDOR), mass assignment, excessive data exposure, rate limit bypass — and builds defenses against the OWASP API Security Top 10.

---

## WHEN TO ACTIVATE

- User asks to secure or test an API
- User provides an OpenAPI/Swagger spec for security review
- User asks about GraphQL, REST, or gRPC security
- User asks about API authentication, rate limiting, or versioning
- User asks about OWASP API Security Top 10

---

## METHODOLOGY

### Step 1: API Discovery & Inventory
- Enumerate all endpoints (from OpenAPI spec, code, or traffic)
- Identify authentication requirements per endpoint
- Map data flow: what input, what output, what data store

### Step 2: OWASP API Security Top 10 (2023) Check

| # | Category | What to Check |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | Can user A access user B's objects via API? |
| API2 | Broken Authentication | Weak token generation, missing rate limits, credential stuffing |
| API3 | Broken Object Property Level Authorization | Mass assignment, excessive data exposure |
| API4 | Unrestricted Resource Consumption | No rate limits, no pagination, large payloads |
| API5 | Broken Function Level Authorization | Can regular user access admin endpoints? |
| API6 | Unrestricted Access to Sensitive Data | Sensitive data in responses without need |
| API7 | Server-Side Request Forgery | Server fetches user-specified URLs |
| API8 | Security Misconfiguration | CORS, verbose errors, default creds |
| API9 | Improper Inventory Management | Old API versions, undocumented endpoints |
| API10 | Unsafe Consumption of APIs | Trusting third-party API responses without validation |

### Step 3: Build Defenses
- Object-level authorization on every endpoint
- Rate limiting per user AND per IP
- Input validation with schema (Zod, Joi, Pydantic)
- Response filtering (never return more than needed)
- API versioning with deprecation
- Comprehensive logging

---

## OUTPUT FORMAT

```markdown
## 🔌 API Security Review: [API Name]

### Endpoint Inventory
| Method | Path | Auth Required | Issues |
|---|---|---|---|
| [method] | [path] | [yes/no] | [findings] |

### Findings
#### Finding 1: [Issue] — [Severity]
[mechanism + fix + code]

### Secure API Implementation
```lang
[complete secure API code with auth, authz, rate limiting, validation]
```

### Test Suite
```lang
[API security tests]
```
```

---

## SECURE API PATTERNS

### Rate Limiting (Per User + Per IP)
```javascript
const rateLimit = require('express-rate-limit');
const SlowMode = require('express-slow-down');

// Per-IP limit
const ipLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
});

// Per-user limit (stricter for sensitive endpoints)
const userLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.user?.id || req.ip,
});

app.use('/api/', ipLimiter);
app.use('/api/login', userLimiter);
```

### GraphQL Security
```javascript
const { graphql } = require('graphql');
const depthLimit = require('graphql-depth-limit');
const costAnalysis = require('graphql-cost-analysis');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),                    // Prevent deeply nested queries
    costAnalysis({
      maximumCost: 1000,              // Prevent expensive queries
      variables: { ... },
    }),
  ],
  context: ({ req }) => ({
    user: authenticate(req),         // Auth on every request
  }),
});

// Field-level authorization in resolvers
const resolvers = {
  User: {
    email: (parent, args, context) => {
      if (context.user?.id !== parent.id && context.user?.role !== 'admin') {
        return null;  // Don't expose email to other users
      }
      return parent.email;
    },
  },
};
```

### Mass Assignment Prevention
```javascript
// WRONG — mass assignment vulnerable
// app.post('/users', (req, res) => {
//   const user = new User(req.body);  // attacker can set role: 'admin'
// });

// CORRECT — explicit field extraction
app.post('/users', (req, res) => {
  const { name, email, password } = req.body;
  // Never accept role, isAdmin, etc. from user input
  const user = new User({ name, email, password });
  user.role = 'user';  // default, server-set
  await user.save();
});
```
