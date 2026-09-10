# Skill 02 — Threat Modeling

> Cyphron's methodology for systematically identifying threats in a system design and producing defensive architecture recommendations.

---

## WHEN TO ACTIVATE

- User asks to "threat model" a system or feature
- User asks "what could go wrong" with a design
- User asks about "attack surface" of a system
- User provides an architecture diagram or description and asks for security analysis
- User is designing a new feature and wants security input
- User asks "is this architecture secure?"

---

## METHODOLOGY

### Step 1: System Decomposition
Before identifying threats, understand the system:

1. **Identify components** — services, databases, queues, APIs, clients
2. **Identify trust boundaries** — where data crosses between trust levels
3. **Identify data flows** — how data moves between components
4. **Identify entry points** — where external input enters the system
5. **Identify assets** — what needs protection (data, credentials, availability)
6. **Identify external dependencies** — third-party services, libraries

Produce a **Data Flow Diagram (DFD)** in text/ASCII form:

```
[External User] → (HTTPS) → [API Gateway] → (gRPC) → [Auth Service]
                                                      ↓
                                               [User Database]
```

Mark trust boundaries with `═══` lines.

### Step 2: Threat Identification (STRIDE)
Apply STRIDE to each component and data flow:

| STRIDE Category | Threat | Questions to Ask |
|---|---|---|
| **S**poofing | Impersonating users/services | Can someone pretend to be another user? Are credentials protected? Is mutual TLS used between services? |
| **T**ampering | Modifying data | Can data be modified in transit? At rest? Are integrity checks in place? |
| **R**epudiation | Denying actions | Are all actions logged with user identity? Are logs tamper-proof? |
| **I**nformation Disclosure | Leaking data | Can users see data they shouldn't? Are error messages verbose? Is encryption used? |
| **D**enial of Service | Disabling service | Are there rate limits? Resource quotas? Can one user exhaust resources? |
| **E**levation of Privilege | Gaining unauthorized access | Can a user access admin functions? Are authorization checks consistent? |

### Step 3: Risk Prioritization (DREAD)
Rate each threat using DREAD:

| Factor | Question | Score (1-10) |
|---|---|---|
| **D**amage | How bad would it be if it happened? | |
| **R**eproducibility | How easy is it to reproduce? | |
| **E**xploitability | How easy is it to exploit? | |
| **A**ffected users | How many users are impacted? | |
| **D**iscoverability | How easy is it to discover? | |

**Risk Score** = average of all five.  
**Priority**: 9-10 Critical, 7-8 High, 5-6 Medium, 1-4 Low.

### Step 4: Mitigation Design
For each prioritized threat, design a mitigation:

| Mitigation Type | Examples |
|---|---|
| Preventive | Input validation, parameterized queries, authorization checks |
| Detective | Logging, monitoring, anomaly detection, SIEM rules |
| Corrective | Incident response playbook, auto-remediation, failover |
| Compensating | WAF, network segmentation, additional authentication |
| Deterrent | Audit logging, warning banners, rate limiting |

### Step 5: Security Architecture Recommendations
Produce architectural-level recommendations:
- Defense in depth layers
- Trust boundary enforcement
- Least privilege design
- Secure defaults
- Fail-safe defaults

---

## OUTPUT FORMAT

```markdown
## 🎯 Threat Model: [System Name]

### System Overview
[Brief description of the system being modeled]

### Data Flow Diagram
```
[ASCII DFD with trust boundaries marked]
```

### Components & Trust Boundaries
| Component | Trust Level | Entry Points |
|---|---|---|
| [component] | [level] | [points] |

### Assets
| Asset | Sensitivity | Protection Required |
|---|---|---|
| [asset] | [level] | [CIA triad needs] |

---

### Threat Analysis (STRIDE)

#### Threat 1: [Name] — [Risk Score: X/10, Severity]

| Field | Value |
|---|---|
| **STRIDE** | [Category] |
| **Component** | [Affected component] |
| **Description** | [What the threat is] |
| **Attack mechanism** | [How an attacker would exploit this — mechanistically] |
| **DREAD** | D:[x] R:[x] E:[x] A:[x] D:[x] = [avg]/10 |
| **Mitigation** | [Specific defensive measure] |
| **Priority** | [Critical/High/Medium/Low] |

#### Threat 2: ...
[repeat]

---

### Mitigation Summary
| # | Threat | Severity | Mitigation | Type |
|---|---|---|---|---|
| 1 | [name] | [sev] | [mitigation] | [Prevent/Detect/Correct/Compensate] |

### Architectural Recommendations
1. [Defense in depth recommendation]
2. [Trust boundary enforcement]
3. [Least privilege design]
4. [Secure defaults]
5. [Monitoring/detection gaps]

### Open Questions
- [Things that need clarification from the user]
- [Assumptions made during modeling]
```

---

## THREAT MODELING PATTERNS BY ARCHITECTURE TYPE

### Microservices
- Service-to-service authentication (mTLS, JWT)
- API gateway as single entry point
- Service mesh for traffic control
- Distributed tracing for repudiation prevention
- Per-service rate limiting

### Serverless
- Function permission scoping (least privilege IAM)
- Event source validation
- Cold start DoS considerations
- Secrets management (no hardcoded credentials)
- Function timeout limits

### Monolith
- Internal trust boundary assumptions (verify them)
- Single deployment = single attack surface
- Database access layer as security boundary
- Session management centralization

### Cloud-Native
- IAM role scoping
- Network security groups / VPC segmentation
- Managed service security configurations
- Container security (non-root, read-only filesystem)
- Secrets in vault, not environment variables

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — for attack mechanisms in threat descriptions
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — for mitigation implementations
