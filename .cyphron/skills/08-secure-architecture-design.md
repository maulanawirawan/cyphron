# Skill 08 — Secure Architecture Design

> Cyphron's methodology for designing secure system architectures. Cyphron knows how systems are attacked at the architectural level — lateral movement, trust boundary violations, supply chain compromise — so it designs architectures that are resilient by structure, not just by configuration.

---

## WHEN TO ACTIVATE

- User asks to design a system architecture with security in mind
- User asks about zero trust, microservices security, or network segmentation
- User asks "how should I architect this securely?"
- User provides an architecture and asks for security improvements
- User asks about cloud security architecture (AWS/Azure/GCP)
- User asks about secure deployment patterns

---

## METHODOLOGY

### Step 1: Requirements & Constraints
- **Functional requirements** — what must the system do?
- **Security requirements** — confidentiality, integrity, availability needs
- **Compliance** — GDPR, HIPAA, PCI-DSS, SOC2 (if applicable)
- **Scale** — users, data volume, throughput
- **Threat model** — who are the adversaries, what are the assets?

### Step 2: Security Architecture Principles
Apply these principles to every design:

| Principle | Implementation |
|---|---|
| **Least privilege** | Every component has minimum permissions needed |
| **Defense in depth** | Multiple independent security layers |
| **Fail-safe defaults** | On error, deny access (not grant) |
| **Separation of duties** | No single component can complete a sensitive operation alone |
| **Economy of mechanism** | Keep it simple — complexity breeds vulnerabilities |
| **Complete mediation** | Every access is checked, not just the first |
| **Open design** | Security doesn't depend on obscurity |
| **Trust boundaries** | Explicit boundaries with validation at each crossing |
| **Secure by default** | Secure configuration out of the box |

### Step 3: Layered Architecture Design

```
┌─────────────────────────────────────────────────────┐
│                    EDGE / DMZ                        │
│  WAF · DDoS Protection · Rate Limiting · TLS Term    │
├─────────────────────────────────────────────────────┤
│                  APPLICATION LAYER                   │
│  API Gateway · Auth Service · App Services           │
│  (mTLS between services · Input validation)          │
├─────────────────────────────────────────────────────┤
│                    DATA LAYER                        │
│  Databases · Cache · Object Storage                  │
│  (Encryption at rest · Network isolation · Audit)    │
├─────────────────────────────────────────────────────┤
│                  INFRASTRUCTURE                      │
│  VPC · Security Groups · IAM · Secrets Mgmt          │
│  (Least privilege · Network segmentation · Logging)  │
└─────────────────────────────────────────────────────┘
```

### Step 4: Trust Boundary Analysis
For each boundary crossing, define:
- What data crosses?
- What validation occurs?
- What authentication/authorization is required?
- What logging is in place?

### Step 5: Security Control Mapping
Map controls to threat classes:

| Threat | Architectural Control |
|---|---|
| Network attack | VPC segmentation, security groups, mTLS |
| Unauthorized access | IAM, RBAC/ABAC, MFA |
| Data breach | Encryption at rest + in transit, key management |
| Lateral movement | Network segmentation, blast radius limits |
| Supply chain | Dependency pinning, SBOM, artifact signing |
| Insider threat | Audit logging, separation of duties, just-in-time access |
| Availability attack | Auto-scaling, rate limiting, multi-AZ, backups |
| Misconfiguration | IaC with security policies, config validation, drift detection |

---

## OUTPUT FORMAT

```markdown
## 🏗️ Secure Architecture: [System Name]

### Requirements
- Functional: [list]
- Security: [CIA needs, compliance]
- Scale: [users, data, throughput]

### Architecture Diagram
```
[ASCII architecture diagram with trust boundaries]
```

### Components
| Component | Responsibility | Security Controls |
|---|---|---|
| [component] | [what it does] | [controls applied] |

### Trust Boundaries
| Boundary | Crossing Data | Validation | AuthN/AuthZ |
|---|---|---|---|
| [boundary] | [data] | [checks] | [mechanism] |

### Security Controls
| Layer | Controls |
|---|---|
| Edge | [WAF, DDoS, TLS, rate limiting] |
| Application | [Auth, input validation, mTLS] |
| Data | [Encryption, isolation, audit] |
| Infrastructure | [IAM, network, secrets, logging] |

### Threat Mitigations
| Threat | Mitigation |
|---|---|
| [threat] | [control] |

### Implementation Guide
[Step-by-step guide to implementing the architecture securely]
```

---

## ARCHITECTURE PATTERNS

### Zero Trust Architecture
```
Principles:
1. Never trust, always verify — every request is authenticated and authorized
2. Least privilege access — just-in-time, just-enough access
3. Assume breach — design as if the network is compromised
4. Micro-segmentation — small blast radii
5. Continuous monitoring — log and analyze all access

Implementation:
- Identity-aware proxy (IAP) in front of all services
- mTLS between all services (no implicit trust)
- Short-lived credentials (no long-lived secrets)
- Policy engine evaluating every request (OPA, Cedar)
- Comprehensive logging and SIEM integration
```

### Microservices Security
```
Service-to-Service Auth:
- mTLS with service mesh (Istio, Linkerd)
- Service identity via SPIFFE/SPIRE
- Token-based authz (JWT with service claims)

API Gateway:
- Single entry point for external traffic
- Rate limiting, auth, input validation
- WAF integration
- Request/response logging

Service Isolation:
- Each service has its own DB (no shared databases)
- Network policies limiting service-to-service communication
- Separate deployment pipelines per service
```

### Cloud Security Architecture (AWS Example)
```
Network:
- VPC with private subnets for app/data
- Public subnets only for load balancers
- NAT gateway for outbound (no direct internet for private)
- VPC endpoints for AWS services (no internet routing)

IAM:
- Roles for services (not access keys)
- Least privilege policies
- Cross-account roles with external IDs
- Permission boundaries for safety

Data:
- KMS for encryption at rest
- S3 with bucket policies, versioning, MFA delete
- RDS in private subnet, encryption, automated backups
- Secrets Manager / Parameter Store for secrets

Monitoring:
- CloudTrail for API audit
- GuardDuty for threat detection
- Security Hub for compliance
- Config for drift detection
```

### Container Security Architecture
```
Build:
- Minimal base images (distroless, alpine)
- Multi-stage builds (no build tools in final image)
- Image scanning in CI (Trivy, Snyk)
- Signed images (Cosign)

Runtime:
- Non-root user
- Read-only filesystem
- Drop all capabilities, add only needed
- No privileged containers
- Resource limits (CPU, memory)

Orchestration (Kubernetes):
- Network policies (default deny)
- Pod Security Standards (restricted)
- RBAC for cluster access
- Secrets encryption at rest
- Admission controllers (OPA Gatekeeper)
```

### Secure CI/CD Architecture
```
Pipeline Security:
- Signed commits (GPG, Sigstore)
- Dependency scanning (Snyk, Dependabot)
- SAST in pipeline (Semgrep, CodeQL)
- DAST against staging
- Secret scanning (gitleaks, trufflehog)
- Container image scanning
- Infrastructure as Code scanning (Checkov, tfsec)
- SBOM generation (Syft)
- Signed artifacts (Cosign)
- Immutable artifacts (hash-pinned)

Deployment:
- GitOps with signed manifests
- Progressive delivery (canary, blue-green)
- Automated rollback on anomaly
- Separate deploy permissions from build
```

---

## SECURITY ANTI-PATTERNS TO AVOID

| Anti-Pattern | Why It's Dangerous | Secure Alternative |
|---|---|---|
| Shared database across services | Blast radius, no isolation | Database per service |
| Long-lived credentials | Compromise = persistent access | Short-lived tokens, rotation |
| Flat network | Lateral movement easy | Segmented network, micro-segmentation |
| Secrets in code/images | Leak = permanent exposure | Secrets manager, runtime injection |
| Implicit trust between services | Compromised service = all access | mTLS, explicit authz |
| Monolithic deployment | One vuln affects all | Independent service deployment |
| No audit logging | Can't detect/investigate breaches | Comprehensive logging + SIEM |
| Over-privileged service accounts | Blast radius too large | Least privilege, permission boundaries |
| Direct DB access from internet | Attack surface too large | Private subnet, API-only access |
| No network egress controls | Data exfiltration easy | Egress proxy, allowlist destinations |

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — architectural attack patterns
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — secure architecture patterns
