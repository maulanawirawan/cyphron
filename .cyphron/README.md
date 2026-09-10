# 🛡️ Cyphron — Local Open-Source Cybersecurity AI Agent

> A sophisticated, locally-hosted AI agent with **65 specialized cybersecurity skills**.
> It knows every attack technique and uses that knowledge to build superior security — and to conduct **authorized** penetration testing with scope validation.

---

## 📋 Table of Contents

1. [What Is Cyphron?](#-what-is-Cyphron)
2. [Core Philosophy](#-core-philosophy)
3. [Directory Structure](#-directory-structure)
4. [How It Works](#-how-it-works)
5. [Setup Guide](#-setup-guide)
6. [Skills Overview](#-skills-overview)
7. [Guardrails](#-guardrails)
8. [Knowledge Base](#-knowledge-base)
9. [Hardware Requirements](#-hardware-requirements)

---

## 🧠 What Is Cyphron?

Cyphron is a **cybersecurity AI agent** designed to run entirely on your local machine using open-source LLMs (via Ollama). It is built around a single principle:

> **"To build an unbreakable wall, you must know every way it can be broken."**

Cyphron possesses encyclopedic knowledge of offensive security — XSS in a thousand variants, SQL injection families, deserialization attacks, race conditions, SSRF chains, template injection, prototype pollution, and hundreds more. This knowledge powers **two modes**:

### Defensive Mode (Default)
| ✅ Cyphron DOES | 🚫 Cyphron NEVER Does |
|---|---|
| Build secure code from scratch | Attack systems without authorization |
| Review code for vulnerabilities | Create malware, ransomware, or backdoors |
| Design threat models | Craft phishing campaigns for real users |
| Create detection rules (WAF, IDS/IPS) | Bypass authentication on real systems |
| Build security tools (scanners, analyzers) | Attack infrastructure it doesn't own |
| Harden configurations | Provide step-by-step exploitation of specific targets |
| Generate remediation patches | |
| Coach and educate developers | |

### Offensive Mode (Authorized Pentesting)
| ✅ Cyphron DOES (with authorization) | 🚫 Cyphron NEVER Does |
|---|---|
| Reconnaissance on authorized targets | Attack systems outside scope |
| Vulnerability scanning on authorized targets | Perform unauthorized exploitation |
| Security testing with scope validation | Cause damage beyond demonstration |
| Pentest report generation | Attack without explicit permission |
| Red team simulation (authorized) | |

---

## 🎯 Core Philosophy

Cyphron operates on three pillars:

### 1. **Know Thy Enemy** (Offensive Literacy)
Cyphron understands attacks at a deep, mechanistic level. It knows *why* XSS works, *how* context determines payload form, *when* SQL injection is blind vs. union-based, and *what* makes deserialization dangerous. This knowledge makes its defenses precise rather than generic.

### 2. **Build, Don't Break** (Defensive Action)
Every response must produce or improve a defensive artifact: secure code, a patch, a detection rule, a hardening config, a test case, an architecture diagram, or an educational explanation. Cyphron's output is always constructive.

### 3. **Do No Harm** (Ethical Constraint)
Cyphron refuses to produce working offensive tooling against real targets. It will explain attack theory, demonstrate with sanitized/sandbox examples, and build defenses — but it will not weaponize knowledge against specific systems.

---

## 📁 Directory Structure

```
.Cyphron/
├── README.md                          ← You are here
├── agent-config.yaml                  # Agent configuration (model, params, skills)
├── system-prompt.md                   # Core identity & behavior prompt
├── guardrails/
│   ├── ethics-boundary.md             # Ethical constraints & exploitation boundary
│   ├── action-protocol.md             # Decision tree for every request
│   └── refusal-templates.md           # How to refuse gracefully + redirect
├── skills/                            # 15 specialized skill modules
│   ├── 01-secure-code-review.md
│   ├── 02-threat-modeling.md
│   ├── 03-vulnerability-detection.md
│   ├── 04-security-tool-builder.md
│   ├── 05-cryptography-engineering.md
│   ├── 06-authn-authz-builder.md
│   ├── 07-input-validation-sanitization.md
│   ├── 08-secure-architecture-design.md
│   ├── 09-detection-engineering.md
│   ├── 10-incident-response-builder.md
│   ├── 11-defensive-security-testing.md
│   ├── 12-owasp-top10-hardening.md
│   ├── 13-forensics-analysis.md
│   ├── 14-security-hardening-config.md
│   └── 15-security-education-coaching.md
├── knowledge/                         # Deep reference knowledge
│   ├── attack-encyclopedia.md         # Attack techniques catalog (for defense)
│   ├── secure-patterns.md            # Secure coding patterns by language
│   ├── remediation-playbook.md       # Fix recipes per vulnerability class
│   └── tool-templates.md             # Reusable security tool code templates
├── ollama/                            # Local model deployment
│   ├── setup-guide.md                # Step-by-step Ollama setup
│   ├── Modelfile                     # Ollama Modelfile for Cyphron
│   └── model-recommendations.md      # Which models fit your RAM
└── ferments/                          # User-generated skill extensions
```

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    USER REQUEST                          │
│  "Review this login code for SQL injection"              │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│              GUARDRAILS (action-protocol.md)              │
│  Is this a build/defend/educate request?  → YES          │
│  Is this an exploit/attack request?       → NO (refuse)  │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│           SKILL ROUTING (agent-config.yaml)              │
│  Match request → Skill 01 (Secure Code Review)          │
│  Load skill instructions + relevant knowledge base       │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│           KNOWLEDGE RETRIEVAL (knowledge/)               │
│  attack-encyclopedia.md → SQLi variants & context        │
│  secure-patterns.md    → Parameterized query patterns    │
│  remediation-playbook  → Fix recipe for SQLi             │
└────────────────────────┬────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    DEFENSIVE OUTPUT                       │
│  1. Vulnerability found (line X)                         │
│  2. Attack theory (how SQLi exploits this)               │
│  3. Patched code (parameterized query)                  │
│  4. Detection rule (WAF/IDS signature)                  │
│  5. Test case (unit test proving the fix)                │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Setup Guide

See [`ollama/setup-guide.md`](ollama/setup-guide.md) for full instructions. Quick start:

```bash
# 1. Install Ollama
#    Windows: Download from https://ollama.com/download/windows
#    Or winget: winget install Ollama.Ollama

# 2. Pull a model (see model-recommendations.md for your RAM tier)
ollama pull qwen2.5-coder:32b    # if you have 32GB+ RAM

# 3. Create the Cyphron model from the Modelfile
cd .Cyphron/ollama
ollama create Cyphron -f Modelfile

# 4. Run it
ollama run Cyphron
```

---

## 🧩 Skills Overview

Cyphron has **65 specialized skills** organized by domain:

### Defensive Core (01-15)
| # | Skill | What It Builds |
|---|---|---|
| 01 | Secure Code Review | Vulnerability reports + patched code |
| 02 | Threat Modeling | STRIDE/DREAD models, data flow diagrams |
| 03 | Vulnerability Detection | Static analysis rules, detection logic |
| 04 | Security Tool Builder | Scanners, analyzers, fuzzers (defensive) |
| 05 | Cryptography Engineering | Secure crypto implementations |
| 06 | AuthN/AuthZ Builder | Authentication & authorization systems |
| 07 | Input Validation & Sanitization | Validation pipelines, sanitizers |
| 08 | Secure Architecture Design | Zero-trust architectures, secure patterns |
| 09 | Detection Engineering | WAF rules, IDS/IPS signatures, SIEM queries |
| 10 | Incident Response Builder | IR playbooks, runbooks, automation |
| 11 | Defensive Security Testing | Security test suites, SAST/DAST configs |
| 12 | OWASP Top 10 Hardening | Hardening guides per vulnerability class |
| 13 | Forensics & Analysis | Analysis scripts, log parsers, timeline tools |
| 14 | Security Hardening Config | Server/DB/container hardening configs |
| 15 | Security Education & Coaching | Tutorials, CTF guidance, secure coding training |

### Platform Security (16-25)
| # | Skill | What It Builds |
|---|---|---|
| 16 | API Security Testing | API security assessments, secure API patterns |
| 17 | Cloud Security Engineering | AWS/Azure/GCP hardening, IAM, secure IaC |
| 18 | Container & Kubernetes Security | Pod security, RBAC, network policies |
| 19 | Supply Chain Security | SBOM, artifact signing, SLSA compliance |
| 20 | Secrets Management | Vault, KMS, secret rotation, scanning |
| 21 | Network Security Engineering | Firewalls, IDS/IPS, VPN, segmentation |
| 22 | Email Security Engineering | SPF, DKIM, DMARC, anti-phishing |
| 23 | Mobile App Security | iOS/Android hardening, MASVS compliance |
| 24 | IoT & Embedded Security | Firmware security, secure boot, OTA |
| 25 | Blockchain & Web3 Security | Smart contract audit, DeFi security |

### Architecture & Data (26-35)
| # | Skill | What It Builds |
|---|---|---|
| 26 | Microservices Security | Service mesh, mTLS, API gateway security |
| 27 | Database Security Engineering | RLS, encryption, audit logging |
| 28 | Data Loss Prevention | DLP policies, data classification, masking |
| 29 | Privacy Engineering | GDPR/CCPA compliance, data subject rights |
| 30 | Secure SDLC | DevSecOps pipeline, security gates |
| 31 | Security Policy Development | Policies, standards, procedures |
| 32 | Risk Assessment & Management | Risk register, FAIR, NIST RMF |
| 33 | Compliance & Audit Management | ISO 27001, SOC 2, PCI-DSS, HIPAA |
| 34 | Vulnerability Management | Scanning, prioritization, SLA tracking |
| 35 | Disaster Recovery & BCP | Backup strategy, failover, RTO/RPO |

### Operations & Intelligence (36-45)
| # | Skill | What It Builds |
|---|---|---|
| 36 | Endpoint Security & EDR | Sysmon, hardening, behavioral detection |
| 37 | Identity & Access Management | SSO, MFA, PAM, access reviews |
| 38 | Security Metrics & KPIs | Dashboards, executive reporting, trends |
| 39 | Malware Analysis & Defense | YARA rules, sandbox analysis, IOCs |
| 40 | Reverse Engineering for Defense | Binary analysis, patch diffing, hardening |
| 41 | Memory Safety & Buffer Overflow Defense | ASan, fuzzing, safe C/C++ patterns |
| 42 | Secure CI/CD Pipeline | Security gates, signing, scanning |
| 43 | Security Documentation & Runbooks | Runbooks, ADRs, knowledge bases |
| 44 | Threat Intelligence Integration | IOC management, ATT&CK mapping, hunting |
| 45 | Security Monitoring & SIEM | Log collection, correlation, alerting |

### Human & Physical Security (46-48)
| # | Skill | What It Builds |
|---|---|---|
| 46 | Phishing Defense & Awareness | Email filtering, simulation, training |
| 47 | Social Engineering Defense | Verification procedures, awareness |
| 48 | Physical Security Engineering | Access control, CCTV, data center security |

### Advanced Security (49-55)
| # | Skill | What It Builds |
|---|---|---|
| 49 | Zero Trust Architecture | NIST 800-207, policy engine, micro-segmentation |
| 50 | WAF & DDoS Protection | ModSecurity rules, rate limiting, CDN security |
| 51 | Secure Configuration Management | CIS benchmarks, drift detection, IaC security |
| 52 | Red Team Defense | Purple teaming, ATT&CK coverage, detection validation |
| 53 | Bug Bounty Program | Program policy, triage, rewards, disclosure |
| 54 | Secure API Gateway | Kong, AWS API Gateway, rate limiting, auth |
| 55 | Data Encryption Strategy | KMS, HSM, envelope encryption, key rotation |

### Enterprise & Emerging (56-65)
| # | Skill | What It Builds |
|---|---|---|
| 56 | Secure Remote Access | VPN, ZTNA, bastion, WireGuard |
| 57 | Log Management & Compliance | Tamper-proof logging, retention, SIEM |
| 58 | Security Champions Program | Champion recruitment, training, community |
| 59 | Third-Party Risk Management | Vendor assessment, monitoring, contracts |
| 60 | Secure Data Pipeline | ETL security, streaming security, masking |
| 61 | Cloud-Native Security | Serverless, event-driven, observability |
| 62 | Security Automation & SOAR | Playbooks, orchestration, automated response |
| 63 | Secure Messaging Queue | Kafka, RabbitMQ, SQS security |
| 64 | AI/ML Security | Adversarial defense, prompt injection, model protection |
| 65 | Security Awareness & Gamification | Points, badges, quests, team competitions |

---

## 🛡️ Guardrails

Cyphron's behavior is governed by three guardrail documents:

- [`guardrails/ethics-boundary.md`](guardrails/ethics-boundary.md) — The hard line between knowledge and action
- [`guardrails/action-protocol.md`](guardrails/action-protocol.md) — Decision tree for every request
- [`guardrails/refusal-templates.md`](guardrails/refusal-templates.md) — Graceful refusal + constructive redirect

---

## 📚 Knowledge Base

- [`knowledge/attack-encyclopedia.md`](knowledge/attack-encyclopedia.md) — Catalog of attack techniques (used to build precise defenses)
- [`knowledge/secure-patterns.md`](knowledge/secure-patterns.md) — Secure coding patterns by language/framework
- [`knowledge/remediation-playbook.md`](knowledge/remediation-playbook.md) — Fix recipes per vulnerability class
- [`knowledge/tool-templates.md`](knowledge/tool-templates.md) — Reusable code templates for security tools

---

## 💻 Hardware Requirements

| RAM | Recommended Model | Approx. Size | Capability Tier |
|-----|-------------------|-------------|-----------------|
| 8 GB | `qwen2.5-coder:7b` | ~4.7 GB | Basic — simple reviews, hardening |
| 16 GB | `qwen2.5-coder:14b` | ~9 GB | Good — most skills functional |
| **32 GB+** | `qwen2.5-coder:32b` | ~20 GB | **Full** — all skills, deep analysis |
| 64 GB+ | `qwen2.5:72b` or `deepseek-coder-v2:16b` | ~40 GB | Expert — research-grade reasoning |

See [`ollama/model-recommendations.md`](ollama/model-recommendations.md) for detailed guidance.

---

## 📝 License & Disclaimer

This framework is for **defensive cybersecurity education and secure software development**. The attack knowledge in the knowledge base is provided so that defenses can be precise and comprehensive — not to enable attacks. Using any output from this agent to attack systems you do not own or have explicit authorization to test is illegal and unethical.

**Cyphron builds. Cyphron does not break.**
