# 🛡️ Cyphron — Ringkasan untuk Teman

> **Cyphron** = AI agent cybersecurity lokal (open-source, jalan di laptop kamu pakai Ollama).
> Punya **65 skill**, **2 mode** (defensive + authorized pentest), **guardrails etika**.
> Nama dari "Cipher" — cocok sama Airon & Protheron teman-teman kamu. 🔐

---

## 🎯 Apa Itu Cyphron?

Cyphron adalah AI agent cybersecurity yang jalan **lokal di laptop kamu** (pakai Ollama + model open-source seperti Qwen 2.5 Coder). Dia tahu **semua teknik serangan** (XSS, SQLi, SSRF, RCE, dll) dan punya **2 mode**:

| Mode | Fungsi | Butuh Izin? |
|---|---|---|
| **Defensive** (default) | Build secure code, review, hardening, detection | Tidak |
| **Offensive** (pentest) | Scan, exploit, report (authorized testing) | **Ya** (authorization + scope) |

**Prinsip:** `BUILD. DEFEND. EDUCATE. AUTHORIZED TESTING ONLY. NEVER HARM.`

---

## 🧩 65 Skill — Ringkasan Singkat

### 1. Defensive Core (Skill 01-15) — Fondasi
| # | Skill | Singkatnya |
|---|---|---|
| 01 | Secure Code Review | Review kode, cari bug, kasih patch |
| 02 | Threat Modeling | STRIDE/DREAD, peta serangan |
| 03 | Vulnerability Detection | Static analysis, deteksi pola bug |
| 04 | Security Tool Builder | Bikin scanner, fuzzer, analyzer |
| 05 | Cryptography Engineering | Enkripsi yang aman (AES-GCM, Argon2) |
| 06 | AuthN/AuthZ Builder | Login, session, JWT, RBAC aman |
| 07 | Input Validation | Validasi & sanitasi input (anti XSS/SQLi) |
| 08 | Secure Architecture | Zero trust, microservices, defense in depth |
| 09 | Detection Engineering | WAF rule, IDS signature, SIEM query |
| 10 | Incident Response | Playbook breach, ransomware, dll |
| 11 | Defensive Testing | SAST, DAST, security test suite |
| 12 | OWASP Top 10 Hardening | Hardening per kategori (A01-A10) |
| 13 | Forensics & Analysis | Analisis log, timeline, IOC |
| 14 | Security Hardening Config | Nginx, Docker, PostgreSQL, K8s config |
| 15 | Security Education | Belajar security, CTF coaching |

### 2. Platform Security (Skill 16-25) — Per Platform
| # | Skill | Singkatnya |
|---|---|---|
| 16 | API Security Testing | REST/GraphQL security, OWASP API Top 10 |
| 17 | Cloud Security Engineering | AWS/Azure/GCP hardening, IAM, IaC |
| 18 | Container & K8s Security | Pod security, RBAC, network policy |
| 19 | Supply Chain Security | SBOM, dependency scan, artifact signing |
| 20 | Secrets Management | Vault, KMS, secret rotation, scanning |
| 21 | Network Security Engineering | Firewall, IDS/IPS, VPN, DNS security |
| 22 | Email Security Engineering | SPF, DKIM, DMARC, anti-phishing |
| 23 | Mobile App Security | iOS/Android hardening, MASVS |
| 24 | IoT & Embedded Security | Firmware security, secure boot, OTA |
| 25 | Blockchain & Web3 Security | Smart contract audit, DeFi, reentrancy |

### 3. Architecture & Data (Skill 26-35) — Arsitektur & Data
| # | Skill | Singkatnya |
|---|---|---|
| 26 | Microservices Security | Service mesh, mTLS, API gateway |
| 27 | Database Security Engineering | RLS, encryption, audit logging |
| 28 | Data Loss Prevention (DLP) | Klasifikasi data, masking, anti-exfiltration |
| 29 | Privacy Engineering | GDPR, CCPA, data subject rights |
| 30 | Secure SDLC | DevSecOps, security gates di pipeline |
| 31 | Security Policy Development | Policy, standard, procedure docs |
| 32 | Risk Assessment & Management | Risk register, FAIR, NIST RMF |
| 33 | Compliance & Audit Management | ISO 27001, SOC 2, PCI-DSS, HIPAA |
| 34 | Vulnerability Management | Scan, prioritization, SLA tracking |
| 35 | Disaster Recovery & BCP | Backup, failover, RTO/RPO |

### 4. Operations & Intelligence (Skill 36-45) — Operasional
| # | Skill | Singkatnya |
|---|---|---|
| 36 | Endpoint Security & EDR | Sysmon, hardening, behavioral detection |
| 37 | Identity & Access Management | SSO, MFA, PAM, access review |
| 38 | Security Metrics & KPIs | Dashboard, MTTR, SLA compliance |
| 39 | Malware Analysis & Defense | YARA rules, sandbox, IOC extraction |
| 40 | Reverse Engineering for Defense | Binary analysis, patch diffing, checksec |
| 41 | Memory Safety & Buffer Overflow | ASan, fuzzing, safe C/C++ patterns |
| 42 | Secure CI/CD Pipeline | Security gates, signing, scanning |
| 43 | Security Documentation & Runbooks | Runbook, ADR, knowledge base |
| 44 | Threat Intelligence Integration | IOC management, MITRE ATT&CK, hunting |
| 45 | Security Monitoring & SIEM | Log collection, correlation, alerting |

### 5. Human & Physical Security (Skill 46-48) — Manusia & Fisik
| # | Skill | Singkatnya |
|---|---|---|
| 46 | Phishing Defense & Awareness | Email filtering, simulation, training |
| 47 | Social Engineering Defense | Verification procedure, anti-pretexting |
| 48 | Physical Security Engineering | Badge, CCTV, data center security |

### 6. Advanced Security (Skill 49-55) — Advanced
| # | Skill | Singkatnya |
|---|---|---|
| 49 | Zero Trust Architecture | NIST 800-207, policy engine, micro-seg |
| 50 | WAF & DDoS Protection | ModSecurity, rate limiting, CDN |
| 51 | Secure Configuration Management | CIS benchmark, drift detection, IaC |
| 52 | Red Team Defense | Purple teaming, ATT&CK coverage |
| 53 | Bug Bounty Program | Program policy, triage, rewards |
| 54 | Secure API Gateway | Kong, AWS API Gateway, auth, rate limit |
| 55 | Data Encryption Strategy | KMS, HSM, envelope encryption, rotation |

### 7. Enterprise & Emerging (Skill 56-65) — Enterprise & Teknologi Baru
| # | Skill | Singkatnya |
|---|---|---|
| 56 | Secure Remote Access | VPN, ZTNA, bastion, WireGuard |
| 57 | Log Management & Compliance | Tamper-proof logging, retention |
| 58 | Security Champions Program | Champion recruitment, training, community |
| 59 | Third-Party Risk Management | Vendor assessment, monitoring, contract |
| 60 | Secure Data Pipeline | ETL security, streaming, masking |
| 61 | Cloud-Native Security | Serverless, Lambda, event-driven |
| 62 | Security Automation & SOAR | Playbook, orchestration, auto-response |
| 63 | Secure Messaging Queue | Kafka, RabbitMQ, SQS security |
| 64 | AI/ML Security | Adversarial defense, prompt injection |
| 65 | Security Awareness & Gamification | Points, badges, quests, competition |

---

## 🔒 Guardrails (Batasan Etika)

Cyphron punya **4 guardrail** yang nggak bisa di-bypass:

1. **Ethics Boundary** — Garis keras: knowledge bebas, weaponization tidak
2. **Action Protocol** — Decision tree 4-gate untuk setiap request
3. **Authorization Protocol** — Pentest butuh authorization + scope validation
4. **Refusal Templates** — Cara menolak + redirect ke defensive equivalent

**Intinya:** Cyphron bisa nge-test sistem yang **diizinkan**, tapi **nggak bisa** nyerang tanpa izin.

---

## 🚀 Cara Pakai

```bash
# Install Ollama
winget install Ollama.Ollama

# Pull model (butuh 32GB RAM untuk full capability)
ollama pull qwen2.5-coder:32b

# Create Cyphron
cd d:/training/.kimchi/ollama
ollama create Cyphron -f Modelfile

# Run!
ollama run Cyphron
```

---

## 💡 Kenapa Cyphron Beda?

| Cyphron | AI Security Lain |
|---|---|
| 65 skill, 7 kategori | Biasanya 5-10 skill |
| Dual-mode (defensive + pentest) | Biasanya hanya satu mode |
| Guardrails dengan authorization protocol | Biasanya tidak ada atau lemah |
| Jalan lokal (privacy) | Biasanya cloud (data keluar) |
| Open-source (Ollama + Qwen) | Biasanya proprietary |
| Knowledge base mendalam | Biasanya surface-level |

---

**Cyphron** — dari "Cipher". Tahu segala cara serangan, bangun pertahanan tak tertembus, pentest dengan izin. 65 skill, 2 mode, 1 prinsip: **AUTHORIZED TESTING ONLY. NEVER HARM.** 🔐
