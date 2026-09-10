# Skill 31 — Security Policy Development

> Cyphron's methodology for developing security policies, standards, and procedures. Cyphron builds comprehensive security governance documents that are practical, enforceable, and aligned with frameworks (ISO 27001, NIST CSF, SOC 2).

---

## WHEN TO ACTIVATE

- User asks to create a security policy
- User asks about security standards or procedures
- User asks about ISO 27001, NIST CSF, or SOC 2 documentation
- User asks about acceptable use, data classification, or access control policies

---

## METHODOLOGY

### Step 1: Identify Policy Type
| Type | Purpose | Examples |
|---|---|---|
| Policy | High-level "what" and "why" | Information Security Policy |
| Standard | Specific "what" | Password Standard, Encryption Standard |
| Procedure | Step-by-step "how" | Incident Response Procedure |
| Guideline | Recommended practices | Secure Coding Guidelines |
| Baseline | Minimum configuration | Server Hardening Baseline |

### Step 2: Align with Framework
- ISO 27001/27002 — Annex A controls
- NIST CSF — Identify, Protect, Detect, Respond, Recover
- SOC 2 — Security, Availability, Confidentiality, Processing Integrity, Privacy

### Step 3: Build Policy Documents

---

## POLICY TEMPLATES

### Information Security Policy (Master)
```markdown
# Information Security Policy

## 1. Purpose
This policy establishes the organization's commitment to protecting
information assets from unauthorized access, use, disclosure, disruption,
modification, or destruction.

## 2. Scope
This policy applies to all employees, contractors, vendors, and third
parties who access [Organization] information systems and data.

## 3. Policy Statements

### 3.1 Information Classification
Information is classified as: Public, Internal, Confidential, Restricted.
Each classification has defined handling requirements (see Data Classification Standard).

### 3.2 Access Control
- Access is granted on a need-to-know basis
- Least privilege is enforced
- Access is reviewed quarterly
- MFA is required for all privileged access

### 3.3 Authentication
- Passwords must meet [Password Standard]
- MFA required for remote access and admin functions
- Failed login attempts are limited and monitored

### 3.4 Encryption
- Data in transit: TLS 1.2+
- Data at rest: AES-256
- Key management: [Key Management Standard]

### 3.5 Incident Response
- All security incidents must be reported within 1 hour
- Incident response follows [Incident Response Procedure]
- Post-incident review within 5 business days

### 3.6 Security Awareness
- All employees complete security training annually
- Phishing simulation conducted quarterly

### 3.7 Vulnerability Management
- Critical vulnerabilities patched within 72 hours
- High within 7 days, Medium within 30 days
- Monthly vulnerability scans

### 3.8 Third-Party Security
- Vendor security assessment before onboarding
- Annual review of critical vendors
- Data Processing Agreements required

## 4. Roles & Responsibilities
- **CISO**: Policy ownership, oversight, risk management
- **Security Team**: Implementation, monitoring, incident response
- **IT**: Technical controls, patching, access management
- **Managers**: Ensure team compliance, report incidents
- **All Staff**: Follow policy, complete training, report incidents

## 5. Enforcement
Violations may result in disciplinary action up to termination and
legal prosecution.

## 6. Review
This policy is reviewed annually by the CISO and approved by [Executive].

## 7. References
- Data Classification Standard
- Password Standard
- Encryption Standard
- Incident Response Procedure
- Acceptable Use Policy

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-01 | CISO | Initial |
```

### Acceptable Use Policy (AUP)
```markdown
# Acceptable Use Policy

## 1. Purpose
Defines acceptable use of [Organization] information systems.

## 2. Acceptable Use
- Use systems for business purposes
- Protect credentials, never share
- Lock screen when away
- Report suspicious activity immediately

## 3. Prohibited Use
- Sharing credentials
- Installing unapproved software
- Accessing data without authorization
- Using personal email for confidential data
- Bypassing security controls
- Connecting personal devices to restricted networks

## 4. Email & Communication
- No sensitive data in unencrypted email
- Verify sender before clicking links
- Report phishing immediately
- No auto-forwarding to personal email

## 5. Internet Use
- No accessing inappropriate content
- No downloading unapproved files
- No using personal cloud storage for company data

## 6. Mobile Devices
- BYOD requires MDM enrollment
- Device encryption required
- Remote wipe capability enabled

## 7. Social Media
- Don't share confidential information
- Don't speak on behalf of company without authorization
- Verify before posting about company
```

### Data Classification Standard
```markdown
# Data Classification Standard

## Classification Levels

| Level | Description | Examples | Handling |
|---|---|---|---|
| Public | Approved for public release | Marketing, public docs | No restrictions |
| Internal | For internal use | Memos, internal reports | Internal access, no external sharing |
| Confidential | Sensitive business data | Financials, customer data | Need-to-know, encrypted, audit logged |
| Restricted | Highly sensitive | PII, PHI, credentials, keys | Strict controls, encryption, MFA, full audit |

## Handling Requirements

### Storage
| Level | Local | Network | Cloud |
|---|---|---|---|
| Public | ✅ | ✅ | ✅ |
| Internal | ⚠️ Encrypted | ✅ | ✅ Approved services |
| Confidential | ❌ | ✅ Encrypted | ✅ Approved + encrypted |
| Restricted | ❌ | ✅ Encrypted + access control | ⚠️ Approved + encrypted + DLP |

### Transmission
| Level | Email | File Share | API |
|---|---|---|---|
| Public | ✅ | ✅ | ✅ |
| Internal | ✅ Internal only | ✅ Internal | ✅ Authenticated |
| Confidential | ✅ Encrypted | ✅ Encrypted + auth | ✅ TLS + auth |
| Restricted | ❌ Use secure transfer | ✅ Encrypted + MFA | ✅ TLS + MFA + audit |

### Disposal
| Level | Method |
|---|---|
| Public | Standard deletion |
| Internal | Secure delete |
| Confidential | Secure delete + verify |
| Restricted | Secure delete + verify + log |
```

---

## FRAMEWORK ALIGNMENT

### ISO 27001 Annex A Controls
```markdown
| Control | Policy/Standard |
|---|---|
| A.5 Information Security Policies | Information Security Policy |
| A.6 Organization of Security | Security Roles & Responsibilities |
| A.7 Human Resource Security | Onboarding/Offboarding Procedure |
| A.8 Asset Management | Asset Management Policy, Data Classification |
| A.9 Access Control | Access Control Policy, Password Standard |
| A.10 Cryptography | Encryption Standard, Key Management |
| A.11 Physical Security | Physical Security Policy |
| A.12 Operations Security | Operations Security Procedures |
| A.13 Communications Security | Network Security Policy |
| A.14 System Acquisition | Secure SDLC Policy |
| A.15 Supplier Relationships | Third-Party Security Policy |
| A.16 Incident Management | Incident Response Procedure |
| A.17 Business Continuity | BCP/DR Policy |
| A.18 Compliance | Compliance Management Policy |
```

### NIST CSF Mapping
```markdown
| Function | Category | Policy/Control |
|---|---|---|
| Identify | Asset Management | Asset Inventory, Data Classification |
| Identify | Risk Assessment | Risk Assessment Procedure |
| Identify | Governance | Security Policy, Roles |
| Protect | Access Control | Access Control Policy, MFA |
| Protect | Awareness Training | Security Awareness Program |
| Protect | Data Security | Encryption Standard, DLP |
| Protect | Protective Technology | Hardening Baselines |
| Detect | Anomalies & Events | Monitoring, SIEM |
| Detect | Continuous Monitoring | Security Monitoring Procedure |
| Respond | Response Planning | Incident Response Procedure |
| Respond | Mitigation | Containment Procedures |
| Recover | Recovery Planning | BCP/DR Plan |
| Recover | Improvements | Post-Incident Review |
```

---

## AUDIT CHECKLIST

- [ ] Information Security Policy (master) approved
- [ ] Acceptable Use Policy signed by all employees
- [ ] Data Classification Standard defined
- [ ] Access Control Policy enforced
- [ ] Password Standard documented
- [ ] Encryption Standard documented
- [ ] Incident Response Procedure documented
- [ ] Third-Party Security Policy
- [ ] Physical Security Policy
- [ ] Business Continuity Plan
- [ ] Policies reviewed annually
- [ ] Policy exceptions documented and approved
- [ ] Framework alignment (ISO/NIST/SOC2)
- [ ] Employee acknowledgment tracked
