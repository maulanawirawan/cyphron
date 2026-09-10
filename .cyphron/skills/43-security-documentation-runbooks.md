# Skill 43 — Security Documentation & Runbooks

> Cyphron's methodology for creating security documentation, runbooks, and knowledge bases. Good security documentation is itself a security control — it ensures consistent, repeatable security practices.

---

## WHEN TO ACTIVATE

- User asks to create security documentation
- User asks for a runbook or SOP
- User asks about security knowledge management
- User asks to document a security process

---

## METHODOLOGY

### Documentation Types

| Type | Purpose | Audience |
|---|---|---|
| Runbook | Step-by-step operational procedures | On-call engineers |
| SOP | Standard Operating Procedure | Operations team |
| Architecture doc | Security architecture decisions | Engineers, architects |
| Playbook | Incident response procedures | IR team |
| Knowledge base | Reference information | All staff |
| Onboarding | Security setup for new hires | New employees |

### Documentation Principles
1. **Actionable** — reader can follow steps and get results
2. **Current** — reviewed and updated regularly
3. **Accessible** — findable when needed (not buried)
4. **Tested** — procedures actually work
5. **Versioned** — changes tracked

---

## TEMPLATES

### Security Runbook Template
```markdown
# Runbook: [Procedure Name]

## Metadata
- **Owner**: [Team/Person]
- **Last reviewed**: [Date]
- **Next review**: [Date + 6 months]
- **Severity**: [Routine/Urgent/Emergency]

## Purpose
[What this runbook accomplishes and when to use it]

## Prerequisites
- [Access requirements]
- [Tools needed]
- [Knowledge required]

## Steps

### Step 1: [Action]
1. [Detailed step]
2. [Detailed step]
   ```bash
   [exact command]
   ```
3. [Expected output]
   ```
   [what you should see]
   ```

### Step 2: [Action]
...

## Verification
[How to confirm the procedure was successful]
```bash
[verification command]
```

## Rollback
[How to undo if something goes wrong]
```bash
[rollback command]
```

## Troubleshooting
| Problem | Solution |
|---|---|
| [common issue] | [fix] |
| [common issue] | [fix] |

## Escalation
- **Level 1**: [On-call engineer]
- **Level 2**: [Team lead]
- **Level 3**: [Manager/CISO]
```

### Security Architecture Decision Record (ADR)
```markdown
# ADR-[Number]: [Decision Title]

## Status
[Proposed | Accepted | Deprecated | Superseded]

## Context
[Why this decision is needed — what problem are we solving?]

## Decision
[What we decided to do]

## Consequences
### Positive
- [benefit 1]
- [benefit 2]

### Negative
- [trade-off 1]
- [trade-off 2]

### Neutral
- [observation]

## Alternatives Considered
### Alternative 1: [Name]
- **Pros**: [list]
- **Cons**: [list]
- **Why not chosen**: [reason]

### Alternative 2: [Name]
- **Pros**: [list]
- **Cons**: [list]
- **Why not chosen**: [reason]

## References
- [Links to relevant docs, standards, research]

## Compliance
- [Which controls does this satisfy?]
```

### Security Onboarding Checklist
```markdown
# Security Onboarding — New Engineer

## Week 1
- [ ] Read Information Security Policy
- [ ] Complete security awareness training
- [ ] Set up MFA on all accounts
- [ ] Configure password manager
- [ ] Read secure coding guidelines
- [ ] Set up VPN access
- [ ] Review data classification standard

## Week 2
- [ ] Complete role-specific security training
- [ ] Review threat model for your team's service
- [ ] Set up SAST in your development environment
- [ ] Review incident response procedure
- [ ] Understand secret management (Vault/SM)
- [ ] Review access control policy

## Month 1
- [ ] Complete secure coding training (OWASP Top 10)
- [ ] Shadow on-call for security incidents
- [ ] Review security architecture for your service
- [ ] Understand compliance requirements (if applicable)
- [ ] Set up pre-commit security hooks
- [ ] Review dependency management process

## Month 3
- [ ] Complete first security code review
- [ ] Participate in tabletop exercise
- [ ] Review and update team's threat model
- [ ] Contribute to security documentation
```

### Security Knowledge Base Structure
```
security-kb/
├── policies/           ← Official policies
│   ├── information-security-policy.md
│   ├── acceptable-use-policy.md
│   └── data-classification.md
├── standards/          ← Technical standards
│   ├── password-standard.md
│   ├── encryption-standard.md
│   └── logging-standard.md
├── procedures/         ← How-to procedures
│   ├── incident-response.md
│   ├── vulnerability-management.md
│   └── access-review.md
├── runbooks/           ← Operational runbooks
│   ├── on-call/
│   ├── deployment/
│   └── incident/
├── architecture/       ← Architecture decisions
│   ├── adr/
│   └── diagrams/
├── training/           ← Training materials
│   ├── secure-coding/
│   ├── awareness/
│   └── role-specific/
└── reference/          ← Reference material
    ├── owasp-top-10/
    ├── compliance/
    └── vendor-security/
```

---

## AUDIT CHECKLIST

- [ ] Security policies documented and accessible
- [ ] Runbooks for all critical operations
- [ ] Incident response playbooks (per incident type)
- [ ] Architecture decision records maintained
- [ ] Onboarding documentation for new hires
- [ ] Secure coding guidelines published
- [ ] Knowledge base organized and searchable
- [ ] Documentation reviewed at least annually
- [ ] Version control on all documentation
- [ ] Documentation tested (procedures actually work)
- [ ] Documentation accessible during incidents (offline copy)
- [ ] Owner assigned to each document
