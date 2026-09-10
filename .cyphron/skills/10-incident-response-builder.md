# Skill 10 — Incident Response Builder

> Cyphron's methodology for building incident response playbooks, runbooks, and automation. Cyphron knows how attackers operate post-compromise — persistence, lateral movement, data exfiltration — so it builds IR processes that detect, contain, and eradicate threats effectively.

---

## WHEN TO ACTIVATE

- User asks to build an incident response playbook or runbook
- User asks "what do I do if [incident type] happens?"
- User asks to create IR automation or SOAR workflows
- User asks about breach response, containment, or eradication
- User asks to build a security operations process
- User asks about tabletop exercises or IR planning

---

## METHODOLOGY

### The IR Lifecycle (NIST SP 800-61)

```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned
    ↑                                                                        │
    └────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Preparation
Build the foundation before an incident occurs:
- IR team roles and contact tree
- Communication plan (internal, external, legal, regulatory)
- Tooling (forensics, analysis, containment)
- Playbooks per incident type
- Tabletop exercise schedule

### Step 2: Detection & Analysis
Define how incidents are detected and triaged:
- Alert sources (SIEM, EDR, WAF, user reports)
- Triage criteria (severity, scope, confidence)
- Initial analysis steps
- Escalation thresholds

### Step 3: Containment
Define immediate containment actions per incident type:
- Short-term containment (stop the bleeding)
- Long-term containment (allow operation while investigating)

### Step 4: Eradication
Define how to remove the threat:
- Identify root cause
- Remove malware/backdoors
- Patch vulnerabilities
- Reset compromised credentials

### Step 5: Recovery
Define how to restore normal operations:
- Restore from clean backups
- Validate system integrity
- Monitor for re-infection
- Phased restoration

### Step 6: Lessons Learned
Define post-incident review:
- Timeline reconstruction
- Root cause analysis
- What worked / what didn't
- Process improvements
- Detection gaps to close

---

## OUTPUT FORMAT

```markdown
## 🚨 Incident Response Playbook: [Incident Type]

### Incident Overview
- **Type:** [e.g., Ransomware, Data Breach, Web Defacement]
- **Severity criteria:** [what makes this P1/P2/P3]
- **Expected impact:** [what's at risk]

### Detection
| Signal | Source | Threshold |
|---|---|---|
| [signal] | [source] | [trigger] |

### Triage
1. [First analysis step]
2. [Second analysis step]
3. [Escalation criteria]

### Containment
**Immediate (within X minutes):**
- [ ] [action 1]
- [ ] [action 2]

**Short-term (within X hours):**
- [ ] [action 1]
- [ ] [action 2]

### Eradication
- [ ] [action to remove threat]
- [ ] [action to prevent recurrence]

### Recovery
- [ ] [restoration step]
- [ ] [validation step]
- [ ] [monitoring step]

### Communication
| Audience | When | Message |
|---|---|---|
| [audience] | [timing] | [what to say] |

### Runbook (Step-by-Step)
```bash
[commands/scripts for each step]
```

### Post-Incident
- [ ] Timeline reconstruction
- [ ] Root cause analysis
- [ ] Detection gap identification
- [ ] Process improvement actions
```

---

## PLAYBOOK TEMPLATES

### Playbook: Ransomware Detection & Response

```markdown
## Ransomware IR Playbook

### Detection
- EDR alerts: mass file encryption, ransomware process signatures
- File server alerts: rapid file modification across many files
- User reports: files inaccessible, ransom note displayed
- Backup system alerts: backup deletion attempts

### Triage
1. Confirm: Is this actual ransomware or false positive (e.g., disk encryption policy)?
2. Scope: Which systems are affected? Is it spreading?
3. Identify: What ransomware strain? (check ransom note, file extensions)
4. Severity: P1 if production systems affected or spreading

### Containment (Immediate — within 15 minutes)
- [ ] Isolate affected systems from network (do NOT power off — preserve forensics)
- [ ] Disable affected user accounts
- [ ] Block known C2 domains/IPs at firewall
- [ ] Snapshot affected VMs for forensics
- [ ] Activate IR team and communication plan

### Eradication
- [ ] Identify entry point (phishing, RDP, vulnerability, stolen creds)
- [ ] Identify persistence mechanisms (scheduled tasks, services, registry)
- [ ] Reimage affected systems from known-good baseline
- [ ] Reset ALL credentials that may have been exposed
- [ ] Patch the vulnerability that allowed entry

### Recovery
- [ ] Restore data from offline/immutable backups (verify backup integrity first)
- [ ] Validate restored systems (scan for malware, verify functionality)
- [ ] Phased restoration: critical systems first
- [ ] Enhanced monitoring for 30 days post-incident
- [ ] Do NOT pay ransom (encourages future attacks, no guarantee of recovery)

### Communication
- Internal: Executive team, legal, IT, affected business units
- External: Law enforcement (FBI/IC3), regulators (if data breach), customers (if applicable)
- Do NOT communicate publicly until legal approves

### Post-Incident
- Timeline: When did entry occur? When detected? When contained?
- Root cause: How did attacker get in?
- Backup review: Were backups adequate? Were they targeted?
- Detection improvement: How to detect faster next time
```

### Playbook: Web Application Compromise

```markdown
## Web App Compromise IR Playbook

### Detection
- WAF alerts: attack patterns (SQLi, XSS, RCE)
- Anomaly detection: unusual API usage, data access patterns
- File integrity monitoring: unexpected file changes on web server
- Log analysis: suspicious admin actions, new user creation

### Triage
1. Confirm: Is this a real compromise or security testing?
2. Scope: Which endpoints/data affected? Is attacker still active?
3. Identify: Attack vector (vulnerability exploited, creds stolen)
4. Severity: P1 if data exfiltration or persistent access

### Containment
- [ ] Block attacker IP at WAF/firewall
- [ ] Disable compromised accounts
- [ ] If RCE: isolate server, route traffic to failover
- [ ] Preserve logs (copy to immutable storage)
- [ ] Snapshot server for forensics

### Eradication
- [ ] Identify and patch exploited vulnerability
- [ ] Remove web shells / backdoors (search for new/modified files)
- [ ] Rotate ALL secrets (DB passwords, API keys, JWT signing keys)
- [ ] Review and remove unauthorized admin accounts
- [ ] Scan all code for injected backdoors

### Recovery
- [ ] Deploy patched version
- [ ] Validate with security testing (SAST, DAST, manual review)
- [ ] Monitor for re-exploitation attempts
- [ ] Notify affected users if data was breached (per regulation)

### Post-Incident
- How was the vulnerability introduced? (code review gap, missing SAST)
- How long was the attacker present? (log timeline analysis)
- What data was accessed/exfiltrated?
- Detection improvement: what alert would have caught this earlier?
```

### Playbook: Credential Compromise

```markdown
## Credential Compromise IR Playbook

### Detection
- Impossible travel: login from geographically distant locations
- Anomalous access: user accessing resources they never access
- Failed MFA: repeated MFA failures followed by success
- Credential dump: credentials found in breach databases
- Unusual data access: bulk download, off-hours access

### Triage
1. Confirm: Is this the legitimate user (new device, travel) or compromise?
2. Scope: What did the compromised account access?
3. Identify: How were credentials obtained? (phishing, breach, brute force)
4. Severity: P1 if admin account or sensitive data access

### Containment
- [ ] Disable compromised account immediately
- [ ] Revoke all active sessions/tokens
- [ ] Force password reset + MFA re-enrollment
- [ ] Block source IP if malicious
- [ ] Check for OAuth app abuse (revoke malicious app grants)

### Eradication
- [ ] Identify credential theft vector (phishing email, fake login page)
- [ ] Remove phishing infrastructure (if internal)
- [ ] Check for mailbox rules created by attacker (forwarding, deletion)
- [ ] Scan endpoint for info-stealer malware
- [ ] Reset credentials for any other accounts using same password

### Recovery
- [ ] User completes security training (if phishing)
- [ ] Enhanced monitoring on recovered account for 30 days
- [ ] Deploy FIDO2 hardware keys for high-privilege accounts
- [ ] Verify no data was exfiltrated via mailbox rules

### Post-Incident
- Was MFA enabled? Was it bypassed? How?
- Was the credential in a known breach? (check HIBP)
- How long was the account compromised?
- Improve: conditional access, impossible travel alerts, FIDO2 rollout
```

---

## IR AUTOMATION (SOAR) PATTERNS

### Automated Containment Workflow
```python
# Pseudo-code for SOAR automation
def handle_alert(alert):
    # 1. Enrich
    alert = enrich_with_context(alert)  # threat intel, user info, asset info

    # 2. Triage
    severity = calculate_severity(alert)
    if severity < THRESHOLD:
        return  # auto-close low severity

    # 3. Contain (based on type)
    if alert.type == 'credential_compromise':
        disable_user(alert.user)
        revoke_sessions(alert.user)
        notify_user(alert.user, "Account secured due to suspicious activity")

    elif alert.type == 'malware_detection':
        isolate_host(alert.host)
        trigger_forensic_snapshot(alert.host)

    elif alert.type == 'web_attack':
        block_ip(alert.src_ip, duration='24h')
        create_waf_rule(alert.pattern)

    # 4. Notify
    notify_ir_team(alert, actions_taken)
    create_ticket(alert)

    # 5. Document
    log_response(alert, actions_taken)
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — attacker post-compromise behavior
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — eradication steps per threat
