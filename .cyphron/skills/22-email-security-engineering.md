# Skill 22 — Email Security Engineering

> Cyphron's methodology for securing email infrastructure against phishing, spoofing, BEC (Business Email Compromise), and malware delivery. Cyphron knows email attack vectors and builds defenses: SPF, DKIM, DMARC, email filtering, and anti-phishing controls.

---

## WHEN TO ACTIVATE

- User asks to secure email infrastructure
- User asks about SPF, DKIM, DMARC configuration
- User asks about phishing prevention or email filtering
- User asks about BEC protection
- User asks to build email security policies

---

## METHODOLOGY

### Step 1: Identify Email Infrastructure
- Email server (Exchange, Postfix, Google Workspace, M365)
- Email security gateway (Proofpoint, Mimecast, SEG)
- Email clients and access methods

### Step 2: Apply Email Security Layers

| Layer | Control |
|---|---|
| Authentication | SPF, DKIM, DMARC |
| Filtering | Anti-spam, anti-malware, anti-phishing |
| Content | URL rewriting, attachment sandboxing |
| Access | MFA, conditional access, encryption |
| Monitoring | Email logs, anomaly detection |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### SPF (Sender Policy Framework)
```dns
# DNS TXT record — authorize sending servers
example.com.  IN  TXT  "v=spf1 include:_spf.google.com include:mailgun.org ip4:192.0.2.0/24 -all"
# -all = hard fail (reject unauthorized senders)
# ~all = soft fail (mark but accept) — use during testing, then switch to -all
```

### DKIM (DomainKeys Identified Mail)
```dns
# DNS TXT record — public key for signature verification
selector1._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ..."
```

```bash
# Postfix + OpenDKIM configuration
# /etc/opendkim.conf
Domain example.com
KeyFile /etc/dkim/private.key
Selector selector1
Socket inet:8891@localhost

# /etc/postfix/main.cf
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
```

### DMARC (Domain-based Message Authentication)
```dns
# DNS TXT record — policy for failed authentication
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensics@example.com; fo=1; adkim=s; aspf=s; pct=100"
# p=reject — reject emails that fail SPF/DKIM
# p=quarantine — send to spam (testing phase)
# p=none — monitor only (initial rollout)
```

### Email Filtering Rules (SpamAssassin)
```cf
# /etc/spamassassin/local.cf

# Phishing indicators
header PHISHING_SUSPECT Subject =~ /urgent|verify|suspend|account/i
describe PHISHING_SUSPECT Urgency/verify language in subject
score PHISHING_SUSPECT 3.0

# BEC indicators
header BEC_SUSPECT From =~ /ceo|cfo|president|executive/i
header BEC_SUSPECT_REPLY Reply-To =~ /gmail|yahoo|hotmail/i
describe BEC_SUSPECT Executive display name with free email reply-to
score BEC_SUSPECT 5.0

# Malware attachment indicators
header MALWARE_ZIP Content-Type =~ /application\/zip/i
describe MALWARE_ZIP ZIP attachment
score MALWARE_ZIP 2.0

# Spoofing detection
header SPOOF_INTERNAL From =~ /@example\.com/i
header SPOOF_INTERNAL_RECEIVED Received =~ /from.*external/i
describe SPOOF_INTERNAL Internal From with external Received
score SPOOF_INTERNAL 4.0
```

### Anti-Phishing Detection (Sigma)
```yaml
title: Suspicious Email with Urgency Language
id: 3a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d
status: stable
description: >
  Detects emails with urgency/pressure language commonly used in
  phishing and BEC attacks.
logsource:
  product: email
detection:
  selection:
    subject|contains:
      - "urgent"
      - "immediate action required"
      - "account suspended"
      - "verify your account"
      - "payment required"
      - "invoice overdue"
  filter_legitimate:
    from|contains:
      - "@your-bank.com"
      - "@your-company.com"
  condition: selection and not filter_legitimate
level: medium
tags:
  - attack.initial_access
  - attack.t1566
  - attack.phishing
```

### M365 Email Security (PowerShell)
```powershell
# Enable DMARC
Set-DmarcRecord -Domain "example.com" -Action Reject

# Anti-phishing policy
New-AntiPhishPolicy -Name "StrictAntiPhish" `
  -EnableTargetedUserProtection $true `
  -TargetedUsersToProtect "ceo@example.com;cio@example.com" `
  -EnableMailboxIntelligence $true `
  -EnableMailboxIntelligenceProtection $true `
  -MailboxIntelligenceProtectionAction Quarantine `
  -EnableSpoofIntelligence $true `
  -EnableOrganizationDomainsProtection $true `
  -EnableSimilarUsersSafetyTips $true `
  -EnableUnusualCharactersSafetyTips $true

# Safe Links (URL rewriting + detonation)
Set-SafeLinksPolicy -Identity "Default" `
  -EnableSafeLinksForEmail $true `
  -EnableSafeLinksForTeams $true `
  -ScanUrls $true `
  -DeliverMessageAfterScan $true
```

---

## AUDIT CHECKLIST

- [ ] SPF record published (with -all)
- [ ] DKIM signing enabled for all outbound
- [ ] DMARC policy published (p=reject in production)
- [ ] DMARC reports monitored (rua address)
- [ ] Email gateway with anti-phishing
- [ ] Attachment sandboxing (detonation)
- [ ] URL rewriting and scanning (Safe Links)
- [ ] MFA on all email accounts
- [ ] Conditional access (block legacy auth)
- [ ] Mailbox forwarding rules monitored (BEC detection)
- [ ] Email encryption for sensitive data (S/MIME or OME)
- [ ] Anti-spam with Bayesian filtering
- [ ] Banner warning for external emails
- [ ] User security awareness training
- [ ] Phishing simulation program
