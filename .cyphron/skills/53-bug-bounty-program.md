# Skill 53 — Bug Bounty Program & Vulnerability Disclosure

> Cyphron's methodology for building bug bounty programs and vulnerability disclosure processes. Cyphron knows how bug bounty programs work — researcher incentives, triage, severity scoring, rewards — and builds programs that attract quality reports and improve security posture.

---

## WHEN TO ACTIVATE

- User asks to build a bug bounty program
- User asks about vulnerability disclosure or responsible disclosure
- User asks about bug bounty platforms (HackerOne, Bugcrowd, Intigriti)
- User asks about severity scoring (CVSS, VRT) or reward structure
- User asks about triage process for security reports

---

## METHODOLOGY

### Bug Bounty Program Types

| Type | Access | Best For |
|---|---|---|
| Public | Anyone can participate | Large companies, mature programs |
| Private | Invited researchers only | Startups, sensitive systems |
| VDP (Vulnerability Disclosure Program) | No rewards, just credit | Early stage, testing the waters |
| Managed | Platform handles triage | Companies without dedicated security team |

### Program Lifecycle

```
Define Scope → Set Rules → Launch → Triage → Validate → Fix → Reward → Disclose
```

### Step 1: Define Scope & Rules
### Step 2: Choose Platform & Launch
### Step 3: Triage Process
### Step 4: Severity Scoring & Rewards
### Step 5: Remediation & Disclosure

---

## PROGRAM TEMPLATES

### Bug Bounty Program Policy
```markdown
# Bug Bounty Program Policy

## Program Overview
[Company] is committed to the security of our users and systems. We
believe that working with the security research community is essential
to maintaining the highest security standards. This bug bounty program
provides a framework for researchers to report vulnerabilities safely
and responsibly.

## Scope

### In Scope
- *.example.com
- api.example.com
- app.example.com
- Mobile applications (iOS, Android)
- Open source projects maintained by [Company]

### Out of Scope
- Third-party services (unless explicitly authorized)
- Physical security of [Company] offices
- Social engineering of [Company] employees
- Denial of Service (DoS/DDoS) attacks
- Spam, phishing, or social engineering attacks against users
- Vulnerabilities in third-party libraries (report to vendor first)
- Recently disclosed vulnerabilities (within 90 days of patch release)
- Vulnerabilities requiring physical access to user devices

### Test Environment
- Staging environment: staging.example.com (preferred for testing)
- Production: Only if staging is not available, and with extreme care

## Rules of Engagement

### Allowed Testing
- Web application testing (XSS, SQLi, CSRF, IDOR, etc.)
- API security testing
- Mobile application testing
- Network-level testing (with prior approval)
- Authentication and authorization testing

### Prohibited Testing
- DoS/DDoS attacks
- Social engineering
- Physical attacks
- Data modification or deletion
- Accessing user data (beyond proof of concept)
- Automated scanning without approval
- Testing on user accounts (use your own test accounts)

### Data Handling
- Do not access, modify, or delete user data
- Do not exfiltrate data beyond what is necessary for proof of concept
- Do not share vulnerability details publicly until fixed
- Report any accidental data access immediately

## Severity & Rewards

### Severity Levels (CVSS v3.1 + Business Impact)

| Severity | CVSS | Business Impact | Reward Range |
|---|---|---|---|
| Critical | 9.0-10.0 | RCE, auth bypass, data breach | $5,000 - $50,000 |
| High | 7.0-8.9 | Privilege escalation, SSRF, significant data exposure | $2,000 - $10,000 |
| Medium | 4.0-6.9 | Stored XSS, CSRF, IDOR with limited data | $500 - $2,000 |
| Low | 0.1-3.9 | Reflected XSS, info disclosure, best practice violations | $100 - $500 |

### Bonus Multipliers
- **Novel attack vector**: +50%
- **Chained vulnerabilities**: +25% per chain
- **High-quality report**: +25% (detailed steps, screenshots, video)
- **Fix verification**: +10% (help verify the fix)

### Reward Determination
Rewards are determined by:
1. CVSS base score (severity)
2. Business impact (data sensitivity, user count)
3. Exploitability (ease of exploitation, reliability)
4. Report quality (clarity, completeness, reproducibility)

## Response SLAs

| Stage | SLA |
|---|---|
| Initial response | 48 hours |
| Triage decision | 5 business days |
| Severity assessment | 10 business days |
| Fix deployed | 30 days (Critical), 90 days (High), 180 days (Medium/Low) |
| Reward issued | 30 days after fix verification |

## Safe Harbor

[Company] pledges not to pursue legal action against researchers who:
- Act in good faith
- Follow this policy
- Do not violate any laws
- Do not access or modify user data beyond what is necessary
- Report vulnerabilities promptly

We consider security research conducted under this policy to be:
- Authorized under the Computer Fraud and Abuse Act (CFAA)
- Exempt from DMCA anti-circumvention provisions
- Lawful and helpful to our security posture

## Disclosure

- **Coordinated disclosure**: We will work with you on public disclosure timing
- **Credit**: We will credit you in our security hall of fame (unless you prefer anonymity)
- **CVE**: We will request CVE assignment for significant vulnerabilities
- **Publication**: You may publish after fix is deployed + 90 days, or with our approval

## Contact

- **Bug bounty platform**: [HackerOne/Bugcrowd/Self-hosted]
- **Security email**: security@example.com
- **PGP key**: [public key for encrypted reports]
- **Emergency**: +1-XXX-XXX-XXXX (24/7 security hotline)

## Hall of Fame

Thank you to the following researchers for helping keep [Company] secure:
- [Researcher Name] — [Vulnerability Type] — [Year]
- [Researcher Name] — [Vulnerability Type] — [Year]

---
Last updated: [Date]
```

### Triage Process (Internal)
```python
#!/usr/bin/env python3
"""
Bug bounty triage system — process and prioritize security reports.
"""
from datetime import datetime, timedelta
from enum import Enum

class TriageStatus(Enum):
    NEW = 'new'
    TRIAGED = 'triaged'
    DUPLICATE = 'duplicate'
    NOT_APPLICABLE = 'not_applicable'
    VALID = 'valid'
    FIXING = 'fixing'
    FIXED = 'fixed'
    REWARDED = 'rewarded'
    DISCLOSED = 'disclosed'

class Severity(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

class BugBountyTriage:
    def __init__(self, db):
        self.db = db

    def submit_report(self, researcher, title, description, severity_claim,
                     poc_steps, affected_endpoint, attachments=None):
        """Receive new vulnerability report."""
        report = {
            'id': self._generate_id(),
            'researcher': researcher,
            'title': title,
            'description': description,
            'severity_claim': severity_claim,
            'severity_assessed': None,
            'status': TriageStatus.NEW.value,
            'poc_steps': poc_steps,
            'affected_endpoint': affected_endpoint,
            'attachments': attachments or [],
            'submitted_at': datetime.now().isoformat(),
            'triaged_at': None,
            'fixed_at': None,
            'reward_amount': None,
            'reward_issued_at': None,
        }
        self.db.insert('reports', report)
        return report

    def triage_report(self, report_id):
        """Triage a report — initial assessment."""
        report = self.db.get('reports', report_id)

        # Check for duplicates
        duplicates = self._find_duplicates(report)
        if duplicates:
            report['status'] = TriageStatus.DUPLICATE.value
            report['duplicate_of'] = duplicates[0]['id']
            self.db.update('reports', report_id, report)
            return report

        # Validate scope
        if not self._validate_scope(report['affected_endpoint']):
            report['status'] = TriageStatus.NOT_APPLICABLE.value
            report['reason'] = 'Out of scope'
            self.db.update('reports', report_id, report)
            return report

        # Validate severity
        assessed_severity = self._assess_severity(report)
        report['severity_assessed'] = assessed_severity.value
        report['status'] = TriageStatus.VALID.value
        report['triaged_at'] = datetime.now().isoformat()

        # Assign to engineer
        assignee = self._assign_engineer(report)
        report['assigned_to'] = assignee

        self.db.update('reports', report_id, report)
        return report

    def _assess_severity(self, report):
        """Assess report severity using CVSS + business impact."""
        # CVSS base score
        cvss = self._calculate_cvss(report)

        # Business impact factors
        data_sensitivity = self._assess_data_sensitivity(report)
        user_impact = self._assess_user_impact(report)
        exploitability = self._assess_exploitability(report)

        # Weighted severity
        score = (cvss * 0.4 + data_sensitivity * 0.25 +
                 user_impact * 0.2 + exploitability * 0.15)

        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score >= 0.1: return Severity.LOW
        return Severity.INFO

    def _calculate_cvss(self, report):
        """Calculate CVSS v3.1 base score."""
        # Simplified CVSS calculation
        # In production: use cvss library
        impact = report.get('impact_score', 0)
        exploitability = report.get('exploitability_score', 0)
        return (impact + exploitability) / 2

    def calculate_reward(self, report):
        """Calculate reward amount."""
        severity = Severity(report['severity_assessed'])

        base_rewards = {
            Severity.CRITICAL: (5000, 50000),
            Severity.HIGH: (2000, 10000),
            Severity.MEDIUM: (500, 2000),
            Severity.LOW: (100, 500),
            Severity.INFO: (0, 0),
        }

        min_reward, max_reward = base_rewards.get(severity, (0, 0))

        # Adjust based on quality
        quality_multiplier = self._assess_quality(report)
        reward = min_reward + (max_reward - min_reward) * quality_multiplier

        # Bonus for novel attack vector
        if report.get('novel_attack'):
            reward *= 1.5

        # Bonus for chained vulnerabilities
        if report.get('chain_count', 0) > 1:
            reward *= (1 + 0.25 * (report['chain_count'] - 1))

        return min(reward, max_reward * 2)  # cap at 2x max

    def _assess_quality(self, report):
        """Assess report quality (0.0-1.0)."""
        score = 0.5  # base

        # Detailed steps
        if len(report['poc_steps']) > 3:
            score += 0.1

        # Screenshots/video
        if report['attachments']:
            score += 0.1

        # Root cause analysis
        if 'root_cause' in report['description'].lower():
            score += 0.1

        # Remediation suggestion
        if 'fix' in report['description'].lower() or 'remediation' in report['description'].lower():
            score += 0.1

        # Clear reproduction
        if 'step' in report['poc_steps'][0].lower():
            score += 0.1

        return min(score, 1.0)
```

### Vulnerability Disclosure Timeline
```python
class DisclosureTimeline:
    """Manage vulnerability disclosure timeline."""

    DISCLOSURE_STAGES = {
        'private': 'Reported to vendor only',
        'embargo': 'Vendor is fixing, no public disclosure',
        'coordinated': 'Fix deployed, preparing public disclosure',
        'public': 'Publicly disclosed',
    }

    def get_disclosure_timeline(self, report):
        """Get disclosure timeline for a report."""
        submitted = datetime.fromisoformat(report['submitted_at'])
        fixed = datetime.fromisoformat(report['fixed_at']) if report.get('fixed_at') else None

        timeline = [
            {
                'stage': 'private',
                'date': submitted.isoformat(),
                'description': 'Report submitted to vendor',
            },
        ]

        if fixed:
            timeline.append({
                'stage': 'embargo',
                'date': fixed.isoformat(),
                'description': 'Fix deployed',
            })

            # Coordinated disclosure: 90 days after fix
            disclosure_date = fixed + timedelta(days=90)
            timeline.append({
                'stage': 'coordinated',
                'date': disclosure_date.isoformat(),
                'description': 'Public disclosure (90 days after fix)',
            })

            timeline.append({
                'stage': 'public',
                'date': disclosure_date.isoformat(),
                'description': 'CVE published, advisory released',
            })

        return timeline
```

---

## AUDIT CHECKLIST

- [ ] Bug bounty program policy published
- [ ] Scope clearly defined (in scope / out of scope)
- [ ] Rules of engagement documented
- [ ] Safe harbor statement included
- [ ] Severity scoring methodology (CVSS + business impact)
- [ ] Reward structure defined
- [ ] Response SLAs defined
- [ ] Triage process documented
- [ ] Duplicate detection process
- [ ] Disclosure timeline (coordinated disclosure)
- [ ] Researcher communication channel
- [ ] PGP key for encrypted reports
- [ ] Hall of fame / credit page
- [ ] Legal review of program terms
- [ ] Bug bounty platform selected (HackerOne, Bugcrowd, self-hosted)
- [ ] Internal triage team assigned
- [ ] Fix verification process
- [ ] Reward payment process
- [ ] Metrics tracking (reports, response time, fix time)
