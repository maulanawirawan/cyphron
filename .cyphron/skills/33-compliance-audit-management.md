# Skill 33 — Compliance & Audit Management

> Cyphron's methodology for managing compliance with security frameworks and regulations. Cyphron builds compliance programs, audit evidence collection, and control mapping for ISO 27001, SOC 2, PCI-DSS, HIPAA, and GDPR.

---

## WHEN TO ACTIVATE

- User asks about compliance (ISO 27001, SOC 2, PCI-DSS, HIPAA)
- User asks to prepare for a security audit
- User asks about control mapping or evidence collection
- User asks about compliance gap analysis

---

## METHODOLOGY

### Step 1: Identify Applicable Frameworks
| Framework | Trigger |
|---|---|
| ISO 27001 | Information security management certification |
| SOC 2 | SaaS/service provider to enterprises |
| PCI-DSS | Processes credit card payments |
| HIPAA | Handles US healthcare data (PHI) |
| GDPR | Processes EU residents' personal data |
| FedRAMP | US government cloud services |

### Step 2: Gap Analysis
- Map current controls to framework requirements
- Identify gaps
- Build remediation plan

### Step 3: Evidence Collection
- Document each control implementation
- Automate evidence collection where possible
- Maintain evidence continuously (not just at audit time)

---

## CONTROL MAPPING

### ISO 27001 → SOC 2 → NIST CSF
```markdown
| Requirement | ISO 27001 | SOC 2 | NIST CSF |
|---|---|---|---|
| Access Control | A.9 | CC6.1-3 | PR.AC-1 |
| Encryption | A.10 | CC6.7 | PR.DS-1 |
| Incident Response | A.16 | CC7.3-5 | RS.RP-1 |
| Vulnerability Mgmt | A.12.6 | CC7.1 | ID.RA-1 |
| Security Awareness | A.7.2.2 | CC1.4 | PR.AT-1 |
| Risk Assessment | A.8.2 | CC3.2 | ID.RA-3 |
| Business Continuity | A.17 | CC7.4 | RC.RP-1 |
| Vendor Management | A.15 | CC9.2 | ID.SC-1 |
```

### PCI-DSS v4.0 Requirements
```markdown
| # | Requirement | Key Controls |
|---|---|---|
| 1 | Network security | Firewalls, segmentation, no direct internet for CDE |
| 2 | Default passwords | Change all defaults, no vendor defaults |
| 3 | Protect stored card data | Encryption, tokenization, minimize storage |
| 4 | Encrypt transmission | TLS 1.2+ for all card data in transit |
| 5 | Anti-malware | Deploy on all systems in CDE |
| 6 | Secure development | SAST, DAST, patching, secure coding |
| 7 | Least privilege | Need-to-know, RBAC, quarterly review |
| 8 | Authentication | Unique IDs, MFA, strong passwords |
| 9 | Physical security | Restrict physical access to CDE |
| 10 | Logging & monitoring | Log all access, time sync, daily review |
| 11 | Security testing | Quarterly ASV scans, annual pentest |
| 12 | Security policy | Maintain IS policy, risk assessments |
```

---

## EVIDENCE COLLECTION AUTOMATION

```python
#!/usr/bin/env python3
"""Automated compliance evidence collection."""
import json
import subprocess
from datetime import datetime
from pathlib import Path

class EvidenceCollector:
    def __init__(self, output_dir='evidence'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.evidence = {}

    def collect_aws_evidence(self):
        """Collect AWS configuration evidence."""
        # IAM users and MFA status
        result = subprocess.run(
            ['aws', 'iam', 'list-users', '--output', 'json'],
            capture_output=True, text=True
        )
        users = json.loads(result.stdout)['Users']
        mfa_status = []
        for user in users:
            mfa = subprocess.run(
                ['aws', 'iam', 'list-mfa-devices', '--user-name', user['UserName'], '--output', 'json'],
                capture_output=True, text=True
            )
            mfa_status.append({
                'user': user['UserName'],
                'has_mfa': len(json.loads(mfa.stdout)['MFADevices']) > 0,
            })
        self.evidence['iam_mfa'] = {
            'control': 'ISO A.9.4.2 / PCI 8.4',
            'evidence': mfa_status,
            'timestamp': datetime.now().isoformat(),
        }

    def collect_s3_evidence(self):
        """Collect S3 bucket public access evidence."""
        result = subprocess.run(
            ['aws', 's3api', 'list-buckets', '--output', 'json'],
            capture_output=True, text=True
        )
        buckets = json.loads(result.stdout)['Buckets']
        bucket_status = []
        for bucket in buckets:
            try:
                acl = subprocess.run(
                    ['aws', 's3api', 'get-bucket-acl', '--bucket', bucket['Name'], '--output', 'json'],
                    capture_output=True, text=True
                )
                grants = json.loads(acl.stdout)['Grants']
                is_public = any(
                    g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for g in grants
                )
                bucket_status.append({
                    'bucket': bucket['Name'],
                    'is_public': is_public,
                })
            except Exception:
                pass
        self.evidence['s3_public_access'] = {
            'control': 'ISO A.8.3.1 / PCI 3.4',
            'evidence': bucket_status,
            'timestamp': datetime.now().isoformat(),
        }

    def save(self):
        """Save evidence to JSON."""
        filename = f"evidence_{datetime.now().strftime('%Y%m%d')}.json"
        with open(self.output_dir / filename, 'w') as f:
            json.dump(self.evidence, f, indent=2)
        print(f"Evidence saved to {filename}")

if __name__ == '__main__':
    collector = EvidenceCollector()
    collector.collect_aws_evidence()
    collector.collect_s3_evidence()
    collector.save()
```

---

## COMPLIANCE GAP ANALYSIS TEMPLATE

```markdown
# Compliance Gap Analysis — [Framework]

## Summary
| Control Area | Total | Implemented | Gap | % Complete |
|---|---|---|---|---|
| Access Control | 12 | 8 | 4 | 67% |
| Encryption | 8 | 6 | 2 | 75% |
| Incident Response | 10 | 5 | 5 | 50% |
| ... | ... | ... | ... | ... |

## Detailed Gaps

### Gap 1: MFA not enforced on all admin accounts
- **Control**: ISO A.9.4.2 / PCI 8.4.2
- **Current state**: MFA on 60% of admin accounts
- **Required state**: MFA on 100% of admin accounts
- **Remediation**: Enforce MFA via conditional access policy
- **Owner**: IT Team
- **Due date**: 2024-03-01
- **Effort**: Low

### Gap 2: No formal incident response procedure
- **Control**: ISO A.16 / SOC 2 CC7.3
- **Current state**: Ad-hoc response
- **Required state**: Documented IR procedure with playbooks
- **Remediation**: Develop IR procedure (see Skill 10)
- **Owner**: Security Team
- **Due date**: 2024-04-01
- **Effort**: Medium
```

---

## AUDIT CHECKLIST

- [ ] Applicable frameworks identified
- [ ] Gap analysis completed
- [ ] Control mapping documented
- [ ] Remediation plan with owners and dates
- [ ] Evidence collection automated
- [ ] Evidence stored securely with timestamps
- [ ] Internal audit before external audit
- [ ] Control owners identified
- [ ] Continuous compliance monitoring
- [ ] Audit findings tracked to closure
- [ ] Policy review aligned with framework
- [ ] Training aligned with compliance requirements
