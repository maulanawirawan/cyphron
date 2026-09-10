# Skill 59 — Third-Party Risk Management (TPRM)

> Cyphron's methodology for managing security risks from third-party vendors, suppliers, and partners. Cyphron knows that your security is only as strong as your weakest vendor — and builds TPRM programs that assess, monitor, and mitigate third-party risks.

---

## WHEN TO ACTIVATE

- User asks about third-party risk management or vendor security
- User asks about vendor assessment or security questionnaires
- User asks about supply chain risk or vendor monitoring
- User asks about SOC 2 reports or vendor compliance

---

## METHODOLOGY

### TPRM Lifecycle

```
Onboard → Assess → Contract → Monitor → Review → Offboard
    ↑                                              │
    └────────────── Continuous Risk Management ────┘
```

### Step 1: Vendor Inventory & Classification
### Step 2: Security Assessment
### Step 3: Contract Security Requirements
### Step 4: Continuous Monitoring
### Step 5: Incident Response for Vendor Breach

---

## SECURE PATTERNS

### Vendor Classification & Risk Tiering
```python
class VendorRiskTier:
    """Classify vendors by risk level."""

    RISK_TIERS = {
        'critical': {
            'description': 'Access to sensitive data or critical systems',
            'examples': ['Cloud provider', 'Payment processor', 'HR system'],
            'assessment_frequency': 'annual',
            'monitoring': 'continuous',
            'contract_requirements': ['SOC 2', 'penetration test', 'BCP', 'insurance'],
        },
        'high': {
            'description': 'Access to internal systems or business data',
            'examples': ['CRM', 'Marketing automation', 'Analytics'],
            'assessment_frequency': 'annual',
            'monitoring': 'quarterly',
            'contract_requirements': ['SOC 2', 'security questionnaire', 'incident notification'],
        },
        'medium': {
            'description': 'Limited access, non-sensitive data',
            'examples': ['Office supplies', 'Facilities', 'Catering'],
            'assessment_frequency': 'biennial',
            'monitoring': 'annual',
            'contract_requirements': ['security questionnaire', 'insurance'],
        },
        'low': {
            'description': 'No system access, no data access',
            'examples': ['Consultants', 'Speakers', 'Trainers'],
            'assessment_frequency': 'on-demand',
            'monitoring': 'none',
            'contract_requirements': ['NDA', 'code of conduct'],
        },
    }

    def classify_vendor(self, vendor):
        """Classify vendor by risk level."""
        # Assess data access
        data_access = vendor.get('data_access', 'none')
        # Assess system access
        system_access = vendor.get('system_access', 'none')
        # Assess criticality
        criticality = vendor.get('criticality', 'low')

        if data_access == 'sensitive' or system_access == 'critical':
            return 'critical'
        elif data_access == 'internal' or system_access == 'internal':
            return 'high'
        elif data_access == 'limited' or system_access == 'limited':
            return 'medium'
        else:
            return 'low'
```

### Vendor Security Assessment Questionnaire
```markdown
# Vendor Security Assessment Questionnaire

## Company Information
- Company name: _______________
- Website: _______________
- Primary contact: _______________
- Security contact: _______________
- Years in business: _______________

## Security Program

### Governance
- [ ] Do you have a documented information security policy?
- [ ] Do you have a CISO or equivalent security leadership?
- [ ] Do you conduct annual risk assessments?
- [ ] Do you have a security steering committee?

### Access Control
- [ ] Do you use multi-factor authentication (MFA) for all employees?
- [ ] Do you have role-based access control (RBAC)?
- [ ] Do you conduct quarterly access reviews?
- [ ] Do you have a joiner-mover-leaver process?

### Data Protection
- [ ] Do you encrypt data at rest?
- [ ] Do you encrypt data in transit?
- [ ] Do you have data classification?
- [ ] Do you have data retention and disposal policies?
- [ ] Do you have data loss prevention (DLP)?

### Application Security
- [ ] Do you have a secure SDLC process?
- [ ] Do you conduct SAST/DAST testing?
- [ ] Do you have a vulnerability management program?
- [ ] Do you have a bug bounty program or VDP?

### Infrastructure Security
- [ ] Do you have network segmentation?
- [ ] Do you have endpoint detection and response (EDR)?
- [ ] Do you have security information and event management (SIEM)?
- [ ] Do you have a patch management program?

### Incident Response
- [ ] Do you have an incident response plan?
- [ ] Do you conduct tabletop exercises?
- [ ] Do you have a 24/7 security operations center?
- [ ] What is your incident notification SLA? (target: 24 hours)

### Business Continuity
- [ ] Do you have a business continuity plan?
- [ ] Do you have a disaster recovery plan?
- [ ] Do you conduct DR tests?
- [ ] What is your RTO/RPO?

### Compliance
- [ ] Do you have SOC 2 Type II report? (most recent date: ____)
- [ ] Do you have ISO 27001 certification?
- [ ] Do you have PCI-DSS compliance (if applicable)?
- [ ] Do you have HIPAA compliance (if applicable)?
- [ ] Do you have GDPR compliance (if applicable)?
- [ ] Do you conduct annual penetration testing?

### Personnel Security
- [ ] Do you conduct background checks on all employees?
- [ ] Do you have security awareness training (annual)?
- [ ] Do you have confidentiality agreements (NDAs)?
- [ ] Do you have a termination process (access revocation within 24h)?

### Third-Party Management
- [ ] Do you assess your own third-party vendors?
- [ ] Do you have a vendor management program?
- [ ] Do you require security assessments from your vendors?

## Attachments Required
- [ ] SOC 2 Type II report (most recent)
- [ ] Penetration test summary (most recent)
- [ ] BCP/DR plan summary
- [ ] Insurance certificate (cyber liability)
- [ ] Security policy summary
- [ ] Compliance certificates (ISO, PCI, etc.)
```

### Vendor Continuous Monitoring
```python
class VendorMonitor:
    """Continuously monitor vendor security posture."""

    def __init__(self, db):
        self.db = db

    def monitor_vendor(self, vendor_id):
        """Monitor a vendor's security posture."""
        vendor = self.db.get('vendors', vendor_id)
        alerts = []

        # Check security rating service (e.g., SecurityScorecard, BitSight)
        rating = self.get_security_rating(vendor['domain'])
        if rating['score'] < vendor['min_rating']:
            alerts.append({
                'type': 'rating_drop',
                'severity': 'medium',
                'message': f"Security rating dropped to {rating['score']} (min: {vendor['min_rating']})",
                'current': rating['score'],
                'previous': vendor['last_rating'],
            })

        # Check for new vulnerabilities
        new_vulns = self.scan_vendor_assets(vendor['domain'])
        if new_vulns:
            alerts.append({
                'type': 'new_vulnerabilities',
                'severity': 'high',
                'message': f"{len(new_vulns)} new vulnerabilities detected",
                'vulnerabilities': new_vulns,
            })

        # Check for data breaches (public sources)
        breaches = self.check_breach_databases(vendor['name'])
        if breaches:
            alerts.append({
                'type': 'data_breach',
                'severity': 'critical',
                'message': f"Data breach reported: {breaches[0]['title']}",
                'breach': breaches[0],
            })

        # Check SOC 2 report status
        soc2_status = self.check_soc2_status(vendor_id)
        if soc2_status['expired']:
            alerts.append({
                'type': 'soc2_expired',
                'severity': 'high',
                'message': 'SOC 2 report expired',
                'expiry_date': soc2_status['expiry_date'],
            })

        # Check certificate expiration
        cert_status = self.check_certificates(vendor['domain'])
        if cert_status['expiring_soon']:
            alerts.append({
                'type': 'cert_expiring',
                'severity': 'medium',
                'message': f"SSL certificate expiring in {cert_status['days_remaining']} days",
            })

        # Update vendor record
        vendor['last_monitored'] = datetime.now().isoformat()
        vendor['last_rating'] = rating['score']
        vendor['alerts'] = alerts
        self.db.update('vendors', vendor_id, vendor)

        return alerts

    def get_security_rating(self, domain):
        """Get security rating from external service."""
        # In production: integrate with SecurityScorecard, BitSight, etc.
        return {'score': 85, 'grade': 'B', 'last_updated': datetime.now().isoformat()}

    def check_breach_databases(self, vendor_name):
        """Check public breach databases."""
        # In production: check Have I Been Pwned, breach disclosure sites
        return []
```

### Vendor Contract Security Requirements
```markdown
# Vendor Contract — Security Requirements

## Security Requirements

### 1. Security Program
Vendor shall maintain a comprehensive information security program that
includes:
- Documented information security policy
- Security leadership (CISO or equivalent)
- Annual risk assessments
- Security awareness training for all employees

### 2. Compliance
Vendor shall maintain compliance with:
- SOC 2 Type II (annual audit)
- ISO 27001 (if applicable)
- PCI-DSS (if processing card data)
- HIPAA (if processing health data)
- GDPR (if processing EU personal data)

### 3. Security Assessments
Vendor shall provide:
- Annual SOC 2 Type II report
- Annual penetration test summary
- Security questionnaire (annual or on-demand)
- Evidence of remediation for critical/high findings

### 4. Incident Response
Vendor shall:
- Maintain incident response plan
- Notify [Company] of security incidents within 24 hours
- Cooperate with [Company] incident investigation
- Provide incident report within 72 hours of resolution

### 5. Data Protection
Vendor shall:
- Encrypt data at rest (AES-256)
- Encrypt data in transit (TLS 1.2+)
- Implement data classification
- Implement data retention and disposal
- Not use [Company] data for any purpose other than providing services

### 6. Access Control
Vendor shall:
- Use multi-factor authentication for all employees
- Implement least privilege access
- Conduct quarterly access reviews
- Revoke access within 24 hours of termination

### 7. Subcontractors
Vendor shall:
- Not subcontract without [Company] written approval
- Flow down these security requirements to subcontractors
- Remain responsible for subcontractor security

### 8. Audit Rights
[Company] shall have the right to:
- Audit Vendor's security program annually
- Request evidence of compliance
- Conduct on-site security assessments (with 30 days notice)

### 9. Insurance
Vendor shall maintain:
- Cyber liability insurance ($5M minimum)
- Errors and omissions insurance ($2M minimum)
- General liability insurance ($1M minimum)

### 10. Termination
Upon termination, Vendor shall:
- Return all [Company] data within 30 days
- Securely delete all [Company] data
- Provide certificate of deletion
- Return or destroy all [Company] materials

## Liability
Vendor shall be liable for:
- Data breaches caused by Vendor negligence
- Failure to comply with security requirements
- Subcontractor security failures

## Indemnification
Vendor shall indemnify [Company] against:
- Claims arising from Vendor security failures
- Regulatory fines caused by Vendor non-compliance
- Costs of breach notification and remediation
```

---

## AUDIT CHECKLIST

- [ ] Vendor inventory (all third parties documented)
- [ ] Vendor classification (critical, high, medium, low)
- [ ] Security assessment for all critical/high vendors
- [ ] Security questionnaire for all vendors
- [ ] SOC 2 report reviewed (critical vendors)
- [ ] Penetration test reviewed (critical vendors)
- [ ] Contract security requirements (all vendors)
- [ ] Incident notification SLA (24 hours for critical)
- [ ] Continuous monitoring (critical/high vendors)
- [ ] Security rating monitoring (SecurityScorecard, BitSight)
- [ ] Data breach monitoring (public sources)
- [ ] Annual vendor review
- [ ] Vendor incident response procedure
- [ ] Vendor offboarding procedure (data return/deletion)
- [ ] Insurance verification (cyber liability)
- [ ] Subcontractor management
- [ ] Audit rights in contracts
- [ ] Vendor risk register maintained
- [ ] Executive reporting on vendor risk
