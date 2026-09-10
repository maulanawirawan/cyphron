# Skill 47 — Social Engineering Defense

> Cyphron's methodology for defending against social engineering attacks beyond email phishing — pretexting, baiting, tailgating, vishing (voice phishing), smishing (SMS phishing), and impersonation. Cyphron builds technical and human defenses.

---

## WHEN TO ACTIVATE

- User asks about social engineering defense
- User asks about vishing, smishing, or pretexting
- User asks about physical security (tailgating, shoulder surfing)
- User asks to build security awareness training
- User asks about insider threat defense

---

## METHODOLOGY

### Social Engineering Attack Types

| Type | Vector | Defense |
|---|---|---|
| Pretexting | Phone/in-person impersonation | Verification procedures |
| Vishing | Voice phishing (phone) | Caller verification, training |
| Smishing | SMS phishing | MDM filtering, training |
| Baiting | USB drops, infected media | USB control, training |
| Tailgating | Physical access following | Badge enforcement, mantraps |
| Shoulder surfing | Visual observation | Privacy screens, awareness |
| Quid pro quo | Fake IT support | Verification procedures |
| Watering hole | Compromised trusted site | Web filtering, patching |

### Defense Framework
1. **Technical controls** — prevent the attack vector
2. **Process controls** — verification procedures
3. **Human controls** — awareness and training
4. **Detection** — monitor for social engineering indicators
5. **Response** — incident handling for social engineering

---

## SECURE PATTERNS

### Verification Procedure (Pretexting Defense)
```markdown
## Verification Procedure — Sensitive Requests

### Rule: NEVER fulfill sensitive requests without verification

Sensitive requests include:
- Password resets
- Account changes
- Payment/invoice changes
- Data access requests
- System configuration changes
- Access badge issuance

### Verification Steps

1. **Identify the requester**
   - Ask for full name and department
   - Look up in directory (don't use provided number)

2. **Verify via independent channel**
   - If request via email → call back using directory number
   - If request via phone → send confirmation to directory email
   - If in-person → check badge and verify with manager

3. **Verify authorization**
   - Does this person have authority for this request?
   - Call their manager if unsure

4. **Document the request**
   - Who, what, when, how verified
   - Approval from manager if required

5. **If anything seems off — STOP and verify**
   - Urgency is a red flag
   - Secrecy is a red flag
   - Unusual request is a red flag
   - "The CEO said to do this now" → verify with CEO's assistant

### Red Flags
- Urgency or pressure
- Requests for secrecy
- Unusual payment method
- New bank account details
- Requests to bypass procedures
- Threats or intimidation
- Too good to be true offers
```

### Vishing Defense (Voice Phishing)
```python
class VishingDefense:
    """Detect and prevent voice phishing (vishing)."""

    VISHING_INDICATORS = [
        'urgent account problem',
        'verify your identity',
        'social security number',
        'wire transfer',
        'tech support',
        'IRS',
        'arrest warrant',
        'prize or lottery',
        'grandparent scam',
        'gift card payment',
    ]

    def analyze_call(self, call_transcript):
        """Analyze call transcript for vishing indicators."""
        transcript_lower = call_transcript.lower()
        indicators_found = []

        for indicator in self.VISHING_INDICATORS:
            if indicator in transcript_lower:
                indicators_found.append(indicator)

        risk_score = len(indicators_found) * 20
        return {
            'risk_level': 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low',
            'indicators': indicators_found,
            'recommendation': 'Block caller, alert security team' if risk_score >= 40 else 'Monitor',
        }
```

### Insider Threat Detection
```python
class InsiderThreatDetector:
    """Detect insider threat indicators."""

    RISK_INDICATORS = {
        'data_access': [
            'bulk_download',
            'access_outside_business_hours',
            'access_to_unrelated_data',
            'unusual_data_volume',
        ],
        'behavioral': [
            'policy_violations',
            'accessing_job_unrelated_systems',
            'disabling_security_tools',
            'excessive_failed_access',
        ],
        'contextual': [
            'resignation_submitted',
            'performance_issues',
            'financial_distress_indicators',
            'conflict_with_management',
        ],
    }

    def assess_risk(self, user_id):
        """Assess insider threat risk for a user."""
        risk_factors = []

        # Data access anomalies
        access_patterns = self.get_access_patterns(user_id)
        if access_patterns['data_volume'] > self.baseline(user_id, 'data_volume') * 5:
            risk_factors.append({
                'category': 'data_access',
                'indicator': 'unusual_data_volume',
                'detail': f"Downloaded {access_patterns['data_volume']} (5x baseline)",
                'weight': 30,
            })

        if access_patterns['after_hours_access'] > 10:
            risk_factors.append({
                'category': 'data_access',
                'indicator': 'access_outside_business_hours',
                'detail': f"{access_patterns['after_hours_access']} after-hours sessions",
                'weight': 20,
            })

        # Behavioral indicators
        if self.has_policy_violations(user_id):
            risk_factors.append({
                'category': 'behavioral',
                'indicator': 'policy_violations',
                'weight': 25,
            })

        # Contextual (HR data — privacy-sensitive)
        hr_flags = self.get_hr_flags(user_id)
        if hr_flags.get('resignation_submitted'):
            risk_factors.append({
                'category': 'contextual',
                'indicator': 'resignation_submitted',
                'weight': 15,
            })

        risk_score = sum(r['weight'] for r in risk_factors)
        return {
            'user_id': user_id,
            'risk_score': risk_score,
            'risk_level': self._level(risk_score),
            'factors': risk_factors,
            'recommended_action': self._action(risk_score),
        }
```

### Security Awareness Training Program
```markdown
## Security Awareness Training Program

### Topics (Annual Training)
1. Phishing recognition (email, SMS, voice)
2. Password security and password manager use
3. Social engineering tactics
4. Data classification and handling
5. Physical security (badge, tailgating, clear desk)
6. Incident reporting procedures
7. Mobile device security
8. Public WiFi risks
9. Social media risks
10. Insider threat awareness

### Role-Specific Training
- **Developers**: Secure coding (OWASP Top 10)
- **Finance**: BEC and wire fraud prevention
- **HR**: Social engineering targeting HR
- **Executives**: Whaling and deepfake threats
- **IT Admins**: Privileged access security

### Reinforcement (Monthly)
- Phishing simulation (varied difficulty)
- Security newsletter (current threats)
- Micro-learning modules (5 min, specific topic)
- Security champions program

### Metrics
- Training completion rate (target: 100%)
- Phishing click rate (target: < 5%)
- Phishing report rate (target: > 80%)
- Time to report phishing (target: < 15 min)
```

---

## AUDIT CHECKLIST

- [ ] Annual security awareness training (100% completion)
- [ ] Quarterly phishing simulation
- [ ] Verification procedures for sensitive requests
- [ ] Caller verification for phone-based requests
- [ ] USB device control (block unknown USBs)
- [ ] Physical access control (badges, mantraps)
- [ ] Privacy screens on monitors
- [ ] Clear desk and clear screen policy
- [ ] Insider threat monitoring program
- [ ] Security champions in each team
- [ ] Incident reporting mechanism (easy, no blame)
- [ ] Role-specific security training
- [ ] Executive protection (whaling defense)
- [ ] Visitor management procedure
- [ ] New hire security orientation
