# Skill 32 — Risk Assessment & Management

> Cyphron's methodology for identifying, assessing, and managing security risks. Cyphron knows how to quantify risk using industry-standard frameworks (NIST RMF, ISO 27005, FAIR) and build risk treatment plans.

---

## WHEN TO ACTIVATE

- User asks to perform a risk assessment
- User asks about risk management or risk treatment
- User asks about NIST RMF, ISO 27005, or FAIR
- User asks to build a risk register or risk matrix
- User asks about risk scoring or prioritization

---

## METHODOLOGY

### Step 1: Asset Identification
- What assets need protection? (data, systems, processes, people)
- What is the value/criticality of each asset?
- Who owns each asset?

### Step 2: Threat Identification
- Who are the threat actors? (external, internal, natural)
- What are their capabilities and motivations?
- What attack vectors are relevant?

### Step 3: Vulnerability Identification
- What weaknesses exist? (technical, process, human)
- What is the likelihood of exploitation?

### Step 4: Risk Scoring
```
Risk = Likelihood × Impact
```

### Step 5: Risk Treatment
| Option | Description |
|---|---|
| Mitigate | Implement controls to reduce risk |
| Transfer | Insurance, third-party (cloud provider) |
| Accept | Acknowledge and monitor (low risk) |
| Avoid | Stop the activity that creates risk |

---

## RISK SCORING

### Qualitative Risk Matrix (5x5)

```
         Impact →
Likelihood  Negligible  Minor  Moderate  Major  Severe
   Almost    Low        Low    Medium   High   Critical
   Likely    Low        Med    Medium   High   High
   Possible  Low        Med    Medium   Med    High
   Unlikely  Low        Low    Low      Med    Medium
   Rare      Low        Low    Low      Low    Low
```

### FAIR (Factor Analysis of Information Risk)
```python
class FAIRRisk:
    """FAIR-based quantitative risk analysis."""

    def __init__(self, asset_value, threat_frequency, vulnerability, loss_magnitude):
        self.asset_value = asset_value  # $ value of asset
        self.threat_frequency = threat_frequency  # events per year
        self.vulnerability = vulnerability  # 0.0-1.0 probability of success
        self.loss_magnitude = loss_magnitude  # $ loss per event

    def calculate_lef(self):
        """Loss Event Frequency = Threat Frequency × Vulnerability"""
        return self.threat_frequency * self.vulnerability

    def calculate_lm(self):
        """Loss Magnitude = Primary + Secondary losses"""
        return self.loss_magnitude

    def calculate_risk(self):
        """Annualized Loss Exposure = LEF × LM"""
        lef = self.calculate_lef()
        lm = self.calculate_lm()
        return {
            'loss_event_frequency': lef,  # events/year
            'loss_magnitude': lm,  # $ per event
            'annualized_loss_exposure': lef * lm,  # $/year
            'risk_rating': self._rating(lef * lm),
        }

    def _rating(self, ale):
        if ale > 1_000_000: return 'Critical'
        if ale > 100_000: return 'High'
        if ale > 10_000: return 'Medium'
        if ale > 1_000: return 'Low'
        return 'Negligible'

# Example: SQL injection risk on customer database
risk = FAIRRisk(
    asset_value=5_000_000,        # $5M customer data
    threat_frequency=4,          # 4 attack attempts/year
    vulnerability=0.3,            # 30% chance of success
    loss_magnitude=500_000,       # $500K per breach
)
print(risk.calculate_risk())
# {'loss_event_frequency': 1.2, 'loss_magnitude': 500000,
#  'annualized_loss_exposure': 600000, 'risk_rating': 'High'}
```

---

## RISK REGISTER TEMPLATE

```markdown
# Risk Register

| ID | Risk Description | Asset | Threat | Vulnerability | Likelihood | Impact | Risk Score | Treatment | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| R001 | SQL injection in login API | Customer DB | External attacker | No parameterized queries | Likely | Major | High | Mitigate (parameterized queries) | Dev Team | In Progress |
| R002 | Phishing of finance staff | Financial data | External attacker | No MFA on email | Possible | Severe | High | Mitigate (MFA + training) | IT | Open |
| R003 | Unpatched server OS | All servers | Malware | Missing patches | Possible | Major | Medium | Mitigate (patching schedule) | Ops | In Progress |
| R004 | Insider data theft | Customer PII | Employee | Excessive access | Unlikely | Severe | Medium | Mitigate (least privilege + DLP) | Security | Open |
| R005 | DDoS attack | Web services | Botnet | No DDoS protection | Possible | Moderate | Medium | Transfer (DDoS service) | IT | Resolved |
```

---

## NIST RMF (Risk Management Framework)

```
1. CATEGORIZE — Identify systems and categorize by impact (FIPS 199)
2. SELECT — Select security controls (NIST 800-53)
3. IMPLEMENT — Implement controls
4. ASSESS — Assess control effectiveness
5. AUTHORIZE — Authorize system operation
6. MONITOR — Continuous monitoring
```

---

## AUDIT CHECKLIST

- [ ] Asset inventory complete (with criticality)
- [ ] Threat model defined (actors, vectors, motivations)
- [ ] Vulnerability assessment completed
- [ ] Risk register maintained and reviewed quarterly
- [ ] Risk scoring methodology defined (qualitative or FAIR)
- [ ] Risk treatment plans for all High/Critical risks
- [ ] Risk acceptance documented and approved
- [ ] Continuous risk monitoring
- [ ] Risk reporting to executive level
- [ ] Third-party/vendor risk assessments
- [ ] Risk assessment before major changes
