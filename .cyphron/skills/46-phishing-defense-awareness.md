# Skill 46 — Phishing Defense & Awareness

> Cyphron's methodology for building phishing defense programs. Cyphron knows phishing techniques — spear phishing, BEC, clone phishing, QR phishing — and builds technical defenses (email filtering, URL rewriting) and human defenses (awareness training, simulation).

---

## WHEN TO ACTIVATE

- User asks to build phishing defenses
- User asks about phishing simulation or awareness training
- User asks about BEC (Business Email Compromise) prevention
- User asks to analyze a phishing email (defensive)

---

## METHODOLOGY

### Defense Layers

| Layer | Control | Effectiveness |
|---|---|---|
| Email auth | SPF, DKIM, DMARC | Blocks domain spoofing |
| Filtering | Anti-spam, anti-phishing, sandboxing | Blocks known phishing |
| URL protection | Rewriting, detonation, blocklists | Blocks malicious links |
| Attachment protection | Sandboxing, type blocking | Blocks malware |
| User awareness | Training, simulation, reporting | Last line of defense |
| Response | IR playbook, account recovery | Limits damage |

---

## SECURE PATTERNS

### Phishing Email Analysis (Defensive)
```python
#!/usr/bin/env python3
"""
Phishing email analyzer — analyze suspicious emails defensively.
Identify indicators, not create phishing.
"""
import re
import email
from email import policy
from urllib.parse import urlparse

class PhishingAnalyzer:
    PHISHING_INDICATORS = {
        'urgency_words': re.compile(
            r'(?i)(urgent|immediate|action required|account suspended|'
            r'verify now|final notice|within 24 hours|last warning)',
            re.IGNORECASE
        ),
        'credential_request': re.compile(
            r'(?i)(password|credential|login|sign in|verify your account|'
            r'confirm your identity|update your information)',
            re.IGNORECASE
        ),
        'financial_lure': re.compile(
            r'(?i)(invoice|payment|refund|wire transfer|bank|'
            r'tax|irs|refund|bonus|prize|lottery|inheritance)',
            re.IGNORECASE
        ),
        'suspicious_links': re.compile(
            r'https?://(?!.*\.company\.com)[^\s<>"]+',
            re.IGNORECASE
        ),
        'ip_url': re.compile(
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            re.IGNORECASE
        ),
    }

    def analyze(self, raw_email):
        """Analyze email for phishing indicators."""
        msg = email.message_from_string(raw_email, policy=policy.default)

        analysis = {
            'from': msg.get('From', ''),
            'reply_to': msg.get('Reply-To', ''),
            'subject': msg.get('Subject', ''),
            'indicators': [],
            'risk_score': 0,
            'risk_level': 'low',
        }

        # Check sender/reply-to mismatch
        from_domain = self._extract_domain(analysis['from'])
        reply_domain = self._extract_domain(analysis['reply_to'])
        if reply_domain and from_domain != reply_domain:
            analysis['indicators'].append({
                'type': 'sender_mismatch',
                'detail': f'From: {from_domain}, Reply-To: {reply_domain}',
                'weight': 30,
            })

        # Check subject for urgency
        subject = analysis['subject'] or ''
        if self.PHISHING_INDICATORS['urgency_words'].search(subject):
            analysis['indicators'].append({
                'type': 'urgency_language',
                'detail': f'Subject contains urgency: {subject}',
                'weight': 20,
            })

        # Extract and analyze body
        body = self._get_body(msg)
        for indicator_name, pattern in self.PHISHING_INDICATORS.items():
            matches = pattern.findall(body)
            if matches:
                analysis['indicators'].append({
                    'type': indicator_name,
                    'detail': f'Found {len(matches)} matches',
                    'weight': 15 if indicator_name == 'credential_request' else 10,
                })

        # Check links
        links = self._extract_links(body)
        for link in links:
            parsed = urlparse(link)
            if self._is_suspicious_link(parsed, from_domain):
                analysis['indicators'].append({
                    'type': 'suspicious_link',
                    'detail': f'Link to: {parsed.netloc}',
                    'weight': 25,
                })

        # Calculate risk score
        analysis['risk_score'] = sum(i['weight'] for i in analysis['indicators'])
        analysis['risk_level'] = self._risk_level(analysis['risk_score'])

        return analysis

    def _is_suspicious_link(self, parsed_url, sender_domain):
        """Check if a link is suspicious."""
        # IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc):
            return True

        # Different domain than sender
        if sender_domain and sender_domain not in parsed_url.netloc:
            return True

        # Known phishing TLDs (simplified)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
            return True

        return False
```

### Phishing Simulation Framework
```python
class PhishingSimulation:
    """Phishing simulation program — train users to recognize phishing."""

    TEMPLATES = {
        'password_expiry': {
            'subject': 'Action Required: Password Expiring in 24 Hours',
            'difficulty': 'easy',
            'teaching_point': 'Check sender domain; IT never asks for passwords via email',
        },
        'package_delivery': {
            'subject': 'Your Package is Waiting - Confirm Address',
            'difficulty': 'medium',
            'teaching_point': 'Hover over links; verify tracking on official site',
        },
        'invoice_overdue': {
            'subject': 'URGENT: Invoice #4823 Overdue - Action Required',
            'difficulty': 'hard',
            'teaching_point': 'Verify with sender through known channel; check for urgency tactics',
        },
    }

    async def run_simulation(self, template_id, targets):
        """Run phishing simulation for training."""
        template = self.TEMPLATES[template_id]
        results = {
            'sent': 0,
            'clicked': 0,
            'reported': 0,
            'ignored': 0,
        }

        for target in targets:
            # Send simulation email (clearly marked as simulation in headers)
            await self.send_simulation(target, template)
            results['sent'] += 1

        # Track: who clicked, who reported, who ignored
        # Report results to security team (not for punishment — for training)
        return results

    async def generate_training_report(self, results):
        """Generate training report from simulation."""
        click_rate = (results['clicked'] / results['sent']) * 100
        report_rate = (results['reported'] / results['sent']) * 100

        return {
            'click_rate': round(click_rate, 1),
            'report_rate': round(report_rate, 1),
            'assessment': self._assess(click_rate, report_rate),
            'recommendation': self._recommend(click_rate, report_rate),
        }

    def _assess(self, click_rate, report_rate):
        if click_rate < 5 and report_rate > 80:
            return 'Excellent — users are vigilant'
        if click_rate < 10 and report_rate > 60:
            return 'Good — room for improvement'
        if click_rate < 20:
            return 'Needs improvement — additional training needed'
        return 'Critical — immediate training required'
```

### BEC (Business Email Compromise) Defense
```python
class BECDefense:
    """Detect and prevent Business Email Compromise."""

    BEC_INDICATORS = [
        # Financial urgency
        (r'(?i)(wire transfer|payment|invoice|urgent payment)', 'financial_request'),
        # Secrecy request
        (r'(?i)(confidential|secret|don\'?t tell|between us|discreet)', 'secrecy_request'),
        # Authority impersonation
        (r'(?i)(CEO|CFO|president|director|executive)', 'authority_impersonation'),
        # Change of payment details
        (r'(?i)(new bank account|update.*account|change.*payment|routing number)', 'payment_change'),
        # Reply-to mismatch
        ('reply_to_mismatch', 'reply_to_mismatch'),
    ]

    def check_bec(self, email_data):
        """Check email for BEC indicators."""
        risk_factors = []

        # Check content
        content = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        for pattern, indicator_type in self.BEC_INDICATORS:
            if isinstance(pattern, str) and pattern == 'reply_to_mismatch':
                if self._check_reply_mismatch(email_data):
                    risk_factors.append({'type': indicator_type, 'weight': 40})
            elif re.search(pattern, content):
                weight = 30 if indicator_type == 'payment_change' else 20
                risk_factors.append({'type': indicator_type, 'weight': weight})

        # Check if sender is external but impersonating internal
        from_domain = self._extract_domain(email_data.get('from', ''))
        reply_domain = self._extract_domain(email_data.get('reply_to', ''))
        display_name = email_data.get('from_display', '')

        if self._is_impersonating_internal(display_name, from_domain):
            risk_factors.append({
                'type': 'display_name_impersonation',
                'weight': 35,
                'detail': f'Display name "{display_name}" but external domain {from_domain}',
            })

        risk_score = sum(r['weight'] for r in risk_factors)
        return {
            'risk_score': risk_score,
            'risk_level': 'critical' if risk_score >= 60 else 'high' if risk_score >= 40 else 'medium',
            'factors': risk_factors,
            'action': 'quarantine' if risk_score >= 60 else 'flag' if risk_score >= 40 else 'monitor',
        }
```

---

## AUDIT CHECKLIST

- [ ] SPF, DKIM, DMARC configured (p=reject)
- [ ] Email gateway with anti-phishing
- [ ] URL rewriting and detonation (Safe Links)
- [ ] Attachment sandboxing
- [ ] External email warning banner
- [ ] BEC detection rules
- [ ] Mailbox forwarding rule monitoring
- [ ] Phishing simulation (quarterly)
- [ ] Security awareness training (annual)
- [ ] Phishing reporting button (one-click)
- [ ] Incident response for phishing (Skill 10)
- [ ] Account recovery procedure
- [ ] MFA to limit credential theft impact
- [ ] Conditional access (block legacy auth)
