# Skill 28 — Data Loss Prevention (DLP)

> Cyphron's methodology for building Data Loss Prevention systems. Cyphron knows how data is exfiltrated — through email, USB, cloud uploads, screenshots, API abuse — and builds DLP controls to detect and prevent unauthorized data movement.

---

## WHEN TO ACTIVATE

- User asks to build a DLP system or policy
- User asks about data classification or data discovery
- User asks about preventing data exfiltration
- User asks about sensitive data detection (PII, PHI, card data)

---

## METHODOLOGY

### Step 1: Data Classification
| Classification | Examples | Handling |
|---|---|---|
| Public | Marketing materials | No restrictions |
| Internal | Internal docs, memos | Internal access only |
| Confidential | Financial data, customer info | Need-to-know, encrypted |
| Restricted | PII, PHI, card data, secrets | Strict controls, audit, encryption |

### Step 2: Identify Data Movement Channels
- Email (outbound, attachments)
- Web (uploads, forms, API calls)
- USB / removable media
- Cloud storage (personal cloud, unsanctioned)
- Print / screenshot
- Clipboard copy-paste

### Step 3: Build DLP Controls

---

## SECURE PATTERNS

### Sensitive Data Detection (Regex Patterns)
```python
import re

DLP_PATTERNS = {
    'credit_card': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'api_key': re.compile(r'\b(?:sk|pk|rk)_[A-Za-z0-9]{20,}\b'),
    'aws_key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    'iban': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'),
}

def scan_content(content):
    """Scan content for sensitive data patterns."""
    findings = []
    for data_type, pattern in DLP_PATTERNS.items():
        for match in pattern.finditer(content):
            findings.append({
                'type': data_type,
                'match': match.group()[:20] + '...' if len(match.group()) > 20 else match.group(),
                'position': match.start(),
            })
    return findings
```

### Email DLP (Outbound Filtering)
```python
class EmailDLP:
    def __init__(self):
        self.patterns = DLP_PATTERNS
        self.blocked_domains = ['gmail.com', 'yahoo.com', 'outlook.com']  # personal email

    def check_outbound(self, email):
        findings = []

        # Check recipients for external domains
        for recipient in email['recipients']:
            domain = recipient.split('@')[-1]
            if domain in self.blocked_domains and email['classification'] == 'confidential':
                findings.append({
                    'action': 'block',
                    'reason': f'Confidential email to personal domain: {domain}',
                })

        # Scan subject and body for sensitive data
        content = email['subject'] + ' ' + email['body']
        for data_type, pattern in self.patterns.items():
            if pattern.search(content):
                findings.append({
                    'action': 'quarantine',
                    'reason': f'Sensitive data detected: {data_type}',
                })

        # Scan attachments
        for attachment in email['attachments']:
            content = attachment.read()
            for data_type, pattern in self.patterns.items():
                if pattern.search(content.decode('utf-8', errors='ignore')):
                    findings.append({
                        'action': 'block',
                        'reason': f'Sensitive data in attachment: {data_type}',
                    })

        return findings
```

### API DLP (Response Filtering)
```javascript
// Express middleware — scan API responses for sensitive data
function dlpResponseFilter(req, res, next) {
  const originalJson = res.json.bind(res);
  res.json = function (data) {
    const sanitized = sanitizeResponse(data, req.user.role);
    originalJson(sanitized);
  };
  next();
}

function sanitizeResponse(data, role) {
  // Mask sensitive fields based on role
  if (role !== 'admin') {
    if (Array.isArray(data)) {
      return data.map(item => sanitizeResponse(item, role));
    }
    const sanitized = { ...data };
    // Mask credit card
    if (sanitized.creditCard) {
      sanitized.creditCard = '****-****-****-' + sanitized.creditCard.slice(-4);
    }
    // Remove SSN entirely
    delete sanitized.ssn;
    // Mask email partially
    if (sanitized.email) {
      const [user, domain] = sanitized.email.split('@');
      sanitized.email = user[0] + '***@' + domain;
    }
    return sanitized;
  }
  return data;
}

app.use(dlpResponseFilter);
```

### Endpoint DLP (USB Blocking)
```python
#!/usr/bin/env python3
"""USB DLP — block removable media or scan for sensitive data."""
import subprocess
import re

DLP_PATTERNS = {  # same as above
    'credit_card': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
}

def monitor_usb():
    """Monitor USB device insertion (udev on Linux)."""
    # In production, use udev rules or endpoint agent
    # This is a simplified example
    import pyudev
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')

    for device in iter(monitor.poll, None):
        if device.action == 'add' and 'ID_BUS' in device and device['ID_BUS'] == 'usb':
            mount_point = mount_device(device)
            if mount_point:
                scan_result = scan_directory(mount_point)
                if scan_result:
                    log_dlp_event('usb_sensitive_data', device, scan_result)
                    unmount_device(mount_point)
                    notify_admin(f'Sensitive data detected on USB: {device}')

def scan_directory(path):
    findings = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    for data_type, pattern in DLP_PATTERNS.items():
                        if pattern.search(content):
                            findings.append({'file': filepath, 'type': data_type})
            except (IOError, PermissionError):
                pass
    return findings
```

### Cloud Upload DLP (Proxy)
```python
class CloudDLPProxy:
    """Intercept cloud uploads and scan for sensitive data."""

    ALLOWED_CLOUD = ['drive.company.com', 's3.company.com']
    BLOCKED_CLOUD = ['dropbox.com', 'mega.nz', 'wetransfer.com']

    def check_upload(self, request):
        # Block unsanctioned cloud services
        if request.destination in self.BLOCKED_CLOUD:
            return {'action': 'block', 'reason': 'Unsanctioned cloud service'}

        # Scan uploaded content
        content = request.body
        findings = scan_content(content)
        if findings:
            return {
                'action': 'block',
                'reason': f'Sensitive data detected: {[f["type"] for f in findings]}',
            }

        # Log sanctioned uploads
        log_upload(request.user, request.destination, request.size)
        return {'action': 'allow'}
```

---

## AUDIT CHECKLIST

- [ ] Data classification policy defined
- [ ] Sensitive data inventory (where is PII/PHI/card data?)
- [ ] Email DLP (outbound scanning, external domain blocking)
- [ ] Web DLP (upload scanning, API response filtering)
- [ ] Endpoint DLP (USB control, clipboard monitoring)
- [ ] Cloud DLP (sanctioned vs unsanctioned services)
- [ ] Data masking in non-production environments
- [ ] Encryption for data at rest and in transit
- [ ] DLP alerts to SIEM
- [ ] Regular DLP policy review
- [ ] User training on data handling
- [ ] Incident response for DLP violations
