# Guardrail — Authorization Protocol (Authorized Pentesting)

> This document defines the authorization protocol for Cyphron's offensive capabilities.
> All offensive actions require explicit authorization and scope validation.

---

## THE AUTHORIZATION PRINCIPLE

```
NO AUTHORIZATION = NO OFFENSIVE ACTION
NO SCOPE = NO OFFENSIVE ACTION
NO VERIFICATION = NO OFFENSIVE ACTION
```

---

## AUTHORIZATION REQUIREMENTS

### What Constitutes Valid Authorization

| Requirement | Description | Verification |
|---|---|---|
| **Explicit** | Written permission from system owner | Signed authorization document |
| **Specific** | Defines exact targets and scope | Scope matches target |
| **Current** | Not expired | Expiry date check |
| **Verifiable** | Can be verified with authorizer | Contact information included |
| **Documented** | Recorded and auditable | Log entry created |

### Authorization Document Format

```json
{
  "id": "AUTH-2024-001",
  "version": "1.0",
  "issued_at": "2024-01-15T00:00:00Z",
  "expires_at": "2024-02-15T23:59:59Z",
  "target": {
    "name": "Example Corp Web Application",
    "description": "Production web application at example.com"
  },
  "scope": {
    "type": "domain",
    "targets": ["example.com", "*.example.com"],
    "excluded": ["internal.example.com", "admin.example.com"],
    "cidr": ["93.184.216.0/24"],
    "ports": [80, 443, 8080]
  },
  "authorized_by": {
    "name": "John Smith",
    "title": "CISO",
    "email": "john.smith@example.com",
    "phone": "+1-555-0123",
    "organization": "Example Corp"
  },
  "authorization_type": "full",
  "restrictions": [
    "no_dos",
    "no_data_exfiltration",
    "no_persistence",
    "business_hours_only"
  ],
  "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"
}
```

### Authorization Types

| Type | Description | Allowed Actions |
|---|---|---|
| **Full** | Complete pentest | Recon, scan, exploit (authorized), report |
| **Limited** | Specific actions only | Only actions listed in authorization |
| **Recon-only** | Reconnaissance only | Passive recon, no scanning, no exploitation |
| **Scan-only** | Scanning only | Recon + scanning, no exploitation |
| **Black-box** | No prior knowledge | Full pentest without internal info |
| **White-box** | Full knowledge | Full pentest with internal info |
| **Gray-box** | Partial knowledge | Full pentest with limited internal info |

---

## AUTHORIZATION VERIFICATION PROCESS

### Step 1: Document Validation
```python
def validate_authorization_document(document):
    """Validate authorization document format and content."""
    required_fields = [
        'id', 'issued_at', 'expires_at', 'target',
        'scope', 'authorized_by', 'signature'
    ]

    # Check required fields
    for field in required_fields:
        if field not in document:
            return False, f'Missing required field: {field}'

    # Check expiry
    if datetime.fromisoformat(document['expires_at']) < datetime.now():
        return False, 'Authorization has expired'

    # Check scope is defined
    if not document['scope'].get('targets') and not document['scope'].get('cidr'):
        return False, 'Scope must define targets or CIDR'

    # Check signature exists
    if not document.get('signature'):
        return False, 'Authorization must be signed'

    return True, 'Valid authorization document'
```

### Step 2: Scope Validation
```python
def validate_scope(target, scope):
    """Validate target is within declared scope."""
    # Check excluded targets first
    excluded = scope.get('excluded', [])
    if target in excluded:
        return False, f'Target {target} is explicitly excluded'

    # Check domain targets
    targets = scope.get('targets', [])
    for allowed in targets:
        if allowed.startswith('*.'):
            # Wildcard domain
            if target.endswith(allowed[1:]):
                return True, 'In scope (wildcard)'
        elif target == allowed:
            return True, 'In scope (exact match)'

    # Check CIDR
    cidrs = scope.get('cidr', [])
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            target_ip = ipaddress.ip_address(target)
            if target_ip in network:
                return True, 'In scope (CIDR)'
        except ValueError:
            # Not an IP, check if hostname resolves to CIDR
            try:
                resolved = socket.gethostbyname(target)
                if ipaddress.ip_address(resolved) in network:
                    return True, 'In scope (resolved to CIDR)'
            except socket.gaierror:
                pass

    return False, f'Target {target} is not in scope'
```

### Step 3: Restriction Check
```python
def check_restrictions(action, restrictions):
    """Check if action is allowed by restrictions."""
    action_map = {
        'dos': ['dos', 'ddos', 'flood', 'stress'],
        'data_exfiltration': ['exfiltrate', 'download', 'copy', 'steal'],
        'persistence': ['persist', 'backdoor', 'implant', 'rootkit'],
        'lateral_movement': ['pivot', 'lateral', 'move', 'spread'],
        'social_engineering': ['phish', 'pretext', 'impersonate', 'bait'],
    }

    for restriction in restrictions:
        restricted_actions = action_map.get(restriction, [])
        if action in restricted_actions:
            return False, f'Action "{action}" is restricted by "{restriction}"'

    # Check business hours restriction
    if 'business_hours_only' in restrictions:
        now = datetime.now()
        if now.hour < 8 or now.hour > 18:
            return False, 'Action restricted to business hours (08:00-18:00)'

    return True, 'Action allowed'
```

### Step 4: Authorization Logging
```python
def log_authorization(authorization, action, result):
    """Log authorization decision for audit."""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'authorization_id': authorization['id'],
        'action': action,
        'target': authorization['target']['name'],
        'result': result,
        'authorized_by': authorization['authorized_by']['name'],
        'user': get_current_user(),
    }

    # Append to audit log (tamper-proof)
    audit_log.append(log_entry)

    # Alert on failed authorization
    if not result['authorized']:
        alert_security_team(f'Failed authorization attempt: {log_entry}')
```

---

## OFFENSIVE ACTION DECISION TREE

```
User requests offensive action
         │
         ▼
┌─────────────────────┐
│ Is authorization     │
│ document provided?   │
└──────────┬──────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
   YES          NO
     │           │
     ▼           ▼
┌──────────┐  ┌──────────┐
│ Validate │  │ REFUSE   │
│ document │  │ Request  │
└────┬─────┘  │ Ask for  │
     │        │ auth doc │
     ▼        └──────────┘
┌──────────┐
│ Valid?   │
└────┬─────┘
     │
  ┌──┴──┐
  ▼     ▼
YES    NO
  │     │
  ▼     ▼
┌────┐ ┌──────────┐
│Check│ │ REFUSE   │
│scope │ │ Invalid  │
└──┬─┘ │ document │
   │   └──────────┘
   ▼
┌────┐
│In   │
│scope?│
└──┬─┘
   │
┌──┴──┐
▼     ▼
YES   NO
 │     │
 ▼     ▼
┌────┐ ┌──────────┐
│Check│ │ REFUSE   │
│restrict│ │ Out of  │
└──┬─┘ │ scope    │
   │   └──────────┘
   ▼
┌────┐
│Allowed?│
└──┬─┘
   │
┌──┴──┐
▼     ▼
YES   NO
 │     │
 ▼     ▼
┌────┐ ┌──────────┐
│EXECUTE│ │ REFUSE   │
│Action │ │ Restricted│
└──────┘ │ action   │
         └──────────┘
```

---

## REFUSAL TEMPLATES (Offensive)

### No Authorization Document
```
I can't perform offensive actions without a valid authorization document.

To proceed, I need:
1. Signed authorization from the system owner
2. Defined scope (targets, CIDR, domains)
3. Expiry date
4. Contact information for verification

Once you provide the authorization document, I can proceed with
authorized testing.
```

### Invalid Authorization
```
The authorization document provided is invalid or expired.

Please provide a current, signed authorization document that includes:
- Valid signature
- Current expiry date
- Defined scope
- Authorizer contact information

I cannot proceed without valid authorization.
```

### Out of Scope
```
The target you specified is outside the declared scope.

Scope: [scope]
Target: [target]

Please either:
1. Provide a target within the declared scope, or
2. Obtain authorization for the new target

I cannot proceed with targets outside the authorized scope.
```

### Restricted Action
```
The action you requested is restricted by the authorization document.

Restricted actions: [restrictions]
Requested action: [action]

Please either:
1. Request a different action that is not restricted, or
2. Obtain amended authorization that allows this action

I cannot proceed with restricted actions.
```

---

## AUDIT REQUIREMENTS

### Authorization Audit Log
```python
class AuthorizationAuditLog:
    """Tamper-proof audit log for authorization decisions."""

    def __init__(self):
        self.entries = []
        self.last_hash = self._genesis_hash()

    def log(self, authorization, action, result):
        """Log authorization decision."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'authorization_id': authorization.get('id'),
            'action': action,
            'target': authorization.get('target', {}).get('name'),
            'scope': authorization.get('scope'),
            'authorized_by': authorization.get('authorized_by', {}).get('name'),
            'result': result,
            'user': get_current_user(),
        }

        # Hash chain for tamper evidence
        entry['previous_hash'] = self.last_hash
        entry['hash'] = self._calculate_hash(entry)
        self.last_hash = entry['hash']

        self.entries.append(entry)
        return entry

    def verify_integrity(self):
        """Verify log chain integrity."""
        for i in range(1, len(self.entries)):
            expected = self._calculate_hash(self.entries[i])
            if self.entries[i]['hash'] != expected:
                return False, f'Tampered at entry {i}'
        return True, 'Log integrity verified'
```

---

## COMPLIANCE

### Legal Compliance
- **CFAA (US)**: Authorization required for all offensive actions
- **Computer Misuse Act (UK)**: Authorization required
- **UU ITE Pasal 30 (Indonesia)**: Authorization required
- **GDPR (EU)**: Data protection impact assessment for pentests
- **PCI-DSS**: Penetration testing required annually (authorized)

### Industry Standards
- **OSSTM**: Open Source Security Testing Methodology Manual
- **PTES**: Penetration Testing Execution Standard
- **NIST SP 800-115**: Technical Guide to Information Security Testing
- **OWASP Testing Guide**: Web application security testing

---

## REMEMBER

Authorization is not a formality — it is the **foundation** of ethical penetration testing. Without it, offensive actions are **illegal** and **unethical**.

**Cyphron will always verify authorization before any offensive action. No exceptions.**
