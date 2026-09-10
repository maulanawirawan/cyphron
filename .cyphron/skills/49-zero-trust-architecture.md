# Skill 49 — Zero Trust Architecture (NIST 800-207)

> Cyphron's methodology for implementing Zero Trust security architecture. Cyphron knows that Zero Trust isn't a product — it's a philosophy: "Never trust, always verify." Cyphron builds ZTA implementations following NIST SP 800-207.

---

## WHEN TO ACTIVATE

- User asks to implement Zero Trust architecture
- User asks about NIST 800-207 or Zero Trust principles
- User asks about micro-segmentation, identity-aware proxy, or policy engine
- User asks about zero trust networking or zero trust identity

---

## METHODOLOGY

### Zero Trust Principles (NIST 800-207)

1. **All data sources and computing services are considered resources** — everything is a resource that needs protection
2. **All communication is secured regardless of network location** — no implicit trust based on network position
3. **Access to individual enterprise resources is granted on a per-session basis** — no standing access
4. **Access to resources is determined by dynamic policy** — context-aware, not static
5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets** — continuous verification
6. **All resource authentication and authorization are dynamic and strictly enforced before access is allowed** — verify before every access
7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture** — data-driven decisions

### ZTA Logical Components (NIST 800-207)

```
Policy Decision Point (PDP)
├── Policy Engine (PE) — makes access decisions
└── Policy Administrator (PA) — executes decisions

Policy Enforcement Point (PEP) — enforces decisions

System Interfaces (SI) — feeds data to PDP
├── Continuous Diagnostics & Mitigation (CDM)
├── Industry Compliance (IC)
├── Threat Intelligence (TI)
├── Data Access Policies (DAP)
├── Enterprise Public Key Infrastructure (PKI)
├── ID Management (IDM)
└── Security Information & Event Management (SIEM)
```

---

## SECURE PATTERNS

### Zero Trust Network Architecture
```
Internet → [IAP/CDN] → [PEP] → [Micro-segmented Services]
              ↓           ↓
           [PDP]      [PEP per service]
              ↓           ↓
        [Policy Engine]  [mTLS + AuthZ]
              ↓
    ┌─────────┼─────────┐
    ▼         ▼         ▼
  [SIEM]   [CDM]    [Threat Intel]
```

### Policy Engine (Open Policy Agent)
```rego
# Zero Trust policy — every request evaluated dynamically
package authz

default allow = false

# Allow if:
# 1. User is authenticated
# 2. Device is managed and compliant
# 3. Location is trusted (or additional verification passed)
# 4. Time is within business hours (or emergency override)
# 5. Resource access is authorized for this user
allow {
    input.user.authenticated == true
    input.device.managed == true
    input.device.compliant == true
    input.user.mfa_verified == true
    resource_authorized
}

resource_authorized {
    # Check RBAC
    input.user.role == "admin"
} else {
    # Check ABAC — department match
    input.user.department == input.resource.department
} else {
    # Check relationship — resource owner
    input.user.id == input.resource.owner_id
}

# Continuous verification — session timeout
session_valid {
    input.session.created_at + 3600000 > input.request.time  # 1 hour max
}

# Device posture — must be compliant
device_compliant {
    input.device.encrypted == true
    input.device.patched == true
    input.device.managed == true
}
```

### Identity-Aware Proxy (IAP)
```python
class IdentityAwareProxy:
    """Zero Trust IAP — every request authenticated and authorized."""

    def __init__(self, policy_engine, session_store):
        self.policy_engine = policy_engine
        self.sessions = session_store

    async def handle_request(self, request):
        # 1. Authenticate — verify identity
        identity = await self.authenticate(request)
        if not identity:
            return {'status': 401, 'message': 'Authentication required'}

        # 2. Collect context — device, location, time, session
        context = {
            'user': identity,
            'device': await self.get_device_posture(request),
            'location': await self.get_location(request),
            'time': request.timestamp,
            'resource': request.resource,
            'session': await self.get_session(request),
        }

        # 3. Evaluate policy — dynamic decision
        decision = self.policy_engine.evaluate(context)

        if not decision.allow:
            return {'status': 403, 'message': decision.reason}

        # 4. Log access — audit trail
        await self.log_access(context, decision)

        # 5. Forward to resource with short-lived token
        token = self.generate_resource_token(context, ttl=300)  # 5 min
        return await self.forward_request(request, token)

    async def authenticate(self, request):
        """Multi-factor authentication."""
        token = request.headers.get('Authorization')
        if not token:
            return None

        # Verify token
        identity = await self.verify_token(token)
        if not identity:
            return None

        # Check MFA
        if not identity.get('mfa_verified'):
            # Require step-up authentication
            mfa_result = await self.require_mfa(identity)
            if not mfa_result:
                return None

        return identity
```

### Micro-Segmentation (Per-Service Policy)
```yaml
# Kubernetes NetworkPolicy — micro-segmentation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: zero-trust-payment-service
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes: [Ingress, Egress]
  ingress:
  # Only allow from API gateway, with specific path
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080
  # Only allow to database, on specific port
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: payment-db
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: secrets-manager
    ports:
    - protocol: TCP
      port: 8200
```

### Continuous Diagnostics & Mitigation (CDM)
```python
class ContinuousVerification:
    """Continuously verify user, device, and session."""

    async def verify_session(self, session_id):
        """Re-verify session continuously — not just at login."""
        session = await self.get_session(session_id)

        checks = {
            'user_active': await self.is_user_active(session.user_id),
            'device_compliant': await self.is_device_compliant(session.device_id),
            'location_trusted': await self.is_location_trusted(session.location),
            'behavior_normal': await self.is_behavior_normal(session.user_id),
            'session_valid': self.is_session_valid(session),
        }

        # If any check fails, require re-authentication
        if not all(checks.values()):
            failed_checks = [k for k, v in checks.items() if not v]
            await self.invalidate_session(session_id, reason=failed_checks)
            return {
                'valid': False,
                'reason': f'Continuous verification failed: {failed_checks}',
                'action': 're-authenticate',
            }

        return {'valid': True}

    async def is_behavior_normal(self, user_id):
        """Behavioral analytics — detect anomalies."""
        baseline = await self.get_user_baseline(user_id)
        current = await self.get_current_behavior(user_id)

        anomalies = []

        # Unusual access time
        if current['access_hour'] not in baseline['typical_hours']:
            anomalies.append('unusual_time')

        # Unusual data volume
        if current['data_volume'] > baseline['avg_volume'] * 3:
            anomalies.append('high_data_volume')

        # Unusual access pattern
        if current['access_pattern'] not in baseline['typical_patterns']:
            anomalies.append('unusual_pattern')

        return len(anomalies) == 0
```

---

## AUDIT CHECKLIST

- [ ] No implicit trust based on network location
- [ ] Every request authenticated (not just at login)
- [ ] Every request authorized (dynamic policy)
- [ ] MFA required for all access
- [ ] Device posture verified (managed, compliant, encrypted)
- [ ] Micro-segmentation implemented (per-service network policy)
- [ ] Continuous session verification (not just login-time)
- [ ] Behavioral analytics for anomaly detection
- [ ] Least privilege access (just-in-time, just-enough)
- [ ] Policy engine centralizes access decisions
- [ ] All access logged and auditable
- [ ] Data feeds to policy engine (CDM, threat intel, SIEM)
- [ ] Zero trust for east-west traffic (not just north-south)
- [ ] Zero trust for internal users (not just external)
- [ ] Zero trust for service-to-service communication
