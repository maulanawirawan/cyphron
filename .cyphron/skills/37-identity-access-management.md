# Skill 37 — Identity & Access Management (IAM)

> Cyphron's methodology for building comprehensive Identity and Access Management systems. Cyphron knows IAM attack vectors — credential theft, privilege escalation, token abuse, federation attacks — and builds IAM systems with least privilege, MFA, and continuous verification.

---

## WHEN TO ACTIVATE

- User asks to build an IAM system or program
- User asks about SSO, federation, or directory services
- User asks about privileged access management (PAM)
- User asks about identity lifecycle or access reviews
- User asks about zero-trust identity

---

## METHODOLOGY

### Step 1: Identity Lifecycle
```
Provisioning → Modification → Access Review → Deprovisioning
     ↑                                              │
     └──────── Joiner-Mover-Leaver Process ─────────┘
```

### Step 2: IAM Architecture Layers

| Layer | Component |
|---|---|
| Identity Source | HR system, directory (AD/LDAP) |
| Identity Provider | Okta, Azure AD, Keycloak |
| Authentication | Password + MFA, FIDO2, SSO |
| Authorization | RBAC, ABAC, policy engine |
| Privileged Access | PAM (CyberArk, Teleport) |
| Governance | Access reviews, recertification |
| Monitoring | Auth logs, anomaly detection |

### Step 3: Build IAM Defenses

---

## SECURE PATTERNS

### SSO with SAML (Identity Provider)
```python
from defusedxml import ElementTree as ET
import base64
import zlib
from cryptography.hazmat.primitives import hashes, signing

class SAMLIdP:
    def __init__(self, private_key, cert):
        self.private_key = private_key
        self.cert = cert

    def generate_assertion(self, user, sp_entity_id, request_id):
        """Generate signed SAML assertion."""
        issue_instant = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')

        assertion = f"""
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                       ID="{generate_id()}"
                       IssueInstant="{issue_instant}"
                       Version="2.0">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <!-- XML Digital Signature -->
          </ds:Signature>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
              {user.email}
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="{expiry}"
                Recipient="{sp_entity_id}"
                InResponseTo="{request_id}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{expiry}">
            <saml:AudienceRestriction>
              <saml:Audience>{sp_entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="{issue_instant}"
            SessionIndex="{generate_id()}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>
                urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
              </saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
        </saml:Assertion>
        """
        # Sign the assertion (XMLDSig)
        return sign_xml(assertion, self.private_key)
```

### OAuth 2.0 with PKCE (Secure Authorization)
```javascript
// Authorization Code flow with PKCE (Proof Key for Code Exchange)
const crypto = require('crypto');

// 1. Client generates code verifier and challenge
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

// 2. Redirect to authorization endpoint
const authUrl = new URL('https://idp.example.com/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', crypto.randomBytes(16).toString('hex'));
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// 3. Exchange code for token (with PKCE verifier)
const tokenResponse = await fetch('https://idp.example.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: codeVerifier,  // PKCE — prevents code interception
  }),
});
```

### Privileged Access Management (Just-in-Time)
```python
class JustInTimeAccess:
    """Grant privileged access only when needed, for limited time."""

    async def request_access(self, user, resource, duration_minutes=60, reason=''):
        """Request temporary privileged access."""
        # 1. Validate request
        if not self.can_request(user, resource):
            raise PermissionError(f'{user} cannot request access to {resource}')

        # 2. Require approval
        approval = await self.request_approval(user, resource, reason)
        if not approval.approved:
            return {'status': 'denied', 'reason': approval.reason}

        # 3. Grant time-limited access
        access_token = self.generate_access_token(user, resource, duration_minutes)
        await self.log_access_grant(user, resource, duration_minutes, reason, approval)

        # 4. Auto-revoke after duration
        await self.schedule_revoke(access_token, duration_minutes)

        return {
            'status': 'granted',
            'token': access_token,
            'expires_at': (datetime.now() + timedelta(minutes=duration_minutes)).isoformat(),
        }

    async def revoke_access(self, token):
        """Revoke access immediately."""
        await self.invalidate_token(token)
        await self.log_access_revoke(token)
```

### Access Review (Recertification)
```python
class AccessReview:
    """Periodic access recertification."""

    async def generate_review(self, manager_id):
        """Generate access review for manager's team."""
        team = await self.get_team_members(manager_id)
        review_items = []

        for member in team:
            access = await self.get_user_access(member.id)
            for item in access:
                review_items.append({
                    'user': member.name,
                    'user_id': member.id,
                    'resource': item.resource,
                    'access_level': item.level,
                    'granted_date': item.granted_at,
                    'last_used': item.last_used,
                    'action': 'pending',  # manager decides: keep/revoke
                })

        return {
            'manager': manager_id,
            'review_period': 'quarterly',
            'items': review_items,
            'due_date': (datetime.now() + timedelta(days=14)).isoformat(),
        }

    async def process_review(self, manager_id, decisions):
        """Process manager's access review decisions."""
        for decision in decisions:
            if decision['action'] == 'revoke':
                await self.revoke_access(decision['user_id'], decision['resource'])
                await self.log_revocation(decision['user_id'], decision['resource'], manager_id)
            elif decision['action'] == 'keep':
                await self.extend_access(decision['user_id'], decision['resource'])
```

### FIDO2 / WebAuthn (Passwordless)
```javascript
// Server-side — registration
app.post('/webauthn/register', auth, async (req, res) => {
  const user = req.user;

  const registrationOptions = await fido2.generateRegistrationOptions({
    rpID: 'example.com',
    rpName: 'My App',
    userID: user.id,
    userName: user.email,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'required',  // biometric required
      residentKey: 'required',       // passwordless
    },
  });

  // Store challenge
  await storeChallenge(user.id, registrationOptions.challenge);

  res.json(registrationOptions);
});

// Verify registration
app.post('/webauthn/register/verify', auth, async (req, res) => {
  const expectedChallenge = await getChallenge(req.user.id);
  const verification = await fido2.verifyRegistrationResponse({
    credential: req.body.credential,
    expectedChallenge,
    expectedOrigin: 'https://app.example.com',
    expectedRPID: 'example.com',
  });

  if (!verification.verified) {
    return res.status(400).json({ error: 'Registration failed' });
  }

  // Store credential public key
  await storeCredential(req.user.id, verification.credentialInfo);
  res.json({ verified: true });
});
```

---

## AUDIT CHECKLIST

- [ ] SSO for all applications (no standalone auth)
- [ ] MFA enforced for all users (FIDO2 preferred)
- [ ] Privileged access via PAM (just-in-time, not standing)
- [ ] Access reviews quarterly (manager recertification)
- [ ] Joiner-Mover-Leaver process automated
- [ ] Deprovisioning within 24h of termination
- [ ] Least privilege (no excessive permissions)
- [ ] Service accounts with rotated credentials
- [ ] Federation with signed assertions (SAML/OIDC)
- [ ] PKCE for OAuth public clients
- [ ] Conditional access (device posture, location, risk)
- [ ] Password policy (length > complexity, breach check)
- [ ] Account lockout with secure unlock
- [ ] Auth logs to SIEM
- [ ] Anomaly detection (impossible travel, new device)
- [ ] Break-glass accounts (emergency, monitored)
