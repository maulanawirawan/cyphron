# Skill 56 — Secure Remote Access

> Cyphron's methodology for securing remote access to infrastructure. Cyphron knows remote access attack vectors — VPN compromise, credential theft, lateral movement via remote access, split tunneling — and builds secure remote access solutions: VPN, ZTNA (Zero Trust Network Access), and bastion hosts.

---

## WHEN TO ACTIVATE

- User asks to secure remote access (VPN, ZTNA, bastion)
- User asks about WireGuard, OpenVPN, or IPsec configuration
- User asks about Zero Trust Network Access (ZTNA)
- User asks about bastion host or jump server security
- User asks about split tunneling or VPN security

---

## METHODOLOGY

### Remote Access Options

| Solution | Best For | Security Level |
|---|---|---|
| Traditional VPN | Legacy apps, full network access | Medium (network-level trust) |
| ZTNA | Modern apps, per-app access | High (identity-based, no network trust) |
| Bastion Host | Server administration | High (controlled, audited access) |
| IAP (Identity-Aware Proxy) | Web applications | High (Google Cloud, Cloudflare) |

### Step 1: Choose Access Model
### Step 2: Implement Authentication
### Step 3: Implement Authorization
### Step 4: Monitor & Audit

---

## SECURE PATTERNS

### WireGuard VPN (Secure Configuration)
```ini
# /etc/wireguard/wg0.conf — Server configuration
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# PostUp — firewall rules when VPN starts
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client 1 — full tunnel (all traffic through VPN)
[Peer]
PublicKey = <client1-public-key>
AllowedIPs = 10.10.0.2/32
# No PersistentKeepalive for server-initiated connections

# Client 2 — split tunnel (only internal traffic through VPN)
[Peer]
PublicKey = <client2-public-key>
AllowedIPs = 10.10.0.3/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# Only internal networks through VPN

# Client 3 — restricted access (specific subnets only)
[Peer]
PublicKey = <client3-public-key>
AllowedIPs = 10.10.0.4/32, 10.0.1.0/24
# Only management subnet
```

```ini
# Client configuration — secure defaults
[Interface]
PrivateKey = <client-private-key>
Address = 10.10.0.2/32
DNS = 10.10.0.1  # Use VPN DNS, not ISP DNS

# Kill switch — block all traffic if VPN drops
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

[Peer]
PublicKey = <server-public-key>
AllowedIPs = 0.0.0.0/0  # Full tunnel
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

### Zero Trust Network Access (ZTNA)
```python
class ZTNAGateway:
    """Zero Trust Network Access — identity-based, per-app access."""

    def __init__(self, policy_engine, identity_provider):
        self.policy_engine = policy_engine
        self.idp = identity_provider

    async def handle_access_request(self, request):
        """Handle ZTNA access request."""
        # 1. Authenticate user (identity, not network)
        identity = await self.idp.authenticate(request.credentials)
        if not identity:
            return {'status': 401, 'message': 'Authentication failed'}

        # 2. Collect device posture
        device = await self.get_device_posture(request.device_id)

        # 3. Build context
        context = {
            'user': identity,
            'device': device,
            'resource': request.resource,
            'action': request.action,
            'time': request.timestamp,
            'location': request.location,
        }

        # 4. Evaluate policy (dynamic, per-request)
        decision = self.policy_engine.evaluate(context)

        if not decision.allow:
            return {'status': 403, 'message': decision.reason}

        # 5. Create application-specific tunnel (not full network access)
        tunnel = await self.create_app_tunnel(
            user=identity,
            device=device,
            app=request.resource,
            ttl=300,  # 5 minutes
        )

        # 6. Log access
        await self.log_access(context, decision, tunnel)

        return {
            'status': 200,
            'tunnel_id': tunnel.id,
            'expires_at': tunnel.expires_at,
            'app_url': tunnel.app_url,
        }

    async def create_app_tunnel(self, user, device, app, ttl):
        """Create per-app encrypted tunnel (not full network access)."""
        # Only allow access to specific application, not entire network
        tunnel = {
            'id': generate_id(),
            'user_id': user.id,
            'device_id': device.id,
            'app_id': app.id,
            'app_url': f'https://{app.internal_hostname}',
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(seconds=ttl),
            'allowed_methods': app.allowed_methods,  # GET, POST only, not arbitrary
            'allowed_paths': app.allowed_paths,      # specific paths only
        }
        return tunnel
```

### Bastion Host (Secure Jump Server)
```bash
#!/bin/bash
# Bastion host setup — secure jump server for administration

# 1. Harden SSH
cat > /etc/ssh/sshd_config << 'EOF'
# Bastion host SSH configuration
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
AllowUsers bastion-admin
DenyUsers root
AllowGroups bastion-users

# Log all commands
ForceCommand internal-sftp -d /home/bastion-admin/logs
EOF

# 2. Session recording (audit all commands)
cat > /etc/profile.d/bastion-logging.sh << 'EOF'
# Log all commands to audit log
export PROMPT_COMMAND='history -a'
export HISTTIMEFORMAT="%F %T "
export HISTFILE=/var/log/bastion/audit-$(date +%Y%m%d).log
export HISTSIZE=10000
export HISTFILESIZE=10000
shopt -s histappend
EOF

# 3. Restricted shell (limit what users can do)
cat > /usr/local/bin/rbash-wrapper << 'EOF'
#!/bin/bash
# Restricted bash — only allow specific commands
exec /bin/rbash -c "$@"
EOF

# 4. MFA for bastion access (TOTP)
apt-get install -y libpam-google-authenticator

cat >> /etc/pam.d/sshd << 'EOF'
auth required pam_google_authenticator.so
EOF

# 5. Firewall — only allow SSH from management network
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.0.1.0/24 to any port 2222 proto tcp
ufw enable

# 6. Auditd — log all activity
auditctl -w /var/log/bastion/ -p wa -k bastion-audit
auditctl -a always,exit -F arch=b64 -S execve -F path=/usr/bin/ssh -k ssh-commands
```

### IAP (Identity-Aware Proxy) — Cloudflare Access
```yaml
# Cloudflare Access — Zero Trust remote access
# config.yaml

applications:
  - name: admin-panel
    domain: admin.example.com
    type: self_hosted
    session_duration: 1h
    app_launcher_visible: true

    policies:
      - name: admin-access
        decision: allow
        include:
          - email:
              domain: example.com
          - group:
              name: administrators
        require:
          - mfa: true
          - device_posture:
              - os: windows
              - version: ">=10.0.0"
              - disk_encryption: true
              - firewall: true
              - antivirus: true

      - name: contractor-access
        decision: allow
        include:
          - email:
              domain: contractor.example.com
        require:
          - mfa: true
          - ip:
              ranges:
                - 203.0.113.0/24
        session_duration: 30m

  - name: internal-api
    domain: api.internal.example.com
    type: self_hosted
    session_duration: 15m

    policies:
      - name: service-account
        decision: service_auth
        include:
          - service_token:
              token_id: abc123
        session_duration: 0  # no session for service tokens

# Device posture checks
device_posture:
  checks:
    - name: disk-encryption
      type: file
      path: /dev/sda1
      encryption: true

    - name: firewall-enabled
      type: firewall
      enabled: true

    - name: antivirus-running
      type: application
      name: Windows Defender
      running: true
```

---

## AUDIT CHECKLIST

- [ ] MFA required for all remote access
- [ ] No password-only authentication (key-based or MFA)
- [ ] Per-app access (not full network access) — ZTNA preferred
- [ ] Device posture verification (managed, encrypted, patched)
- [ ] Session recording for bastion access
- [ ] Audit logging for all remote access
- [ ] Time-limited sessions (not standing access)
- [ ] Just-in-time access (request → approve → grant → auto-revoke)
- [ ] Split tunneling disabled (or documented exceptions)
- [ ] Kill switch on VPN clients
- [ ] DNS through VPN (not ISP DNS)
- [ ] Firewall rules on VPN server (default deny)
- [ ] Bastion host hardened (no direct server access)
- [ ] Regular access review (quarterly)
- [ ] Anomaly detection (unusual access time, location, volume)
- [ ] Incident response for remote access compromise
- [ ] Alternative access method (if primary fails)
- [ ] Documentation for all remote access methods
