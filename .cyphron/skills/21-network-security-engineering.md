# Skill 21 — Network Security Engineering

> Cyphron's methodology for securing network infrastructure. Cyphron knows network attack patterns — MITM, ARP spoofing, DNS poisoning, lateral movement, port scanning — and builds network defenses: segmentation, firewalls, IDS/IPS, VPN, and zero-trust networking.

---

## WHEN TO ACTIVATE

- User asks to secure network infrastructure
- User asks about firewalls, IDS/IPS, VPN, or network segmentation
- User asks about DNS security, TLS inspection, or proxy configuration
- User asks about zero-trust networking
- User asks to build network detection rules

---

## METHODOLOGY

### Step 1: Network Architecture Review
- Map network topology (subnets, VLANs, zones)
- Identify trust zones (internet, DMZ, internal, restricted)
- Map data flows between zones
- Identify entry points and exposure

### Step 2: Defense in Depth Layers

| Layer | Control |
|---|---|
| Perimeter | Firewall, DDoS protection, WAF |
| DMZ | Reverse proxy, load balancer, bastion host |
| Internal | Network segmentation, micro-segmentation |
| Endpoint | Host firewall, EDR, port hardening |
| Monitoring | IDS/IPS, NetFlow, SIEM |

### Step 3: Build Network Defenses

---

## SECURE PATTERNS

### Network Segmentation (Zero Trust)
```
Internet → [WAF/DDoS] → DMZ (LB, Proxy) → App Tier → Data Tier
                              ↑                ↑           ↑
                         mTLS            mTLS      DB-only network
                         AuthZ           AuthZ     No internet egress
```

### Firewall Rules (iptables/nftables)
```bash
# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from management subnet only
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT

# Allow HTTPS from anywhere
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow DNS to specific resolvers
iptables -A OUTPUT -p udp --dport 53 -d 8.8.8.8 -j ACCEPT

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "FW-DROP: "
iptables -A INPUT -j DROP
```

### Suricata IDS Rules
```
# Detect port scanning
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible Port Scan"; \
  detection_filter:track by_src, count 30, seconds 60; \
  classtype:attempted-recon; sid:2002001; rev:1;)

# Detect DNS exfiltration (large DNS queries)
alert udp any any -> any 53 (msg:"Possible DNS Exfiltration"; \
  dsize:>100; classtype:trojan-activity; sid:2002002; rev:1;)

# Detect lateral movement (SMB from external)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB from External Network"; \
  flow:to_server,established; classtype:attempted-admin; sid:2002003; rev:1;)
```

### WireGuard VPN (Secure Remote Access)
```ini
# /etc/wireguard/wg0.conf — Server
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# Client (each client gets unique key)
[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.10.0.2/32  # specific IP per client
```

### DNS Security (DNSSEC + DoH)
```bash
# Enable DNSSEC validation
named-checkconf /etc/named.conf
# options { dnssec-validation yes; };

# Block known malicious domains (RPZ)
# zone "rpz.block" { type master; file "rpz.block"; };
```

### Egress Filtering (Prevent Data Exfiltration)
```bash
# Allow only approved destinations
iptables -A OUTPUT -d approved-api.example.com -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT  # internal
iptables -A OUTPUT -j LOG --log-prefix "EGRESS-DROP: "
iptables -A OUTPUT -j DROP
```

---

## AUDIT CHECKLIST

- [ ] Default deny on all firewalls
- [ ] Network segmentation (DMZ, app, data tiers separated)
- [ ] No direct internet access for database tier
- [ ] IDS/IPS deployed at perimeter and internal
- [ ] VPN for remote access (WireGuard/IPsec, not PPTP)
- [ ] DNSSEC enabled
- [ ] Egress filtering (allowlist destinations)
- [ ] TLS 1.2+ for all internal service communication
- [ ] mTLS between microservices
- [ ] Network monitoring (NetFlow, SIEM)
- [ ] No 0.0.0.0/0 on sensitive ports (SSH, RDP, DB)
- [ ] Bastion host for admin access
- [ ] NAC (Network Access Control) for endpoints
