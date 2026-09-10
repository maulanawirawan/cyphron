# Skill 50 — WAF & DDoS Protection

> Cyphron's methodology for building Web Application Firewalls (WAF) and DDoS protection systems. Cyphron knows WAF bypass techniques and DDoS attack vectors — and builds defenses that are precise, performant, and resilient.

---

## WHEN TO ACTIVATE

- User asks to build or configure a WAF
- User asks about DDoS protection or mitigation
- User asks about ModSecurity rules or WAF bypass
- User asks about rate limiting or traffic shaping
- User asks about CDN security (Cloudflare, AWS CloudFront)

---

## METHODOLOGY

### WAF Rule Categories

| Category | Purpose | Examples |
|---|---|---|
| Core Rule Set | OWASP ModSecurity CRS | SQLi, XSS, RCE, LFI |
| Custom Rules | Application-specific | Business logic, API abuse |
| Rate Limiting | Throttle requests | Per-IP, per-user, per-endpoint |
| Geo Blocking | Restrict by location | Country allow/block list |
| Bot Management | Distinguish bots from humans | JS challenge, CAPTCHA |
| Virtual Patching | Temporary fix for known vulns | CVE-specific rules |

### DDoS Defense Layers

| Layer | Defense | Capacity |
|---|---|---|
| Edge (CDN) | Absorb at edge | 100+ Tbps (Cloudflare) |
| Network | Scrubbing center | 10-100 Gbps |
| Application | Rate limiting, WAF | Application-specific |
| Infrastructure | Auto-scaling | Cloud-native |

---

## SECURE PATTERNS

### ModSecurity CRS + Custom Rules
```apache
# ModSecurity — OWASP Core Rule Set + custom application rules

# Load OWASP CRS
Include modsecurity.d/owasp-crs/crs-setup.conf
Include modsecurity.d/owasp-crs/rules/*.conf

# ─── Custom Application Rules ───

# Block SQLi in specific parameter
SecRule ARGS:username "@rx (?i)(?:union\s+select|select\s+.*\s+from|'\s*or\s*'|1\s*=\s*1)" \
    "id:100001,\
    phase:2,\
    deny,\
    log,\
    msg:'SQLi in username parameter',\
    tag:'application-sql-injection',\
    severity:CRITICAL"

# Block XSS in comment field
SecRule ARGS:comment "@rx (?i)(?:<script|javascript:|onerror\s*=|onload\s*=|<iframe)" \
    "id:100002,\
    phase:2,\
    deny,\
    log,\
    msg:'XSS in comment field',\
    tag:'application-xss',\
    severity:CRITICAL"

# Rate limiting — login endpoint (5 per minute)
SecRule IP:bf_counter "@gt 5" \
    "id:100003,\
    phase:2,\
    deny,\
    log,\
    msg:'Brute force attempt on login',\
    tag:'brute-force',\
    severity:HIGH"

# Count login attempts
SecRule REQUEST_URI "@contains /login" \
    "id:100004,\
    phase:1,\
    pass,\
    nolog,\
    setvar:ip.bf_counter=+1,\
    expirevar:ip.bf_counter=60"

# API rate limiting (100 requests per minute)
SecRule IP:api_counter "@gt 100" \
    "id:100005,\
    phase:2,\
    deny,\
    log,\
    msg:'API rate limit exceeded',\
    tag:'api-abuse',\
    severity:MEDIUM"

SecRule REQUEST_URI "@beginsWith /api/" \
    "id:100006,\
    phase:1,\
    pass,\
    nolog,\
    setvar:ip.api_counter=+1,\
    expirevar:ip.api_counter=60"

# Block known bad bots (User-Agent)
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas)" \
    "id:100007,\
    phase:1,\
    deny,\
    log,\
    msg:'Scanner detected',\
    tag:'recon-scanner',\
    severity:HIGH"

# Virtual patch — specific CVE (example: CVE-2021-44228 Log4Shell)
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS "@rx (?i)(?:jndi:ldap|jndi:rmi|jndi:dns)" \
    "id:100008,\
    phase:2,\
    deny,\
    log,\
    msg:'Log4Shell JNDI lookup attempt',\
    tag:'CVE-2021-44228',\
    severity:CRITICAL"
```

### Rate Limiting (Nginx)
```nginx
# Nginx rate limiting — protect against DDoS and brute force

# Define rate limit zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=upload:10m rate=2r/m;

# Connection limit
limit_conn_zone $binary_remote_addr zone=conn:10m;

server {
    # General rate limit
    location / {
        limit_req zone=general burst=20 nodelay;
        limit_conn conn 10;
        proxy_pass http://backend;
    }

    # Login — strict rate limit
    location /login {
        limit_req zone=login burst=3 nodelay;
        limit_conn conn 2;
        proxy_pass http://backend;
    }

    # API — moderate rate limit
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        limit_conn conn 20;
        proxy_pass http://backend;
    }

    # Upload — strict rate limit
    location /upload {
        limit_req zone=upload burst=2 nodelay;
        limit_conn conn 1;
        proxy_pass http://backend;
    }
}
```

### DDoS Protection (Cloudflare Configuration)
```yaml
# Cloudflare security configuration
security:
  # DDoS protection
  ddos_protection:
    enabled: true
    sensitivity: high
    layers: [3, 4, 7]

  # WAF
  waf:
    enabled: true
    managed_rules:
      - cloudflare_managed
      - owasp_core
    custom_rules:
      - name: block_sqlmap
        expression: '(http.user_agent contains "sqlmap")'
        action: block

      - name: rate_limit_api
        expression: '(http.request.uri.path contains "/api/")'
        action: challenge
        rate_limit:
          count: 100
          period: 60

  # Bot management
  bot_management:
    enabled: true
    fight_mode: true  # aggressive bot blocking
    verified_bots: allow  # allow Google, Bing, etc.

  # Rate limiting
  rate_limiting:
    rules:
      - name: login_brute_force
        url: "*/login"
        requests_per_period: 5
        period: 60
        action: challenge

      - name: api_abuse
        url: "*/api/*"
        requests_per_period: 100
        period: 60
        action: block

  # Geo blocking
  geo_blocking:
    blocked_countries: []  # add if needed
    allowed_countries: []  # leave empty for all

  # Browser integrity check
  browser_integrity_check: true

  # Challenge passage
  challenge_passage: 30  # minutes before re-challenge
```

### Custom WAF (Python — Lightweight)
```python
#!/usr/bin/env python3
"""
Lightweight WAF — detect common attack patterns.
Defensive: block malicious requests before they reach the application.
"""
import re
from flask import Flask, request, abort
import time
from collections import defaultdict

app = Flask(__name__)

class LightweightWAF:
    ATTACK_PATTERNS = {
        'sqli': re.compile(
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|"
            r"drop\s+table|update\s+.*\s+set|'\s*or\s*'|1\s*=\s*1|--\s*$|"
            r"/\*.*\*/|;\s*(?:drop|delete|insert)|0x[0-9a-f]{8,}|@@version|"
            r"benchmark\s*\(|sleep\s*\(|load_file\s*\(|into\s+outfile)",
            re.IGNORECASE
        ),
        'xss': re.compile(
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|onfocus\s*=|"
            r"<iframe|<svg|<img[^>]+src[^>]*>|<object|<embed|<base|"
            r"data:text/html|alert\s*\(|confirm\s*\(|prompt\s*\()",
            re.IGNORECASE
        ),
        'path_traversal': re.compile(
            r"(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e|....//|\.\.\\)",
            re.IGNORECASE
        ),
        'command_injection': re.compile(
            r"(;|\||&&|`|\$\(|%0a|%0d)\s*(\w+)",
            re.IGNORECASE
        ),
        'scanner': re.compile(
            r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|w3af|burp)",
            re.IGNORECASE
        ),
    }

    def __init__(self):
        self.rate_limits = defaultdict(list)
        self.blocked_ips = set()

    def check_request(self, request):
        """Check request for attack patterns."""
        ip = request.remote_addr

        # Check if IP is blocked
        if ip in self.blocked_ips:
            return {'blocked': True, 'reason': 'IP blocked', 'status': 403}

        # Check User-Agent for scanners
        user_agent = request.headers.get('User-Agent', '')
        if self.ATTACK_PATTERNS['scanner'].search(user_agent):
            return {'blocked': True, 'reason': 'Scanner detected', 'status': 403}

        # Check all parameters for attack patterns
        all_params = {}
        all_params.update(request.args.to_dict())
        all_params.update(request.form.to_dict())
        all_params.update(request.json if request.is_json else {})

        for param_name, param_value in all_params.items():
            if not isinstance(param_value, str):
                continue

            # SQLi
            if self.ATTACK_PATTERNS['sqli'].search(param_value):
                self.log_attack(ip, 'sqli', param_name, param_value)
                return {'blocked': True, 'reason': 'SQL injection detected', 'status': 403}

            # XSS
            if self.ATTACK_PATTERNS['xss'].search(param_value):
                self.log_attack(ip, 'xss', param_name, param_value)
                return {'blocked': True, 'reason': 'XSS detected', 'status': 403}

            # Path traversal
            if self.ATTACK_PATTERNS['path_traversal'].search(param_value):
                self.log_attack(ip, 'path_traversal', param_name, param_value)
                return {'blocked': True, 'reason': 'Path traversal detected', 'status': 403}

            # Command injection
            if self.ATTACK_PATTERNS['command_injection'].search(param_value):
                self.log_attack(ip, 'command_injection', param_name, param_value)
                return {'blocked': True, 'reason': 'Command injection detected', 'status': 403}

        # Rate limiting
        if not self.check_rate_limit(ip, request.path):
            return {'blocked': True, 'reason': 'Rate limit exceeded', 'status': 429}

        return {'blocked': False}

    def check_rate_limit(self, ip, path, limit=100, window=60):
        """Rate limiting per IP and path."""
        now = time.time()
        key = f"{ip}:{path}"

        # Clean old entries
        self.rate_limits[key] = [t for t in self.rate_limits[key] if now - t < window]

        # Check limit
        if len(self.rate_limits[key]) >= limit:
            return False

        self.rate_limits[key].append(now)
        return True

    def log_attack(self, ip, attack_type, param, value):
        """Log attack attempt."""
        print(f"🚨 ATTACK: {attack_type} from {ip} on param {param}: {value[:50]}")
        # In production: send to SIEM

@app.before_request
def waf_filter():
    waf = LightweightWAF()
    result = waf.check_request(request)
    if result['blocked']:
        abort(result['status'], description=result['reason'])
```

---

## AUDIT CHECKLIST

- [ ] WAF deployed (ModSecurity, Cloudflare, AWS WAF, or custom)
- [ ] OWASP Core Rule Set enabled
- [ ] Custom rules for application-specific attacks
- [ ] Rate limiting on all endpoints
- [ ] Strict rate limiting on login/API endpoints
- [ ] Bot management (JS challenge, CAPTCHA)
- [ ] Geo blocking (if applicable)
- [ ] Scanner detection (User-Agent filtering)
- [ ] Virtual patching for known CVEs
- [ ] DDoS protection at edge (CDN)
- [ ] DDoS protection at network (scrubbing)
- [ ] Auto-scaling for traffic spikes
- [ ] WAF logging to SIEM
- [ ] WAF bypass testing (annual)
- [ ] Rate limit tuning (not too strict, not too loose)
- [ ] Positive security model (allowlist) where possible
