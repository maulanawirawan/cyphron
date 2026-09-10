# Skill 09 — Detection Engineering

> Cyphron's methodology for building detection rules — WAF rules, IDS/IPS signatures, SIEM queries, and alert logic. Cyphron knows exactly how attacks look at the network and log level, so it builds detections that catch real attacks while minimizing false positives.

---

## WHEN TO ACTIVATE

- User asks for a WAF rule, IDS signature, or SIEM query
- User asks to "detect this attack" or "write a detection rule"
- User asks to build alerting/monitoring for a specific threat
- User asks about Sigma rules, Suricata/Snort rules, or ModSecurity
- User asks to detect SQLi, XSS, SSRF, or other attack classes in traffic/logs
- User asks to build a detection engineering pipeline

---

## METHODOLOGY

### Step 1: Understand the Detection Goal
- **What attack** are we detecting? (specific technique or class)
- **Where** does the attack manifest? (HTTP traffic, logs, network, endpoint)
- **What's the data source?** (WAF logs, app logs, network captures, EDR telemetry)
- **What's the response?** (alert, block, rate limit, quarantine)

### Step 2: Attack Signature Analysis
For each attack class, identify the **observable indicators**:

| Attack Class | Network/HTTP Indicators | Log Indicators |
|---|---|---|
| SQL Injection | SQL keywords in parameters, `' OR`, `UNION SELECT`, comments (`--`, `#`, `/**/`), hex encoding | DB error messages, slow queries, unexpected query results |
| XSS | `<script>`, `onerror=`, `onload=`, `javascript:`, encoded `<` (`%3C`), event handlers | Reflected parameters in HTML, CSP violations |
| SSRF | Internal IPs in URL params, `localhost`, `169.254.169.254`, `file://`, `gopher://` | Outbound requests to internal IPs, metadata endpoint access |
| Path Traversal | `../`, `..\\`, `%2e%2e%2f`, `....//`, null bytes | File access errors, access to unexpected paths |
| Command Injection | `;`, `|`, `&&`, backticks, `$()`, `%0a`, `%0d` in parameters | Process creation logs, unexpected child processes |
| XXE | `<!DOCTYPE`, `ENTITY`, `SYSTEM`, `file://`, `http://` in XML | XML parser errors, outbound DNS/HTTP from parser |
| Brute Force | Many failed logins from same IP, distributed IPs same account | Repeated 401/403 responses, login failure spikes |
| Credential Stuffing | Many login attempts, different accounts, same IP/bot signature | Login success after many failures, new geo for user |
| SSRF to metadata | Requests to `169.254.169.254` | Cloud metadata API access from app |

### Step 3: Rule Construction
Build the detection rule in the appropriate format, balancing:
- **Sensitivity** — catch real attacks (minimize false negatives)
- **Precision** — don't alert on benign traffic (minimize false positives)
- **Performance** — efficient evaluation (regex complexity matters)

### Step 4: Tuning & Validation
- Test against known attack traffic (true positives)
- Test against benign traffic (false positive rate)
- Document exclusions/allowlists for known-good patterns

---

## OUTPUT FORMAT

```markdown
## 🎯 Detection Rule: [Attack Class]

### Detection Goal
[What this rule detects and why]

### Data Source
[Where the data comes from — HTTP logs, app logs, network, etc.]

### Rule
```[format]
[detection rule]
```

### Indicators Detected
| Indicator | Pattern | Confidence |
|---|---|---|
| [indicator] | [pattern] | [level] |

### False Positive Considerations
- [Known benign patterns that might trigger]
- [Recommended exclusions]

### Tuning Guide
[How to adjust sensitivity/precision for your environment]

### Test Cases
```[format]
[attack traffic that triggers the rule]
[benign traffic that does NOT trigger]
```
```

---

## RULE FORMATS

### ModSecurity (WAF) — SQL Injection Detection
```apache
# ModSecurity rule for SQL injection detection
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS|XML:/* \
    "@rx (?i)(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'|--\s*$|/\*.*\*/|;\s*(?:drop|delete|update|insert)|0x[0-9a-f]+|@@version|benchmark\s*\(|sleep\s*\(|load_file\s*\(|into\s+outfile)" \
    "id:1001,\
    phase:2,\
    deny,\
    log,\
    msg:'SQL Injection Attempt Detected',\
    tag:'attack-sqli',\
    tag:'OWASP_TOP10/A03',\
    severity:CRITICAL,\
    logdata:'Matched data: %{MATCHED_VAR}'"
```

### ModSecurity — XSS Detection
```apache
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS|XML:/* \
    "@rx (?i)(?:<script[^>]*>|javascript:|on(?:error|load|click|mouseover|focus|blur|submit|change)\s*=|<iframe[^>]*>|<img[^>]+src[^>]*>|<svg[^>]*>|data:text/html|<object[^>]*>|<embed[^>]*>|<base[^>]*>)" \
    "id:1002,\
    phase:2,\
    deny,\
    log,\
    msg:'XSS Attempt Detected',\
    tag:'attack-xss',\
    tag:'OWASP_TOP10/A03',\
    severity:CRITICAL,\
    logdata:'Matched data: %{MATCHED_VAR}'"
```

### Sigma Rule — Brute Force Detection
```yaml
title: Authentication Brute Force Attempt
id: 0e0343d1-2b5a-4a0c-9d1e-1f2a3b4c5d6e
status: stable
description: >
  Detects multiple failed authentication attempts from a single source
  within a short time window, indicating brute force attack.
logsource:
  product: linux
  service: auth
detection:
  selection:
    message:
      - Failed password
      - authentication failure
  timeframe: 5m
  condition: selection | count() by src_ip > 10
fields:
  - src_ip
  - user
  - message
falsepositives:
  - Misconfigured application with wrong credentials
  - Load balancer health checks (exclude known LB IPs)
level: medium
tags:
  - attack.credential_access
  - attack.t1110
  - attack.brute_force
```

### Sigma Rule — SQL Injection in Web Logs
```yaml
title: SQL Injection Pattern in HTTP Requests
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: stable
description: >
  Detects SQL injection patterns in HTTP request parameters
  from web server access logs.
logsource:
  category: webserver
detection:
  sqli_patterns:
    cs-uri-query|contains:
      - "UNION SELECT"
      - "' OR '1'='1"
      - "' OR 1=1"
      - "--"
      - "/*"
      - "; DROP"
      - "; DELETE"
      - "xp_cmdshell"
      - "0x[0-9a-fA-F]{8,}"
      - "@@version"
  filter_benign:
    cs-uri-query|contains:
      - "session_id="  # exclude session IDs that might contain hex
  condition: sqli_patterns and not filter_benign
fields:
  - src_ip
  - cs-uri-query
  - cs-method
  - cs-user-agent
falsepositives:
  - Legitimate database admin tools
  - Applications with SQL-like syntax in parameters
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.sqli
```

### Suricata/Snort — Network-Level SSRF Detection
```
# Detect SSRF attempts to cloud metadata endpoints
alert http any any -> any any (msg:"SSRF Attempt - Cloud Metadata Endpoint Access"; \
  flow:to_server,established; \
  http.uri; content:"169.254.169.254"; \
  classtype:attempted-recon; \
  sid:2001001; rev:1; \
  metadata:attack_target_Server, tag SSRF;)

# Detect SSRF to internal network from external-facing service
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Potential SSRF - External Request to Internal Service"; \
  flow:to_server,established; \
  http.uri; pcre:"/(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/i"; \
  classtype:attempted-recon; \
  sid:2001002; rev:1;)
```

### Splunk SPL — Detecting Path Traversal
```splunk
index=web sourcetype=access_combined
| where match(uri, "(?i)(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c|....//)")
| stats count by src_ip, uri, status
| where count > 3
| eval severity=if(status=200, "CRITICAL", "HIGH")
| table _time, src_ip, uri, status, severity
```

### Splunk SPL — Detecting Credential Stuffing
```splunk
index=auth action=login
| bin _time span=5m
| stats count as attempts, dc(user) as unique_users, values(user) as users by src_ip, _time
| where attempts > 20 and unique_users > 5
| eval risk_score = attempts * unique_users
| table _time, src_ip, attempts, unique_users, risk_score, users
| sort - risk_score
```

### Elasticsearch/Kibana — Detecting Command Injection
```json
{
  "query": {
    "bool": {
      "should": [
        { "regexp": { "request.params": { "value": "(?i).*(;|\\||&&|`|\\$\\().*", "flags": "ALL" } } },
        { "wildcard": { "request.params": "*%0a*" } },
        { "wildcard": { "request.params": "*%0d*" } }
      ],
      "minimum_should_match": 1,
      "filter": [
        { "range": { "response.status": { "gte": 400 } } }
      ]
    }
  }
}
```

---

## DETECTION ENGINEERING PIPELINE

```
Threat Intelligence → Detection Hypothesis → Rule Development
        ↑                                          ↓
   Feedback ← Alert Triage ← Deployment ← Testing/Validation
```

### Pipeline Steps:
1. **Identify threat** — what attack technique to detect
2. **Hypothesize indicator** — what would this look like in our data?
3. **Develop rule** — write detection in appropriate format
4. **Test** — validate against attack samples + benign traffic
5. **Deploy** — roll out to detection platform
6. **Tune** — adjust based on false positive/negative feedback
7. **Document** — record what it detects, FP rate, tuning guide

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — attack indicators per class
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — what to do when detection fires
