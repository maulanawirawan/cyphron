# Skill 45 — Security Monitoring & SIEM Engineering

> Cyphron's methodology for building security monitoring and SIEM (Security Information and Event Management) systems. Cyphron knows what attacker behavior looks like in logs and builds detection rules, correlation logic, and alerting pipelines.

---

## WHEN TO ACTIVATE

- User asks to build a SIEM or log monitoring system
- User asks about security monitoring or alerting
- User asks about log collection, correlation, or analysis
- User asks about Splunk, ELK, or SIEM queries
- User asks about security operations center (SOC)

---

## METHODOLOGY

### Step 1: Define Monitoring Scope
- What systems to monitor (network, endpoints, apps, cloud)
- What events to collect (auth, access, changes, errors)
- What to alert on (detections, anomalies, thresholds)

### Step 2: Log Collection Architecture
```
Sources → Collectors → Normalization → Storage → Detection → Alerting → Response
  │           │            │             │          │           │          │
  ↓           ↓            ↓             ↓          ↓           ↓          ↓
Endpoints  Filebeat    Common       Elastic/   Sigma/     PagerDuty   SOAR
Network    Winlogbeat  Event        Splunk     Correlation Slack      Ticket
Apps       Syslog      Format       SIEM       Rules       Email      Auto
Cloud      API         (CEF/JSON)              Anomaly
```

### Step 3: Detection Strategy
| Type | Method | Example |
|---|---|---|
| Signature | Known pattern match | SQLi in URL |
| Anomaly | Deviation from baseline | Unusual login time |
| Correlation | Multi-event sequence | Failed logins → success → admin action |
| Behavioral | User/entity behavior | New geo + new device + data access |
| Threat intel | IOC match | Known malicious IP |

---

## SECURE PATTERNS

### Log Collection (Filebeat/Winlogbeat)
```yaml
# filebeat.yml — collect and forward security logs
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
      - /var/log/nginx/access.log
      - /var/log/nginx/error.log
    fields:
      log_type: system
    fields_under_root: true

  - type: filestream
    id: application-logs
    enabled: true
    paths:
      - /app/logs/security.log
    fields:
      log_type: application_security

output.logstash:
  hosts: ["logstash:5044"]
  tls:
    certificate_authorities: ["/etc/filebeat/ca.crt"]
    certificate: "/etc/filebeat/client.crt"
    key: "/etc/filebeat/client.key"
```

```yaml
# winlogbeat.yml — Windows event log collection
winlogbeat.event_logs:
  - name: Security
    ignore_older: 72h
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h
  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 72h
  - name: Windows PowerShell
    ignore_older: 72h
  - name: Application
    ignore_older: 72h
  - name: System
    ignore_older: 72h

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  tls.certificate_authorities: ["/etc/winlogbeat/ca.crt"]
```

### Correlation Rules (Sigma)
```yaml
# Detect brute force followed by successful login
title: Brute Force Followed by Successful Login
id: 5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d
status: stable
description: >
  Multiple failed login attempts followed by a successful login
  from the same source, indicating possible credential compromise.
logsource:
  product: linux
  service: auth
detection:
  failed:
    message: "Failed password"
  success:
    message: "Accepted password"
  timeframe: 10m
  condition: (failed | count(user) by src_ip > 5) and success
fields:
  - src_ip
  - user
  - message
level: high
tags:
  - attack.credential_access
  - attack.t1110
  - attack.brute_force
```

```yaml
# Detect lateral movement via PsExec
title: PsExec Lateral Movement
id: 6b7c8d9e-0f1a-2b3c-4d5e-6f7a8b9c0d1e
status: stable
description: >
  Detects PsExec or similar remote execution tools being used
  for lateral movement within the network.
logsource:
  product: windows
  service: security
detection:
  selection_service:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: Negotiate
  selection_process:
    EventID: 1
    Image|endswith:
      - \psexec.exe
      - \psexesvc.exe
  filter_admin:
    SubjectUserName|contains: admin
  condition: (selection_service or selection_process) and not filter_admin
level: medium
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1569
```

### Splunk SPL Detection Queries
```splunk
// ─── Detect impossible travel ───
index=auth action=login status=success
| streamstats time_window=1h count as recent_logins by user
| stats min(_time) as first_login max(_time) as last_login
        values(src_ip) as src_ips values(geo_country) as countries by user
| where mvcount(countries) > 1
| eval time_diff = last_login - first_login
| where time_diff < 3600  // less than 1 hour between different countries
| eval risk = "HIGH - Impossible travel detected"

// ─── Detect data exfiltration (large data transfer) ───
index=network dest_port=443
| stats sum(bytes_out) as total_bytes by src_ip dest_ip
| where total_bytes > 1000000000  // > 1GB
| eval risk = "HIGH - Potential data exfiltration"
| table _time src_ip dest_ip total_bytes risk

// ─── Detect privilege escalation ───
index=windows EventID=4720 OR EventID=4728 OR EventID=4732
| stats count by SubjectUserName TargetUserName Action
| where Action IN ("User Created", "Added to Admin Group")
| eval risk = "HIGH - Privilege escalation activity"
```

### Anomaly Detection (Python)
```python
#!/usr/bin/env python3
"""
Anomaly detection for security monitoring.
Detects deviations from normal behavior patterns.
"""
from collections import defaultdict
from datetime import datetime, timedelta
import statistics

class AnomalyDetector:
    def __init__(self):
        self.baselines = {}

    def build_baseline(self, events, metric, group_by):
        """Build behavioral baseline from historical data."""
        groups = defaultdict(list)
        for event in events:
            key = event.get(group_by)
            value = event.get(metric)
            if key and value is not None:
                groups[key].append(value)

        for key, values in groups.items():
            if len(values) > 10:  # need enough data
                self.baselines[key] = {
                    'mean': statistics.mean(values),
                    'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                    'min': min(values),
                    'max': max(values),
                    'count': len(values),
                }

    def detect_anomaly(self, event, metric, group_by, threshold=3):
        """Detect if current value is anomalous."""
        key = event.get(group_by)
        value = event.get(metric)

        if key not in self.baselines:
            return None  # no baseline

        baseline = self.baselines[key]
        if baseline['stdev'] == 0:
            return None  # can't detect with no variance

        z_score = (value - baseline['mean']) / baseline['stdev']

        if abs(z_score) > threshold:
            return {
                'metric': metric,
                'entity': key,
                'value': value,
                'baseline_mean': baseline['mean'],
                'z_score': z_score,
                'severity': 'high' if abs(z_score) > 5 else 'medium',
                'message': f'{metric} for {key} is {z_score:.1f}σ from baseline',
            }

        return None

    def detect_login_anomaly(self, login_event):
        """Detect anomalous login patterns."""
        anomalies = []

        # Unusual time (outside business hours)
        hour = login_event.get('timestamp').hour
        if hour < 6 or hour > 22:
            anomalies.append({
                'type': 'unusual_time',
                'severity': 'low',
                'message': f'Login at {hour}:00 (outside business hours)',
            })

        # New location
        user = login_event.get('user')
        location = login_event.get('location')
        if user in self.baselines and 'locations' in self.baselines[user]:
            if location not in self.baselines[user]['locations']:
                anomalies.append({
                    'type': 'new_location',
                    'severity': 'medium',
                    'message': f'Login from new location: {location}',
                })

        # New device
        device = login_event.get('device_id')
        if user in self.baselines and 'devices' in self.baselines[user]:
            if device not in self.baselines[user]['devices']:
                anomalies.append({
                    'type': 'new_device',
                    'severity': 'medium',
                    'message': f'Login from new device: {device}',
                })

        return anomalies
```

### Alert Triage & Prioritization
```python
class AlertTriage:
    """Prioritize and triage security alerts."""

    PRIORITY_WEIGHTS = {
        'severity': {'critical': 40, 'high': 30, 'medium': 20, 'low': 10},
        'asset_criticality': {'critical': 30, 'high': 20, 'medium': 10, 'low': 5},
        'confidence': {'high': 20, 'medium': 10, 'low': 5},
        'user_privilege': {'admin': 10, 'user': 5, 'service': 3},
    }

    def calculate_priority(self, alert):
        """Calculate alert priority score."""
        score = 0
        for factor, weights in self.PRIORITY_WEIGHTS.items():
            value = alert.get(factor, 'medium')
            score += weights.get(value, 5)
        return score

    def triage(self, alerts):
        """Triage and prioritize alerts."""
        for alert in alerts:
            alert['priority_score'] = self.calculate_priority(alert)
            alert['priority'] = self._priority_label(alert['priority_score'])

        return sorted(alerts, key=lambda a: a['priority_score'], reverse=True)

    def _priority_label(self, score):
        if score >= 80: return 'P1 - Immediate'
        if score >= 60: return 'P2 - High'
        if score >= 40: return 'P3 - Medium'
        return 'P4 - Low'
```

---

## AUDIT CHECKLIST

- [ ] Log collection from all critical systems
- [ ] Logs normalized to common format (CEF, JSON)
- [ ] Logs forwarded to centralized SIEM
- [ ] Logs encrypted in transit
- [ ] Log retention per compliance (1-7 years)
- [ ] Tamper-proof log storage (WORM, append-only)
- [ ] Detection rules for OWASP Top 10 attack patterns
- [ ] Detection rules for MITRE ATT&CK techniques
- [ ] Correlation rules (multi-event sequences)
- [ ] Anomaly detection (behavioral baselines)
- [ ] Threat intelligence integration (IOC matching)
- [ ] Alert triage and prioritization
- [ ] Alert routing to on-call (PagerDuty, Slack)
- [ ] SOAR integration for automated response
- [ ] Alert tuning (false positive reduction)
- [ ] Detection coverage gap analysis (ATT&CK)
- [ ] 24/7 monitoring (SOC or on-call rotation)
- [ ] Mean time to detect (MTTD) tracked
- [ ] Mean time to respond (MTTR) tracked
