# Skill 13 — Forensics & Analysis

> Cyphron's methodology for building forensic analysis tools, log parsers, and timeline reconstruction scripts. Cyphron knows how attackers leave traces — and how to find them. This skill builds analysis tools; it doesn't perform attacks.

---

## WHEN TO ACTIVATE

- User asks to analyze logs for security events
- User asks to build a forensic timeline
- User asks "what happened" during an incident
- User asks to build a log parser or analyzer
- User asks to investigate suspicious activity
- User asks to build SIEM queries or detection logic from logs
- User asks about memory/disk forensics tooling

---

## METHODOLOGY

### Step 1: Identify the Data Source
- **Web server logs** (Apache, Nginx, IIS) — HTTP requests, status codes, user agents
- **Application logs** — auth events, business logic, errors
- **OS logs** (syslog, Event Log, journald) — process, service, login events
- **Cloud logs** (CloudTrail, Azure Activity, GCP Audit) — API calls, config changes
- **Network logs** (firewall, IDS/IPS, proxy) — connections, blocked traffic
- **Endpoint logs** (EDR, Sysmon) — process creation, file access, registry
- **Database logs** — queries, access, changes

### Step 2: Define the Investigation Question
- What are we looking for? (attack, anomaly, specific event)
- What's the time window?
- What's the scope? (single host, entire network, specific user)

### Step 3: Build Analysis Pipeline
```
Collect → Normalize → Enrich → Correlate → Analyze → Report
```

### Step 4: Timeline Reconstruction
Build a chronological timeline of events with:
- Timestamp (UTC, normalized)
- Source (host, service)
- Event type
- Actor (user, process, IP)
- Details
- Confidence (confirmed, inferred, suspicious)

---

## OUTPUT FORMAT

```markdown
## 🔍 Forensic Analysis: [Investigation]

### Investigation Question
[What we're trying to determine]

### Data Sources
| Source | Type | Time Range |
|---|---|---|
| [source] | [type] | [range] |

### Analysis Script
```lang
[complete analysis script — parser, correlator, reporter]
```

### Findings
#### Finding 1: [Event] — [Time]
**Evidence:** [log lines / data]
**Interpretation:** [what this means]
**Confidence:** [level]

### Timeline
| Time (UTC) | Event | Source | Actor | Details |
|---|---|---|---|---|
| [time] | [event] | [source] | [actor] | [details] |

### Indicators of Compromise (IOCs)
| Type | Value | Context |
|---|---|---|
| [type] | [value] | [where found] |

### Recommendations
- [Containment actions]
- [Further investigation steps]
- [Detection improvements]
```

---

## ANALYSIS SCRIPT TEMPLATES

### Web Log Analyzer — Detect Attack Patterns
```python
#!/usr/bin/env python3
"""Web log analyzer — detects attack patterns in access logs."""
import re
from collections import Counter, defaultdict
from datetime import datetime
import sys

# Attack signatures
SIGNATURES = {
    'sqli': re.compile(
        r"(?i)(union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|"
        r"'\s*or\s*'|--\s*$|/\*.*\*/|;\s*(?:drop|delete|insert)|"
        r"0x[0-9a-f]{8,}|@@version|benchmark\s*\(|sleep\s*\()",
        re.IGNORECASE
    ),
    'xss': re.compile(
        r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<iframe|"
        r"<svg|<img[^>]+src[^>]*onerror|alert\s*\()",
        re.IGNORECASE
    ),
    'path_traversal': re.compile(
        r"(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e|....//)",
        re.IGNORECASE
    ),
    'command_injection': re.compile(
        r"(;|\||&&|`|\$\(|%0a|%0d)\s*(\w+)",
        re.IGNORECASE
    ),
    'ssrf': re.compile(
        r"(169\.254\.169\.254|localhost|127\.0\.0\.1|file://|gopher://)",
        re.IGNORECASE
    ),
}

# Log format: IP - - [timestamp] "METHOD URI PROTOCOL" status size "referer" "user-agent"
LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
)

def parse_log(line):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    return {
        'ip': match.group(1),
        'timestamp': match.group(2),
        'method': match.group(3),
        'uri': match.group(4),
        'protocol': match.group(5),
        'status': int(match.group(6)),
        'size': match.group(7),
        'referer': match.group(8),
        'user_agent': match.group(9),
    }

def analyze_log(log_file):
    attacks = defaultdict(list)
    ip_activity = Counter()
    status_codes = Counter()

    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            entry = parse_log(line)
            if not entry:
                continue

            ip_activity[entry['ip']] += 1
            status_codes[entry['status']] += 1

            # Check for attack patterns in URI
            for attack_type, pattern in SIGNATURES.items():
                if pattern.search(entry['uri']):
                    attacks[attack_type].append({
                        'timestamp': entry['timestamp'],
                        'ip': entry['ip'],
                        'uri': entry['uri'],
                        'status': entry['status'],
                        'user_agent': entry['user_agent'],
                    })

    # Report
    print("=" * 70)
    print("WEB LOG SECURITY ANALYSIS REPORT")
    print("=" * 70)

    print(f"\n📊 Summary:")
    print(f"  Total requests analyzed: {sum(ip_activity.values())}")
    print(f"  Unique IPs: {len(ip_activity)}")
    print(f"  Status codes: {dict(status_codes.most_common())}")

    print(f"\n🚨 Attack Patterns Detected:")
    for attack_type, events in attacks.items():
        print(f"\n  {attack_type.upper()}: {len(events)} events")
        unique_ips = set(e['ip'] for e in events)
        print(f"    Unique source IPs: {len(unique_ips)}")
        print(f"    Top IPs: {Counter(e['ip'] for e in events).most_common(5)}")
        print(f"    Sample events:")
        for event in events[:5]:
            print(f"      [{event['timestamp']}] {event['ip']} "
                  f"→ {event['uri'][:80]} (HTTP {event['status']})")

    print(f"\n🔝 Top 10 Most Active IPs:")
    for ip, count in ip_activity.most_common(10):
        print(f"  {ip}: {count} requests")

    # Suspicious: high volume + attack patterns
    attacker_ips = set()
    for events in attacks.values():
        for e in events:
            attacker_ips.add(e['ip'])

    print(f"\n⚠️  Suspicious IPs (attack patterns detected):")
    for ip in attacker_ips:
        attack_count = sum(
            1 for events in attacks.values()
            for e in events if e['ip'] == ip
        )
        total = ip_activity[ip]
        print(f"  {ip}: {total} total requests, {attack_count} attack patterns")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python analyze_logs.py <access.log>")
        sys.exit(1)
    analyze_log(sys.argv[1])
```

### Authentication Log Analyzer — Detect Brute Force
```python
#!/usr/bin/env python3
"""Auth log analyzer — detects brute force and credential stuffing."""
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# Common auth log patterns
FAILED_LOGIN = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\s+\S+:\s+'
    r'Failed password for (?:invalid user )?(\S+) from (\S+)'
)
SUCCESS_LOGIN = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\s+\S+:\s+'
    r'Accepted password for (\S+) from (\S+)'
)

def analyze_auth_log(log_file, threshold=10, window_minutes=5):
    events = []
    failed_by_ip = defaultdict(list)
    failed_by_user = defaultdict(list)
    successful_logins = []

    with open(log_file, 'r') as f:
        for line in f:
            if match := FAILED_LOGIN.search(line):
                timestamp_str, host, user, ip = match.groups()
                events.append({
                    'time': timestamp_str,
                    'type': 'failed',
                    'user': user,
                    'ip': ip,
                })
                failed_by_ip[ip].append(timestamp_str)
                failed_by_user[user].append(timestamp_str)

            elif match := SUCCESS_LOGIN.search(line):
                timestamp_str, host, user, ip = match.groups()
                successful_logins.append({
                    'time': timestamp_str,
                    'user': user,
                    'ip': ip,
                })

    print("=" * 60)
    print("AUTHENTICATION LOG ANALYSIS")
    print("=" * 60)

    # Brute force detection (many failures from same IP)
    print("\n🚨 Potential Brute Force (by IP):")
    for ip, times in failed_by_ip.items():
        if len(times) >= threshold:
            print(f"  {ip}: {len(times)} failed attempts")
            print(f"    First: {times[0]}")
            print(f"    Last: {times[-1]}")

    # Credential stuffing (many users from same IP)
    print("\n🚨 Potential Credential Stuffing:")
    ip_users = defaultdict(set)
    for event in events:
        if event['type'] == 'failed':
            ip_users[event['ip']].add(event['user'])
    for ip, users in ip_users.items():
        if len(users) >= 5:
            print(f"  {ip}: {len(users)} unique usernames attempted")

    # Successful login after failures (possible compromise)
    print("\n⚠️  Successful Login After Failures:")
    for success in successful_logins:
        prior_failures = [
            f for f in failed_by_ip.get(success['ip'], [])
            if f <= success['time']
        ]
        if len(prior_failures) >= 3:
            print(f"  {success['time']}: {success['user']} from {success['ip']}")
            print(f"    {len(prior_failures)} prior failures from this IP")

if __name__ == '__main__':
    import sys
    analyze_auth_log(sys.argv[1])
```

### Sysmon Process Analysis — Detect Suspicious Activity
```python
#!/usr/bin/env python3
"""Sysmon log analyzer — detects suspicious process activity."""
import xml.etree.ElementTree as ET
from collections import defaultdict

SUSPICIOUS_PARENTS = {
    'word.exe', 'excel.exe', 'powerpoint.exe', 'outlook.exe',
    'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe',
    'rundll32.exe', 'msiexec.exe', 'forfiles.exe', 'syncappvpublishingserver.exe',
}

SUSPICIOUS_COMMANDS = [
    'powershell -enc', 'powershell -e ', 'powershell -w hidden',
    'certutil -decode', 'certutil -urlcache',
    'bitsadmin /transfer', 'regsvr32 /s /u /i:',
    'mshta http', 'rundll32 javascript',
    'net user', 'net localgroup administrators',
    'whoami /all', 'systeminfo',
    'taskkill /f', 'vssadmin delete shadows',
    'wbadmin delete catalog', 'bcdedit /set',
]

def analyze_sysmon(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    suspicious = []

    for event in root.findall('.//Event'):
        event_id = event.find('.//EventID')
        if event_id is None:
            continue
        eid = event_id.text

        # Process Create (Event ID 1)
        if eid == '1':
            data = {d.get('Name'): d.text for d in event.findall('.//Data')}
            parent = (data.get('ParentImage') or '').lower()
            command = data.get('CommandLine') or ''
            image = (data.get('Image') or '').lower()

            # Office app spawning child process
            parent_name = parent.split('\\')[-1] if parent else ''
            if parent_name in SUSPICIOUS_PARENTS:
                suspicious.append({
                    'type': 'suspicious_parent',
                    'parent': parent_name,
                    'child': image,
                    'command': command,
                })

            # Suspicious command line
            for pattern in SUSPICIOUS_COMMANDS:
                if pattern in command.lower():
                    suspicious.append({
                        'type': 'suspicious_command',
                        'pattern': pattern,
                        'command': command,
                        'image': image,
                    })

    print("=" * 60)
    print("SYSMON PROCESS ANALYSIS")
    print("=" * 60)
    print(f"\nSuspicious events found: {len(suspicious)}")
    for event in suspicious:
        print(f"\n  Type: {event['type']}")
        if event['type'] == 'suspicious_parent':
            print(f"  Parent: {event['parent']}")
            print(f"  Child: {event['child']}")
        else:
            print(f"  Pattern: {event['pattern']}")
            print(f"  Command: {event['command'][:100]}")

if __name__ == '__main__':
    import sys
    analyze_sysmon(sys.argv[1])
```

---

## TIMELINE RECONSTRUCTION TEMPLATE

```python
#!/usr/bin/env python3
"""Build a forensic timeline from multiple log sources."""
from datetime import datetime
import json

def build_timeline(events):
    """Events: list of {timestamp, source, event, actor, details, confidence}"""
    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e['timestamp'])

    print("=" * 80)
    print("FORENSIC TIMELINE")
    print("=" * 80)
    for e in sorted_events:
        confidence_marker = {
            'confirmed': '✓',
            'inferred': '~',
            'suspicious': '?!',
        }.get(e.get('confidence', 'confirmed'), '?')
        print(f"\n[{e['timestamp']}] {confidence_marker} {e['event']}")
        print(f"  Source: {e['source']}")
        print(f"  Actor: {e['actor']}")
        print(f"  Details: {e['details']}")

# Example usage:
events = [
    {
        'timestamp': '2024-01-15T10:23:01Z',
        'source': 'auth.log',
        'event': 'Failed login attempt',
        'actor': 'unknown from 203.0.113.50',
        'details': 'User: admin, Method: password',
        'confidence': 'confirmed',
    },
    # ... more events
]
build_timeline(events)
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — attacker behavior patterns to look for
- [`knowledge/remediation-playbook.md`](../knowledge/remediation-playbook.md) — what to do with findings
