# Skill 44 — Threat Intelligence Integration

> Cyphron's methodology for integrating threat intelligence into security operations. Cyphron knows how threat intelligence is used — IOC matching, TTP analysis, threat actor tracking — and builds intelligence-driven defense systems.

---

## WHEN TO ACTIVATE

- User asks about threat intelligence or threat feeds
- User asks to build a threat intelligence program
- User asks about MITRE ATT&CK framework
- User asks about IOC management or threat hunting
- User asks to integrate threat feeds with SIEM/EDR

---

## METHODOLOGY

### Threat Intelligence Pyramid (David Bianco)
```
                    /\
                   /  \        Threat Hunting
                  / TTPs\       (most valuable, hardest)
                 /--------\
                /  Tools   \    Detect attacker toolsets
               /------------\
              /   Infrastructure\  Detect IPs, domains, URLs
             /------------------\
            /       Indicators    \  Hashes (least valuable)
           /------------------------\
```

### Intelligence Lifecycle
```
Requirements → Collection → Processing → Analysis → Dissemination → Feedback
```

### Step 1: Define Intelligence Requirements (PIRs)
### Step 2: Collect from Multiple Sources
### Step 3: Process & Enrich
### Step 4: Analyze & Produce Intelligence
### Step 5: Disseminate to Defenders
### Step 6: Collect Feedback

---

## SECURE PATTERNS

### IOC Management System
```python
#!/usr/bin/env python3
"""
Threat intelligence platform — manage IOCs and match against telemetry.
Defensive: use intelligence to detect and prevent attacks.
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict

class IOCManager:
    def __init__(self, db):
        self.db = db

    def add_ioc(self, ioc_type, value, source, confidence='medium',
                tags=None, expiry_days=90):
        """Add an Indicator of Compromise."""
        ioc = {
            'type': ioc_type,  # ip, domain, url, hash, email, mutex
            'value': value,
            'source': source,  # 'misp', 'virustotal', 'manual', 'feed'
            'confidence': confidence,  # low, medium, high
            'tags': tags or [],
            'first_seen': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=expiry_days)).isoformat(),
            'active': True,
        }
        self.db.insert('iocs', ioc)
        return ioc

    def match_telemetry(self, events):
        """Match events against IOC database."""
        matches = []
        for event in events:
            # Check IP addresses
            if 'src_ip' in event:
                ioc = self.db.query(
                    'SELECT * FROM iocs WHERE type = "ip" AND value = ? AND active = 1',
                    [event['src_ip']]
                )
                if ioc:
                    matches.append({
                        'event': event,
                        'ioc': ioc,
                        'match_type': 'src_ip',
                    })

            # Check domains
            if 'domain' in event:
                ioc = self.db.query(
                    'SELECT * FROM iocs WHERE type = "domain" AND value = ? AND active = 1',
                    [event['domain']]
                )
                if ioc:
                    matches.append({
                        'event': event,
                        'ioc': ioc,
                        'match_type': 'domain',
                    })

            # Check file hashes
            if 'file_hash' in event:
                ioc = self.db.query(
                    'SELECT * FROM iocs WHERE type = "hash" AND value = ? AND active = 1',
                    [event['file_hash']]
                )
                if ioc:
                    matches.append({
                        'event': event,
                        'ioc': ioc,
                        'match_type': 'file_hash',
                    })

        return matches

    def cleanup_expired(self):
        """Remove expired IOCs."""
        self.db.execute(
            'UPDATE iocs SET active = 0 WHERE expires_at < datetime("now")'
        )
```

### MITRE ATT&CK Mapping
```python
class AttackMapper:
    """Map detections and incidents to MITRE ATT&CK techniques."""

    TECHNIQUE_MAP = {
        # Initial Access
        'phishing_email': {'tactic': 'Initial Access', 'technique': 'T1566', 'name': 'Phishing'},
        'exploit_public_app': {'tactic': 'Initial Access', 'technique': 'T1190', 'name': 'Exploit Public-Facing Application'},
        'valid_accounts': {'tactic': 'Initial Access', 'technique': 'T1078', 'name': 'Valid Accounts'},

        # Execution
        'powershell_exec': {'tactic': 'Execution', 'technique': 'T1059.001', 'name': 'PowerShell'},
        'cmd_exec': {'tactic': 'Execution', 'technique': 'T1059.003', 'name': 'Command and Scripting Interpreter'},
        'scheduled_task': {'tactic': 'Execution', 'technique': 'T1053', 'name': 'Scheduled Task/Job'},

        # Persistence
        'registry_run_key': {'tactic': 'Persistence', 'technique': 'T1547.001', 'name': 'Registry Run Keys'},
        'startup_folder': {'tactic': 'Persistence', 'technique': 'T1547.001', 'name': 'Startup Folder'},
        'service_creation': {'tactic': 'Persistence', 'technique': 'T1543.003', 'name': 'Windows Service'},
        'wmi_subscription': {'tactic': 'Persistence', 'technique': 'T1546.003', 'name': 'WMI Event Subscription'},

        # Credential Access
        'credential_dumping': {'tactic': 'Credential Access', 'technique': 'T1003', 'name': 'OS Credential Dumping'},
        'kerberoasting': {'tactic': 'Credential Access', 'technique': 'T1558.003', 'name': 'Kerberoasting'},
        'keylogging': {'tactic': 'Credential Access', 'technique': 'T1056', 'name': 'Input Capture'},

        # Lateral Movement
        'smb_admin_share': {'tactic': 'Lateral Movement', 'technique': 'T1021.002', 'name': 'SMB/Windows Admin Shares'},
        'rdp': {'tactic': 'Lateral Movement', 'technique': 'T1021.001', 'name': 'Remote Desktop Protocol'},
        'psexec': {'tactic': 'Lateral Movement', 'technique': 'T1569.002', 'name': 'PSExec'},

        # Exfiltration
        'dns_tunneling': {'tactic': 'Exfiltration', 'technique': 'T1048.003', 'name': 'DNS Exfiltration'},
        'https_c2': {'tactic': 'Exfiltration', 'technique': 'T1041', 'name': 'Exfiltration Over C2 Channel'},

        # Impact
        'data_encrypted': {'tactic': 'Impact', 'technique': 'T1486', 'name': 'Data Encrypted for Impact'},
        'shadow_copy_delete': {'tactic': 'Impact', 'technique': 'T1490', 'name': 'Inhibit System Recovery'},
    }

    def map_detection(self, detection_name):
        """Map a detection rule to ATT&CK technique."""
        return self.TECHNIQUE_MAP.get(detection_name, {
            'tactic': 'Unknown',
            'technique': 'Unknown',
            'name': 'Unmapped',
        })

    def coverage_report(self, detections):
        """Generate ATT&CK coverage report."""
        tactics_covered = {}
        for det in detections:
            mapping = self.map_detection(det)
            tactic = mapping['tactic']
            if tactic not in tactics_covered:
                tactics_covered[tactic] = []
            tactics_covered[tactic].append({
                'detection': det,
                'technique': mapping['technique'],
                'name': mapping['name'],
            })

        print("MITRE ATT&CK Coverage Report")
        print("=" * 60)
        for tactic, techniques in sorted(tactics_covered.items()):
            print(f"\n{tactic}:")
            for t in techniques:
                print(f"  {t['technique']} - {t['name']} ({t['detection']})")
```

### Threat Feed Integration
```python
class ThreatFeedIntegrator:
    """Integrate multiple threat intelligence feeds."""

    def __init__(self, ioc_manager):
        self.ioc = ioc_manager
        self.feeds = {
            'misp': self._fetch_misp,
            'abuseipdb': self._fetch_abuseipdb,
            'virustotal': self._fetch_virustotal,
            'alienvault_otx': self._fetch_otx,
        }

    async def sync_feeds(self):
        """Sync all threat intelligence feeds."""
        for feed_name, fetcher in self.feeds.items():
            try:
                indicators = await fetcher()
                for ind in indicators:
                    self.ioc.add_ioc(
                        ioc_type=ind['type'],
                        value=ind['value'],
                        source=feed_name,
                        confidence=ind.get('confidence', 'medium'),
                        tags=ind.get('tags', []),
                    )
                print(f"Synced {len(indicators)} IOCs from {feed_name}")
            except Exception as e:
                print(f"Error syncing {feed_name}: {e}")

    async def _fetch_misp(self):
        """Fetch from MISP instance."""
        # In production: use pymisp library
        return [
            {'type': 'ip', 'value': '203.0.113.50', 'confidence': 'high',
             'tags': ['apt29', 'c2']},
            {'type': 'domain', 'value': 'evil-c2.example.com', 'confidence': 'high',
             'tags': ['c2', 'malware']},
        ]

    async def _fetch_abuseipdb(self):
        """Fetch from AbuseIPDB."""
        # In production: use API
        return [
            {'type': 'ip', 'value': '198.51.100.23', 'confidence': 'medium',
             'tags': ['scanner', 'brute_force']},
        ]
```

### Threat Hunting Query (Splunk SPL)
```splunk
// Hunt for lateral movement via SMB
index=windows EventID=5140 OR EventID=5145
| stats count by src_ip, dest_host, ShareName, AccessMask
| where count > 10
| eval risk = if(match(ShareName, "(?i)C\$|ADMIN\$"), "HIGH", "MEDIUM")
| table _time, src_ip, dest_host, ShareName, AccessMask, count, risk

// Hunt for credential dumping
index=windows EventID=4663
| where process_name IN ("lsass.exe", "procdump.exe", "mimikatz.exe")
| OR (process_name="rundll32.exe" AND CommandLine="*comsvcs*MiniDump*")
| stats count by host, process_name, user, _time
| where count > 0

// Hunt for DNS exfiltration
index=dns
| eval query_length = len(query)
| where query_length > 50
| stats count, max(query_length) as max_len by src_ip
| where count > 20
| eval risk = if(max_len > 100, "HIGH", "MEDIUM")
```

---

## AUDIT CHECKLIST

- [ ] Threat intelligence requirements defined (PIRs)
- [ ] Multiple threat feeds integrated (MISP, OTX, AbuseIPDB, etc.)
- [ ] IOC database maintained (auto-expiry, deduplication)
- [ ] IOC matching integrated with SIEM and EDR
- [ ] MITRE ATT&CK mapping for all detections
- [ ] ATT&CK coverage gaps identified and addressed
- [ ] Threat hunting program (proactive, not just reactive)
- [ ] Threat actor tracking for relevant adversaries
- [ ] Intelligence shared with stakeholders (weekly brief)
- [ ] Feedback loop (which IOCs were useful?)
- [ ] False positive management (retire bad IOCs)
- [ ] Intelligence quality scoring
