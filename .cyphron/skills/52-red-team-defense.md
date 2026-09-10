# Skill 52 — Red Team Defense (Purple Teaming)

> Cyphron's methodology for defending against red team exercises and building purple team capabilities. Cyphron knows red team TTPs (Tactics, Techniques, Procedures) — initial access, persistence, lateral movement, exfiltration — and builds defenses that are tested against realistic adversary simulation.

---

## WHEN TO ACTIVATE

- User asks about red team defense or purple teaming
- User asks about adversary simulation or emulation
- User asks about MITRE ATT&CK-based defense
- User asks about red team exercise preparation
- User asks about detection engineering against red teams

---

## METHODOLOGY

### Red Team vs Blue Team vs Purple Team

| Team | Role | Goal |
|---|---|---|
| Red Team | Attack (simulate adversary) | Test defenses, find gaps |
| Blue Team | Defend (detect, respond) | Improve detection, response |
| Purple Team | Collaborate (share knowledge) | Improve both offense and defense |

### Red Team Attack Lifecycle (Lockheed Martin Cyber Kill Chain)
```
Recon → Weaponize → Deliver → Exploit → Install → C2 → Act on Objectives
   ↑         ↑          ↑         ↑          ↑        ↑         ↑
   └─────────┴──────────┴─────────┴──────────┴────────┴─────────┘
                        Blue Team Detection Points
```

### Purple Team Methodology
1. **Plan** — Define objectives, scope, rules of engagement
2. **Attack** — Red team executes realistic TTPs
3. **Detect** — Blue team attempts to detect and respond
4. **Review** — Both teams review what worked and what didn't
5. **Improve** — Update defenses based on findings
6. **Repeat** — Continuous improvement cycle

---

## SECURE PATTERNS

### Purple Team Exercise Plan
```markdown
## Purple Team Exercise Plan

### Exercise Overview
- **Objective**: Test detection and response capabilities against realistic adversary TTPs
- **Scope**: Production environment (non-destructive)
- **Duration**: 2 weeks
- **Rules**: No destructive actions, no data exfiltration (simulated only), no DoS

### MITRE ATT&CK TTPs to Simulate

#### Initial Access
- [ ] T1566.001 - Spearphishing Attachment
- [ ] T1566.002 - Spearphishing Link
- [ ] T1190 - Exploit Public-Facing Application
- [ ] T1078 - Valid Accounts (compromised credentials)

#### Execution
- [ ] T1059.001 - PowerShell
- [ ] T1059.003 - Command and Scripting Interpreter
- [ ] T1059.005 - Visual Basic
- [ ] T1204 - User Execution

#### Persistence
- [ ] T1547.001 - Registry Run Keys / Startup Folder
- [ ] T1543.003 - Windows Service
- [ ] T1053 - Scheduled Task/Job
- [ ] T1136 - Create Account

#### Privilege Escalation
- [ ] T1068 - Exploitation for Privilege Escalation
- [ ] T1078 - Valid Accounts
- [ ] T1548 - Abuse Elevation Control Mechanism

#### Defense Evasion
- [ ] T1027 - Obfuscated Files or Information
- [ ] T1070 - Indicator Removal on Host
- [ ] T1036 - Masquerading
- [ ] T1055 - Process Injection

#### Credential Access
- [ ] T1003 - OS Credential Dumping
- [ ] T1110 - Brute Force
- [ ] T1555 - Credentials from Password Stores

#### Discovery
- [ ] T1087 - Account Discovery
- [ ] T1083 - File and Directory Discovery
- [ ] T1046 - Network Service Discovery
- [ ] T1018 - Remote System Discovery

#### Lateral Movement
- [ ] T1021.001 - Remote Desktop Protocol
- [ ] T1021.002 - SMB/Windows Admin Shares
- [ ] T1021.004 - SSH
- [ ] T1569 - System Services

#### Collection
- [ ] T1005 - Data from Local System
- [ ] T1039 - Data from Network Shared Drive
- [ ] T1056 - Input Capture

#### Exfiltration
- [ ] T1041 - Exfiltration Over C2 Channel
- [ ] T1048 - Exfiltration Over Alternative Protocol
- [ ] T1567 - Exfiltration Over Web Service

#### Command & Control
- [ ] T1071 - Application Layer Protocol
- [ ] T1572 - Protocol Tunneling
- [ ] T1573 - Encrypted Channel
```

### Detection Validation (Purple Team)
```python
#!/usr/bin/env python3
"""
Purple team detection validation — verify that detections work against
red team TTPs.
"""
from datetime import datetime
from enum import Enum

class DetectionResult(Enum):
    DETECTED = 'detected'
    PARTIAL = 'partial'
    MISSED = 'missed'
    FALSE_POSITIVE = 'false_positive'

class PurpleTeamValidator:
    def __init__(self, siem_client, edr_client):
        self.siem = siem_client
        self.edr = edr_client
        self.results = []

    def validate_detection(self, technique_id, detection_rule, simulated_event):
        """Validate that a detection rule catches a simulated TTP."""
        # Inject simulated event into SIEM
        self.siem.inject_event(simulated_event)

        # Wait for detection
        detection = self.siem.wait_for_alert(detection_rule, timeout=60)

        # Check if detection fired
        if detection:
            result = DetectionResult.DETECTED
            details = {
                'alert_time': detection.get('timestamp'),
                'alert_severity': detection.get('severity'),
                'detection_latency': self._calculate_latency(simulated_event, detection),
            }
        else:
            result = DetectionResult.MISSED
            details = {'reason': 'No alert generated within timeout'}

        self.results.append({
            'technique': technique_id,
            'detection_rule': detection_rule,
            'result': result.value,
            'details': details,
            'timestamp': datetime.now().isoformat(),
        })

        return result

    def _calculate_latency(self, event, detection):
        """Calculate time from event to detection."""
        event_time = datetime.fromisoformat(event['timestamp'])
        detection_time = datetime.fromisoformat(detection['timestamp'])
        return (detection_time - event_time).total_seconds()

    def generate_coverage_report(self):
        """Generate ATT&CK coverage report."""
        total = len(self.results)
        detected = sum(1 for r in self.results if r['result'] == 'detected')
        partial = sum(1 for r in self.results if r['result'] == 'partial')
        missed = sum(1 for r in self.results if r['result'] == 'missed')

        coverage = (detected + partial) / total * 100 if total > 0 else 0

        print("=" * 60)
        print("PURPLE TEAM DETECTION COVERAGE REPORT")
        print("=" * 60)
        print(f"\nTotal TTPs tested: {total}")
        print(f"Detected: {detected} ({detected/total*100:.1f}%)")
        print(f"Partially detected: {partial} ({partial/total*100:.1f}%)")
        print(f"Missed: {missed} ({missed/total*100:.1f}%)")
        print(f"\nOverall coverage: {coverage:.1f}%")

        print(f"\n{'='*60}")
        print("DETAILED RESULTS")
        print(f"{'='*60}")
        for r in self.results:
            icon = '✅' if r['result'] == 'detected' else '⚠️' if r['result'] == 'partial' else '❌'
            print(f"\n{icon} {r['technique']}: {r['result']}")
            print(f"   Detection rule: {r['detection_rule']}")
            if 'detection_latency' in r.get('details', {}):
                print(f"   Latency: {r['details']['detection_latency']:.1f}s")
            if 'reason' in r.get('details', {}):
                print(f"   Reason: {r['details']['reason']}")
```

### Red Team Detection Rules (Sigma)
```yaml
# Detect red team initial access — spearphishing attachment
title: Red Team - Spearphishing Attachment Execution
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: stable
description: >
  Detects execution of spearphishing attachments by monitoring
  Office applications spawning suspicious child processes.
logsource:
  product: windows
  service: sysmon
detection:
  selection_parent:
    EventID: 1
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \powerpnt.exe
      - \outlook.exe
  selection_child:
    Image|endswith:
      - \powershell.exe
      - \cmd.exe
      - \wscript.exe
      - \cscript.exe
      - \mshta.exe
      - \rundll32.exe
      - \regsvr32.exe
  filter_legitimate:
    CommandLine|contains:
      - "Microsoft Office"
      - "Office365"
  condition: selection_parent and selection_child and not filter_legitimate
level: high
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059

# Detect red team credential dumping
title: Red Team - LSASS Memory Access
id: 8b9c0d1e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: stable
description: >
  Detects access to LSASS process memory, indicating
  credential dumping attempts (Mimikatz, ProcDump).
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: \lsass.exe
    GrantedAccess: 0x1010
  filter_legitimate:
    SourceImage|endswith:
      - \svchost.exe
      - \lsm.exe
      - \csrss.exe
      - \wininit.exe
  condition: selection and not filter_legitimate
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.defense_evasion
  - attack.t1003

# Detect red team lateral movement — PsExec
title: Red Team - PsExec Service Installation
id: 9c0d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: stable
description: >
  Detects PsExec service installation for lateral movement.
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName|contains: PSEXESVC
    ImagePath|contains: ADMIN$
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.execution
  - attack.t1569.002
```

### Purple Team Reporting
```python
class PurpleTeamReport:
    def __init__(self, exercise_name, start_date, end_date):
        self.exercise_name = exercise_name
        self.start_date = start_date
        self.end_date = end_date
        self.findings = []
        self.improvements = []

    def add_finding(self, technique, detection_status, details):
        """Add exercise finding."""
        self.findings.append({
            'technique': technique,
            'detection_status': detection_status,  # detected, partial, missed
            'details': details,
        })

    def add_improvement(self, area, description, priority, owner):
        """Add improvement action."""
        self.improvements.append({
            'area': area,
            'description': description,
            'priority': priority,  # high, medium, low
            'owner': owner,
            'status': 'open',
        })

    def generate_report(self):
        """Generate purple team exercise report."""
        print("=" * 70)
        print(f"PURPLE TEAM EXERCISE REPORT: {self.exercise_name}")
        print(f"Period: {self.start_date} to {self.end_date}")
        print("=" * 70)

        # Detection summary
        detected = sum(1 for f in self.findings if f['detection_status'] == 'detected')
        partial = sum(1 for f in self.findings if f['detection_status'] == 'partial')
        missed = sum(1 for f in self.findings if f['detection_status'] == 'missed')
        total = len(self.findings)

        print(f"\n📊 Detection Summary:")
        print(f"  Total TTPs tested: {total}")
        print(f"  Detected: {detected} ({detected/total*100:.1f}%)")
        print(f"  Partial: {partial} ({partial/total*100:.1f}%)")
        print(f"  Missed: {missed} ({missed/total*100:.1f}%)")

        # Missed TTPs (need attention)
        if missed > 0:
            print(f"\n❌ Missed TTPs (require attention):")
            for f in self.findings:
                if f['detection_status'] == 'missed':
                    print(f"  - {f['technique']}: {f['details']}")

        # Improvements
        print(f"\n🔧 Improvement Actions ({len(self.improvements)}):")
        for imp in self.improvements:
            print(f"  [{imp['priority'].upper()}] {imp['area']}: {imp['description']}")
            print(f"    Owner: {imp['owner']}, Status: {imp['status']}")

        print(f"\n{'='*70}")
```

---

## AUDIT CHECKLIST

- [ ] Purple team exercises conducted (at least annually)
- [ ] MITRE ATT&CK TTPs mapped to detections
- [ ] Detection coverage measured (percentage of TTPs detected)
- [ ] Detection latency measured (time from attack to alert)
- [ ] False positive rate measured
- [ ] Missed TTPs documented and addressed
- [ ] Improvement actions tracked to closure
- [ ] Red team tools tested against defenses (in sandbox)
- [ ] Detection rules updated based on exercise findings
- [ ] Response playbooks tested during exercises
- [ ] Communication channels tested (red ↔ blue ↔ management)
- [ ] Rules of engagement documented and approved
- [ ] Exercise scope clearly defined
- [ ] Legal approval for red team activities
- [ ] Post-exercise review completed
- [ ] Continuous improvement cycle established
