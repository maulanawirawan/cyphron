# Skill 48 — Physical Security Engineering

> Cyphron's methodology for securing physical access to facilities and data centers. Cyphron knows physical attack vectors — tailgating, lock bypass, RFID cloning, USB drops — and builds physical security controls that complement cybersecurity.

---

## WHEN TO ACTIVATE

- User asks about physical security for facilities or data centers
- User asks about access control systems, badges, or CCTV
- User asks about data center security
- User asks about physical penetration testing defense
- User asks about secure facility design

---

## METHODOLOGY

### Physical Security Layers (Concentric Rings)

```
Perimeter → Building → Floor → Room → Cabinet → Device
   │           │          │       │        │        │
   ↓           ↓          ↓       ↓        ↓        ↓
Fence       Badge      Badge   Badge    Lock     TPM/HSM
Gate        Reader     Reader  Reader    Biometric
CCTV        CCTV       CCTV    CCTV      Tamper
Guard       Guard      Mantrap           Sensor
```

### Step 1: Perimeter Security
### Step 2: Building Access Control
### Step 3: Sensitive Area Protection
### Step 4: Device-Level Security

---

## SECURE PATTERNS

### Access Control System Design
```markdown
## Access Control Design

### Badge System
- **Technology**: MIFARE DESFire EV3 (encrypted, not clonable like older MIFARE Classic)
- **Authentication**: Mutual authentication (badge ↔ reader)
- **Encryption**: AES-128 encrypted communication
- **Unique per badge**: UID + cryptographic key
- **Anti-passback**: Can't use same badge for entry twice without exit
- **Two-factor for sensitive areas**: Badge + PIN or Badge + Biometric

### Access Levels
| Level | Areas | Examples |
|---|---|---|
| Public | Lobby, common areas | Visitors, deliveries |
| Employee | General office, meeting rooms | All employees |
| Restricted | Server room, finance, executive | IT, finance, executives |
| High Security | Data center, vault, SCIF | Authorized personnel only |

### Visitor Management
1. Pre-registration by host
2. Government ID verification at reception
3. Photo capture
4. Temporary badge (time-limited, area-restricted)
5. Escort required for restricted areas
6. Badge return and sign-out
7. Audit log of all visitor access
```

### Data Center Physical Security
```markdown
## Data Center Physical Security

### Tier Requirements (Uptime Institute)
| Tier | Redundancy | Physical Security |
|---|---|---|
| I | None | Basic lock and key |
| II | N+1 | Badge access, CCTV |
| III | 2N | Badge + biometric, mantrap, 24/7 guard |
| IV | 2(N+1) | Full multi-factor, dual authentication, armed guard |

### Physical Controls
- [ ] Fenced perimeter with anti-climb topping
- [ ] Crash-rated bollards at vehicle entry
- [ ] 24/7 CCTV with 90-day retention
- [ ] Badge + biometric (fingerprint or iris) for entry
- [ ] Mantrap (two-door interlock) for data center entry
- [ ] Two-person rule for high-security areas
- [ ] Tamper sensors on cabinets
- [ ] Environmental monitoring (temp, humidity, water, smoke)
- [ ] UPS and generator backup
- [ ] Fire suppression (clean agent, not water)
- [ ] Secure shipping/receiving (separate from data center)
- [ ] No exterior windows in data center
- [ ] Cable management (no exposed cables)
- [ ] Locked cabinets with individual keys
- [ ] Asset tags on all equipment
- [ ] Secure decommissioning (disk wiping, physical destruction)
```

### Physical Intrusion Detection
```python
class PhysicalIntrusionDetection:
    """Monitor physical security sensors for intrusion."""

    SENSORS = {
        'door_contact': 'Door opened/closed',
        'motion_detector': 'Motion in monitored area',
        'glass_break': 'Glass break detected',
        'tamper_switch': 'Cabinet/device tampered',
        'vibration': 'Vibration on wall/fence',
        'environmental': 'Temperature/humidity/water',
    }

    def analyze_event(self, sensor_event):
        """Analyze physical security sensor event."""
        sensor_type = sensor_event['sensor_type']
        location = sensor_event['location']
        timestamp = sensor_event['timestamp']
        state = sensor_event['state']

        alerts = []

        # Door opened outside business hours
        if sensor_type == 'door_contact' and state == 'open':
            if self._is_after_hours(timestamp) and location in self.RESTRICTED_AREAS:
                alerts.append({
                    'type': 'after_hours_access',
                    'severity': 'high',
                    'message': f'Door opened at {location} after hours',
                    'action': 'Verify with badge system; dispatch guard if unauthorized',
                })

        # Motion in unoccupied area
        if sensor_type == 'motion_detector' and state == 'triggered':
            if not self._is_occupied(location, timestamp):
                alerts.append({
                    'type': 'motion_unoccupied',
                    'severity': 'medium',
                    'message': f'Motion detected in unoccupied area: {location}',
                    'action': 'Check CCTV; dispatch guard to investigate',
                })

        # Tamper alarm
        if sensor_type == 'tamper_switch' and state == 'triggered':
            alerts.append({
                'type': 'tamper_alarm',
                'severity': 'critical',
                'message': f'Tamper alarm at {location}',
                'action': 'Immediate guard dispatch; preserve evidence',
            })

        return alerts
```

### Secure Facility Design Checklist
```markdown
## Secure Facility Design

### Perimeter
- [ ] Anti-climb fencing (minimum 2.4m)
- [ ] Crash-rated bollards at vehicle entry points
- [ ] Perimeter CCTV with analytics (loitering, intrusion)
- [ ] Adequate lighting (no blind spots)
- [ ] Guard patrol (randomized schedule)

### Building Entry
- [ ] Single point of entry (visitor management)
- [ ] Badge reader at all exterior doors
- [ ] Anti-tailgating measures (mantrap or turnstile)
- [ ] Reception with ID verification
- [ ] CCTV at all entry points
- [ ] Door forced/door held open alarms

### Interior
- [ ] Badge access for all interior doors
- [ ] Restricted areas with biometric verification
- [ ] Clear desk policy (no sensitive data visible)
- [ ] Lockable storage for sensitive documents
- [ ] Privacy screens on monitors
- [ ] Visitor escort policy
- [ ] CCTV in common areas (not in private offices)

### Data Center / Server Room
- [ ] No exterior windows
- [ ] Badge + biometric (two-factor)
- [ ] Mantrap entry
- [ ] Environmental monitoring (temp, humidity, water, smoke)
- [ ] Fire suppression (clean agent)
- [ ] UPS + generator
- [ ] Locked cabinets
- [ ] Tamper sensors
- [ ] CCTV (entry + interior)
- [ ] Two-person rule

### Secure Disposal
- [ ] Document shredding (cross-cut, not strip)
- [ ] Media destruction (disk wiping + physical destruction)
- [ ] Certificate of destruction
- [ ] Secure disposal bins
```

---

## AUDIT CHECKLIST

- [ ] Perimeter fencing and lighting adequate
- [ ] Badge access on all exterior doors
- [ ] Anti-tailgating controls (mantrap/turnstile)
- [ ] Visitor management process
- [ ] CCTV coverage with 90-day retention
- [ ] Two-factor for restricted areas
- [ ] Data center physical security (Tier III+)
- [ ] Environmental monitoring
- [ ] Fire suppression (clean agent)
- [ ] UPS and generator backup
- [ ] Tamper sensors on cabinets
- [ ] Secure document/media disposal
- [ ] Guard service (24/7 for critical facilities)
- [ ] Physical penetration testing (annual)
- [ ] Key/badge inventory and audit
- [ ] Emergency procedures (fire, evacuation, lockdown)
