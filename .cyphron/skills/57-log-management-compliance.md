# Skill 57 — Log Management & Compliance

> Cyphron's methodology for building log management systems that meet compliance requirements. Cyphron knows log-based attack vectors — log tampering, log injection, log deletion, insufficient logging — and builds log management systems that are comprehensive, tamper-proof, and compliant.

---

## WHEN TO ACTIVATE

- User asks about log management or log retention
- User asks about compliance logging (PCI-DSS, HIPAA, GDPR, SOC 2)
- User asks about log integrity or tamper-proof logging
- User asks about log aggregation or SIEM integration
- User asks about log analysis or log forensics

---

## METHODOLOGY

### Log Management Lifecycle

```
Generate → Collect → Transport → Store → Protect → Analyze → Retain → Dispose
    ↑                                                                    │
    └────────────────────── Compliance & Audit ──────────────────────────┘
```

### Step 1: Define What to Log
### Step 2: Ensure Log Integrity
### Step 3: Centralize & Protect
### Step 4: Retain & Dispose

---

## SECURE PATTERNS

### Comprehensive Logging Standard
```python
#!/usr/bin/env python3
"""
Security logging standard — what to log for compliance and detection.
"""

LOGGING_STANDARD = {
    # Authentication events
    'authentication': {
        'events': [
            'login_success', 'login_failure', 'logout',
            'mfa_success', 'mfa_failure', 'password_change',
            'password_reset', 'account_lockout', 'session_created',
            'session_expired', 'session_invalidated',
        ],
        'fields': [
            'timestamp', 'user_id', 'username', 'source_ip',
            'user_agent', 'session_id', 'auth_method',
            'mfa_method', 'result', 'failure_reason',
        ],
        'retention': '7 years',  # PCI-DSS
    },

    # Authorization events
    'authorization': {
        'events': [
            'access_granted', 'access_denied',
            'privilege_escalation', 'role_change',
            'permission_change', 'admin_action',
        ],
        'fields': [
            'timestamp', 'user_id', 'resource', 'action',
            'result', 'previous_role', 'new_role',
            'approved_by', 'reason',
        ],
        'retention': '7 years',
    },

    # Data access events
    'data_access': {
        'events': [
            'data_read', 'data_create', 'data_update', 'data_delete',
            'data_export', 'data_download', 'data_print',
            'sensitive_data_access',
        ],
        'fields': [
            'timestamp', 'user_id', 'data_type', 'data_id',
            'data_classification', 'action', 'volume',
            'source_ip', 'destination',
        ],
        'retention': '7 years',  # HIPAA, GDPR
    },

    # System events
    'system': {
        'events': [
            'service_start', 'service_stop', 'service_crash',
            'config_change', 'package_install', 'package_remove',
            'user_created', 'user_deleted', 'user_modified',
            'file_created', 'file_deleted', 'file_modified',
        ],
        'fields': [
            'timestamp', 'host', 'service', 'action',
            'user', 'config_item', 'old_value', 'new_value',
            'result', 'error_message',
        ],
        'retention': '1 year',
    },

    # Network events
    'network': {
        'events': [
            'connection_allowed', 'connection_denied',
            'firewall_rule_match', 'ids_alert', 'ips_block',
            'dns_query', 'dns_response',
        ],
        'fields': [
            'timestamp', 'source_ip', 'dest_ip', 'source_port',
            'dest_port', 'protocol', 'action', 'rule_id',
            'bytes_in', 'bytes_out',
        ],
        'retention': '1 year',
    },

    # Application events
    'application': {
        'events': [
            'api_request', 'api_response', 'api_error',
            'business_logic_error', 'validation_error',
            'rate_limit_exceeded', 'input_validation_failure',
        ],
        'fields': [
            'timestamp', 'user_id', 'endpoint', 'method',
            'status_code', 'latency', 'request_id',
            'error_message', 'stack_trace',
        ],
        'retention': '90 days',
    },
}
```

### Tamper-Proof Logging (WORM + Hash Chain)
```python
import hashlib
import json
import time
from datetime import datetime

class TamperProofLogger:
    """Tamper-proof logging with hash chain and WORM storage."""

    def __init__(self, storage_backend):
        self.storage = storage_backend
        self.last_hash = self._get_last_hash()

    def log(self, event_type, event_data, severity='info'):
        """Log event with hash chain for tamper evidence."""
        # 1. Create log entry
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'data': event_data,
            'sequence': self._get_next_sequence(),
        }

        # 2. Calculate hash (includes previous hash for chain)
        entry_hash = self._calculate_hash(entry, self.last_hash)
        entry['hash'] = entry_hash
        entry['previous_hash'] = self.last_hash

        # 3. Store to WORM (Write Once, Read Many)
        self.storage.write_once(entry)

        # 4. Update last hash for chain
        self.last_hash = entry_hash

        return entry

    def _calculate_hash(self, entry, previous_hash):
        """Calculate hash of log entry (includes previous hash)."""
        content = json.dumps({
            'timestamp': entry['timestamp'],
            'event_type': entry['event_type'],
            'data': entry['data'],
            'previous_hash': previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_integrity(self, start_sequence, end_sequence):
        """Verify log chain integrity — detect tampering."""
        entries = self.storage.read_range(start_sequence, end_sequence)

        for i in range(1, len(entries)):
            expected_hash = self._calculate_hash(
                entries[i],
                entries[i-1]['hash']
            )
            if entries[i]['hash'] != expected_hash:
                return {
                    'valid': False,
                    'tampered_at': entries[i]['sequence'],
                    'expected_hash': expected_hash,
                    'actual_hash': entries[i]['hash'],
                }

        return {'valid': True, 'entries_verified': len(entries)}

    def _get_last_hash(self):
        """Get hash of last log entry (or genesis hash)."""
        last_entry = self.storage.read_last()
        if last_entry:
            return last_entry['hash']
        # Genesis hash — first entry in chain
        return hashlib.sha256(b'genesis').hexdigest()
```

### Log Retention & Compliance
```python
class ComplianceLogManager:
    """Manage log retention per compliance requirements."""

    RETENTION_POLICIES = {
        'pci_dss': {
            'authentication': '1 year',  # PCI-DSS 10.2
            'data_access': '1 year',
            'system': '1 year',
            'network': '1 year',
        },
        'hipaa': {
            'authentication': '6 years',  # HIPAA 164.312(b)
            'data_access': '6 years',
            'system': '6 years',
        },
        'gdpr': {
            'authentication': 'as_needed',  # GDPR — minimize retention
            'data_access': 'as_needed',
            'consent': 'as_needed',
        },
        'soc2': {
            'authentication': '1 year',  # SOC 2 CC7.2
            'data_access': '1 year',
            'system': '1 year',
            'availability': '1 year',
        },
        'iso27001': {
            'authentication': '1 year',  # ISO 27001 A.12.4
            'data_access': '1 year',
            'system': '1 year',
            'incident': '3 years',
        },
    }

    def __init__(self, compliance_frameworks):
        self.frameworks = compliance_frameworks
        self.retention = self._calculate_retention()

    def _calculate_retention(self):
        """Calculate longest retention requirement across frameworks."""
        retention = {}
        for framework in self.frameworks:
            for category, period in self.RETENTION_POLICIES.get(framework, {}).items():
                current = retention.get(category, '0 days')
                retention[category] = self._longer_period(current, period)
        return retention

    def _longer_period(self, period1, period2):
        """Return longer of two periods."""
        # Parse periods (simplified)
        if 'year' in period1 and 'year' in period2:
            years1 = int(period1.split()[0])
            years2 = int(period2.split()[0])
            return f"{max(years1, years2)} years"
        return max(period1, period2)

    def get_retention_policy(self, log_category):
        """Get retention period for a log category."""
        return self.retention.get(log_category, '90 days')  # default

    def enforce_retention(self, log_store):
        """Enforce retention — delete expired logs."""
        for category, period in self.retention.items():
            cutoff = self._calculate_cutoff(period)
            log_store.delete_before(category, cutoff)
            print(f"Deleted {category} logs older than {cutoff}")
```

### Log Aggregation (Syslog-NG)
```syslog-ng
# /etc/syslog-ng/syslog-ng.conf — centralized log aggregation

# Sources
source s_local {
    system();
    internal();
};

source s_network {
    network(
        ip("0.0.0.0")
        port(514)
        transport("tcp")
        tls(
            key-file("/etc/syslog-ng/certs/server.key")
            cert-file("/etc/syslog-ng/certs/server.crt")
            ca-file("/etc/syslog-ng/certs/ca.crt")
            peer-verify("required-trusted")
        )
    );
};

# Destinations
destination d_remote {
    network(
        "logs.example.com"
        port(6514)
        transport("tcp")
        tls(
            key-file("/etc/syslog-ng/certs/client.key")
            cert-file("/etc/syslog-ng/certs/client.crt")
            ca-file("/etc/syslog-ng/certs/ca.crt")
        )
    );
};

destination d_local_secure {
    file("/var/log/secure/${YEAR}${MONTH}${DAY}/${HOST}.log"
        create-dirs(yes)
        perm(0640)
        dir-perm(0750)
    );
};

# Filters
filter f_auth {
    facility(auth) or facility(authpriv);
};

filter f_security {
    match("security" value("PROGRAM"))
    or match("audit" value("PROGRAM"));
};

# Log paths
log {
    source(s_local);
    filter(f_auth);
    destination(d_local_secure);
    destination(d_remote);
};

log {
    source(s_local);
    filter(f_security);
    destination(d_local_secure);
    destination(d_remote);
};

log {
    source(s_network);
    destination(d_local_secure);
    destination(d_remote);
};
```

---

## AUDIT CHECKLIST

- [ ] All security events logged (auth, authz, data access, system, network)
- [ ] Log fields include: timestamp, user, source IP, action, result
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Log integrity (hash chain, WORM storage, digital signatures)
- [ ] Centralized log aggregation (SIEM or log management)
- [ ] Log transport encrypted (TLS)
- [ ] Log storage encrypted (at rest)
- [ ] Access to logs restricted (need-to-know)
- [ ] Log retention per compliance (PCI 1yr, HIPAA 6yr, SOC2 1yr)
- [ ] Log disposal (secure deletion after retention)
- [ ] Time synchronization (NTP, all sources UTC)
- [ ] Log monitoring (alert on log service failure)
- [ ] Log analysis (SIEM rules, anomaly detection)
- [ ] Log forensics capability (search, filter, export)
- [ ] Compliance reporting (automated log reports)
- [ ] Tamper detection (alert on log chain break)
- [ ] Log backup (secondary copy)
- [ ] Log rotation (prevent disk full)
