# Skill 35 — Disaster Recovery & Business Continuity

> Cyphron's methodology for building Disaster Recovery (DR) and Business Continuity Plans (BCP). Cyphron knows how systems fail — ransomware, natural disasters, cloud outages, data corruption — and builds recovery strategies that minimize downtime and data loss.

---

## WHEN TO ACTIVATE

- User asks to build a disaster recovery plan
- User asks about RTO/RPO, backup strategy, or failover
- User asks about business continuity planning
- User asks about ransomware recovery
- User asks about multi-region or multi-cloud resilience

---

## METHODOLOGY

### Step 1: Define Recovery Objectives

| Metric | Definition | Example |
|---|---|---|
| **RTO** (Recovery Time Objective) | Max acceptable downtime | 4 hours |
| **RPO** (Recovery Point Objective) | Max acceptable data loss | 1 hour |
| **RTO/RPO** drive | Backup frequency, failover strategy, architecture | |

### Step 2: Business Impact Analysis (BIA)
| Process | Criticality | RTO | RPO | Impact of Downtime |
|---|---|---|---|---|
| Payment processing | Critical | 1h | 0 | $100K/hour |
| Customer portal | High | 4h | 1h | $50K/hour |
| Reporting | Medium | 24h | 24h | $5K/hour |
| Internal tools | Low | 72h | 72h | Minimal |

### Step 3: Recovery Strategy Selection

| Strategy | RTO | RPO | Cost | Description |
|---|---|---|---|---|
| Backup & Restore | 24-72h | 24h | Low | Restore from backups |
| Pilot Light | 4-8h | 1h | Medium | Minimal DR env, scale up |
| Warm Standby | 1-4h | Minutes | High | Scaled-down replica |
| Multi-Site Active-Active | <1h | ~0 | Highest | Full duplicate, load balanced |

### Step 4: Build Recovery Plans

---

## RECOVERY PLAN TEMPLATES

### Ransomware Recovery Plan
```markdown
## Ransomware Recovery Plan

### Phase 1: Isolate (0-1 hour)
- [ ] Identify affected systems
- [ ] Isolate from network (do NOT power off — preserve evidence)
- [ ] Activate IR team
- [ ] Notify executives and legal

### Phase 2: Assess (1-4 hours)
- [ ] Identify ransomware strain
- [ ] Determine scope (which systems, which data)
- [ ] Check backup integrity (are backups encrypted too?)
- [ ] Identify entry point

### Phase 3: Recover (4-24 hours)
- [ ] Restore from clean, offline backups
- [ ] Verify backup integrity before restore
- [ ] Rebuild systems from known-good images
- [ ] Patch the vulnerability that allowed entry
- [ ] Reset all credentials
- [ ] Deploy EDR on all systems

### Phase 4: Validate (24-48 hours)
- [ ] Verify all systems functional
- [ ] Scan for residual malware/backdoors
- [ ] Monitor for re-infection
- [ ] Gradual service restoration

### Phase 5: Post-Incident (1-2 weeks)
- [ ] Root cause analysis
- [ ] Backup strategy review
- [ ] Security control improvements
- [ ] Tabletop exercise with lessons learned
```

### Database Recovery Plan
```python
#!/usr/bin/env python3
"""Automated database recovery procedures."""
import subprocess
import time
from datetime import datetime, timedelta

class DatabaseRecovery:
    def __init__(self, db_config):
        self.config = db_config

    def restore_from_backup(self, backup_time, target='staging'):
        """Restore database from point-in-time backup."""
        print(f"[{datetime.now()}] Starting DB restore to {target}")
        print(f"  Backup point: {backup_time}")

        # 1. Verify backup exists and is clean
        if not self.verify_backup(backup_time):
            raise Exception("Backup verification failed — may be corrupted")

        # 2. Create safety backup of current state
        self.create_safety_backup()

        # 3. Stop application connections
        self.stop_app_connections()

        # 4. Restore database
        if self.config['type'] == 'postgresql':
            self.restore_postgres(backup_time)
        elif self.config['type'] == 'mysql':
            self.restore_mysql(backup_time)
        elif self.config['type'] == 'mongodb':
            self.restore_mongodb(backup_time)

        # 5. Verify restore
        if not self.verify_restore():
            print("Restore failed — rolling back to safety backup")
            self.restore_safety_backup()
            return False

        # 6. Resume connections
        self.start_app_connections()

        print(f"[{datetime.now()}] DB restore complete")
        return True

    def restore_postgres(self, backup_time):
        """PostgreSQL point-in-time recovery."""
        # Stop PostgreSQL
        subprocess.run(['systemctl', 'stop', 'postgresql'])

        # Move current data dir
        subprocess.run(['mv', '/var/lib/postgresql/data',
                        f'/var/lib/postgresql/data.pre-restore.{int(time.time())}'])

        # Restore base backup
        subprocess.run([
            'pg_basebackup', '-h', self.config['backup_server'],
            '-D', '/var/lib/postgresql/data', '-U', 'replication',
        ])

        # Configure PITR
        recovery_conf = f"""
        restore_command = 'cp /backups/wal/%f %p'
        recovery_target_time = '{backup_time.isoformat()}'
        recovery_target_action = 'promote'
        """
        with open('/var/lib/postgresql/data/recovery.signal', 'w') as f:
            f.write('')

        with open('/var/lib/postgresql/data/postgresql.auto.conf', 'a') as f:
            f.write(recovery_conf)

        # Start PostgreSQL (will begin recovery)
        subprocess.run(['systemctl', 'start', 'postgresql'])

        # Wait for recovery to complete
        while not self.is_postgres_ready():
            time.sleep(5)

    def failover_to_replica(self):
        """Promote read replica to primary."""
        print("Initiating failover to replica...")

        # 1. Update DNS to point to replica
        self.update_dns(self.config['replica_host'])

        # 2. Promote replica to primary
        subprocess.run([
            'psql', '-h', self.config['replica_host'],
            '-c', "SELECT pg_promote();"
        ])

        # 3. Verify replica is now primary (accepting writes)
        if self.verify_writes(self.config['replica_host']):
            print("Failover successful — replica is now primary")
            return True
        return False
```

### Multi-Region Failover (AWS)
```python
import boto3

class MultiRegionFailover:
    def __init__(self, primary_region, dr_region):
        self.primary = primary_region  # 'us-east-1'
        self.dr = dr_region            # 'us-west-2'
        self.route53 = boto3.client('route53')

    def failover(self, health_check_id, hosted_zone_id, record_name):
        """Failover traffic from primary to DR region."""
        print(f"Initiating failover: {self.primary} → {self.dr}")

        # 1. Verify DR region is healthy
        if not self.check_dr_health():
            raise Exception("DR region is not healthy — aborting failover")

        # 2. Update Route 53 to point to DR
        self.route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': record_name,
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': self.dr_alb_zone_id,
                            'DNSName': self.dr_alb_dns,
                            'EvaluateTargetHealth': True,
                        },
                    },
                }],
            },
        )

        # 3. Scale up DR infrastructure
        self.scale_dr_to_full()

        # 4. Verify traffic flowing to DR
        if self.verify_traffic_dr():
            print("Failover complete — traffic now served by DR region")
            return True
        return False

    def failback(self):
        """Failback to primary region after recovery."""
        print(f"Initiating failback: {self.dr} → {self.primary}")

        # 1. Sync data from DR back to primary
        self.sync_data(self.dr, self.primary)

        # 2. Verify primary is healthy
        if not self.check_primary_health():
            raise Exception("Primary region not healthy — aborting failback")

        # 3. Update Route 53 back to primary
        self.update_dns_to_primary()

        # 4. Scale down DR
        self.scale_dr_to_minimal()
```

---

## BACKUP STRATEGY (3-2-1 Rule)

```
3 copies of data
2 different media types
1 copy offsite (or offline/immutable)
```

```python
class BackupStrategy:
    """3-2-1 backup strategy implementation."""

    def create_backups(self, data_source):
        # Copy 1: Primary backup (on-site, different media)
        self.backup_to_nas(data_source)

        # Copy 2: Secondary backup (different format)
        self.backup_to_tape_or_disk(data_source)

        # Copy 3: Offsite/immutable (cloud, air-gapped)
        self.backup_to_immutable_cloud(data_source)

    def backup_to_immutable_cloud(self, data_source):
        """Backup to immutable storage (ransomware-proof)."""
        s3 = boto3.client('s3')
        # Object Lock prevents deletion/modification
        s3.put_object(
            Bucket='immutable-backups',
            Key=f'backup/{datetime.now().isoformat()}.tar.gz',
            Body=data_source,
            # Object Lock enabled at bucket level
        )
```

---

## AUDIT CHECKLIST

- [ ] BIA completed for all critical processes
- [ ] RTO/RPO defined per system
- [ ] DR strategy selected (backup, pilot light, warm standby, active-active)
- [ ] Backups follow 3-2-1 rule
- [ ] Backups are immutable (ransomware-proof)
- [ ] Backup encryption enabled
- [ ] Backup restoration tested (quarterly minimum)
- [ ] Failover tested (annually minimum)
- [ ] DR runbook documented
- [ ] Contact tree for emergencies
- [ ] Alternative communication channel (if primary down)
- [ ] Multi-region or multi-cloud (for critical systems)
- [ ] Data replication to DR site
- [ ] RTO/RPO measured during tests
- [ ] Post-test review and improvements
- [ ] Ransomware-specific recovery plan
