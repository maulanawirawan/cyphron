# Skill 51 — Secure Configuration Management

> Cyphron's methodology for managing and maintaining secure configurations across infrastructure. Cyphron knows configuration drift attack vectors — unauthorized changes, misconfigurations, default settings — and builds configuration management systems that detect and prevent drift.

---

## WHEN TO ACTIVATE

- User asks about configuration management or drift detection
- User asks about IaC (Infrastructure as Code) security
- User asks about CIS benchmarks or configuration baselines
- User asks about configuration compliance or auditing
- User asks about tools like Ansible, Chef, Puppet, or Terraform security

---

## METHODOLOGY

### Configuration Management Lifecycle

```
Baseline → Enforce → Monitor → Detect Drift → Remediate → Verify
    ↑                                                          │
    └──────────────── Continuous Compliance ───────────────────┘
```

### Step 1: Define Secure Baselines
### Step 2: Enforce with IaC
### Step 3: Monitor for Drift
### Step 4: Auto-Remediate
### Step 5: Verify Compliance

---

## SECURE PATTERNS

### Secure Baseline (CIS Benchmark)
```yaml
# CIS Benchmark — Linux secure configuration baseline
# File: cis-baseline.yml

- name: Ensure SSH is configured securely
  hosts: all
  become: yes
  tasks:
    - name: Disable SSH root login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
      notify: restart sshd

    - name: Disable SSH password authentication
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PasswordAuthentication'
        line: 'PasswordAuthentication no'
      notify: restart sshd

    - name: Set SSH protocol to 2
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^Protocol'
        line: 'Protocol 2'
      notify: restart sshd

    - name: Set SSH max auth tries
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^MaxAuthTries'
        line: 'MaxAuthTries 3'
      notify: restart sshd

    - name: Set SSH client alive interval
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^ClientAliveInterval'
        line: 'ClientAliveInterval 300'
      notify: restart sshd

- name: Ensure firewall is configured
  hosts: all
  become: yes
  tasks:
    - name: Install ufw
      apt:
        name: ufw
        state: present

    - name: Set default deny incoming
      ufw:
        direction: incoming
        policy: deny

    - name: Set default allow outgoing
      ufw:
        direction: outgoing
        policy: allow

    - name: Allow SSH from management subnet
      ufw:
        rule: allow
        from_ip: 10.0.1.0/24
        to_port: '22'
        proto: tcp

    - name: Allow HTTPS
      ufw:
        rule: allow
        to_port: '443'
        proto: tcp

    - name: Enable firewall
      ufw:
        state: enabled

- name: Ensure audit logging is configured
  hosts: all
  become: yes
  tasks:
    - name: Install auditd
      apt:
        name: auditd
        state: present

    - name: Enable auditd
      systemd:
        name: auditd
        enabled: yes
        state: started

    - name: Configure audit rules
      copy:
        dest: /etc/audit/rules.d/hardening.rules
        content: |
          -w /etc/passwd -p wa -k identity
          -w /etc/group -p wa -k identity
          -w /etc/shadow -p wa -k identity
          -w /etc/sudoers -p wa -k scope
          -a always,exit -F arch=b64 -S execve -k exec
      notify: restart auditd
```

### Configuration Drift Detection (Python)
```python
#!/usr/bin/env python3
"""
Configuration drift detection — compare actual vs desired state.
Defensive: detect unauthorized or accidental configuration changes.
"""
import json
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path

class ConfigDriftDetector:
    def __init__(self, baseline_file):
        with open(baseline_file) as f:
            self.baseline = json.load(f)
        self.drift_findings = []

    def check_file_integrity(self, filepath, expected_hash):
        """Check if file matches expected hash."""
        try:
            with open(filepath, 'rb') as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()

            if actual_hash != expected_hash:
                self.drift_findings.append({
                    'type': 'file_integrity',
                    'file': filepath,
                    'expected_hash': expected_hash[:16] + '...',
                    'actual_hash': actual_hash[:16] + '...',
                    'severity': 'high',
                })
                return False
            return True
        except FileNotFoundError:
            self.drift_findings.append({
                'type': 'file_missing',
                'file': filepath,
                'severity': 'critical',
            })
            return False

    def check_package_versions(self, packages):
        """Check installed package versions."""
        for package, expected_version in packages.items():
            try:
                result = subprocess.run(
                    ['dpkg', '-l', package],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    # Parse version from dpkg output
                    for line in result.stdout.split('\n'):
                        if package in line:
                            actual_version = line.split()[2]
                            if actual_version != expected_version:
                                self.drift_findings.append({
                                    'type': 'package_version',
                                    'package': package,
                                    'expected': expected_version,
                                    'actual': actual_version,
                                    'severity': 'medium',
                                })
            except Exception:
                pass

    def check_service_status(self, services):
        """Check if services are running as expected."""
        for service, expected_state in services.items():
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True, text=True
                )
                actual_state = result.stdout.strip()

                if actual_state != expected_state:
                    self.drift_findings.append({
                        'type': 'service_status',
                        'service': service,
                        'expected': expected_state,
                        'actual': actual_state,
                        'severity': 'high' if expected_state == 'active' else 'medium',
                    })
            except Exception:
                pass

    def check_sysctl(self, parameters):
        """Check kernel parameters."""
        for param, expected_value in parameters.items():
            try:
                result = subprocess.run(
                    ['sysctl', '-n', param],
                    capture_output=True, text=True
                )
                actual_value = result.stdout.strip()

                if actual_value != expected_value:
                    self.drift_findings.append({
                        'type': 'sysctl',
                        'parameter': param,
                        'expected': expected_value,
                        'actual': actual_value,
                        'severity': 'medium',
                    })
            except Exception:
                pass

    def run_all_checks(self):
        """Run all drift detection checks."""
        # File integrity
        for file_config in self.baseline.get('files', []):
            self.check_file_integrity(
                file_config['path'],
                file_config['sha256']
            )

        # Package versions
        self.check_package_versions(self.baseline.get('packages', {}))

        # Service status
        self.check_service_status(self.baseline.get('services', {}))

        # Kernel parameters
        self.check_sysctl(self.baseline.get('sysctl', {}))

        return self.drift_findings

    def generate_report(self):
        """Generate drift detection report."""
        if not self.drift_findings:
            print("✅ No configuration drift detected")
            return

        print("=" * 60)
        print("CONFIGURATION DRIFT REPORT")
        print(f"Generated: {datetime.now().isoformat()}")
        print("=" * 60)

        by_severity = {}
        for finding in self.drift_findings:
            by_severity.setdefault(finding['severity'], []).append(finding)

        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                print(f"\n{severity.upper()}: {len(by_severity[severity])} findings")
                for f in by_severity[severity]:
                    print(f"  {f['type']}: {f.get('file', f.get('package', f.get('service', f.get('parameter'))))}")
                    if 'expected' in f and 'actual' in f:
                        print(f"    Expected: {f['expected']}, Actual: {f['actual']}")
```

### Terraform Secure Configuration
```hcl
# Terraform — secure infrastructure as code

# Provider with least privilege
provider "aws" {
  region = "us-east-1"
  # Use IAM role, not access keys
  assume_role {
    role_arn = "arn:aws:iam::123456789:role/terraform-deploy"
  }
}

# Remote state with encryption and locking
terraform {
  backend "s3" {
    bucket         = "terraform-state-secure"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    # Versioning enabled on bucket
  }
}

# Security group with explicit rules (no 0.0.0.0/0)
resource "aws_security_group" "app" {
  name_prefix = "app-sg"
  vpc_id      = aws_vpc.main.id

  # Ingress — only from load balancer
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
    description     = "HTTPS from load balancer"
  }

  # Egress — only to database and internet (for updates)
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db.id]
    description     = "PostgreSQL to database"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for package updates"
  }

  tags = {
    Name        = "app-sg"
    Environment = "production"
    ManagedBy   = "terraform"
    Compliance  = "pci-dss"
  }
}

# EC2 with hardened configuration
resource "aws_instance" "app" {
  ami                    = data.aws_ami.hardened.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  # IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # EBS encryption
  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs.arn
    volume_size = 30
    volume_type = "gp3"
  }

  # User data for hardening
  user_data = base64encode(templatefile("hardened-init.sh", {
    hostname = "app-server"
  }))

  tags = {
    Name        = "app-server"
    Environment = "production"
    ManagedBy   = "terraform"
    Compliance  = "pci-dss"
    Backup      = "daily"
  }

  # Prevent accidental termination
  disable_api_termination = true
}
```

---

## AUDIT CHECKLIST

- [ ] Secure baselines defined (CIS benchmarks)
- [ ] Infrastructure as Code (Terraform, Ansible, etc.)
- [ ] Version control for all configurations
- [ ] Drift detection running (daily minimum)
- [ ] Auto-remediation for non-critical drift
- [ ] Manual approval for critical changes
- [ ] Configuration compliance reporting
- [ ] Secrets not in configuration files (use vault)
- [ ] Configuration backup before changes
- [ ] Rollback procedure for failed changes
- [ ] Change management process (ticket → approve → deploy → verify)
- [ ] Configuration audit logging
- [ ] Baseline review (quarterly)
- [ ] Compliance scanning (CIS, STIG)
- [ ] IaC security scanning (Checkov, tfsec)
