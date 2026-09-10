# Skill 36 — Endpoint Security & EDR

> Cyphron's methodology for securing endpoints (workstations, servers) and building EDR (Endpoint Detection & Response) capabilities. Cyphron knows endpoint attack vectors — malware execution, living-off-the-land, persistence mechanisms, lateral movement — and builds endpoint defenses.

---

## WHEN TO ACTIVATE

- User asks to secure endpoints (workstations, servers)
- User asks about EDR, antivirus, or host-based intrusion detection
- User asks about endpoint hardening or CIS benchmarks
- User asks about Sysmon configuration or endpoint logging
- User asks about malware detection on endpoints

---

## METHODOLOGY

### Step 1: Endpoint Inventory
- Workstations (Windows, macOS, Linux)
- Servers (Windows, Linux)
- Mobile devices (MDM-managed)
- Specialized (kiosks, POS, IoT)

### Step 2: Defense Layers

| Layer | Control |
|---|---|
| Prevention | Hardening, application allowlisting, patching |
| Detection | EDR, Sysmon, file integrity monitoring |
| Response | Isolation, forensics, remediation |
| Recovery | Reimage, restore, verify |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### Sysmon Configuration (Endpoint Telemetry)
```xml
<!-- sysmon-config.xml — comprehensive endpoint monitoring -->
<Sysmon schemaversion="4.82">
  <HashAlgorithms>SHA256</HashAlgorithms>

  <!-- Log all process creation -->
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <!-- Suspicious parent-child relationships -->
      <RuleGroup name="Suspicious Process Chains" groupRelation="or">
        <ParentImage condition="contains">winword.exe</ParentImage>
        <ParentImage condition="contains">excel.exe</ParentImage>
        <ParentImage condition="contains">powerpnt.exe</ParentImage>
        <ParentImage condition="contains">outlook.exe</ParentImage>
      </RuleGroup>

      <!-- Suspicious commands -->
      <RuleGroup name="Suspicious Commands" groupRelation="or">
        <CommandLine condition="contains">powershell -enc</CommandLine>
        <CommandLine condition="contains">powershell -e </CommandLine>
        <CommandLine condition="contains">powershell -w hidden</CommandLine>
        <CommandLine condition="contains">certutil -decode</CommandLine>
        <CommandLine condition="contains">certutil -urlcache</CommandLine>
        <CommandLine condition="contains">bitsadmin /transfer</CommandLine>
        <CommandLine condition="contains">regsvr32 /s /u /i:</CommandLine>
        <CommandLine condition="contains">mshta http</CommandLine>
        <CommandLine condition="contains">rundll32 javascript</CommandLine>
        <CommandLine condition="contains">net user</CommandLine>
        <CommandLine condition="contains">vssadmin delete shadows</CommandLine>
        <CommandLine condition="contains">wbadmin delete catalog</CommandLine>
        <CommandLine condition="contains">bcdedit /set</CommandLine>
      </RuleGroup>
    </ProcessCreate>

    <!-- Log network connections by suspicious processes -->
    <NetworkConnect onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <Image condition="contains">cmd.exe</Image>
      <Image condition="contains">certutil.exe</Image>
      <Image condition="contains">mshta.exe</Image>
    </NetworkConnect>

    <!-- Log file creation in sensitive locations -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Temp\</TargetFilename>
      <TargetFilename condition="contains">\Downloads\</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="end with">.bat</TargetFilename>
      <TargetFilename condition="end with">.vbs</TargetFilename>
    </FileCreate>

    <!-- Detect persistence mechanisms -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">\Services\</TargetObject>
      <TargetObject condition="contains">\ScheduledTasks\</TargetObject>
      <TargetObject condition="contains">\Winlogon\Shell</TargetObject>
    </RegistryEvent>

    <!-- Detect DLL loading -->
    <ImageLoad onmatch="include">
      <Image condition="contains">winword.exe</Image>
      <ImageLoaded condition="contains">\Temp\</ImageLoaded>
      <ImageLoaded condition="end with">.dll</ImageLoaded>
    </ImageLoad>
  </EventFiltering>
</Sysmon>
```

### EDR Detection Logic (Python)
```python
#!/usr/bin/env python3
"""Endpoint detection — analyze Sysmon/EDR events for threats."""
from collections import defaultdict
from datetime import datetime, timedelta

class EndpointDetection:
    SUSPICIOUS_PARENTS = {
        'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
        'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe',
    }

    SUSPICIOUS_CHILDREN = {
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
    }

    def __init__(self):
        self.alerts = []

    def analyze_process_creation(self, event):
        """Analyze process creation events."""
        parent = event.get('parent_image', '').lower()
        parent_name = parent.split('\\')[-1]
        child = event.get('image', '').lower()
        child_name = child.split('\\')[-1]
        command = event.get('command_line', '')

        # Office app spawning shell/scripting
        if parent_name in self.SUSPICIOUS_PARENTS and child_name in self.SUSPICIOUS_CHILDREN:
            self.alerts.append({
                'type': 'suspicious_process_chain',
                'severity': 'high',
                'message': f'{parent_name} spawned {child_name}: {command[:100]}',
                'host': event.get('computer'),
                'timestamp': event.get('time_created'),
            })

        # PowerShell encoded command
        if 'powershell' in child_name and ('-enc' in command or '-e ' in command):
            self.alerts.append({
                'type': 'encoded_powershell',
                'severity': 'high',
                'message': f'Encoded PowerShell command: {command[:100]}',
                'host': event.get('computer'),
                'timestamp': event.get('time_created'),
            })

        # Ransomware indicators
        ransomware_commands = [
            'vssadmin delete shadows', 'wbadmin delete catalog',
            'bcdedit /set', 'cipher /w',
        ]
        for cmd in ransomware_commands:
            if cmd in command.lower():
                self.alerts.append({
                    'type': 'ransomware_indicator',
                    'severity': 'critical',
                    'message': f'Ransomware command detected: {cmd}',
                    'host': event.get('computer'),
                    'timestamp': event.get('time_created'),
                })

    def analyze_network_connection(self, event):
        """Analyze network connections."""
        image = event.get('image', '').lower()
        dest_ip = event.get('destination_ip')
        dest_port = event.get('destination_port')

        # PowerShell making network connections
        if 'powershell' in image:
            self.alerts.append({
                'type': 'powershell_network',
                'severity': 'medium',
                'message': f'PowerShell network connection to {dest_ip}:{dest_port}',
                'host': event.get('computer'),
                'timestamp': event.get('time_created'),
            })

    def analyze_registry_persistence(self, event):
        """Detect persistence via registry."""
        target = event.get('target_object', '')
        persistence_keys = [
            'CurrentVersion\\Run', 'CurrentVersion\\RunOnce',
            'Winlogon\\Shell', 'Winlogon\\Userinit',
        ]
        for key in persistence_keys:
            if key.lower() in target.lower():
                self.alerts.append({
                    'type': 'registry_persistence',
                    'severity': 'high',
                    'message': f'Registry persistence: {target}',
                    'host': event.get('computer'),
                    'timestamp': event.get('time_created'),
                })
```

### Windows Hardening (Group Policy)
```powershell
# Windows hardening via PowerShell / GPO

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples

# Enable Attack Surface Reduction rules
Add-MpPreference -AttackSurfaceReductionRules_Ids `
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from email
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block all Office apps from creating child processes
  "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block Office apps from injecting into other processes
  "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office apps from creating executable content
  "26190899-1602-49E8-8B27-EB1D0A1CE869",  # Block Office communication apps from creating child processes
  "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block untrusted/unsigned processes from USB
  "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"   # Block execution of potentially obfuscated code

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Disable LLMNR (prevents spoofing)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -Value 0

# Enable Audit logging
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
```

### Linux Hardening
```bash
#!/bin/bash
# Linux hardening script

# Disable unnecessary services
systemctl disable telnet
systemctl disable rsh
systemctl disable rlogin
systemctl disable rexec

# Configure SSH
cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Protocol 2
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers @ssh-users
X11Forwarding no
AllowTcpForwarding no
EOF
systemctl restart sshd

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl enable fail2ban
systemctl start fail2ban

# Enable audit daemon
systemctl enable auditd
systemctl start auditd

# Configure audit rules
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /var/log/auth.log -p wa -k logins
-a always,exit -F arch=b64 -S execve -k exec
EOF
augenrules --load

# Set file permissions
chmod 600 /boot/grub/grub.cfg
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

---

## AUDIT CHECKLIST

- [ ] EDR deployed on all endpoints
- [ ] Antivirus with real-time scanning
- [ ] Sysmon or equivalent telemetry
- [ ] Application allowlisting (AppLocker, AppArmor)
- [ ] Full disk encryption (BitLocker, FileVault, LUKS)
- [ ] Screen lock (5 min idle)
- [ ] Patch management (OS + applications)
- [ ] Least privilege (no local admin for standard users)
- [ ] USB device control
- [ ] Host-based firewall enabled
- [ ] Audit logging enabled
- [ ] Logs forwarded to SIEM
- [ ] SMBv1 disabled
- [ ] LLMNR/NBT-NS disabled
- [ ] PowerShell logging enabled
- [ ] Attack Surface Reduction rules (Windows)
- [ ] fail2ban (Linux)
- [ ] MDM for mobile devices
