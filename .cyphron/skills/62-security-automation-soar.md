# Skill 62 — Security Automation & SOAR

> Cyphron's methodology for building Security Orchestration, Automation, and Response (SOAR) systems. Cyphron knows that manual security operations don't scale — and builds automation that detects, investigates, and responds to security incidents automatically.

---

## WHEN TO ACTIVATE

- User asks to build SOAR or security automation
- User asks about security playbooks or automated response
- User asks about incident automation or orchestration
- User asks about security workflow automation

---

## METHODOLOGY

### SOAR Architecture

```
Detection → Triage → Investigate → Respond → Document → Learn
    ↑                                                      │
    └────────────────── Feedback Loop ─────────────────────┘
```

### Step 1: Define Automation Triggers
### Step 2: Build Playbooks
### Step 3: Implement Response Actions
### Step 4: Measure & Improve

---

## SECURE PATTERNS

### SOAR Playbook Framework
```python
#!/usr/bin/env python3
"""
SOAR playbook framework — automated security response.
"""
from datetime import datetime
from enum import Enum
import json

class PlaybookStatus(Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class SOARPlaybook:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.steps = []
        self.status = PlaybookStatus.PENDING
        self.results = {}
        self.started_at = None
        self.completed_at = None

    def add_step(self, name, action, params=None, condition=None, timeout=300):
        """Add step to playbook."""
        self.steps.append({
            'name': name,
            'action': action,
            'params': params or {},
            'condition': condition,  # run only if condition is True
            'timeout': timeout,
            'status': 'pending',
            'result': None,
            'error': None,
        })

    async def execute(self, context):
        """Execute playbook."""
        self.status = PlaybookStatus.RUNNING
        self.started_at = datetime.now().isoformat()

        for step in self.steps:
            # Check condition
            if step['condition'] and not self._evaluate_condition(step['condition'], context):
                step['status'] = 'skipped'
                continue

            step['status'] = 'running'
            try:
                # Execute action with timeout
                result = await asyncio.wait_for(
                    step['action'](context, step['params']),
                    timeout=step['timeout']
                )
                step['result'] = result
                step['status'] = 'completed'

                # Update context with result
                context[step['name']] = result

            except asyncio.TimeoutError:
                step['status'] = 'failed'
                step['error'] = 'Timeout'
                self.status = PlaybookStatus.FAILED
                break

            except Exception as e:
                step['status'] = 'failed'
                step['error'] = str(e)
                self.status = PlaybookStatus.FAILED
                break

        self.completed_at = datetime.now().isoformat()
        if self.status == PlaybookStatus.RUNNING:
            self.status = PlaybookStatus.COMPLETED

        return self

    def _evaluate_condition(self, condition, context):
        """Evaluate step condition."""
        # Simple condition evaluation
        # In production: use proper expression parser
        return eval(condition, {'context': context})

# ─── Example Playbooks ───

class PhishingResponsePlaybook(SOARPlaybook):
    def __init__(self):
        super().__init__('phishing_response', 'Automated phishing incident response')

        # Step 1: Enrich alert
        self.add_step(
            'enrich',
            self.enrich_alert,
            params={'fields': ['src_ip', 'sender', 'subject', 'urls']},
        )

        # Step 2: Check if sender is known phishing
        self.add_step(
            'check_threat_intel',
            self.check_threat_intel,
            condition='context["enrich"]["sender"] is not None',
        )

        # Step 3: Block sender (if phishing confirmed)
        self.add_step(
            'block_sender',
            self.block_sender,
            condition='context["check_threat_intel"]["is_phishing"] == True',
        )

        # Step 4: Quarantine email
        self.add_step(
            'quarantine_email',
            self.quarantine_email,
            condition='context["check_threat_intel"]["is_phishing"] == True',
        )

        # Step 5: Notify user
        self.add_step(
            'notify_user',
            self.notify_user,
        )

        # Step 6: Create ticket
        self.add_step(
            'create_ticket',
            self.create_ticket,
        )

    async def enrich_alert(self, context, params):
        """Enrich alert with threat intelligence."""
        alert = context['alert']
        enriched = {}

        for field in params['fields']:
            if field == 'src_ip':
                enriched['src_ip'] = await self.lookup_ip(alert.get('src_ip'))
            elif field == 'sender':
                enriched['sender'] = await self.lookup_sender(alert.get('sender'))
            elif field == 'urls':
                enriched['urls'] = await self.lookup_urls(alert.get('urls', []))

        return enriched

    async def check_threat_intel(self, context, params):
        """Check sender against threat intelligence."""
        sender = context['enrich']['sender']
        # Check against phishing database
        is_phishing = await self.query_phishing_db(sender)
        return {'is_phishing': is_phishing, 'confidence': 0.9 if is_phishing else 0.1}

    async def block_sender(self, context, params):
        """Block sender at email gateway."""
        sender = context['alert']['sender']
        result = await self.email_gateway.block_sender(sender)
        return {'blocked': result, 'sender': sender}

    async def quarantine_email(self, context, params):
        """Quarantine the phishing email."""
        email_id = context['alert']['email_id']
        result = await self.email_gateway.quarantine(email_id)
        return {'quarantined': result, 'email_id': email_id}

    async def notify_user(self, context, params):
        """Notify affected user."""
        user = context['alert']['recipient']
        result = await self.notification.send(
            user=user,
            template='phishing_warning',
            data={'sender': context['alert']['sender']},
        )
        return {'notified': result}

    async def create_ticket(self, context, params):
        """Create incident ticket."""
        ticket = await self.ticketing.create({
            'title': f'Phishing email from {context["alert"]["sender"]}',
            'severity': 'high',
            'type': 'phishing',
            'assignee': 'security-team',
            'description': json.dumps(context, indent=2),
        })
        return {'ticket_id': ticket['id']}

class CredentialCompromisePlaybook(SOARPlaybook):
    def __init__(self):
        super().__init__('credential_compromise', 'Automated credential compromise response')

        # Step 1: Disable account
        self.add_step('disable_account', self.disable_account)

        # Step 2: Revoke sessions
        self.add_step('revoke_sessions', self.revoke_sessions)

        # Step 3: Reset password
        self.add_step('reset_password', self.reset_password)

        # Step 4: Check for malicious activity
        self.add_step('check_activity', self.check_activity)

        # Step 5: Notify user
        self.add_step('notify_user', self.notify_user)

        # Step 6: Notify manager
        self.add_step('notify_manager', self.notify_manager)

    async def disable_account(self, context, params):
        """Disable compromised account."""
        user_id = context['alert']['user_id']
        result = await self.identity_provider.disable_user(user_id)
        return {'disabled': result, 'user_id': user_id}

    async def revoke_sessions(self, context, params):
        """Revoke all active sessions."""
        user_id = context['alert']['user_id']
        sessions = await self.session_manager.get_active_sessions(user_id)
        for session in sessions:
            await self.session_manager.revoke(session['id'])
        return {'revoked_count': len(sessions)}

    async def reset_password(self, context, params):
        """Force password reset."""
        user_id = context['alert']['user_id']
        result = await self.identity_provider.force_password_reset(user_id)
        return {'reset_required': result}

    async def check_activity(self, context, params):
        """Check for malicious activity."""
        user_id = context['alert']['user_id']
        # Check recent logins
        logins = await self.audit_log.get_logins(user_id, hours=24)
        suspicious = [l for l in logins if l['anomaly_score'] > 0.8]
        return {'suspicious_logins': len(suspicious), 'details': suspicious}

class MalwareResponsePlaybook(SOARPlaybook):
    def __init__(self):
        super().__init__('malware_response', 'Automated malware incident response')

        # Step 1: Isolate host
        self.add_step('isolate_host', self.isolate_host)

        # Step 2: Capture forensic image
        self.add_step('capture_forensics', self.capture_forensics)

        # Step 3: Scan for lateral movement
        self.add_step('scan_lateral', self.scan_lateral)

        # Step 4: Block C2
        self.add_step('block_c2', self.block_c2)

        # Step 5: Reimage host
        self.add_step('reimage_host', self.reimage_host)

    async def isolate_host(self, context, params):
        """Isolate infected host from network."""
        host_id = context['alert']['host_id']
        result = await self.edr.isolate_host(host_id)
        return {'isolated': result, 'host_id': host_id}

    async def capture_forensics(self, context, params):
        """Capture forensic image."""
        host_id = context['alert']['host_id']
        result = await self.forensics.capture_image(host_id)
        return {'image_captured': result, 'image_id': result.get('image_id')}

    async def scan_lateral(self, context, params):
        """Scan for lateral movement."""
        host_id = context['alert']['host_id']
        # Check network connections from this host
        connections = await self.network.get_connections(host_id, hours=1)
        lateral = [c for c in connections if c['is_internal']]
        return {'lateral_connections': len(lateral), 'details': lateral}

    async def block_c2(self, context, params):
        """Block command & control domains."""
        c2_domains = context['alert'].get('c2_domains', [])
        for domain in c2_domains:
            await self.firewall.block_domain(domain)
        return {'blocked_domains': len(c2_domains)}

    async def reimage_host(self, context, params):
        """Reimage infected host from known-good image."""
        host_id = context['alert']['host_id']
        result = await self.mdm.reimage(host_id)
        return {'reimaged': result}
```

### SOAR Workflow Engine
```python
import asyncio
from typing import Dict, List, Callable

class SOAREngine:
    """SOAR workflow engine — execute playbooks automatically."""

    def __init__(self):
        self.playbooks: Dict[str, SOARPlaybook] = {}
        self.triggers: List[Dict] = []
        self.running_playbooks: Dict[str, asyncio.Task] = {}

    def register_playbook(self, playbook: SOARPlaybook):
        """Register a playbook."""
        self.playbooks[playbook.name] = playbook

    def register_trigger(self, event_type, condition, playbook_name):
        """Register trigger — auto-run playbook on event."""
        self.triggers.append({
            'event_type': event_type,
            'condition': condition,
            'playbook': playbook_name,
        })

    async def handle_event(self, event):
        """Handle incoming event — trigger matching playbooks."""
        for trigger in self.triggers:
            if event['type'] == trigger['event_type']:
                # Evaluate condition
                if self._evaluate_condition(trigger['condition'], event):
                    playbook = self.playbooks[trigger['playbook']]
                    await self.execute_playbook(playbook, {'event': event})

    async def execute_playbook(self, playbook, context):
        """Execute playbook in background."""
        task = asyncio.create_task(playbook.execute(context))
        self.running_playbooks[f'{playbook.name}_{id(task)}'] = task

        # Wait for completion (or timeout)
        try:
            result = await asyncio.wait_for(task, timeout=3600)  # 1 hour max
            return result
        except asyncio.TimeoutError:
            task.cancel()
            playbook.status = PlaybookStatus.CANCELLED
            return playbook

    def _evaluate_condition(self, condition, event):
        """Evaluate trigger condition."""
        # Simple condition evaluation
        return eval(condition, {'event': event})

# ─── Setup Example ───
engine = SOAREngine()

# Register playbooks
engine.register_playbook(PhishingResponsePlaybook())
engine.register_playbook(CredentialCompromisePlaybook())
engine.register_playbook(MalwareResponsePlaybook())

# Register triggers
engine.register_trigger(
    event_type='phishing_alert',
    condition='event["severity"] in ["high", "critical"]',
    playbook_name='phishing_response',
)

engine.register_trigger(
    event_type='credential_alert',
    condition='event["anomaly_score"] > 0.8',
    playbook_name='credential_compromise',
)

engine.register_trigger(
    event_type='malware_alert',
    condition='event["severity"] == "critical"',
    playbook_name='malware_response',
)
```

---

## AUDIT CHECKLIST

- [ ] SOAR platform deployed (or custom engine built)
- [ ] Playbooks for common incidents (phishing, malware, credential compromise)
- [ ] Automated enrichment (threat intel, asset info, user info)
- [ ] Automated containment (isolate host, block IP, disable account)
- [ ] Automated notification (user, manager, security team)
- [ ] Automated ticketing (create, update, close)
- [ ] Playbook versioning and change management
- [ ] Playbook testing (in sandbox before production)
- [ ] Playbook approval workflow (security team review)
- [ ] Playbook metrics (execution time, success rate, false positive rate)
- [ ] Playbook documentation (what it does, when it triggers)
- [ ] Human-in-the-loop (approval for destructive actions)
- [ ] Rollback capability (undo automated actions)
- [ ] Integration with SIEM, EDR, firewall, email gateway
- [ ] Integration with ticketing system (Jira, ServiceNow)
- [ ] Audit logging (all automated actions logged)
- [ ] Continuous improvement (learn from playbook results)
