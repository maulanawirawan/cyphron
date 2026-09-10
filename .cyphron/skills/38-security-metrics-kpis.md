# Skill 38 — Security Metrics & KPIs

> Cyphron's methodology for building security metrics and KPIs that measure security program effectiveness. Cyphron knows that "you can't manage what you can't measure" — and builds metrics that are actionable, meaningful, and aligned with business risk.

---

## WHEN TO ACTIVATE

- User asks to build security metrics or a security dashboard
- User asks about security KPIs or OKRs
- User asks to measure security program effectiveness
- User asks about security reporting to executives or board

---

## METHODOLOGY

### Step 1: Define Metric Categories

| Category | Purpose | Audience |
|---|---|---|
| Operational | Day-to-day security operations | Security team |
| Programmatic | Security program maturity | CISO, management |
| Risk | Risk posture and trends | Executive, board |
| Compliance | Regulatory adherence | Compliance, audit |
| Incident | Incident metrics | Security, executive |

### Step 2: Apply SMART Criteria
Metrics should be: Specific, Measurable, Actionable, Relevant, Time-bound

### Step 3: Build Metrics Program

---

## METRICS CATALOG

### Operational Metrics
```python
class SecurityMetrics:
    def __init__(self, data_source):
        self.db = data_source

    # ─── Vulnerability Metrics ───
    def vuln_mttr(self, period_days=30):
        """Mean Time To Remediate vulnerabilities."""
        query = """
            SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - discovered_at))/3600) as mttr_hours
            FROM vulnerabilities
            WHERE status = 'resolved'
              AND resolved_at > NOW() - INTERVAL '%s days'
        """
        result = self.db.execute(query % period_days)
        return {'mttr_hours': result[0]['mttr_hours']}

    def vuln_sla_compliance(self, period_days=30):
        """Percentage of vulnerabilities remediated within SLA."""
        query = """
            SELECT
              COUNT(*) FILTER (WHERE resolved_at <= sla_deadline) as within_sla,
              COUNT(*) as total
            FROM vulnerabilities
            WHERE status = 'resolved'
              AND resolved_at > NOW() - INTERVAL '%s days'
        """
        result = self.db.execute(query % period_days)[0]
        pct = (result['within_sla'] / result['total'] * 100) if result['total'] > 0 else 100
        return {'sla_compliance_pct': round(pct, 1)}

    def open_vulns_by_severity(self):
        """Count of open vulnerabilities by severity."""
        query = """
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            WHERE status = 'open'
            GROUP BY severity
            ORDER BY
              CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
              END
        """
        return self.db.execute(query)

    # ─── Patch Metrics ───
    def patch_coverage(self):
        """Percentage of systems patched within SLA."""
        query = """
            SELECT
              COUNT(*) FILTER (WHERE patched_within_sla) as patched,
              COUNT(*) as total
            FROM systems
            WHERE last_scan > NOW() - INTERVAL '7 days'
        """
        result = self.db.execute(query)[0]
        pct = (result['patched'] / result['total'] * 100) if result['total'] > 0 else 0
        return {'patch_coverage_pct': round(pct, 1)}

    # ─── Incident Metrics ───
    def incident_metrics(self, period_days=90):
        """Incident response metrics."""
        query = """
            SELECT
              COUNT(*) as total_incidents,
              COUNT(*) FILTER (WHERE severity = 'Critical') as critical,
              COUNT(*) FILTER (WHERE severity = 'High') as high,
              AVG(EXTRACT(EPOCH FROM (contained_at - detected_at))/3600) as mttd_hours,
              AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at))/3600) as mttr_hours
            FROM incidents
            WHERE detected_at > NOW() - INTERVAL '%s days'
        """
        return self.db.execute(query % period_days)[0]

    # ─── Detection Metrics ───
    def detection_metrics(self, period_days=30):
        """Detection engineering metrics."""
        query = """
            SELECT
              COUNT(*) as total_alerts,
              COUNT(*) FILTER (WHERE true_positive) as true_positives,
              COUNT(*) FILTER (WHERE NOT true_positive) as false_positives,
              AVG(EXTRACT(EPOCH FROM (triaged_at - alert_time))/60) as mtt_triage_min
            FROM alerts
            WHERE alert_time > NOW() - INTERVAL '%s days'
        """
        result = self.db.execute(query % period_days)[0]
        precision = (result['true_positives'] / result['total_alerts'] * 100) \
            if result['total_alerts'] > 0 else 0
        return {
            **result,
            'detection_precision_pct': round(precision, 1),
        }

    # ─── Access Control Metrics ───
    def access_metrics(self):
        """IAM and access control metrics."""
        return {
            'mfa_coverage_pct': self._mfa_coverage(),
            'orphaned_accounts': self._orphaned_accounts(),
            'privileged_accounts': self._privileged_accounts(),
            'access_reviews_overdue': self._overdue_reviews(),
        }

    def _mfa_coverage(self):
        query = """
            SELECT
              COUNT(*) FILTER (WHERE mfa_enabled) as with_mfa,
              COUNT(*) as total
            FROM users WHERE active = true
        """
        result = self.db.execute(query)[0]
        return round(result['with_mfa'] / result['total'] * 100, 1) if result['total'] > 0 else 0

    # ─── Security Awareness Metrics ───
    def awareness_metrics(self):
        """Security training and awareness metrics."""
        return {
            'training_completion_pct': self._training_completion(),
            'phishing_click_rate': self._phishing_click_rate(),
            'phishing_report_rate': self._phishing_report_rate(),
        }

    def _phishing_click_rate(self):
        query = """
            SELECT
              COUNT(*) FILTER (WHERE clicked) as clicked,
              COUNT(*) as total
            FROM phishing_simulations
            WHERE sent_at > NOW() - INTERVAL '90 days'
        """
        result = self.db.execute(query)[0]
        return round(result['clicked'] / result['total'] * 100, 1) if result['total'] > 0 else 0

    # ─── Executive Dashboard ───
    def executive_dashboard(self):
        """Generate executive security dashboard."""
        return {
            'risk_posture': {
                'critical_open_vulns': self.open_vulns_by_severity()[0]['count'],
                'overdue_sla': self._overdue_vulns(),
                'open_incidents': self._open_incidents(),
            },
            'operational_health': {
                'patch_coverage': self.patch_coverage()['patch_coverage_pct'],
                'vuln_mttr_hours': self.vuln_mttr()['mttr_hours'],
                'detection_precision': self.detection_metrics()['detection_precision_pct'],
            },
            'compliance': {
                'policy_compliance_pct': self._policy_compliance(),
                'training_completion': self._training_completion(),
                'access_reviews_current': self._access_reviews_current(),
            },
            'trend': self._risk_trend(),
        }
```

---

## KPI DEFINITIONS

### Security Program KPIs
```markdown
| KPI | Target | Measurement | Frequency |
|---|---|---|---|
| Critical vuln MTTR | < 72 hours | Avg time to fix critical | Weekly |
| Vuln SLA compliance | > 95% | % fixed within SLA | Monthly |
| Patch coverage | > 98% | % systems patched | Weekly |
| MFA coverage | 100% | % users with MFA | Monthly |
| Phishing click rate | < 5% | % who click in simulation | Quarterly |
| Phishing report rate | > 80% | % who report phishing | Quarterly |
| Training completion | 100% | % completed annual training | Quarterly |
| Detection precision | > 80% | % true positive alerts | Monthly |
| MTTD (Mean Time To Detect) | < 1 hour | Avg detection time | Monthly |
| MTTR (Mean Time To Respond) | < 4 hours | Avg response time | Monthly |
| Access review completion | 100% | % completed on time | Quarterly |
| Incident count trend | Decreasing | YoY incident count | Quarterly |
| Security findings in code | Decreasing | SAST findings per release | Per release |
| Third-party risk assessed | 100% | % vendors assessed | Quarterly |
```

### Board-Level Metrics (Simplified)
```markdown
| Metric | Target | Current | Trend |
|---|---|---|---|
| Overall risk score | < Medium | [value] | [↑/↓/→] |
| Critical vulnerabilities (open) | 0 | [count] | [trend] |
| Security incidents (this quarter) | 0 Critical | [count] | [trend] |
| Compliance status | 100% | [%] | [trend] |
| Security investment vs. budget | On track | [%] | [trend] |
```

---

## AUDIT CHECKLIST

- [ ] Security metrics defined and documented
- [ ] Metrics aligned with business risk
- [ ] Automated data collection (not manual)
- [ ] Metrics dashboard accessible to stakeholders
- [ ] Executive reporting (monthly/quarterly)
- [ ] Board reporting (quarterly)
- [ ] Trend analysis (not just point-in-time)
- [ ] Benchmarks against industry (where available)
- [ ] Action items derived from metrics
- [ ] Metrics reviewed and updated annually
