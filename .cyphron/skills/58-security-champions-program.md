# Skill 58 — Security Champions Program

> Cyphron's methodology for building security champions programs. Cyphron knows that security can't scale through a central team alone — you need security advocates embedded in every development team. Cyphron builds programs that turn developers into security champions.

---

## WHEN TO ACTIVATE

- User asks to build a security champions program
- User asks about scaling security across development teams
- User asks about security advocacy or security culture
- User asks about developer security training

---

## METHODOLOGY

### Security Champions Program Structure

```
Security Team (Central)
    ├── Security Champions (Per Team)
    │       ├── Team A — 1-2 champions
    │       ├── Team B — 1-2 champions
    │       └── Team C — 1-2 champions
    │
    └── Security Community (All Champions)
            ├── Monthly meetings
            ├── Slack channel
            ├── Training sessions
            └── Tool sharing
```

### Champion Responsibilities

| Responsibility | Time Commitment |
|---|---|
| Review team's code for security issues | 2-4 hours/week |
| Attend security training | 1 hour/week |
| Share security knowledge with team | 1 hour/week |
| Escalate security issues to security team | As needed |
| Participate in security community | 2 hours/month |

### Program Phases
1. **Recruit** — Identify and recruit champions from each team
2. **Train** — Provide security training and resources
3. **Enable** — Give champions tools and authority
4. **Support** — Ongoing support from security team
5. **Measure** — Track program effectiveness
6. **Scale** — Expand to more teams

---

## PROGRAM TEMPLATES

### Security Champion Role Description
```markdown
# Security Champion — Role Description

## Overview
Security Champions are developers who advocate for security within
their teams. They are the first line of defense, helping their team
build secure software by design.

## Responsibilities

### Code Review (Primary)
- Review team's pull requests for security issues
- Use SAST tools (Semgrep, CodeQL) to catch common vulnerabilities
- Apply secure coding guidelines (OWASP Top 10)
- Escalate complex security issues to security team

### Security Advocacy
- Share security best practices with team
- Answer security questions from teammates
- Promote security awareness within team
- Represent team in security community meetings

### Threat Modeling
- Participate in threat modeling for new features
- Identify security requirements during design
- Ensure security is considered from the start

### Incident Support
- Assist in security incident response
- Provide context about team's code and architecture
- Help implement security fixes

## Qualifications

### Required
- 2+ years of development experience
- Strong understanding of team's codebase
- Interest in security (no prior security experience required)
- Good communication skills
- Willingness to learn

### Preferred
- Experience with SAST/DAST tools
- Understanding of OWASP Top 10
- Previous security training or certification
- Experience with threat modeling

## Training Provided

### Initial Training (8 hours)
- Secure coding fundamentals (OWASP Top 10)
- Code review for security
- SAST/DAST tool usage
- Threat modeling basics
- Incident response overview

### Ongoing Training (1 hour/week)
- Advanced secure coding topics
- New attack techniques and defenses
- Tool updates and new features
- Case studies from real incidents

### Certification (Optional)
- Security+ or equivalent (company-sponsored)
- Secure coding certification
- Conference attendance (one per year)

## Time Commitment
- **Code review**: 2-4 hours/week
- **Training**: 1 hour/week
- **Community**: 2 hours/month
- **Total**: ~4-6 hours/week

## Benefits
- Security training and certification
- Conference attendance
- Recognition (champion badge, hall of fame)
- Career development (security career path)
- Direct access to security team
- Influence on security tooling and process

## Reporting
- **Primary**: Team lead (day-to-day work)
- **Secondary**: Security team (security responsibilities)
- **Community**: Security champions community

## Success Metrics
- Code review coverage (% of PRs reviewed)
- Security issues found in review (vs. found in production)
- Time to fix security issues (vs. before program)
- Team security knowledge (survey scores)
- Security incidents in team's code (trending down)
```

### Security Champions Program Plan
```python
class SecurityChampionsProgram:
    """Manage security champions program."""

    def __init__(self):
        self.champions = {}
        self.teams = {}
        self.training_records = {}

    def recruit_champion(self, team_id, developer_id, name, email):
        """Recruit a security champion for a team."""
        if team_id not in self.teams:
            self.teams[team_id] = {'champions': [], 'lead': None}

        champion = {
            'id': developer_id,
            'name': name,
            'email': email,
            'team_id': team_id,
            'recruited_at': datetime.now().isoformat(),
            'training_completed': False,
            'active': True,
            'stats': {
                'prs_reviewed': 0,
                'issues_found': 0,
                'escalations': 0,
            },
        }

        self.teams[team_id]['champions'].append(champion)
        self.champions[developer_id] = champion
        return champion

    def complete_training(self, developer_id, training_type='initial'):
        """Record training completion."""
        if developer_id in self.champions:
            self.champions[developer_id]['training_completed'] = True
            self.champions[developer_id]['training_type'] = training_type
            self.champions[developer_id]['training_completed_at'] = datetime.now().isoformat()

    def record_review(self, developer_id, pr_id, issues_found):
        """Record a code review by champion."""
        if developer_id in self.champions:
            stats = self.champions[developer_id]['stats']
            stats['prs_reviewed'] += 1
            stats['issues_found'] += issues_found

    def record_escalation(self, developer_id, issue_id):
        """Record an escalation to security team."""
        if developer_id in self.champions:
            self.champions[developer_id]['stats']['escalations'] += 1

    def get_program_metrics(self):
        """Get program effectiveness metrics."""
        total_champions = len([c for c in self.champions.values() if c['active']])
        total_teams = len(self.teams)
        teams_with_champion = len([t for t in self.teams.values() if t['champions']])

        total_reviews = sum(c['stats']['prs_reviewed'] for c in self.champions.values())
        total_issues = sum(c['stats']['issues_found'] for c in self.champions.values())
        total_escalations = sum(c['stats']['escalations'] for c in self.champions.values())

        return {
            'total_champions': total_champions,
            'total_teams': total_teams,
            'teams_with_champion': teams_with_champion,
            'coverage_pct': round(teams_with_champion / total_teams * 100, 1) if total_teams > 0 else 0,
            'total_reviews': total_reviews,
            'total_issues_found': total_issues,
            'total_escalations': total_escalations,
            'avg_issues_per_review': round(total_issues / total_reviews, 2) if total_reviews > 0 else 0,
        }
```

### Security Champions Community Structure
```markdown
# Security Champions Community

## Communication Channels

### Slack Channel (#security-champions)
- Daily: Quick questions, tool tips, article sharing
- Weekly: Review stats, challenge of the week
- Monthly: Program updates, training announcements

### Monthly Meeting (1 hour)
- **15 min**: Security news and updates
- **20 min**: Case study (real vulnerability found by champion)
- **15 min**: Tool demo or training
- **10 min**: Q&A and discussion

### Quarterly Workshop (2 hours)
- Deep dive on specific security topic
- Hands-on lab (secure coding, threat modeling)
- Guest speaker (external security expert)
- Program feedback and improvement

## Resources

### Security Champions Portal
- Secure coding guidelines
- Code review checklist
- SAST/DAST tool documentation
- Threat modeling templates
- Incident response runbook
- Training videos and materials

### Security Champions Toolkit
- SAST tools (Semgrep, CodeQL)
- DAST tools (OWASP ZAP)
- Dependency scanning (Snyk)
- Secret scanning (gitleaks)
- Security headers checker
- CSP evaluator

## Recognition

### Champion Badges
- **Bronze**: Complete initial training
- **Silver**: 6 months active + 50 PRs reviewed
- **Gold**: 1 year active + 100 PRs reviewed + 10 escalations
- **Platinum**: 2 years active + mentor new champions

### Hall of Fame
- Monthly: Champion of the month
- Quarterly: Top issue finder
- Annually: Champion of the year

### Rewards
- Conference attendance (top performers)
- Security certification sponsorship
- Special training sessions
- Direct access to security leadership
```

---

## AUDIT CHECKLIST

- [ ] Security champions program documented
- [ ] Champions recruited from each development team
- [ ] Initial training completed (8 hours per champion)
- [ ] Ongoing training scheduled (1 hour/week)
- [ ] Champions have access to SAST/DAST tools
- [ ] Code review checklist provided
- [ ] Escalation path to security team defined
- [ ] Community channels established (Slack, meetings)
- [ ] Recognition program (badges, hall of fame)
- [ ] Program metrics tracked (reviews, issues, escalations)
- [ ] Program effectiveness measured (before/after comparison)
- [ ] Champions supported by security team
- [ ] Program expanded to all teams
- [ ] Champions retention tracked
- [ ] Program feedback collected and acted on
