# Skill 65 — Security Awareness & Gamification

> Cyphron's methodology for building gamified security awareness programs. Cyphron knows that traditional security training is boring and ineffective — and builds gamified programs that engage users, measure learning, and change behavior.

---

## WHEN TO ACTIVATE

- User asks to build a security awareness program
- User asks about gamification for security training
- User asks about security culture or behavior change
- User asks about CTF-style training or security games

---

## METHODOLOGY

### Gamification Principles

| Principle | Application | Example |
|---|---|---|
| Points | Reward engagement | +10 pts for reporting phishing |
| Badges | Recognize achievements | "Phishing Hunter" badge |
| Leaderboards | Foster competition | Top reporters per team |
| Levels | Show progression | Level 1 → Level 5 security expert |
| Challenges | Create engagement | Monthly security challenge |
| Story | Make it memorable | "Defend the Kingdom" narrative |
| Feedback | Show progress | Real-time score updates |

### Program Structure

```
Onboarding → Learning → Practice → Compete → Master → Mentor
    ↑                                                        │
    └──────────────── Continuous Engagement ─────────────────┘
```

---

## PROGRAM TEMPLATES

### Gamified Security Awareness Platform
```python
class SecurityGamification:
    """Gamified security awareness platform."""

    def __init__(self, db):
        self.db = db

    # ─── Points System ───
    def award_points(self, user_id, action, points=None):
        """Award points for security actions."""
        points_map = {
            'report_phishing': 10,
            'complete_training': 50,
            'pass_quiz': 20,
            'find_vulnerability': 100,
            'mentor_colleague': 30,
            'attend_workshop': 15,
            'complete_challenge': 25,
            'report_suspicious_activity': 15,
            'update_password': 5,
            'enable_mfa': 20,
        }

        points = points or points_map.get(action, 5)
        user = self.db.get('users', user_id)
        user['points'] = user.get('points', 0) + points

        # Check for level up
        new_level = self._calculate_level(user['points'])
        if new_level > user.get('level', 1):
            user['level'] = new_level
            self._send_level_up_notification(user_id, new_level)

        self.db.update('users', user_id, user)
        return {'points_awarded': points, 'total_points': user['points'], 'level': new_level}

    def _calculate_level(self, points):
        """Calculate user level from points."""
        levels = [0, 100, 250, 500, 1000, 2000, 5000, 10000]
        for i, threshold in enumerate(levels):
            if points < threshold:
                return i
        return len(levels)

    # ─── Badges System ───
    def award_badge(self, user_id, badge_id):
        """Award badge for achievement."""
        badges = {
            'first_report': {'name': 'First Report', 'description': 'Reported first phishing email'},
            'phishing_hunter': {'name': 'Phishing Hunter', 'description': 'Reported 10 phishing emails'},
            'phishing_master': {'name': 'Phishing Master', 'description': 'Reported 50 phishing emails'},
            'training_complete': {'name': 'Trained', 'description': 'Completed annual security training'},
            'quiz_master': {'name': 'Quiz Master', 'description': 'Scored 100% on security quiz'},
            'vulnerability_finder': {'name': 'Vuln Finder', 'description': 'Found a security vulnerability'},
            'mentor': {'name': 'Mentor', 'description': 'Mentored 3 colleagues on security'},
            'champion': {'name': 'Security Champion', 'description': 'Became security champion'},
            'mfa_enabled': {'name': 'MFA Enabled', 'description': 'Enabled multi-factor authentication'},
            'password_pro': {'name': 'Password Pro', 'description': 'Used password manager for 30 days'},
        }

        user = self.db.get('users', user_id)
        if 'badges' not in user:
            user['badges'] = []

        if badge_id not in [b['id'] for b in user['badges']]:
            badge = badges.get(badge_id)
            if badge:
                user['badges'].append({
                    'id': badge_id,
                    'name': badge['name'],
                    'description': badge['description'],
                    'awarded_at': datetime.now().isoformat(),
                })
                self.db.update('users', user_id, user)
                self._send_badge_notification(user_id, badge)

        return badge

    # ─── Leaderboard ───
    def get_leaderboard(self, period='monthly', limit=10):
        """Get leaderboard for period."""
        users = self.db.query('SELECT * FROM users ORDER BY points DESC LIMIT ?', [limit])

        leaderboard = []
        for i, user in enumerate(users):
            leaderboard.append({
                'rank': i + 1,
                'user_id': user['id'],
                'name': user['name'],
                'points': user['points'],
                'level': user.get('level', 1),
                'badges': len(user.get('badges', [])),
                'team': user.get('team', 'Unknown'),
            })

        return leaderboard

    # ─── Challenges ───
    def create_challenge(self, title, description, challenge_type, points, start_date, end_date):
        """Create security challenge."""
        challenge = {
            'id': generate_id(),
            'title': title,
            'description': description,
            'type': challenge_type,  # 'quiz', 'ctf', 'scenario', 'puzzle'
            'points': points,
            'start_date': start_date,
            'end_date': end_date,
            'status': 'active',
            'participants': [],
            'completions': [],
        }
        self.db.insert('challenges', challenge)
        return challenge

    def complete_challenge(self, user_id, challenge_id, score=100):
        """Record challenge completion."""
        challenge = self.db.get('challenges', challenge_id)
        user = self.db.get('users', user_id)

        # Award points
        points_earned = int(challenge['points'] * (score / 100))
        self.award_points(user_id, 'complete_challenge', points_earned)

        # Record completion
        completion = {
            'user_id': user_id,
            'challenge_id': challenge_id,
            'score': score,
            'completed_at': datetime.now().isoformat(),
            'points_earned': points_earned,
        }
        challenge['completions'].append(completion)
        self.db.update('challenges', challenge_id, challenge)

        # Check for badge
        if score == 100:
            self.award_badge(user_id, 'quiz_master')

        return completion

    # ─── Phishing Simulation with Gamification ───
    def run_phishing_simulation(self, template_id, targets):
        """Run phishing simulation with gamified scoring."""
        results = {
            'sent': 0,
            'clicked': 0,
            'reported': 0,
            'ignored': 0,
        }

        for target in targets:
            # Send simulation
            self._send_simulation(target, template_id)
            results['sent'] += 1

        # Track results
        for target in targets:
            action = self._get_user_action(target, template_id)
            if action == 'clicked':
                results['clicked'] += 1
                # Deduct points for clicking
                self.award_points(target, 'phishing_click', -5)
            elif action == 'reported':
                results['reported'] += 1
                # Award points for reporting
                self.award_points(target, 'report_phishing')
                # Check for badge
                user = self.db.get('users', target)
                report_count = user.get('phishing_reports', 0) + 1
                user['phishing_reports'] = report_count
                self.db.update('users', target, user)

                if report_count == 1:
                    self.award_badge(target, 'first_report')
                elif report_count == 10:
                    self.award_badge(target, 'phishing_hunter')
                elif report_count == 50:
                    self.award_badge(target, 'phishing_master')
            else:
                results['ignored'] += 1

        # Team competition
        self._update_team_scores(results)

        return results

    # ─── Security Quest (CTF-style) ───
    def create_security_quest(self, title, description, stages):
        """Create multi-stage security quest (CTF-style)."""
        quest = {
            'id': generate_id(),
            'title': title,
            'description': description,
            'stages': stages,  # list of stage objects
            'status': 'active',
            'participants': [],
            'completions': [],
        }
        self.db.insert('quests', quest)
        return quest

    def get_quest_progress(self, user_id, quest_id):
        """Get user's progress on quest."""
        quest = self.db.get('quests', quest_id)
        user_progress = next(
            (p for p in quest['participants'] if p['user_id'] == user_id),
            {'current_stage': 0, 'completed_stages': []}
        )
        return {
            'quest': quest['title'],
            'current_stage': user_progress['current_stage'],
            'total_stages': len(quest['stages']),
            'completed_stages': user_progress['completed_stages'],
            'progress_pct': round(user_progress['current_stage'] / len(quest['stages']) * 100, 1),
        }

    def complete_quest_stage(self, user_id, quest_id, stage_id, answer):
        """Complete a quest stage."""
        quest = self.db.get('quests', quest_id)
        stage = next((s for s in quest['stages'] if s['id'] == stage_id), None)

        if not stage:
            return {'error': 'Stage not found'}

        # Verify answer
        if self._verify_answer(stage, answer):
            # Award points
            self.award_points(user_id, 'complete_challenge', stage['points'])

            # Update progress
            user_progress = next(
                (p for p in quest['participants'] if p['user_id'] == user_id),
                None
            )
            if not user_progress:
                user_progress = {'user_id': user_id, 'current_stage': 0, 'completed_stages': []}
                quest['participants'].append(user_progress)

            user_progress['completed_stages'].append(stage_id)
            user_progress['current_stage'] = len(user_progress['completed_stages'])

            # Check if quest complete
            if len(user_progress['completed_stages']) == len(quest['stages']):
                self.award_badge(user_id, 'champion')

            self.db.update('quests', quest_id, quest)

            return {
                'correct': True,
                'points_earned': stage['points'],
                'next_stage': user_progress['current_stage'],
                'quest_complete': len(user_progress['completed_stages']) == len(quest['stages']),
            }

        return {'correct': False, 'message': 'Incorrect answer, try again'}
```

### Gamified Training Content
```markdown
# Security Quest: The Kingdom Defense

## Story
You are the newly appointed Security Guardian of the Kingdom of Cyphron.
The kingdom is under attack from the Dark Hacker Army. Your mission is to
defend the kingdom by completing security challenges and earning badges.

## Stage 1: The Phishing Invasion (100 points)
The Dark Hacker Army has launched a phishing campaign against the kingdom.
Citizens are receiving suspicious emails claiming to be from the Royal Bank.

**Challenge**: Identify which emails are phishing attempts.

**Emails to analyze**:
1. "URGENT: Your account has been suspended. Click here to verify."
   From: royal-bank@secure-verify.com
   
2. "Your monthly statement is ready."
   From: royal-bank@kingdom.com

3. "Congratulations! You've won a prize. Claim now!"
   From: royal-lottery@winner-kingdom.com

**Answer**: [Interactive email analysis]

## Stage 2: The Password Fortress (150 points)
The kingdom's password fortress is weak. Many citizens use weak passwords
that are easily guessed by the Dark Hacker Army.

**Challenge**: Create a strong password policy and identify weak passwords.

**Weak passwords to identify**:
- password123
- kingdom2024
- qwerty
- royal
- 12345678

**Answer**: [Interactive password analyzer]

## Stage 3: The Malware Trap (200 points)
The Dark Hacker Army has planted malware in the kingdom's software supply
chain. Some packages are infected with malicious code.

**Challenge**: Identify which code snippets contain malware.

**Code snippets to analyze**:
[Interactive code review]

## Stage 4: The Insider Threat (250 points)
A traitor has been discovered within the kingdom's walls. Someone is
leaking sensitive information to the Dark Hacker Army.

**Challenge**: Analyze access logs to identify the insider.

**Log entries to analyze**:
[Interactive log analysis]

## Stage 5: The Final Defense (300 points)
The Dark Hacker Army is launching a full-scale attack on the kingdom's
main server. You must configure the final defenses.

**Challenge**: Configure firewall rules, set up monitoring, and prepare
incident response.

**Answer**: [Interactive security configuration]

## Rewards
- Complete Stage 1: "Phishing Hunter" badge + 100 points
- Complete Stage 2: "Password Pro" badge + 150 points
- Complete Stage 3: "Code Guardian" badge + 200 points
- Complete Stage 4: "Threat Hunter" badge + 250 points
- Complete Stage 5: "Kingdom Defender" badge + 300 points
- Complete all stages: "Security Champion" badge + 500 bonus points

## Leaderboard
Top defenders will be honored in the Royal Hall of Fame.
```

### Team Competition
```python
class TeamCompetition:
    """Team-based security competition."""

    def __init__(self, db):
        self.db = db

    def create_competition(self, name, start_date, end_date, teams):
        """Create team competition."""
        competition = {
            'id': generate_id(),
            'name': name,
            'start_date': start_date,
            'end_date': end_date,
            'teams': teams,
            'status': 'active',
            'scores': {team: 0 for team in teams},
            'activities': [],
        }
        self.db.insert('competitions', competition)
        return competition

    def record_activity(self, competition_id, team, activity_type, points):
        """Record team activity and update score."""
        competition = self.db.get('competitions', competition_id)

        activity = {
            'team': team,
            'type': activity_type,
            'points': points,
            'timestamp': datetime.now().isoformat(),
        }
        competition['activities'].append(activity)
        competition['scores'][team] = competition['scores'].get(team, 0) + points

        self.db.update('competitions', competition_id, competition)

        return {
            'team': team,
            'activity': activity_type,
            'points_earned': points,
            'team_total': competition['scores'][team],
        }

    def get_competition_standings(self, competition_id):
        """Get current competition standings."""
        competition = self.db.get('competitions', competition_id)

        standings = sorted(
            competition['scores'].items(),
            key=lambda x: x[1],
            reverse=True
        )

        return {
            'competition': competition['name'],
            'standings': [
                {'rank': i + 1, 'team': team, 'score': score}
                for i, (team, score) in enumerate(standings)
            ],
            'period': f"{competition['start_date']} to {competition['end_date']}",
        }
```

---

## AUDIT CHECKLIST

- [ ] Gamified security awareness program documented
- [ ] Points system (reward security actions)
- [ ] Badges system (recognize achievements)
- [ ] Leaderboard (foster competition)
- [ ] Levels system (show progression)
- [ ] Security challenges (monthly, varied difficulty)
- [ ] Security quests (CTF-style, multi-stage)
- [ ] Team competitions (quarterly, cross-team)
- [ ] Phishing simulation with gamified scoring
- [ ] Real-time feedback (score updates, notifications)
- [ ] Progress tracking (dashboard, metrics)
- [ ] Story/narrative (make it memorable)
- [ ] Rewards (recognition, not just points)
- [ ] Mentorship program (experienced users help new users)
- [ ] Continuous engagement (not just annual training)
- [ ] Behavior measurement (click rate, report rate, training completion)
- [ ] Program effectiveness measured (before/after comparison)
- [ ] User feedback collected and acted on
- [ ] Program updated regularly (new challenges, new content)
