# Skill 29 — Privacy Engineering (GDPR/CCPA)

> Cyphron's methodology for building privacy-preserving systems. Cyphron knows privacy attack vectors — re-identification, data linkage, inference attacks — and builds privacy controls following GDPR, CCPA, and Privacy by Design principles.

---

## WHEN TO ACTIVATE

- User asks about GDPR, CCPA, or data privacy compliance
- User asks to implement data subject rights (access, deletion, portability)
- User asks about data minimization, anonymization, or pseudonymization
- User asks about consent management or privacy policies
- User asks about Privacy by Design

---

## METHODOLOGY

### Step 1: Identify Applicable Regulations
- GDPR (EU) — if processing EU residents' data
- CCPA/CPRA (California) — if processing California residents' data
- HIPAA (US healthcare)
- PDPA (Singapore, Indonesia)
- LGPD (Brazil)

### Step 2: Privacy by Design (7 Principles)
1. **Proactive not reactive** — prevent privacy invasions before they happen
2. **Privacy as default** — no action needed to protect privacy
3. **Privacy embedded in design** — not bolted on
4. **Full functionality** — positive-sum, not zero-sum
5. **End-to-end security** — full lifecycle protection
6. **Visibility & transparency** — accountable, auditable
7. **Respect for user privacy** — user-centric

### Step 3: Build Privacy Controls

---

## SECURE PATTERNS

### Data Subject Rights — Right to Erasure (GDPR Article 17)
```javascript
// Express endpoint — handle deletion requests
app.delete('/api/privacy/data/:userId', auth, requireRole('user', 'admin'), async (req, res) => {
  const userId = req.params.userId === 'me' ? req.user.id : req.params.userId;

  // Only allow users to delete their own data (or admin)
  if (req.params.userId !== 'me' && req.user.id !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const deletion = await executeDataDeletion(userId);

  res.json({
    message: 'Data deletion completed',
    deletedRecords: deletion.count,
    deletedTables: deletion.tables,
    requestId: deletion.requestId,  // for audit trail
    completedAt: new Date().toISOString(),
  });
});

async function executeDataDeletion(userId) {
  const tables = [
    'users', 'orders', 'addresses', 'payment_methods',
    'preferences', 'sessions', 'audit_logs', 'feedback'
  ];
  let totalDeleted = 0;

  for (const table of tables) {
    const result = await db.query(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
    totalDeleted += result.rowCount;
  }

  // Anonymize instead of delete where data must be retained (e.g., financial records)
  await db.query(
    `UPDATE transactions SET user_id = NULL, user_email = 'deleted@anonymous',
     user_ip = NULL WHERE user_id = $1`,
    [userId]
  );

  // Log the deletion (without retaining the user's data)
  await db.query(
    `INSERT INTO deletion_requests (user_id_hash, completed_at, records_deleted)
     VALUES ($1, NOW(), $2)`,
    [hash(userId), totalDeleted]
  );

  return { count: totalDeleted, tables, requestId: generateRequestId() };
}
```

### Data Subject Rights — Right to Access (GDPR Article 15)
```javascript
app.get('/api/privacy/data/export', auth, async (req, res) => {
  const userId = req.user.id;

  const userData = {
    profile: await db.query('SELECT * FROM users WHERE id = $1', [userId]),
    orders: await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]),
    addresses: await db.query('SELECT * FROM addresses WHERE user_id = $1', [userId]),
    preferences: await db.query('SELECT * FROM preferences WHERE user_id = $1', [userId]),
    sessions: await db.query('SELECT ip, user_agent, created_at FROM sessions WHERE user_id = $1', [userId]),
    consentHistory: await db.query('SELECT * FROM consent_log WHERE user_id = $1', [userId]),
  };

  // Generate downloadable JSON export
  const exportData = JSON.stringify(userData, null, 2);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="data-export-${userId}.json"`);
  res.send(exportData);
});
```

### Consent Management
```javascript
class ConsentManager {
  async recordConsent(userId, purpose, granted, source = 'web') {
    await db.query(
      `INSERT INTO consent_log (user_id, purpose, granted, source, timestamp)
       VALUES ($1, $2, $3, $4, NOW())`,
      [userId, purpose, granted, source]
    );
  }

  async hasConsent(userId, purpose) {
    const result = await db.query(
      `SELECT granted FROM consent_log
       WHERE user_id = $1 AND purpose = $2
       ORDER BY timestamp DESC LIMIT 1`,
      [userId, purpose]
    );
    return result.rows[0]?.granted || false;
  }

  async withdrawConsent(userId, purpose) {
    await this.recordConsent(userId, purpose, false, 'user_request');
    // Also stop processing for this purpose
    await this.stopProcessing(userId, purpose);
  }
}

// Middleware — check consent before processing
function requireConsent(purpose) {
  return async (req, res, next) => {
    const hasConsent = await consentManager.hasConsent(req.user.id, purpose);
    if (!hasConsent) {
      return res.status(403).json({ error: `Consent not granted for: ${purpose}` });
    }
    next();
  };
}

app.post('/api/marketing/email', auth, requireConsent('marketing_email'), sendMarketingEmail);
```

### Data Minimization (Collect Only What's Needed)
```javascript
// ✅ CORRECT — collect only necessary fields
const registrationSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  // NO: ssn, birthday, address — not needed for registration
});

// ❌ WRONG — collect everything
// const registrationSchema = z.object({
//   email, password, ssn, birthday, address, phone, gender, ...
// });
```

### Pseudonymization
```python
import hashlib
import hmac

class Pseudonymizer:
    def __init__(self, key):
        self.key = key.encode() if isinstance(key, str) else key

    def pseudonymize(self, identifier):
        """Replace direct identifiers with pseudonyms."""
        return hmac.new(self.key, identifier.encode(), hashlib.sha256).hexdigest()

    def anonymize_ip(self, ip):
        """Anonymize IP by zeroing last octet (IPv4) or 3 hextets (IPv6)."""
        if '.' in ip:
            parts = ip.split('.')
            parts[-1] = '0'
            return '.'.join(parts)
        elif ':' in ip:
            parts = ip.split(':')
            return ':'.join(parts[:5]) + '::'
        return ip

# Usage — store pseudonymized identifiers for analytics
pseudonymizer = Pseudonymizer(get_secret('pseudonymization_key'))
analytics_id = pseudonymizer.pseudonymize(user_email)
# Store analytics_id, not the email — can't reverse without the key
```

### Data Retention Policy
```python
class DataRetention:
    RETENTION_POLICIES = {
        'user_sessions': 30 * 24 * 3600,        # 30 days
        'audit_logs': 7 * 365 * 24 * 3600,       # 7 years
        'marketing_data': 2 * 365 * 24 * 3600,   # 2 years
        'transaction_records': 7 * 365 * 24 * 3600,  # 7 years (legal requirement)
        'support_tickets': 1 * 365 * 24 * 3600,  # 1 year
    }

    async def enforce_retention(self):
        """Delete data past retention period."""
        for table, retention_seconds in self.RETENTION_POLICIES.items():
            await db.execute(
                f"DELETE FROM {table} WHERE created_at < NOW() - INTERVAL '{retention_seconds} seconds'"
            )
            logger.info(f"Retention: cleaned {table} (>{retention_seconds}s old)")
```

---

## AUDIT CHECKLIST

- [ ] Data inventory (what PII do you collect, where is it stored?)
- [ ] Data minimization (only collect what's necessary)
- [ ] Consent management (record, verify, allow withdrawal)
- [ ] Data subject rights implemented (access, deletion, portability)
- [ ] Data retention policy (auto-delete old data)
- [ ] Privacy policy published and accurate
- [ ] Data Processing Agreements with vendors
- [ ] Encryption for PII at rest and in transit
- [ ] Access controls on PII (least privilege)
- [ ] Audit logging for PII access
- [ ] Data breach notification procedure (72 hours for GDPR)
- [ ] Privacy Impact Assessment for new features
- [ ] DPO appointed (if required)
- [ ] Cross-border transfer safeguards (SCCs, adequacy decisions)
- [ ] Cookie consent banner (if applicable)
- [ ] Do Not Sell My Info link (CCPA)
