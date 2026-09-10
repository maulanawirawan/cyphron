# Skill 27 — Database Security Engineering

> Cyphron's methodology for securing databases. Cyphron knows database attack vectors — SQL injection, privilege escalation, data exfiltration, lateral movement via DB links, backup theft — and builds database defenses.

---

## WHEN TO ACTIVATE

- User asks to secure a database (PostgreSQL, MySQL, MongoDB, Redis, etc.)
- User asks about database encryption, access control, or auditing
- User asks about database hardening or CIS benchmarks
- User asks about data masking or row-level security

---

## METHODOLOGY

### Step 1: Identify Database
- Relational (PostgreSQL, MySQL, Oracle, SQL Server)
- NoSQL (MongoDB, Redis, Cassandra, DynamoDB)
- Search (Elasticsearch)

### Step 2: Security Layers

| Layer | Control |
|---|---|
| Network | Private subnet, firewall, TLS |
| Authentication | Strong auth, no default creds, MFA for admin |
| Authorization | Least privilege roles, row-level security |
| Encryption | At rest (TDE), in transit (TLS) |
| Auditing | Query logging, access logging |
| Data Protection | Masking, tokenization, minimization |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### PostgreSQL — Row Level Security
```sql
-- Enable RLS on a table
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- Policy: users can only see their own orders
CREATE POLICY user_isolation ON orders
  FOR ALL
  USING (user_id = current_setting('app.current_user_id')::int);

-- Force RLS even for table owners
ALTER TABLE orders FORCE ROW LEVEL SECURITY;

-- Application sets the user context per session
SET app.current_user_id = '42';
-- Now SELECT * FROM orders only returns user 42's orders
```

### PostgreSQL — Column-Level Encryption
```sql
-- Encrypt sensitive columns with pgcrypto
CREATE EXTENSION pgcrypto;

-- Store encrypted (never store plaintext PII)
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT,
  ssn BYTEA  -- encrypted
);

-- Insert with encryption
INSERT INTO users (email, ssn) VALUES (
  'user@example.com',
  pgp_sym_encrypt('123-45-6789', current_setting('app.encryption_key'))
);

-- Decrypt on read (with key from secrets manager, not hardcoded)
SELECT email, pgp_sym_decrypt(ssn, current_setting('app.encryption_key')) AS ssn
FROM users WHERE id = 1;
```

### PostgreSQL — Audit Logging
```sql
-- pgAudit extension for comprehensive logging
CREATE EXTENSION pgaudit;

-- In postgresql.conf:
-- pgaudit.log = 'read,write,ddl,role'
-- pgaudit.log_parameter = on
-- pgaudit.log_relation = on

-- All queries now logged with:
-- user, database, query, parameters, timestamp, relation
```

### MongoDB — Field-Level Encryption
```javascript
// Client-side field-level encryption (CSFLE)
const { MongoClient, Binary } = require('mongodb');
const { ClientEncryption } = require('mongodb-client-encryption');

// Encrypt SSN before sending to database
const encryption = new ClientEncryption(client, {
  keyVaultNamespace: 'encryption.__keyVault',
  kmsProviders: { local: { key: localMasterKey } },
});

const encryptedSSN = await encryption.encrypt('123-45-6789', {
  algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
  keyAltName: 'ssn-key',
});

// Insert encrypted data
await db.collection('users').insertOne({
  email: 'user@example.com',
  ssn: encryptedSSN,  // encrypted at client, stored encrypted
});

// Data is encrypted at rest, in transit, and in memory on server
```

### Redis — Security Configuration
```conf
# redis.conf — hardened
bind 127.0.0.1 ::1
protected-mode yes
port 0
unixsocket /var/run/redis/redis.sock
unixsocketperm 700
requirepass <strong-password>
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command KEYS ""
rename-command DEBUG ""
maxmemory 256mb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
```

### Data Masking (Dynamic)
```sql
-- PostgreSQL — dynamic data masking with views
CREATE TABLE users_raw (
  id SERIAL PRIMARY KEY,
  email TEXT,
  phone TEXT,
  credit_card TEXT
);

-- Masked view for non-privileged users
CREATE VIEW users_masked AS
SELECT
  id,
  email,
  regexp_replace(phone, '(\d{3})\d{3}(\d{4})', '\1-XXX-\2') AS phone,
  'XXXX-XXXX-XXXX-' || right(credit_card, 4) AS credit_card
FROM users_raw;

-- Grant masked view to app role, raw table to admin only
GRANT SELECT ON users_masked TO app_role;
GRANT SELECT ON users_raw TO admin_role;
```

---

## AUDIT CHECKLIST

- [ ] Database in private subnet (no internet access)
- [ ] TLS for all connections
- [ ] Encryption at rest (TDE or volume encryption)
- [ ] No default passwords
- [ ] Least privilege roles (app role can't DDL)
- [ ] Row-level security for multi-tenant data
- [ ] Sensitive fields encrypted (SSN, credit card)
- [ ] Audit logging enabled (all queries)
- [ ] Connection pooling with auth
- [ ] Automated backups (encrypted)
- [ ] Backup access restricted
- [ ] Database version current (patched)
- [ ] No unnecessary extensions installed
- [ ] Connection limits per role
- [ ] Idle session timeout
- [ ] Failed login monitoring
