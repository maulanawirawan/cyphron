# Skill 55 — Data Encryption Strategy & Key Management

> Cyphron's methodology for building enterprise data encryption strategies. Cyphron knows encryption attack vectors — weak algorithms, key management failures, side-channel attacks, downgrade attacks — and builds encryption systems that protect data at rest, in transit, and in use.

---

## WHEN TO ACTIVATE

- User asks to build an encryption strategy
- User asks about key management or KMS
- User asks about encryption at rest, in transit, or in use
- User asks about HSM, TPM, or hardware security
- User asks about cryptographic agility or post-quantum crypto

---

## METHODOLOGY

### Encryption Layers

| Layer | Purpose | Technology |
|---|---|---|
| Data at Rest | Protect stored data | AES-256-GCM, LUKS, TDE |
| Data in Transit | Protect network data | TLS 1.3, WireGuard, IPsec |
| Data in Use | Protect data during processing | Homomorphic, TEE (SGX, SEV) |
| Key Management | Protect encryption keys | HSM, KMS, Vault |

### Step 1: Data Classification & Encryption Requirements
### Step 2: Key Management Architecture
### Step 3: Encryption Implementation
### Step 4: Key Rotation & Lifecycle
### Step 5: Cryptographic Agility

---

## SECURE PATTERNS

### Enterprise Key Management Architecture
```
┌─────────────────────────────────────────┐
│           HSM (Hardware Root)           │
│  Master keys stored in tamper-proof HSM │
│  FIPS 140-2 Level 3 certified           │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┼────────────┐
    ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐
│  KMS   │  │  KMS   │  │  KMS   │
│ Region1│  │ Region2│  │ Region3│
└───┬────┘  └───┬────┘  └───┬────┘
    │            │            │
    ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐
│ Data   │  │ Data   │  │ Data   │
│ Encryption│  │ Encryption│  │ Encryption│
│ Keys   │  │ Keys   │  │ Keys   │
│ (DEK)  │  │ (DEK)  │  │ (DEK)  │
└────────┘  └────────┘  └────────┘
```

### Envelope Encryption (KMS)
```python
import boto3
import json
from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
import os

class EnvelopeEncryption:
    """Envelope encryption — encrypt data with DEK, encrypt DEK with KMS master key."""

    def __init__(self, kms_key_id, region='us-east-1'):
        self.kms = boto3.client('kms', region_name=region)
        self.kms_key_id = kms_key_id

    def encrypt(self, plaintext, context=None):
        """Encrypt data using envelope encryption."""
        # 1. Generate data encryption key (DEK)
        dek_response = self.kms.generate_data_key(
            KeyId=self.kms_key_id,
            KeySpec='AES_256',
            EncryptionContext=context or {},
        )
        dek_plaintext = dek_response['Plaintext']
        dek_encrypted = dek_response['CiphertextBlob']

        # 2. Encrypt data with DEK
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek_plaintext)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), context or b'')

        # 3. Return encrypted DEK + nonce + ciphertext
        # The DEK plaintext is never stored — only the encrypted version
        return {
            'encrypted_dek': dek_encrypted,
            'nonce': nonce,
            'ciphertext': ciphertext,
            'context': context,
        }

    def decrypt(self, encrypted_data):
        """Decrypt data using envelope encryption."""
        # 1. Decrypt DEK using KMS
        dek_response = self.kms.decrypt(
            CiphertextBlob=encrypted_data['encrypted_dek'],
            EncryptionContext=encrypted_data['context'] or {},
        )
        dek_plaintext = dek_response['Plaintext']

        # 2. Decrypt data with DEK
        aesgcm = AESGCM(dek_plaintext)
        plaintext = aesgcm.decrypt(
            encrypted_data['nonce'],
            encrypted_data['ciphertext'],
            encrypted_data['context'] or b'',
        )

        return plaintext.decode()

    def rotate_key(self):
        """Rotate KMS master key (automatic with KMS)."""
        # Enable automatic key rotation (annual)
        self.kms.enable_key_rotation(KeyId=self.kms_key_id)

        # Get rotation status
        status = self.kms.get_key_rotation_status(KeyId=self.kms_key_id)
        return status
```

### Database Encryption (TDE + Column-Level)
```sql
-- PostgreSQL — Transparent Data Encryption (TDE)
-- Enable at cluster level (requires pgcrypto)

-- 1. Enable pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Create encryption key table (keys stored in KMS, not in DB)
CREATE TABLE encryption_keys (
    id SERIAL PRIMARY KEY,
    key_name VARCHAR(255) UNIQUE,
    key_id VARCHAR(255),  -- KMS key ID, not the actual key
    created_at TIMESTAMP DEFAULT NOW(),
    rotated_at TIMESTAMP,
    active BOOLEAN DEFAULT true
);

-- 3. Insert key reference
INSERT INTO encryption_keys (key_name, key_id) VALUES
    ('pii_encryption', 'arn:aws:kms:us-east-1:123456789:key/abcd1234');

-- 4. Encrypt sensitive columns
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    ssn BYTEA,  -- encrypted
    credit_card BYTEA,  -- encrypted
    encrypted_with VARCHAR(255) REFERENCES encryption_keys(key_name)
);

-- 5. Insert with encryption (key retrieved from KMS at runtime)
-- In application code, not SQL:
-- dek = kms.generate_data_key(key_id)
-- encrypted_ssn = aesgcm.encrypt(dek, ssn)
-- INSERT INTO users (email, ssn, encrypted_with) VALUES (?, ?, ?)

-- 6. Decrypt on read (with key from KMS)
-- In application code:
-- dek = kms.decrypt(encrypted_dek)
-- ssn = aesgcm.decrypt(dek, encrypted_ssn)
```

### TLS Configuration (Perfect Forward Secrecy)
```nginx
# Nginx — TLS 1.3 with perfect forward secrecy
server {
    listen 443 ssl http2;
    server_name example.com;

    # Certificates
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # TLS 1.3 only (no TLS 1.2 fallback for maximum security)
    ssl_protocols TLSv1.3;

    # If TLS 1.2 needed (for compatibility):
    # ssl_protocols TLSv1.2 TLSv1.3;
    # ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

    # Prefer server ciphers (but TLS 1.3 uses client's preference)
    ssl_prefer_server_ciphers off;

    # ECDH curve for perfect forward secrecy
    ssl_ecdh_curve X25519:secp384r1:secp256r1;

    # Session tickets off (for perfect forward secrecy)
    ssl_session_tickets off;

    # Session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

### Key Rotation Strategy
```python
class KeyRotationStrategy:
    """Manage encryption key lifecycle and rotation."""

    def __init__(self, kms_client):
        self.kms = kms_client

    def rotate_database_key(self, key_name, new_key_id):
        """Rotate database encryption key."""
        # 1. Generate new key in KMS
        new_key = self.kms.create_key(
            Description=f'Database encryption key for {key_name}',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS',
        )

        # 2. Mark old key as inactive (but keep for decryption)
        self.kms.disable_key(KeyId=old_key_id)

        # 3. Re-encrypt data with new key (gradual)
        self._reencrypt_data(key_name, old_key_id, new_key_id)

        # 4. Schedule old key deletion (30 days)
        self.kms.schedule_key_deletion(
            KeyId=old_key_id,
            PendingWindowInDays=30,
        )

        return {
            'new_key_id': new_key_id,
            'old_key_id': old_key_id,
            'deletion_date': (datetime.now() + timedelta(days=30)).isoformat(),
        }

    def _reencrypt_data(self, key_name, old_key_id, new_key_id):
        """Gradually re-encrypt data with new key."""
        # Get all records encrypted with old key
        records = self.db.query(
            'SELECT id, encrypted_data, encrypted_dek FROM sensitive_data WHERE key_name = ?',
            [key_name]
        )

        for record in records:
            # Decrypt with old key
            old_dek = self.kms.decrypt(
                CiphertextBlob=record['encrypted_dek'],
                KeyId=old_key_id,
            )
            plaintext = self._decrypt(old_dek['Plaintext'], record['encrypted_data'])

            # Re-encrypt with new key
            new_dek = self.kms.generate_data_key(KeyId=new_key_id)
            new_encrypted = self._encrypt(new_dek['Plaintext'], plaintext)

            # Update record
            self.db.execute(
                'UPDATE sensitive_data SET encrypted_data = ?, encrypted_dek = ? WHERE id = ?',
                [new_encrypted, new_dek['CiphertextBlob'], record['id']]
            )

            # Verify decryption works with new key
            verify_dek = self.kms.decrypt(
                CiphertextBlob=new_dek['CiphertextBlob'],
                KeyId=new_key_id,
            )
            verify_plaintext = self._decrypt(verify_dek['Plaintext'], new_encrypted)
            assert verify_plaintext == plaintext, 'Re-encryption verification failed'

    def rotate_application_key(self, app_name):
        """Rotate application-level encryption key."""
        # 1. Generate new key pair (asymmetric)
        new_private, new_public = self._generate_key_pair()

        # 2. Deploy new public key to all services
        self._deploy_public_key(app_name, new_public)

        # 3. Wait for deployment (all services have new key)
        self._wait_for_deployment(app_name, new_public)

        # 4. Switch to new private key for signing
        self._switch_signing_key(app_name, new_private)

        # 5. Keep old public key for verification (30 days)
        self._retire_old_key(app_name, days=30)
```

### Cryptographic Agility (Post-Quantum Ready)
```python
class CryptoAgility:
    """Design for cryptographic agility — easily swap algorithms."""

    SUPPORTED_ALGORITHMS = {
        'aes-256-gcm': {
            'type': 'symmetric',
            'key_size': 256,
            'status': 'current',
            'quantum_safe': False,
        },
        'chacha20-poly1305': {
            'type': 'symmetric',
            'key_size': 256,
            'status': 'current',
            'quantum_safe': False,
        },
        'kyber-1024': {
            'type': 'asymmetric',
            'key_size': 1024,
            'status': 'future',
            'quantum_safe': True,
        },
        'dilithium-5': {
            'type': 'signature',
            'key_size': 5,
            'status': 'future',
            'quantum_safe': True,
        },
    }

    def __init__(self):
        self.current_algorithm = 'aes-256-gcm'
        self.fallback_algorithms = ['chacha20-poly1305']
        self.post_quantum_ready = ['kyber-1024', 'dilithium-5']

    def encrypt(self, plaintext, algorithm=None):
        """Encrypt with specified algorithm (or current default)."""
        algo = algorithm or self.current_algorithm

        if algo == 'aes-256-gcm':
            return self._encrypt_aes_gcm(plaintext)
        elif algo == 'chacha20-poly1305':
            return self._encrypt_chacha20(plaintext)
        else:
            raise ValueError(f'Unsupported algorithm: {algo}')

    def get_migration_path(self):
        """Get algorithm migration path for crypto agility."""
        return {
            'current': self.current_algorithm,
            'fallback': self.fallback_algorithms,
            'post_quantum': self.post_quantum_ready,
            'migration_plan': [
                '1. Deploy post-quantum hybrid (current + PQ)',
                '2. Monitor for quantum threat maturity',
                '3. Switch to post-quantum only when needed',
                '4. Retire current algorithm',
            ],
        }
```

---

## AUDIT CHECKLIST

- [ ] Data classified by sensitivity (public, internal, confidential, restricted)
- [ ] Encryption required for confidential and restricted data
- [ ] AES-256-GCM or ChaCha20-Poly1305 for data at rest
- [ ] TLS 1.3 for data in transit (or TLS 1.2 with modern ciphers)
- [ ] Perfect forward secrecy (ECDHE key exchange)
- [ ] HSM for master keys (FIPS 140-2 Level 3)
- [ ] KMS for key management (envelope encryption)
- [ ] Key rotation policy (annual minimum)
- [ ] Key lifecycle documented (generation, use, rotation, destruction)
- [ ] No hardcoded keys (all keys from KMS/HSM)
- [ ] Key access audit logging
- [ ] Encryption context for additional authenticated data
- [ ] Cryptographic agility (easy algorithm swap)
- [ ] Post-quantum readiness plan
- [ ] Encrypted backups
- [ ] Encrypted database connections
- [ ] Encrypted file storage
- [ ] Secure key destruction (crypto-shredding)
- [ ] Compliance with encryption standards (FIPS, PCI-DSS)
