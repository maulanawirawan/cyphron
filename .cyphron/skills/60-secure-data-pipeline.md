# Skill 60 — Secure Data Pipeline

> Cyphron's methodology for securing data pipelines (ETL, streaming, data lakes, data warehouses). Cyphron knows data pipeline attack vectors — injection, data poisoning, unauthorized access, exfiltration — and builds secure data architectures.

---

## WHEN TO ACTIVATE

- User asks to secure a data pipeline or data architecture
- User asks about ETL security, streaming security, or data lake security
- User asks about data warehouse security (Snowflake, BigQuery, Redshift)
- User asks about data governance or data lineage

---

## METHODOLOGY

### Data Pipeline Security Layers

```
Source → Ingestion → Processing → Storage → Consumption
   │         │           │           │          │
   ↓         ↓           ↓           ↓          ↓
Validate  Authenticate  Isolate    Encrypt    Authorize
Sanitize  Rate limit    Sandbox    Mask       Audit
Schema    Queue         Transform  Classify   Monitor
```

### Step 1: Source Security
### Step 2: Ingestion Security
### Step 3: Processing Security
### Step 4: Storage Security
### Step 5: Consumption Security

---

## SECURE PATTERNS

### Secure ETL Pipeline (Python)
```python
#!/usr/bin/env python3
"""
Secure ETL pipeline — extract, transform, load with security controls.
"""
import hashlib
import hmac
import json
from datetime import datetime
from typing import Dict, List, Any

class SecureETL:
    def __init__(self, config):
        self.config = config
        self.audit_log = []

    # ─── Source Security ───
    def validate_source(self, source_data, expected_schema):
        """Validate source data against expected schema."""
        # Schema validation
        for field, field_type in expected_schema.items():
            if field not in source_data:
                raise ValueError(f'Missing required field: {field}')

            value = source_data[field]
            if not isinstance(value, field_type):
                raise ValueError(f'Invalid type for {field}: expected {field_type}, got {type(value)}')

        # Range validation
        for field, constraints in self.config.get('field_constraints', {}).items():
            if field in source_data:
                value = source_data[field]
                if 'min' in constraints and value < constraints['min']:
                    raise ValueError(f'{field} below minimum: {value} < {constraints["min"]}')
                if 'max' in constraints and value > constraints['max']:
                    raise ValueError(f'{field} above maximum: {value} > {constraints["max"]}')
                if 'pattern' in constraints:
                    import re
                    if not re.match(constraints['pattern'], str(value)):
                        raise ValueError(f'{field} does not match pattern: {value}')

        return True

    def sanitize_input(self, data):
        """Sanitize input data — remove or escape dangerous content."""
        if isinstance(data, str):
            # Remove null bytes
            data = data.replace('\x00', '')
            # Escape SQL-like patterns (if used in SQL)
            # data = data.replace("'", "''")
            # Limit length
            max_length = self.config.get('max_string_length', 10000)
            if len(data) > max_length:
                data = data[:max_length]
        elif isinstance(data, dict):
            return {k: self.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_input(item) for item in data]
        return data

    # ─── Ingestion Security ───
    def authenticate_source(self, credentials):
        """Authenticate data source."""
        expected_key = self.config['source_api_key']
        provided_key = credentials.get('api_key')

        if not provided_key or not hmac.compare_digest(provided_key, expected_key):
            raise PermissionError('Invalid API key')

        return True

    def rate_limit_source(self, source_id):
        """Rate limit data ingestion per source."""
        # Check rate limit (simplified)
        current_count = self._get_source_count(source_id)
        max_rate = self.config.get('max_rate_per_source', 1000)

        if current_count >= max_rate:
            raise RateLimitError(f'Rate limit exceeded for source {source_id}')

        self._increment_source_count(source_id)
        return True

    # ─── Processing Security ───
    def process_in_sandbox(self, data, processor_func):
        """Process data in isolated sandbox."""
        import multiprocessing
        import queue

        def worker(data, result_queue):
            try:
                result = processor_func(data)
                result_queue.put({'status': 'success', 'result': result})
            except Exception as e:
                result_queue.put({'status': 'error', 'error': str(e)})

        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(target=worker, args=(data, result_queue))
        process.start()
        process.join(timeout=30)  # 30 second timeout

        if process.is_alive():
            process.terminate()
            raise TimeoutError('Processing timeout')

        try:
            result = result_queue.get_nowait()
            if result['status'] == 'error':
                raise ProcessingError(result['error'])
            return result['result']
        except queue.Empty:
            raise ProcessingError('No result from processor')

    def validate_output(self, output_data, expected_schema):
        """Validate processed output data."""
        return self.validate_source(output_data, expected_schema)

    # ─── Storage Security ───
    def encrypt_sensitive_fields(self, data, sensitive_fields):
        """Encrypt sensitive fields before storage."""
        from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
        import os

        key = AESGCM.generate_key(bit_length=256)

        encrypted = data.copy()
        for field in sensitive_fields:
            if field in encrypted:
                nonce = os.urandom(12)
                aesgcm = AESGCM(key)
                value = str(encrypted[field]).encode()
                encrypted[field] = {
                    'encrypted': True,
                    'nonce': nonce.hex(),
                    'ciphertext': aesgcm.encrypt(nonce, value, None).hex(),
                }

        return encrypted, key

    def mask_sensitive_fields(self, data, sensitive_fields):
        """Mask sensitive fields for non-privileged access."""
        masked = data.copy()
        for field in sensitive_fields:
            if field in masked:
                value = str(masked[field])
                if field == 'credit_card':
                    masked[field] = '****-****-****-' + value[-4:]
                elif field == 'ssn':
                    masked[field] = '***-**-' + value[-4:]
                elif field == 'email':
                    user, domain = value.split('@')
                    masked[field] = user[0] + '***@' + domain
                else:
                    masked[field] = '***MASKED***'
        return masked

    # ─── Audit & Monitoring ───
    def audit(self, action, details):
        """Log audit event."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'pipeline_id': self.config.get('pipeline_id'),
        }
        self.audit_log.append(entry)
        # In production: send to SIEM

    def detect_anomalies(self, data_volume, data_rate, source_id):
        """Detect data pipeline anomalies."""
        baseline = self._get_baseline(source_id)

        anomalies = []

        # Volume anomaly
        if data_volume > baseline['avg_volume'] * 3:
            anomalies.append({
                'type': 'volume_spike',
                'severity': 'high',
                'message': f'Data volume {data_volume} is 3x baseline {baseline["avg_volume"]}',
            })

        # Rate anomaly
        if data_rate > baseline['avg_rate'] * 5:
            anomalies.append({
                'type': 'rate_spike',
                'severity': 'medium',
                'message': f'Data rate {data_rate} is 5x baseline {baseline["avg_rate"]}',
            })

        # Schema anomaly
        if self._schema_drift_detected(source_id):
            anomalies.append({
                'type': 'schema_drift',
                'severity': 'high',
                'message': 'Schema drift detected — source data structure changed',
            })

        if anomalies:
            self.audit('anomaly_detected', {'source_id': source_id, 'anomalies': anomalies})

        return anomalies
```

### Secure Streaming (Kafka)
```python
from confluent_kafka import Producer, Consumer, KafkaError
from confluent_kafka.admin import AdminClient, AclBinding, AclBindingFilter, ResourceType, AclOperation, AclPermissionType
import ssl
import json

class SecureKafkaPipeline:
    def __init__(self, bootstrap_servers):
        self.bootstrap_servers = bootstrap_servers

    def create_producer(self):
        """Create secure Kafka producer."""
        return Producer({
            'bootstrap.servers': self.bootstrap_servers,
            'security.protocol': 'SASL_SSL',
            'sasl.mechanism': 'SCRAM-SHA-512',
            'sasl.username': get_secret('kafka_username'),
            'sasl.password': get_secret('kafka_password'),
            'ssl.ca.location': '/etc/kafka/certs/ca.crt',
            'ssl.certificate.location': '/etc/kafka/certs/client.crt',
            'ssl.key.location': '/etc/kafka/certs/client.key',
            'ssl.endpoint.identification.algorithm': 'https',
            'acks': 'all',  # Wait for all replicas
            'retries': 3,
            'max.in.flight.requests.per.connection': 1,  # Ensure ordering
        })

    def create_consumer(self, group_id):
        """Create secure Kafka consumer."""
        return Consumer({
            'bootstrap.servers': self.bootstrap_servers,
            'group.id': group_id,
            'security.protocol': 'SASL_SSL',
            'sasl.mechanism': 'SCRAM-SHA-512',
            'sasl.username': get_secret('kafka_username'),
            'sasl.password': get_secret('kafka_password'),
            'ssl.ca.location': '/etc/kafka/certs/ca.crt',
            'ssl.certificate.location': '/etc/kafka/certs/client.crt',
            'ssl.key.location': '/etc/kafka/certs/client.key',
            'ssl.endpoint.identification.algorithm': 'https',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,  # Manual commit for reliability
        })

    def set_acls(self, admin_client, topic, principal, operations):
        """Set ACLs on Kafka topic — least privilege."""
        acl = AclBinding(
            resource_type=ResourceType.TOPIC,
            resource_name=topic,
            principal=f'User:{principal}',
            operation=AclOperation.ALL,
            permission_type=AclPermissionType.ALLOW,
            host='*',
        )

        for op in operations:
            acl.operation = op
            admin_client.create_acls([acl])

    def validate_message(self, message):
        """Validate Kafka message before processing."""
        try:
            data = json.loads(message.value().decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError('Invalid message format')

        # Schema validation
        required_fields = ['id', 'timestamp', 'source', 'data']
        for field in required_fields:
            if field not in data:
                raise ValueError(f'Missing required field: {field}')

        # Size limit
        if len(message.value()) > 1048576:  # 1 MB
            raise ValueError('Message too large')

        return data
```

### Data Warehouse Security (Snowflake)
```sql
-- Snowflake — secure data warehouse configuration

-- 1. Role-based access control (RBAC)
CREATE ROLE data_engineer;
CREATE ROLE data_analyst;
CREATE ROLE data_scientist;

-- 2. Warehouse access (least privilege)
GRANT USAGE ON WAREHOUSE etl_wh TO ROLE data_engineer;
GRANT USAGE ON WAREHOUSE analytics_wh TO ROLE data_analyst;

-- 3. Database access
GRANT USAGE ON DATABASE raw_data TO ROLE data_engineer;
GRANT USAGE ON DATABASE analytics TO ROLE data_analyst;
GRANT USAGE ON DATABASE analytics TO ROLE data_scientist;

-- 4. Schema access (data masking)
GRANT USAGE ON SCHEMA raw_data.public TO ROLE data_engineer;
GRANT USAGE ON SCHEMA analytics.public TO ROLE data_analyst;

-- 5. Table access with row-level security
CREATE OR REPLACE ROW ACCESS POLICY pii_policy
AS (user_id VARCHAR) RETURNS BOOLEAN ->
    CURRENT_ROLE() IN ('data_engineer')
    OR user_id = CURRENT_USER();

ALTER TABLE users ADD ROW ACCESS POLICY pii_policy ON (user_id);

-- 6. Column-level masking
CREATE OR REPLACE MASKING POLICY ssn_mask
AS (val VARCHAR) RETURNS VARCHAR ->
    CASE
        WHEN CURRENT_ROLE() IN ('data_engineer') THEN val
        ELSE '***-**-' || RIGHT(val, 4)
    END;

ALTER TABLE users MODIFY COLUMN ssn SET MASKING POLICY ssn_mask;

-- 7. Network policy (IP allowlist)
CREATE OR REPLACE NETWORK POLICY corp_network
    ALLOWED_IP_LIST = ('10.0.0.0/8', '172.16.0.0/12')
    BLOCKED_IP_LIST = ('192.168.0.0/16');

ALTER ACCOUNT SET NETWORK_POLICY = corp_network;

-- 8. Data encryption (automatic in Snowflake, verify)
SHOW PARAMETERS LIKE 'ENCRYPTION%';

-- 9. Audit logging
CREATE OR REPLACE TABLE audit_log (
    timestamp TIMESTAMP_LTZ,
    user_name VARCHAR,
    role_name VARCHAR,
    query_text VARCHAR,
    execution_status VARCHAR,
    error_message VARCHAR,
    rows_produced NUMBER,
    bytes_scanned NUMBER
);

-- 10. Data retention (time travel + fail-safe)
ALTER DATABASE analytics SET DATA_RETENTION_TIME_IN_DAYS = 7;
```

---

## AUDIT CHECKLIST

- [ ] Source authentication (API key, mTLS, OAuth)
- [ ] Source validation (schema, range, format)
- [ ] Input sanitization (null bytes, injection patterns)
- [ ] Rate limiting per source
- [ ] Processing isolation (sandbox, container)
- [ ] Output validation
- [ ] Encryption at rest (AES-256)
- [ ] Encryption in transit (TLS 1.2+)
- [ ] Data masking for non-privileged users
- [ ] Row-level security for multi-tenant data
- [ ] Column-level masking for sensitive data
- [ ] Network policy (IP allowlist)
- [ ] Audit logging (all pipeline operations)
- [ ] Anomaly detection (volume, rate, schema drift)
- [ ] Data lineage tracking (source → destination)
- [ ] Data retention policy (auto-delete old data)
- [ ] Data classification (public, internal, confidential, restricted)
- [ ] Access control (RBAC, least privilege)
- [ ] Error handling (no sensitive data in errors)
- [ ] Backup and recovery for pipeline data
