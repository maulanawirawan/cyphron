# Skill 63 — Secure Messaging Queue (Kafka, RabbitMQ, SQS)

> Cyphron's methodology for securing message queues and event streaming platforms. Cyphron knows message queue attack vectors — unauthorized access, message injection, data exposure, replay attacks — and builds secure messaging architectures.

---

## WHEN TO ACTIVATE

- User asks to secure Kafka, RabbitMQ, Amazon SQS, or similar
- User asks about message queue security or event streaming security
- User asks about message encryption, ACLs, or authentication
- User asks about secure pub/sub or event-driven architecture

---

## METHODOLOGY

### Message Queue Security Layers

| Layer | Control |
|---|---|
| Transport | TLS encryption, mutual TLS |
| Authentication | SASL, OAuth, client certificates |
| Authorization | ACLs, topic/queue-level permissions |
| Message | Encryption, signing, schema validation |
| Network | Private subnets, firewall rules |
| Monitoring | Audit logging, anomaly detection |

---

## SECURE PATTERNS

### Apache Kafka Security (Complete)
```python
from confluent_kafka import Producer, Consumer, KafkaError
from confluent_kafka.admin import AdminClient, AclBinding, ResourceType, AclOperation, AclPermissionType
import ssl
import json

class SecureKafka:
    """Secure Kafka configuration and operations."""

    def __init__(self, bootstrap_servers):
        self.bootstrap_servers = bootstrap_servers
        self.admin = AdminClient({
            'bootstrap.servers': bootstrap_servers,
            'security.protocol': 'SASL_SSL',
            'sasl.mechanism': 'SCRAM-SHA-512',
            'sasl.username': get_secret('kafka_admin_user'),
            'sasl.password': get_secret('kafka_admin_password'),
            'ssl.ca.location': '/etc/kafka/certs/ca.crt',
        })

    # ─── Security Configuration ───
    def get_server_config(self):
        """Kafka server security configuration (server.properties)."""
        return '''
# ─── Listeners ───
listeners=SASL_SSL://:9093
advertised.listeners=SASL_SSL://kafka.example.com:9093

# ─── SSL/TLS ───
ssl.keystore.location=/etc/kafka/certs/kafka.keystore.jks
ssl.keystore.password=<keystore-password>
ssl.key.password=<key-password>
ssl.truststore.location=/etc/kafka/certs/kafka.truststore.jks
ssl.truststore.password=<truststore-password>
ssl.client.auth=required
ssl.enabled.protocols=TLSv1.2,TLSv1.3
ssl.cipher.suites=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

# ─── SASL Authentication ───
sasl.enabled.mechanisms=SCRAM-SHA-512
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="admin" password="<admin-password>";

# ─── Authorization ───
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
super.users=User:admin
allow.everyone.if.no.acl.found=false

# ─── Inter-broker Security ───
security.inter.broker.protocol=SASL_SSL

# ─── Logging ───
log4j.logger.kafka.authorizer.logger=INFO
log4j.logger.kafka.security.auth=INFO
'''

    # ─── ACL Management ───
    def set_topic_acls(self, topic, principal, operations):
        """Set ACLs on topic — least privilege."""
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
            self.admin.create_acls([acl])

    def setup_service_acls(self):
        """Set up ACLs for services."""
        # Producer service — only produce to specific topics
        self.set_topic_acls('orders', 'orders-producer', [AclOperation.WRITE])
        self.set_topic_acls('payments', 'orders-producer', [AclOperation.WRITE])

        # Consumer service — only consume from specific topics
        self.set_topic_acls('orders', 'orders-consumer', [AclOperation.READ])
        self.set_topic_acls('orders', 'orders-consumer', [AclOperation.DESCRIBE])

        # Consumer group
        group_acl = AclBinding(
            resource_type=ResourceType.GROUP,
            resource_name='orders-consumer-group',
            principal='User:orders-consumer',
            operation=AclOperation.READ,
            permission_type=AclPermissionType.ALLOW,
            host='*',
        )
        self.admin.create_acls([group_acl])

    # ─── Secure Producer ───
    def create_producer(self, client_id):
        """Create secure Kafka producer."""
        return Producer({
            'bootstrap.servers': self.bootstrap_servers,
            'client.id': client_id,
            'security.protocol': 'SASL_SSL',
            'sasl.mechanism': 'SCRAM-SHA-512',
            'sasl.username': get_secret(f'kafka_{client_id}_user'),
            'sasl.password': get_secret(f'kafka_{client_id}_password'),
            'ssl.ca.location': '/etc/kafka/certs/ca.crt',
            'ssl.certificate.location': f'/etc/kafka/certs/{client_id}.crt',
            'ssl.key.location': f'/etc/kafka/certs/{client_id}.key',
            'ssl.endpoint.identification.algorithm': 'https',
            # Reliability
            'acks': 'all',
            'retries': 3,
            'max.in.flight.requests.per.connection': 1,
            # Idempotence (exactly-once)
            'enable.idempotence': True,
        })

    # ─── Secure Consumer ───
    def create_consumer(self, group_id, client_id):
        """Create secure Kafka consumer."""
        return Consumer({
            'bootstrap.servers': self.bootstrap_servers,
            'group.id': group_id,
            'client.id': client_id,
            'security.protocol': 'SASL_SSL',
            'sasl.mechanism': 'SCRAM-SHA-512',
            'sasl.username': get_secret(f'kafka_{client_id}_user'),
            'sasl.password': get_secret(f'kafka_{client_id}_password'),
            'ssl.ca.location': '/etc/kafka/certs/ca.crt',
            'ssl.certificate.location': f'/etc/kafka/certs/{client_id}.crt',
            'ssl.key.location': f'/etc/kafka/certs/{client_id}.key',
            'ssl.endpoint.identification.algorithm': 'https',
            # Consumer settings
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
            'isolation.level': 'read_committed',  # Only read committed messages
        })

    # ─── Message Security ───
    def encrypt_message(self, message, key):
        """Encrypt message payload."""
        from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
        import os

        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(message).encode(), None)

        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'encrypted': True,
        }

    def sign_message(self, message, private_key):
        """Sign message for integrity verification."""
        from cryptography.hazmat.primitives import hashes, signing
        from cryptography.hazmat.primitives.asymmetric import padding

        signature = private_key.sign(
            json.dumps(message, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )

        return {
            'message': message,
            'signature': signature.hex(),
            'signed': True,
        }

    def validate_message(self, message):
        """Validate message schema and integrity."""
        # Schema validation
        required_fields = ['id', 'timestamp', 'type', 'data']
        for field in required_fields:
            if field not in message:
                raise ValueError(f'Missing required field: {field}')

        # Size limit
        if len(json.dumps(message)) > 1048576:  # 1 MB
            raise ValueError('Message too large')

        # Timestamp validation (not too old, not in future)
        msg_time = datetime.fromisoformat(message['timestamp'])
        now = datetime.now()
        if msg_time > now:
            raise ValueError('Message timestamp in future')
        if (now - msg_time).days > 7:
            raise ValueError('Message too old (possible replay)')

        return True
```

### RabbitMQ Security
```python
import pika
import ssl
import json

class SecureRabbitMQ:
    """Secure RabbitMQ configuration and operations."""

    def __init__(self, host, port=5671):
        self.host = host
        self.port = port

    def create_connection(self, username, password, vhost='/'):
        """Create secure RabbitMQ connection."""
        # TLS context
        context = ssl.create_default_context()
        context.load_verify_locations('/etc/rabbitmq/certs/ca.crt')
        context.load_cert_chain(
            '/etc/rabbitmq/certs/client.crt',
            '/etc/rabbitmq/certs/client.key',
        )

        credentials = pika.PlainCredentials(username, password)

        return pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                virtual_host=vhost,
                credentials=credentials,
                ssl_options=pika.SSLOptions(context, self.host),
                heartbeat=30,
                blocked_connection_timeout=300,
            )
        )

    def setup_secure_queue(self, channel, queue_name, durable=True):
        """Set up secure queue with encryption and ACLs."""
        # Declare queue with arguments
        channel.queue_declare(
            queue=queue_name,
            durable=durable,
            arguments={
                'x-message-ttl': 86400000,  # 24 hours
                'x-max-length': 1000000,
                'x-dead-letter-exchange': 'dlx',
                'x-dead-letter-routing-key': f'{queue_name}.dlq',
            }
        )

        # Set permissions (least privilege)
        # In production: configure via RabbitMQ management API
        # rabbitmqctl set_permissions -p / user "^{queue_name}$" "^{queue_name}$" "^{queue_name}$"

    def publish_secure(self, channel, exchange, routing_key, message, encrypt=True):
        """Publish message with encryption."""
        body = json.dumps(message)

        if encrypt:
            # Encrypt message body
            from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
            import os
            key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, body.encode(), None)
            body = json.dumps({
                'nonce': nonce.hex(),
                'ciphertext': ciphertext.hex(),
                'encrypted': True,
            })

        channel.basic_publish(
            exchange=exchange,
            routing_key=routing_key,
            body=body,
            properties=pika.BasicProperties(
                delivery_mode=2,  # Persistent
                content_type='application/json',
                content_encoding='utf-8',
                timestamp=int(datetime.now().timestamp()),
                message_id=generate_id(),
                app_id='secure-producer',
            ),
            mandatory=True,  # Return if unroutable
        )
```

### Amazon SQS Security
```python
import boto3
import json
from cryptography.hazmat.primitives.ciphertext.aead import AESGCM
import os

class SecureSQS:
    """Secure Amazon SQS configuration and operations."""

    def __init__(self, region='us-east-1'):
        self.sqs = boto3.client('sqs', region_name=region)
        self.kms = boto3.client('kms', region_name=region)

    def create_secure_queue(self, queue_name, kms_key_id):
        """Create SQS queue with encryption and least privilege."""
        # Create queue with KMS encryption
        response = self.sqs.create_queue(
            QueueName=queue_name,
            Attributes={
                'KmsMasterKeyId': kms_key_id,
                'KmsDataKeyReusePeriodSeconds': '300',  # 5 minutes
                'VisibilityTimeout': '30',
                'MessageRetentionPeriod': '1209600',  # 14 days
                'ReceiveMessageWaitTimeSeconds': '20',  # Long polling
                'RedrivePolicy': json.dumps({
                    'deadLetterTargetArn': f'arn:aws:sqs:{region}:123456789:{queue_name}-dlq',
                    'maxReceiveCount': '3',
                }),
            },
        )
        queue_url = response['QueueUrl']

        # Set queue policy (least privilege)
        policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789:role/producer-role'},
                'Action': 'sqs:SendMessage',
                'Resource': f'arn:aws:sqs:{region}:123456789:{queue_name}',
            }, {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789:role/consumer-role'},
                'Action': ['sqs:ReceiveMessage', 'sqs:DeleteMessage'],
                'Resource': f'arn:aws:sqs:{region}:123456789:{queue_name}',
            }],
        }

        self.sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={'Policy': json.dumps(policy)},
        )

        return queue_url

    def send_encrypted(self, queue_url, message, kms_key_id):
        """Send encrypted message to SQS."""
        # Generate data key
        dek_response = self.kms.generate_data_key(
            KeyId=kms_key_id,
            KeySpec='AES_256',
        )
        dek = dek_response['Plaintext']
        encrypted_dek = dek_response['CiphertextBlob']

        # Encrypt message
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(message).encode(), None)

        # Send with encrypted DEK as attribute
        self.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps({
                'nonce': nonce.hex(),
                'ciphertext': ciphertext.hex(),
            }),
            MessageAttributes={
                'encrypted_dek': {
                    'DataType': 'Binary',
                    'BinaryValue': encrypted_dek,
                },
                'kms_key_id': {
                    'DataType': 'String',
                    'StringValue': kms_key_id,
                },
            },
        )

    def receive_encrypted(self, queue_url):
        """Receive and decrypt message from SQS."""
        response = self.sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            MessageAttributeNames=['All'],
            WaitTimeSeconds=20,
        )

        if 'Messages' not in response:
            return None

        message = response['Messages'][0]
        body = json.loads(message['Body'])

        # Decrypt DEK
        encrypted_dek = message['MessageAttributes']['encrypted_dek']['BinaryValue']
        dek_response = self.kms.decrypt(CiphertextBlob=encrypted_dek)
        dek = dek_response['Plaintext']

        # Decrypt message
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(
            bytes.fromhex(body['nonce']),
            bytes.fromhex(body['ciphertext']),
            None,
        )

        # Delete message after processing
        self.sqs.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=message['ReceiptHandle'],
        )

        return json.loads(plaintext)
```

---

## AUDIT CHECKLIST

- [ ] TLS encryption for all connections
- [ ] Mutual TLS (client certificates) for authentication
- [ ] SASL/SCRAM or OAuth for authentication
- [ ] ACLs with least privilege (per topic/queue)
- [ ] No anonymous access
- [ ] Message encryption (payload encrypted)
- [ ] Message signing (integrity verification)
- [ ] Schema validation on all messages
- [ ] Message size limits
- [ ] Message TTL (time-to-live)
- [ ] Dead letter queue for failed messages
- [ ] Idempotent producers (exactly-once delivery)
- [ ] Read committed isolation (no dirty reads)
- [ ] Network isolation (private subnets, firewall)
- [ ] Audit logging (all operations logged)
- [ ] Monitoring (message rate, error rate, lag)
- [ ] Anomaly detection (unusual message patterns)
- [ ] Key rotation for encryption keys
- [ ] Backup and disaster recovery
- [ ] Regular security review (quarterly)
