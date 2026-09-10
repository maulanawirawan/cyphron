# Skill 20 — Secrets Management

> Cyphron's methodology for managing secrets (API keys, passwords, certificates) securely. Cyphron knows how secrets are leaked — hardcoded in code, in environment variables, in CI logs, in container images — and builds secret management systems that prevent exposure.

---

## WHEN TO ACTIVATE

- User asks about secrets, API keys, passwords, or certificates management
- User asks to scan for leaked secrets
- User asks about HashiCorp Vault, AWS Secrets Manager, or similar
- User asks how to securely store/pass secrets to applications
- User asks about secret rotation

---

## METHODOLOGY

### Step 1: Identify Secret Types
- API keys (third-party services)
- Database credentials
- TLS certificates and private keys
- SSH keys
- OAuth client secrets
- Encryption keys

### Step 2: Apply Secret Management Principles
1. **Never hardcode** — no secrets in source code
2. **Never in images** — no secrets baked into Docker images
3. **Never in logs** — redact secrets from all log output
4. **Centralized storage** — use a secrets manager
5. **Rotation** — rotate secrets regularly
6. **Least privilege** — each service accesses only its secrets
7. **Audit** — log all secret access

### Step 3: Choose Secret Manager

| Manager | Best For |
|---|---|
| HashiCorp Vault | Multi-cloud, on-prem, advanced features |
| AWS Secrets Manager | AWS-native workloads |
| Azure Key Vault | Azure-native workloads |
| GCP Secret Manager | GCP-native workloads |
| Kubernetes Secrets + Sealed Secrets | K8s workloads |
| Doppler/Infisical | Developer-friendly, SaaS |

---

## SECURE PATTERNS

### HashiCorp Vault (Application Integration)
```python
import hvac

client = hvac.Client(url='https://vault.example.com')

# Authenticate with AppRole (machine identity)
client.auth.approle.login(role_id=os.environ['ROLE_ID'], secret_id=os.environ['SECRET_ID'])

# Read secret at runtime (never stored in code/env long-term)
secret = client.secrets.kv.read_secret_version(path='database/creds')
db_password = secret['data']['data']['password']

# Use secret
conn = psycopg2.connect(host=db_host, password=db_password)
```

### AWS Secrets Manager
```python
import boto3
import json

client = boto3.client('secretsmanager', region_name='us-east-1')

response = client.get_secret_value(SecretId='prod/database/credentials')
secret = json.loads(response['SecretString'])
db_password = secret['password']

# Automatic rotation with Lambda
# Configure rotation every 30 days
```

### Kubernetes Secrets (Encrypted at Rest)
```yaml
# Enable encryption at rest (encryption-config.yaml)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources: ["secrets"]
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
  - identity: {}
```

```yaml
# Sealed Secrets — encrypt for Git storage
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-secret
spec:
  encryptedData:
    DB_PASSWORD: AgB...encrypted...  # safe to commit to Git
```

### Secret Scanning in CI/CD
```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # scan full history
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Runtime Secret Injection (No env vars)
```yaml
# Docker Compose — inject via secrets, not environment
services:
  app:
    image: app:latest
    secrets:
      - db_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password  # read from file

secrets:
  db_password:
    file: ./secrets/db_password.txt  # not in image, mounted at runtime
```

### Secret Rotation Pattern
```python
import boto3

def rotate_secret(secret_id):
    """Rotate a database password."""
    client = boto3.client('secretsmanager')

    # 1. Generate new password
    new_password = generate_secure_password(32)

    # 2. Update database with new password
    update_database_password(current_creds, new_password)

    # 3. Update secret in manager
    client.put_secret_value(
        SecretId=secret_id,
        SecretString=json.dumps({'password': new_password, ...})
    )

    # 4. Verify new credentials work
    verify_connection(new_password)

    # 5. Mark old version for deletion (staged rotation)
    client.update_secret_version_stage(
        SecretId=secret_id,
        MoveToVersion='NEW_VERSION_ID',
        RemoveFromVersion='OLD_VERSION_ID'
    )
```

---

## AUDIT CHECKLIST

- [ ] No secrets in source code (scan with gitleaks/trufflehog)
- [ ] No secrets in environment variables in production (use secrets manager)
- [ ] No secrets in container images (mount at runtime)
- [ ] No secrets in CI/CD logs (masked in output)
- [ ] No secrets in version control (pre-commit hooks)
- [ ] Secrets manager configured (Vault/SM/Key Vault)
- [ ] Secret rotation policy (30-90 days)
- [ ] Access logging on secret reads
- [ ] Least privilege (each service reads only its secrets)
- [ ] Encryption at rest for stored secrets
- [ ] Encryption in transit for secret retrieval
- [ ] Break-glass procedure for emergency access
- [ ] Secret inventory (know what secrets exist)
