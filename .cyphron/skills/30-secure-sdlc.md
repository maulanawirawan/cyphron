# Skill 30 — Secure SDLC (SSDLC)

> Cyphron's methodology for integrating security into the Software Development Lifecycle. Cyphron knows where vulnerabilities are introduced — design flaws, coding errors, dependency choices, deployment misconfigurations — and builds security gates at every SDLC phase.

---

## WHEN TO ACTIVATE

- User asks to build a secure SDLC process
- User asks about security in requirements, design, coding, testing, or deployment
- User asks about DevSecOps or security automation in CI/CD
- User asks about security gates or security checkpoints

---

## METHODOLOGY

### SDLC Phases & Security Activities

| Phase | Security Activity | Output |
|---|---|---|
| Requirements | Security requirements, abuse cases | Security requirements doc |
| Design | Threat modeling, secure design review | Threat model, design review |
| Development | Secure coding, SAST, pre-commit hooks | Secure code |
| Testing | DAST, SCA, security testing, fuzzing | Security test results |
| Deployment | Security config review, IaC scanning | Hardened deployment |
| Operations | Monitoring, patching, incident response | Security operations |
| Maintenance | Dependency updates, vulnerability management | Patched software |

### Step 1: Define Security Requirements
### Step 2: Design with Security (Threat Modeling)
### Step 3: Code Securely (SAST, linting)
### Step 4: Test Security (DAST, SCA, fuzzing)
### Step 5: Deploy Securely (IaC scanning, config review)
### Step 6: Operate Securely (monitoring, patching)

---

## SECURE PATTERNS

### Security Requirements Template
```markdown
## Security Requirements — [Feature Name]

### Authentication
- [ ] All endpoints require authentication
- [ ] MFA for sensitive operations
- [ ] Session timeout: 30 minutes idle

### Authorization
- [ ] Object-level authorization on all data access
- [ ] Role-based access control (user, admin)
- [ ] Default-deny policy

### Input Validation
- [ ] All input validated with allowlist
- [ ] Maximum length enforced
- [ ] File upload: type + size validation

### Data Protection
- [ ] Encryption at rest (AES-256)
- [ ] Encryption in transit (TLS 1.2+)
- [ ] No sensitive data in logs

### Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side only
- [ ] No stack traces in production

### Logging & Monitoring
- [ ] All auth events logged
- [ ] All access control failures logged
- [ ] Anomaly detection on critical endpoints
```

### Pre-Commit Hooks (Security)
```bash
#!/bin/bash
# .git/hooks/pre-commit — security checks before commit

echo "Running security pre-commit checks..."

# 1. Secret scanning
if ! command -v gitleaks &> /dev/null; then
  echo "Installing gitleaks..."
  go install github.com/zricethezav/gitleaks/v8@latest
fi
gitleaks protect --staged --redact
if [ $? -ne 0 ]; then
  echo "❌ Secrets detected in commit! Remove them before committing."
  exit 1
fi

# 2. SAST (if semgrep available)
if command -v semgrep &> /dev/null; then
  semgrep --config auto --error
  if [ $? -ne 0 ]; then
    echo "❌ SAST found issues. Fix before committing."
    exit 1
  fi
fi

# 3. Dependency check (if npm)
if [ -f "package.json" ]; then
  npm audit --audit-level=high
  if [ $? -ne 0 ]; then
    echo "⚠️  High-severity vulnerabilities in dependencies."
    # Don't block, just warn
  fi
fi

echo "✅ Pre-commit security checks passed."
```

### CI/CD Security Pipeline (Complete)
```yaml
# .github/workflows/security.yml
name: Security Pipeline
on: [push, pull_request]

jobs:
  # ─── Phase: Development ───
  sast:
    name: SAST (Semgrep)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/javascript
            p/python
            p/sql-injection
            p/xss

  secret-scan:
    name: Secret Scanning (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  # ─── Phase: Testing ───
  dependency-scan:
    name: Dependency Scanning (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: npm audit
        run: npm audit --audit-level=high --production
      - name: Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

  security-tests:
    name: Security Test Suite
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test -- --grep "Security|XSS|SQL|Auth|IDOR|CSRF"

  dast:
    name: DAST (ZAP)
    runs-on: ubuntu-latest
    needs: [sast, secret-scan]
    steps:
      - uses: actions/checkout@v4
      - name: Start app
        run: |
          npm ci
          npm start &
          sleep 10
      - uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          cmd_options: '-a -j'

  # ─── Phase: Deployment ───
  iac-scan:
    name: IaC Security (Checkov)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: terraform dockerfile kubernetes

  container-scan:
    name: Container Scan (Trivy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t app:${{ github.sha }} .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          severity: HIGH,CRITICAL
          exit-code: 1

  # ─── Phase: Release ───
  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    needs: [sast, dependency-scan, container-scan]
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM (Syft)
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json

  sign:
    name: Sign Artifacts (Cosign)
    runs-on: ubuntu-latest
    needs: [container-scan]
    permissions:
      id-token: write
      packages: write
    steps:
      - uses: sigstore/cosign-installer@v3
      - name: Sign image
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker tag app:${{ github.sha }} ghcr.io/${{ github.repository }}:${{ github.sha }}
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
          cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### Security Design Review Checklist
```markdown
## Security Design Review — [Feature Name]

### Threat Model
- [ ] Threat model completed (STRIDE)
- [ ] Trust boundaries identified
- [ ] Attack surface mapped

### Authentication & Authorization
- [ ] Authentication mechanism defined
- [ ] Authorization model defined (RBAC/ABAC)
- [ ] Object-level authorization planned

### Data Handling
- [ ] Data classification completed
- [ ] Encryption at rest planned
- [ ] Encryption in transit planned
- [ ] Data retention defined
- [ ] PII handling defined (GDPR/CCPA)

### Input/Output
- [ ] Input validation strategy defined
- [ ] Output encoding strategy defined
- [ ] API contract reviewed

### Infrastructure
- [ ] Network segmentation planned
- [ ] Secrets management planned
- [ ] Logging & monitoring defined
- [ ] Backup & recovery defined

### Dependencies
- [ ] Third-party components reviewed
- [ ] Supply chain risks assessed
```

---

## AUDIT CHECKLIST (SSDLC)

- [ ] Security requirements defined for every feature
- [ ] Threat modeling before implementation
- [ ] Secure coding standards documented
- [ ] SAST in CI/CD (blocks on critical/high)
- [ ] Secret scanning in pre-commit + CI
- [ ] Dependency scanning in CI (SCA)
- [ ] DAST against staging
- [ ] Security test suite in CI
- [ ] IaC scanning (Checkov/tfsec)
- [ ] Container image scanning (Trivy)
- [ ] SBOM generated for every release
- [ ] Artifacts signed (Cosign)
- [ ] Security design review for major features
- [ ] Security training for developers
- [ ] Bug bounty or vulnerability disclosure program
- [ ] Post-deployment security monitoring
