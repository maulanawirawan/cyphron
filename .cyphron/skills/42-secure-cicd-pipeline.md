# Skill 42 — Secure CI/CD Pipeline Engineering

> Cyphron's methodology for building secure CI/CD pipelines (DevSecOps). Cyphron knows pipeline attack vectors — secret injection, artifact tampering, build system compromise, dependency confusion — and builds pipelines with security gates at every stage.

---

## WHEN TO ACTIVATE

- User asks to build or secure a CI/CD pipeline
- User asks about DevSecOps or security automation
- User asks about pipeline security gates
- User asks about secure build environments

---

## METHODOLOGY

### Pipeline Security Gates

```
Commit → Build → Test → Scan → Sign → Deploy → Monitor
  │        │       │      │      │       │       │
  ↓        ↓       ↓      ↓      ↓       ↓       ↓
Secret   Build   Unit   SAST   Cosign  IaC    Runtime
Scan     Isolation Tests  SCA   SBOM    Scan   Monitoring
         No      DAST   Image
         Secrets        Scan
```

### Step 1: Secure Each Pipeline Stage
### Step 2: Isolate Build Environment
### Step 3: Sign & Verify Artifacts
### Step 4: Monitor Deployments

---

## SECURE PATTERNS

### Complete Secure Pipeline (GitHub Actions)
```yaml
name: Secure CI/CD Pipeline
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  id-token: write  # for OIDC keyless signing
  packages: write

jobs:
  # ─── Stage 1: Pre-Merge Security ───
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
      - name: Trufflehog
        uses: trufflesecurity/trufflehog@main
        with:
          path: .

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten p/sql-injection p/xss
            p/command-injection p/crypto-bad-modes
      - name: CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: javascript, python
      - uses: github/codeql-action/analyze@v3

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - name: npm audit
        run: npm audit --audit-level=high --production
      - name: Snyk
        uses: snyk/actions/node@master
        env: { SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }} }
      - name: Socket (supply chain)
        uses: socketsdev/socket-action@v1

  # ─── Stage 2: Build (Isolated) ───
  build:
    needs: [secret-scan, sast, dependency-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.sha }} }  # pinned commit
      - name: Build
        run: |
          docker build \
            --build-arg BUILDKIT_INLINE_CACHE=1 \
            --label org.opencontainers.image.revision=${{ github.sha }} \
            -t app:${{ github.sha }} .
      - name: Export image
        run: docker save app:${{ github.sha }} -o image.tar

  # ─── Stage 3: Security Testing ───
  container-scan:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
        with: { name: image }
      - run: docker load -i image.tar
      - name: Trivy (vulns)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          severity: HIGH,CRITICAL
          exit-code: 1
      - name: Trivy (secrets in image)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          scanners: secret
          exit-code: 1
      - name: Grype
        uses: anchore/scan-action@v3
        with:
          image: app:${{ github.sha }}
          fail-build: true
          severity-cutoff: high

  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Checkov (Terraform/Dockerfile/K8s)
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: terraform dockerfile kubernetes
          output_format: sarif
      - name: tfsec
        uses: aquasecurity/tfsec-action@v1.0.0

  dast:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start app
        run: |
          docker load -i image.tar
          docker run -d -p 3000:3000 app:${{ github.sha }}
          sleep 15
      - name: OWASP ZAP Baseline
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          cmd_options: '-a -j'

  # ─── Stage 4: Sign & SBOM ───
  sign-and-sbom:
    needs: [container-scan, iac-scan, dast]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
        with: { name: image }
      - run: docker load -i image.tar

      # Generate SBOM
      - name: Syft SBOM
        uses: anchore/sbom-action@v0
        with:
          image: app:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.json
      - uses: actions/upload-artifact@v3
        with: { name: sbom, path: sbom.json }

      # Sign image (keyless with OIDC)
      - uses: sigstore/cosign-installer@v3
      - name: Sign image
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | \
            docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker tag app:${{ github.sha }} ghcr.io/${{ github.repository }}:${{ github.sha }}
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
          cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}

      # Generate SLSA provenance
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0

  # ─── Stage 5: Deploy (Verified) ───
  deploy:
    needs: sign-and-sbom
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3

      # Verify image signature before deploy
      - name: Verify signature
        run: |
          cosign verify \
            --certificate-identity-regexp "https://github.com/${{ github.repository }}/.github/" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            ghcr.io/${{ github.repository }}:${{ github.sha }}

      # Deploy with canary
      - name: Deploy (canary)
        run: |
          kubectl set image deployment/app app=ghcr.io/${{ github.repository }}:${{ github.sha }}
          kubectl rollout status deployment/app --timeout=300s

      # Monitor for issues
      - name: Monitor (5 min)
        run: |
          sleep 300
          ERROR_RATE=$(kubectl logs deployment/app --tail=1000 | grep -c "ERROR")
          if [ "$ERROR_RATE" -gt 10 ]; then
            echo "High error rate — rolling back"
            kubectl rollout undo deployment/app
            exit 1
          fi
```

### Pipeline Secret Management
```yaml
# Never hardcode secrets in pipeline — use secret store
env:
  # ✅ From GitHub Secrets (encrypted at rest)
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
  API_KEY: ${{ secrets.API_KEY }}

  # ✅ From OIDC (no stored secrets — keyless)
  AWS_ROLE: arn:aws:iam::123456789:role/github-actions

steps:
  # ✅ OIDC authentication (no long-lived keys)
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: ${{ env.AWS_ROLE }}
      aws-region: us-east-1

  # ❌ NEVER do this:
  # env:
  #   DB_PASSWORD: "hardcoded-password"  # visible in logs!
```

### Branch Protection Rules
```yaml
# Required: branch protection for main
rules:
  - name: Require PR review
    required_reviews: 2
    dismiss_stale_reviews: true
    require_code_owner_reviews: true

  - name: Require status checks
    required_checks:
      - secret-scan
      - sast
      - dependency-scan
      - container-scan
      - iac-scan
      - dast

  - name: Require signed commits
    required_signatures: true

  - name: Require linear history
    required_linear_history: true

  - name: No force push
    allow_force_pushes: false

  - name: No deletions
    allow_deletions: false
```

---

## AUDIT CHECKLIST

- [ ] Secret scanning in pre-commit and CI
- [ ] SAST in CI (blocks on critical/high)
- [ ] SCA/dependency scanning in CI
- [ ] Container image scanning in CI
- [ ] IaC scanning (Terraform, Dockerfile, K8s)
- [ ] DAST against staging
- [ ] SBOM generated for every release
- [ ] Artifacts signed (Cosign/Sigstore)
- [ ] Image signatures verified before deploy
- [ ] SLSA provenance (L3+)
- [ ] Branch protection (required reviews, status checks)
- [ ] Signed commits required
- [ ] No long-lived secrets (OIDC keyless)
- [ ] Build environment isolated
- [ ] Least privilege pipeline tokens
- [ ] Canary deployment with auto-rollback
- [ ] Pipeline audit logging
- [ ] Separate deploy permissions from build
