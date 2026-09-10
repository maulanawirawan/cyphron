# Skill 19 — Supply Chain Security

> Cyphron's methodology for securing the software supply chain. Cyphron knows supply chain attack vectors — dependency compromise, build pipeline hijacking, artifact tampering, typosquatting — and builds defenses following SLSA framework.

---

## WHEN TO ACTIVATE

- User asks about supply chain security or SBOM
- User asks to secure CI/CD pipelines
- User asks about dependency management or SCA
- User asks about artifact signing (Cosign, Sigstore)
- User asks about SLSA levels or build provenance

---

## METHODOLOGY

### Step 1: Map the Supply Chain
```
Source Code → Build → Package → Distribute → Deploy
    ↑            ↑         ↑           ↑          ↑
  Signing     Isolated  SBOM      Registry    Verification
  Commits     Build Env  Gen      Signing     Before Deploy
```

### Step 2: Apply SLSA Framework

| SLSA Level | Requirement | What It Prevents |
|---|---|---|
| L1 | Build documentation | Basic provenance |
| L2 | Hosted build service, signed provenance | Tampering during build |
| L3 | Hardened build platform, isolated builds | Build system compromise |
| L4 | Hermetic, reproducible builds | Insider build tampering |

### Step 3: Implement Controls

---

## SECURE PATTERNS

### Dependency Pinning & Verification
```json
// package.json — pin exact versions (no ^ or ~)
{
  "dependencies": {
    "express": "4.18.2",        // exact version
    "lodash": "4.17.21"
  }
}
```

```yaml
# .github/dependabot.yml — automated dependency updates
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      security:
        update-types: ["security"]
```

### SBOM Generation (Syft)
```bash
# Generate SBOM
syft dir:. --output cyclonedx-json=sbom.json

# Verify against known vulnerabilities
grype sbom:sbom.json
```

### Artifact Signing (Cosign)
```bash
# Generate key pair
cosign generate-key-pair

# Sign container image
cosign sign --key cosign.key myregistry.com/app:v1.0

# Verify signature before deploy
cosign verify --key cosign.pub myregistry.com/app:v1.0
```

### Secure CI/CD Pipeline
```yaml
name: Secure Build Pipeline
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # for OIDC (keyless signing)
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # for commit verification

      # Verify commits are signed
      - name: Verify commit signatures
        run: |
          git verify-commit HEAD || exit 1

      # Dependency scanning
      - name: Dependency Review
        uses: actions/dependency-review-action@v3

      # SAST
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1

      # Secret scanning
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2

      # Build (isolated)
      - name: Build
        run: docker build -t app:${{ github.sha }} .

      # Image scanning
      - name: Trivy scan
        run: trivy image --exit-code 1 --severity HIGH,CRITICAL app:${{ github.sha }}

      # Generate SBOM
      - name: Generate SBOM
        run: syft app:${{ github.sha }} -o cyclonedx-json=sbom.json

      # Sign image (keyless with OIDC)
      - name: Sign image
        uses: sigstore/cosign-installer@v3
      - run: cosign sign --yes app:${{ github.sha }}

      # SLSA provenance
      - name: Generate provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.9.0
```

### Dependency Allowlist (npm)
```json
// .npmrc — restrict package registry
{
  "allow": ["express", "lodash", "react"],
  "registry": "https://registry.npmjs.org/"
}
```

---

## SUPPLY CHAIN AUDIT CHECKLIST

- [ ] All dependencies pinned to exact versions
- [ ] Automated dependency update (Dependabot/Renovate)
- [ ] Dependency vulnerability scanning (Snyk/Grype)
- [ ] SBOM generated for every release
- [ ] Container images scanned (Trivy)
- [ ] Images signed (Cosign/Sigstore)
- [ ] Image signatures verified before deploy
- [ ] Commits signed (GPG/Sigstore)
- [ ] Build pipeline isolated (no secrets in build)
- [ ] Build provenance (SLSA L3+)
- [ ] Private package registry for critical deps
- [ ] Typosquatting detection (socket.dev)
- [ ] Lockfile integrity verified
- [ ] No `latest` tags in production
- [ ] Reproducible builds where possible
