# Skill 18 — Container & Kubernetes Security

> Cyphron's methodology for securing containers and Kubernetes clusters. Cyphron knows container escape techniques, pod security risks, RBAC misconfigurations, and supply chain threats — and builds hardened container deployments.

---

## WHEN TO ACTIVATE

- User asks to secure Docker, containerd, or Kubernetes
- User asks about container escape, pod security, or RBAC
- User asks to harden Dockerfiles or Kubernetes manifests
- User asks about admission controllers, network policies, or service mesh
- User asks about container image scanning

---

## METHODOLOGY

### Step 1: Identify Container Stack
- Container runtime (Docker, containerd, CRI-O)
- Orchestrator (Kubernetes, Docker Swarm, Nomad)
- Service mesh (Istio, Linkerd)

### Step 2: Security Layers

| Layer | Controls |
|---|---|
| Image | Minimal base, no secrets, scanning, signing |
| Build | Multi-stage, non-root, pinned dependencies |
| Runtime | Non-root, read-only FS, dropped capabilities, seccomp |
| Network | Network policies (default deny), mTLS |
| Access | RBAC, admission controllers, audit logging |
| Supply chain | SBOM, signed images, admission validation |

### Step 3: Apply Pod Security Standards (Restricted)

---

## SECURE PATTERNS

### Kubernetes Pod Security (Restricted)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app@sha256:abc123...  # Pin by digest
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop: [ALL]
        add: [NET_BIND_SERVICE]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
      requests:
        memory: "128Mi"
        cpu: "100m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

### Network Policy (Default Deny)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
spec:
  podSelector:
    matchLabels: { app: app }
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector:
        matchLabels: { app: db }
    ports:
    - protocol: TCP
      port: 5432
```

### RBAC (Least Privilege)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-reader
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
  resourceNames: ["app-config", "app-secret"]  # specific resources only
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-binding
subjects:
- kind: ServiceAccount
  name: app-sa
roleRef:
  kind: Role
  name: app-reader
  apiGroup: rbac.authorization.k8s.io
```

### Admission Controller (OPA Gatekeeper)
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredlabels
      violation[{"msg": msg}] {
        not input.review.object.metadata.labels.app
        msg := "Missing required label: app"
      }
```

### Service Mesh mTLS (Istio)
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT  # Enforce mTLS for all workloads
```

---

## AUDIT CHECKLIST

- [ ] All pods run as non-root
- [ ] All pods have readOnlyRootFilesystem
- [ ] All capabilities dropped (add only needed)
- [ ] Resource limits on all containers
- [ ] Network policies (default deny)
- [ ] RBAC with least privilege
- [ ] Images pinned by digest (not tag)
- [ ] Image scanning in CI (Trivy, Grype)
- [ ] No privileged containers
- [ ] No hostPath mounts
- [ ] No host network/pid/ipc
- [ ] Audit logging enabled
- [ ] Secrets encrypted at rest
- [ ] Admission controllers active
