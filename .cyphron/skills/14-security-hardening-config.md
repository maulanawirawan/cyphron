# Skill 14 — Security Hardening Config

> Cyphron's methodology for producing hardened configurations for servers, databases, containers, and cloud services. Cyphron knows how misconfigurations are exploited — exposed admin panels, default credentials, overly permissive CORS — so it produces configs that close every gap.

---

## WHEN TO ACTIVATE

- User asks to harden nginx, Apache, IIS, or other web servers
- User asks to harden Docker, Kubernetes, or container configs
- User asks to harden databases (PostgreSQL, MySQL, MongoDB, Redis)
- User asks to harden OS (Linux, Windows)
- User asks for secure CORS, CSP, or HTTP header configs
- User asks to harden cloud services (AWS, Azure, GCP)
- User asks "is this config secure?"

---

## METHODOLOGY

### Step 1: Identify the Component
Determine what's being hardened:
- Web server (Nginx, Apache, IIS)
- Application server (Node.js, Tomcat, Gunicorn)
- Database (PostgreSQL, MySQL, MongoDB, Redis)
- Container runtime (Docker, containerd)
- Orchestrator (Kubernetes)
- Operating system (Linux, Windows)
- Cloud service (S3, RDS, IAM, etc.)

### Step 2: Baseline Against Security Standards
- CIS Benchmarks (CIS Controls)
- NIST guidelines
- Vendor security best practices
- OWASP recommendations

### Step 3: Apply Hardening Categories
For each component, check:
1. **Authentication & Access** — strong auth, least privilege, no defaults
2. **Network** — minimal exposure, TLS, firewall rules
3. **Data Protection** — encryption at rest and in transit
4. **Logging & Monitoring** — comprehensive, tamper-proof
5. **Resource Limits** — DoS protection, quotas
6. **Information Disclosure** — hide versions, suppress errors
7. **Patching** — current versions, security updates

### Step 4: Produce Complete Config
Generate a complete, production-ready configuration file — not fragments.

---

## OUTPUT FORMAT

```markdown
## 🔧 Hardened Configuration: [Component]

### Hardening Summary
| Category | Controls Applied |
|---|---|
| [category] | [controls] |

### Configuration
```[format]
[complete hardened config]
```

### Explanation
[Why each setting matters — what attack it prevents]

### Verification
```bash
[commands to verify the config is applied and effective]
```

### Further Hardening
[Additional steps beyond the config file]
```

---

## HARDENED CONFIGURATION TEMPLATES

### Nginx — Production Hardened
```nginx
# /etc/nginx/nginx.conf — Production Hardened

user nginx;
worker_processes auto;
pid /run/nginx.pid;

# Security: limit file descriptor leak
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
}

http {
    # ─── Basic Settings ───
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30;
    keepalive_requests 100;
    types_hash_max_size 2048;
    server_tokens off;                    # Hide nginx version
    client_max_body_size 10m;             # Limit upload size
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # ─── MIME ───
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # ─── Logging ───
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        'rt=$request_time uct="$upstream_connect_time" '
                        'uht="$upstream_header_time" urt="$upstream_response_time"';
    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    # ─── SSL/TLS Hardening ───
    ssl_protocols TLSv1.2 TLSv1.3;                    # No TLS 1.0/1.1, no SSL
    ssl_prefer_server_ciphers off;                     # Let client choose (TLS 1.3)
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_ecdh_curve secp384r1:secp256r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;                           # Disable for forward secrecy
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # ─── Rate Limiting ───
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
    limit_conn_zone $binary_remote_addr zone=conn:10m;

    # ─── Gzip ───
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # ─── Include site configs ───
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

```nginx
# /etc/nginx/sites-available/app.conf — Site-level hardening

server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;              # Force HTTPS
}

server {
    listen 443 ssl http2;
    server_name example.com;

    # SSL certificates
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # ─── Security Headers ───
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # ─── Rate Limiting ───
    limit_req zone=general burst=20 nodelay;
    limit_conn conn 10;

    # ─── Hide sensitive files ───
    location ~ /\. {
        deny all;                                       # Hidden files (.git, .env)
    }
    location ~ ~$ {
        deny all;                                       # Backup files
    }
    location ~* \.(bak|config|sql|fla|md|ini|log|sh|inc|swp|dist|zip|tar\.gz)$ {
        deny all;                                       # Sensitive extensions
    }

    # ─── Login endpoint — stricter rate limit ───
    location /login {
        limit_req zone=login burst=5 nodelay;
        limit_conn conn 3;
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ─── API — moderate rate limit ───
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ─── Main app ───
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_hide_header X-Powered-By;                 # Hide backend info
    }
}
```

### Dockerfile — Hardened
```dockerfile
# Hardened Dockerfile
FROM node:20-slim AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

# ─── Final stage — minimal runtime ───
FROM node:20-slim

# Install only necessary packages, then clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends dumb-init && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy from builder
COPY --from=builder /app /app

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Security: no shell, minimal environment
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=512"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

EXPOSE 3000

# Use dumb-init for proper signal handling (PID 1)
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
```

### Docker Compose — Hardened
```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"          # Bind to localhost only
    read_only: true                      # Read-only filesystem
    tmpfs:
      - /tmp                             # Writable temp directory
    cap_drop:
      - ALL                              # Drop all capabilities
    cap_add:
      - CHOWN                            # Add only what's needed
      - SETGID
      - SETUID
    security_opt:
      - no-new-privileges:true           # Prevent privilege escalation
    mem_limit: 512m                      # Resource limits
    cpus: 1.0
    pids_limit: 100
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    networks:
      - app-network
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}     # From .env, not in image
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  db:
    image: postgres:16-alpine
    restart: unless-stopped
    volumes:
      - db-data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=${DB_NAME}
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID
      - DAC_OVERRIDE
    security_opt:
      - no-new-privileges:true
    networks:
      - app-network
    # No ports exposed — only accessible within network

networks:
  app-network:
    driver: bridge
    internal: false                       # Set true if no external access needed

volumes:
  db-data:
```

### PostgreSQL — Hardened
```sql
-- pg_hba.conf — restrict connections
# TYPE  DATABASE  USER  ADDRESS          METHOD
local   all       all                    peer
host    all       all   127.0.0.1/32     scram-sha-256
host    all       all   ::1/128          scram-sha-256
# Only allow app server subnet, reject everything else
host    appdb     app   10.0.1.0/24      scram-sha-256
# Reject all other connections
host    all       all   0.0.0.0/0        reject
```

```ini
# postgresql.conf — hardened settings
listen_addresses = '127.0.0.1'           # Only listen on localhost (or specific IP)
port = 5432
max_connections = 100
password_encryption = scram-sha-256      # Strong password hashing
ssl = on                                 # Enable SSL
ssl_cert_file = '/etc/ssl/certs/postgres.crt'
ssl_key_file = '/etc/ssl/private/postgres.key'
ssl_min_protocol_version = 'TLSv1.2'     # No old TLS

# Logging
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%m [%p] %u@%d %h '
log_statement = 'ddl'                    # Log DDL statements
log_min_error_statement = 'error'

# Connection limits
idle_in_transaction_session_timeout = 300000  # 5 minutes
statement_timeout = 60000                     # 1 minute
lock_timeout = 10000                          # 10 seconds
```

### Redis — Hardened
```conf
# redis.conf — hardened
bind 127.0.0.1 ::1                       # Only localhost
protected-mode yes                        # Reject external commands
port 0                                   # Disable TCP, use Unix socket
unixsocket /var/run/redis/redis.sock
unixsocketperm 700

requirepass <strong-password-here>        # Authentication (use ACL for finer control)

# Rename dangerous commands
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command KEYS ""
rename-command DEBUG ""

maxmemory 256mb                          # Memory limit
maxmemory-policy allkeys-lru

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log

# Persistence
appendonly yes
appendfsync everysec
```

### Kubernetes — Pod Security
```yaml
# Pod Security Standard — Restricted
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  labels:
    app: secure-app
spec:
  securityContext:
    runAsNonRoot: true                   # Must run as non-root
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault               # Default seccomp profile
  containers:
  - name: app
    image: app:latest@sha256:abc123...   # Pin by digest, not tag
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
          - ALL
        add:
          - NET_BIND_SERVICE
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

```yaml
# Network Policy — default deny
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}                        # Apply to all pods in namespace
  policyTypes:
  - Ingress
  - Egress
  # No rules = deny all
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: app
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: db
    ports:
    - protocol: TCP
      port: 5432
```

---

## VERIFICATION COMMANDS

```bash
# Nginx — verify config and test
nginx -t                                  # Test config syntax
curl -sI https://example.com | grep -i 'strict-transport\|x-frame\|x-content\|content-security'

# Docker — verify container security
docker inspect <container> --format='{{.HostConfig.SecurityOpt}}'
docker inspect <container> --format='{{.Config.User}}'
docker scan <image>                       # Scan for vulnerabilities

# Kubernetes — verify pod security
kubectl get pods -o jsonpath='{.items[*].spec.securityContext}'
kubectl auth can-i --list --as=system:serviceaccount:default:default

# PostgreSQL — verify
psql -c "SHOW password_encryption;"
psql -c "SHOW ssl;"
psql -c "SELECT * FROM pg_user;"          # Check for default users

# Redis — verify
redis-cli CONFIG GET requirepass
redis-cli CONFIG GET bind
```

---

## KNOWLEDGE BASE REFERENCES

- [`knowledge/attack-encyclopedia.md`](../knowledge/attack-encyclopedia.md) — misconfiguration exploitation
- [`knowledge/secure-patterns.md`](../knowledge/secure-patterns.md) — secure config patterns
