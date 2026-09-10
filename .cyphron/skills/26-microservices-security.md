# Skill 26 — Microservices Security

> Cyphron's methodology for securing microservices architectures. Cyphron knows microservices attack vectors — service-to-service spoofing, lateral movement, API gateway bypass, broken trust boundaries — and builds microservices defenses.

---

## WHEN TO ACTIVATE

- User asks to secure a microservices architecture
- User asks about service mesh, API gateway, or service-to-service auth
- User asks about distributed tracing for security
- User asks about microservices authentication or authorization

---

## METHODOLOGY

### Step 1: Map Microservices Architecture
- Identify all services and their trust relationships
- Map communication patterns (sync REST, async events, gRPC)
- Identify the API gateway and service mesh
- Map data ownership (which service owns which data)

### Step 2: Security Controls Per Layer

| Layer | Control |
|---|---|
| Edge | API gateway (auth, rate limit, WAF) |
| Service-to-Service | mTLS, service identity (SPIFFE) |
| Service Mesh | Traffic policies, authorization |
| Data | Database per service, encrypted connections |
| Observability | Distributed tracing, audit logs |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### Service-to-Service mTLS (Istio)
```yaml
# Enforce mTLS for all traffic
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# Authorization policy — restrict which services can call which
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: orders-to-payment
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/orders-service"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/v1/charge"]
```

### API Gateway Security
```yaml
# Kong API Gateway — secure configuration
services:
  - name: orders-service
    url: http://orders-service:8080
    routes:
      - paths: ["/api/orders"]
        methods: [GET, POST]
    plugins:
      - name: jwt              # Authentication
      - name: rate-limiting     # Rate limiting
        config:
          minute: 100
      - name: correlation-id    # Trace ID propagation
      - name: prometheus        # Metrics
```

### Service Identity (SPIFFE/SPIRE)
```yaml
# SPIRE — workload identity
apiVersion: spire.spiffe.io/v1alpha1
kind: SPIREServer
metadata:
  name: spire-server
spec:
  trustDomain: example.com
  nodeAttestor: k8s_sat
---
# Each service gets a SPIFFE ID
# orders-service → spiffe://example.com/ns/production/sa/orders-service
# payment-service → spiffe://example.com/ns/production/sa/payment-service
# mTLS verifies SPIFFE IDs — no shared secrets
```

### Distributed Tracing for Security (OpenTelemetry)
```python
from opentelemetry import trace
from opentelemetry.instrumentation.flask import FlaskInstrumentor

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

@app.route('/api/orders', methods=['POST'])
@require_auth
def create_order():
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("create_order") as span:
        span.set_attribute("user.id", request.user.id)
        span.set_attribute("user.role", request.user.role)
        span.set_attribute("request.action", "create_order")

        # Call payment service with trace context propagated
        result = call_payment_service(order, trace_context=span.context)

        span.set_attribute("order.id", result.order_id)
        span.set_attribute("payment.status", result.status)
        return jsonify(result)
```

### Event-Driven Security (Kafka)
```python
from confluent_kafka import Producer, Consumer
import ssl

# Secure Kafka configuration
conf = {
    'bootstrap.servers': 'kafka:9093',
    'security.protocol': 'SASL_SSL',
    'sasl.mechanism': 'SCRAM-SHA-512',
    'sasl.username': 'orders-service',
    'sasl.password': get_secret('kafka_password'),
    'ssl.ca.location': '/etc/ssl/kafka-ca.pem',
    'group.id': 'orders-consumer',
    'enable.auto.commit': False,  # manual commit for reliability
}

consumer = Consumer(conf)
consumer.subscribe(['order-events'])

# ACLs on Kafka — each service can only access its topics
# orders-service → produce to order-events, consume from payment-events
# payment-service → produce to payment-events, consume from order-events
```

---

## AUDIT CHECKLIST

- [ ] mTLS between all services (no plaintext)
- [ ] Service identity (SPIFFE or mutual cert auth)
- [ ] API gateway with auth, rate limiting, WAF
- [ ] Authorization policies (which service can call which)
- [ ] Database per service (no shared databases)
- [ ] Distributed tracing with security context
- [ ] Audit logging on all service calls
- [ ] Circuit breakers (prevent cascading failures)
- [ ] No service bypasses the API gateway for external traffic
- [ ] Secrets per service (not shared)
- [ ] Health checks don't expose sensitive info
- [ ] Graceful degradation (fail-safe defaults)
