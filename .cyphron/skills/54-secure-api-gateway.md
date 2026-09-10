# Skill 54 — Secure API Gateway

> Cyphron's methodology for building secure API gateways. Cyphron knows API gateway attack vectors — authentication bypass, rate limit bypass, authorization flaws, token abuse — and builds API gateways that are secure by design.

---

## WHEN TO ACTIVATE

- User asks to build or secure an API gateway
- User asks about Kong, AWS API Gateway, Azure API Management, or Tyk
- User asks about API authentication, authorization, or rate limiting
- User asks about API versioning, transformation, or caching security

---

## METHODOLOGY

### API Gateway Security Layers

```
Client → [TLS Termination] → [Authentication] → [Authorization] → [Rate Limit] → [Transform] → [Backend]
              ↓                    ↓                  ↓               ↓            ↓          ↓
           TLS 1.3              JWT/OAuth          RBAC/ABAC      Per-user/     Input      Backend
           HSTS                 API Key            Scope check    Per-IP        validation service
                                 mTLS               Path-based     Per-endpoint  Sanitize
```

### Step 1: Authentication & Authorization
### Step 2: Rate Limiting & Quotas
### Step 3: Input Validation & Transformation
### Step 4: Monitoring & Logging
### Step 5: Versioning & Deprecation

---

## SECURE PATTERNS

### Kong API Gateway (Secure Configuration)
```yaml
# Kong declarative configuration — secure API gateway
_format_version: "3.0"

services:
  - name: orders-service
    url: http://orders-service:8080
    routes:
      - name: orders-route
        paths:
          - /api/v1/orders
        methods:
          - GET
          - POST
        strip_path: true
    plugins:
      # Authentication — JWT
      - name: jwt
        config:
          key_claim_name: iss
          secret_is_base64: false
          claims_to_verify:
            - exp
            - nbf
          maximum_expiration: 3600  # 1 hour max token lifetime

      # Authorization — scope check
      - name: acl
        config:
          allow:
            - orders-read
            - orders-write

      # Rate limiting — per consumer
      - name: rate-limiting
        config:
          minute: 100
          hour: 1000
          policy: local
          fault_tolerant: false
          hide_client_headers: false

      # Rate limiting — per endpoint (stricter)
      - name: rate-limiting-advanced
        config:
          limit: 10
          window_size: 60
          identifier: consumer
          dictionary_name: kong_rate_limiting_counters

      # Request size limiting
      - name: request-size-limiting
        config:
          allowed_payload_size: 1048576  # 1 MB

      # Request validation
      - name: request-validator
        config:
          version: draft4
          body_schema: |
            {
              "type": "object",
              "required": ["items"],
              "properties": {
                "items": {
                  "type": "array",
                  "minItems": 1,
                  "maxItems": 100,
                  "items": {
                    "type": "object",
                    "required": ["product_id", "quantity"],
                    "properties": {
                      "product_id": {"type": "string", "pattern": "^[a-zA-Z0-9-]+$"},
                      "quantity": {"type": "integer", "minimum": 1, "maximum": 1000}
                    }
                  }
                }
              }
            }

      # Response transformation — remove sensitive headers
      - name: response-transformer
        config:
          remove:
            headers:
              - X-Powered-By
              - X-Debug-Info
              - X-Internal-Trace

      # Correlation ID — for distributed tracing
      - name: correlation-id
        config:
          header_name: X-Correlation-ID
          generator: uuid
          echo_downstream: true

      # Logging — audit trail
      - name: file-log
        config:
          path: /var/log/kong/orders-audit.log
          custom_fields_by_lua:
            user_id: "return kong.client.get_consumer().id"
            ip: "return kong.client.get_forwarded_ip()"
            latency: "return kong.ctx.shared.latency"

      # Bot detection
      - name: bot-detection
        config:
          deny:
            - curl
            - wget
            - python-requests
            - sqlmap
            - nikto

  - name: payment-service
    url: http://payment-service:8080
    routes:
      - name: payment-route
        paths:
          - /api/v1/payments
        methods:
          - POST
    plugins:
      # Strict authentication — mTLS + JWT
      - name: mtls-auth
        config:
          ca_certificates:
            - /etc/kong/certs/ca.crt
          skip_consumer_lookup: false

      # Strict rate limiting
      - name: rate-limiting
        config:
          minute: 10
          policy: local

      # IP restriction — internal only
      - name: ip-restriction
        config:
          allow:
            - 10.0.0.0/8
            - 172.16.0.0/12

# Global plugins (apply to all services)
plugins:
  # Security headers
  - name: response-transformer
    config:
      add:
        headers:
          - "X-Content-Type-Options:nosniff"
          - "X-Frame-Options:DENY"
          - "X-XSS-Protection:1; mode=block"
          - "Strict-Transport-Security:max-age=63072000; includeSubDomains; preload"
          - "Content-Security-Policy:default-src 'self'"

  # Global rate limiting
  - name: rate-limiting
    config:
      minute: 1000
      policy: local
```

### AWS API Gateway (Secure Configuration)
```python
import boto3
import json

class SecureAPIGateway:
    def __init__(self, region='us-east-1'):
        self.client = boto3.client('apigateway', region_name=region)
        self.waf_client = boto3.client('wafv2', region_name=region)

    def create_secure_api(self, name, description):
        """Create API Gateway with security best practices."""
        # 1. Create REST API
        api = self.client.create_rest_api(
            name=name,
            description=description,
            endpointConfiguration={'types': ['REGIONAL']},
            minimumCompressionSize=1024,
        )
        api_id = api['id']

        # 2. Create resource and method with authorization
        root_id = self.client.get_resources(restApiId=api_id)['items'][0]['id']

        resource = self.client.create_resource(
            restApiId=api_id,
            parentId=root_id,
            pathPart='orders',
        )

        # 3. Add method with JWT authorization
        self.client.put_method(
            restApiId=api_id,
            resourceId=resource['id'],
            httpMethod='POST',
            authorizationType='CUSTOM',  # Lambda authorizer for JWT
            authorizerId=self._create_jwt_authorizer(api_id),
            requestParameters={
                'method.request.header.Authorization': True,
                'method.request.header.Content-Type': True,
            },
        )

        # 4. Add request validator
        self.client.put_method(
            restApiId=api_id,
            resourceId=resource['id'],
            httpMethod='POST',
            requestValidatorId=self._create_request_validator(api_id),
        )

        # 5. Add integration with request transformation
        self.client.put_integration(
            restApiId=api_id,
            resourceId=resource['id'],
            httpMethod='POST',
            type='HTTP',
            integrationHttpMethod='POST',
            uri='http://backend.example.com/orders',
            requestParameters={
                'integration.request.header.X-User-Id': "context.authorizer.userId",
                'integration.request.header.X-Request-Id': "context.requestId",
            },
            requestTemplates={
                'application/json': json.dumps({
                    "user_id": "$context.authorizer.userId",
                    "request_id": "$context.requestId",
                    "body": "$input.body",
                })
            },
        )

        # 6. Deploy with stage variables
        self.client.create_deployment(
            restApiId=api_id,
            stageName='production',
            variables={
                'environment': 'production',
                'backend_url': 'http://backend.example.com',
            },
        )

        # 7. Enable WAF
        self._attach_waf(api_id, 'production')

        # 8. Enable CloudWatch logging
        self.client.update_stage(
            restApiId=api_id,
            stageName='production',
            patchOperations=[
                {'op': 'replace', 'path': '/accessLogSettings/destinationArn',
                 'value': 'arn:aws:logs:us-east-1:123456789:log-group:api-gateway-logs'},
                {'op': 'replace', 'path': '/accessLogSettings/format',
                 'value': json.dumps({
                     'requestId': '$context.requestId',
                     'ip': '$context.identity.sourceIp',
                     'user': '$context.authorizer.userId',
                     'method': '$context.httpMethod',
                     'path': '$context.resourcePath',
                     'status': '$context.status',
                     'latency': '$context.responseLatency',
                 })},
            ],
        )

        # 9. Enable throttling
        self.client.update_stage(
            restApiId=api_id,
            stageName='production',
            patchOperations=[
                {'op': 'replace', 'path': '/throttle/rateLimit', 'value': '100'},
                {'op': 'replace', 'path': '/throttle/burstLimit', 'value': '200'},
            ],
        )

        return api_id

    def _create_jwt_authorizer(self, api_id):
        """Create Lambda authorizer for JWT validation."""
        authorizer = self.client.create_authorizer(
            restApiId=api_id,
            name='jwt-authorizer',
            type='TOKEN',
            authorizerUri=f'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789:function:jwt-auth/invocations',
            identitySource='method.request.header.Authorization',
            authorizerResultTtlInSeconds=300,
        )
        return authorizer['id']

    def _attach_waf(self, api_id, stage_name):
        """Attach WAF to API Gateway."""
        self.waf_client.associate_web_acl(
            WebACLArn='arn:aws:wafv2:us-east-1:123456789:regional/webacl/api-gateway-waf',
            ResourceArn=f'arn:aws:apigateway:us-east-1::/restapis/{api_id}/stages/{stage_name}',
        )
```

### API Gateway Security Middleware (Express)
```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const app = express();

// ─── Authentication Middleware ───
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'api.example.com',
      audience: 'api-users',
      maxAge: '1h',
    });

    // Check token expiration
    if (payload.exp * 1000 < Date.now()) {
      return res.status(401).json({ error: 'Token expired' });
    }

    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Authorization Middleware ───
function authorize(...requiredScopes) {
  return (req, res, next) => {
    const userScopes = req.user?.scope?.split(' ') || [];

    const hasScope = requiredScopes.some(scope => userScopes.includes(scope));
    if (!hasScope) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: requiredScopes,
      });
    }

    next();
  };
}

// ─── Rate Limiting ───
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 100,             // 100 requests per minute
  keyGenerator: (req) => req.user?.id || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.user?.id || req.ip,
});

// ─── Request Validation ───
const orderSchema = z.object({
  items: z.array(z.object({
    product_id: z.string().regex(/^[a-zA-Z0-9-]+$/),
    quantity: z.number().int().min(1).max(1000),
  })).min(1).max(100),
});

function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: result.error.flatten(),
      });
    }
    req.body = result.data;
    next();
  };
}

// ─── Security Headers ───
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Correlation-ID', req.id);
  next();
});

// ─── Routes ───
app.post('/api/v1/orders',
  authenticate,
  authorize('orders:write'),
  apiLimiter,
  validateBody(orderSchema),
  async (req, res) => {
    // Process order
    const order = await createOrder(req.body, req.user.id);
    res.status(201).json(order);
  }
);

app.post('/api/v1/payments',
  authenticate,
  authorize('payments:write'),
  strictLimiter,  // stricter rate limit for payments
  async (req, res) => {
    // Process payment
    const payment = await processPayment(req.body, req.user.id);
    res.status(201).json(payment);
  }
);
```

---

## AUDIT CHECKLIST

- [ ] TLS 1.2+ termination at gateway
- [ ] Authentication on all endpoints (JWT, OAuth, API key, mTLS)
- [ ] Authorization (scope/role check) on all endpoints
- [ ] Rate limiting per user, per IP, per endpoint
- [ ] Stricter rate limits on sensitive endpoints (payments, auth)
- [ ] Request validation (schema validation)
- [ ] Request size limits
- [ ] Response transformation (remove sensitive headers)
- [ ] Security headers (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Correlation ID for distributed tracing
- [ ] Audit logging (who, what, when, where)
- [ ] Bot detection and blocking
- [ ] IP restriction for internal endpoints
- [ ] API versioning with deprecation policy
- [ ] WAF integration
- [ ] DDoS protection at edge
- [ ] Monitoring and alerting (latency, errors, rate limits)
- [ ] Documentation (OpenAPI/Swagger) with security requirements
- [ ] API key rotation policy
- [ ] Gateway health checks (don't expose sensitive info)
