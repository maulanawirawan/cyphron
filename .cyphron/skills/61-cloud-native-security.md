# Skill 61 — Cloud-Native Security

> Cyphron's methodology for securing cloud-native applications (serverless, containers, Kubernetes, service mesh). Cyphron knows cloud-native attack vectors — function abuse, container escape, service mesh bypass, IAM privilege escalation — and builds cloud-native defenses.

---

## WHEN TO ACTIVATE

- User asks about serverless security (AWS Lambda, Azure Functions, GCP Cloud Functions)
- User asks about cloud-native application security
- User asks about FaaS security or event-driven security
- User asks about cloud-native observability for security

---

## METHODOLOGY

### Cloud-Native Security Layers

```
Edge (CDN/WAF) → API Gateway → Compute (Lambda/Container) → Data (DB/Storage)
     ↓              ↓                ↓                        ↓
   DDoS          AuthN/Z        Runtime security          Encryption
   WAF           Rate limit     IAM (least privilege)     Access control
   TLS           Validation     Secrets management        Audit logging
```

### Step 1: Serverless Security
### Step 2: Event-Driven Security
### Step 3: Cloud-Native Observability
### Step 4: IAM for Cloud-Native

---

## SECURE PATTERNS

### AWS Lambda Security
```python
import boto3
import json
import os
from functools import wraps

class SecureLambda:
    """Secure AWS Lambda function patterns."""

    def __init__(self):
        self.secrets = boto3.client('secretsmanager')
        self.ssm = boto3.client('ssm')

    # ─── Secure Configuration ───
    @staticmethod
    def get_terraform_config():
        """Terraform for secure Lambda deployment."""
        return '''
# Secure Lambda configuration
resource "aws_lambda_function" "secure_function" {
  function_name = "secure-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256

  # VPC configuration (private subnet)
  vpc_config {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Environment variables (no secrets — use Secrets Manager)
  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "INFO"
      # No secrets here — retrieve from Secrets Manager at runtime
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  # Reserved concurrency (prevent runaway costs)
  reserved_concurrent_executions = 10

  # X-Ray tracing
  tracing_config {
    mode = "Active"
  }

  # Code signing
  code_signing_config_arn = aws_lambda_code_signing_config.this.arn

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Compliance  = "pci-dss"
  }
}

# IAM role — least privilege
resource "aws_iam_role" "lambda_role" {
  name = "secure-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "secure-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Only allow reading specific secret
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.app_secret.arn
      },
      # Only allow writing to specific log group
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      # Only allow VPC networking
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch log group with retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/secure-function"
  retention_in_days = 30

  # Encrypt logs
  kms_key_id = aws_kms_key.logs.arn
}
'''

    # ─── Secure Code Patterns ───
    def get_secret(self, secret_name):
        """Retrieve secret from Secrets Manager (not environment variables)."""
        response = self.secrets.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])

    def validate_event(self, event, expected_schema):
        """Validate Lambda event input."""
        import jsonschema

        try:
            jsonschema.validate(instance=event, schema=expected_schema)
            return True
        except jsonschema.ValidationError as e:
            raise ValueError(f'Event validation failed: {e.message}')

    def sanitize_input(self, event):
        """Sanitize Lambda event input."""
        if isinstance(event, dict):
            return {k: self.sanitize_input(v) for k, v in event.items()}
        elif isinstance(event, list):
            return [self.sanitize_input(item) for item in event]
        elif isinstance(event, str):
            # Remove null bytes
            event = event.replace('\x00', '')
            # Limit length
            max_length = 10000
            if len(event) > max_length:
                event = event[:max_length]
        return event

    def audit_log(self, action, details):
        """Log security event."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'function_name': os.environ.get('AWS_LAMBDA_FUNCTION_NAME'),
            'request_id': os.environ.get('AWS_REQUEST_ID'),
        }
        print(json.dumps(log_entry))  # CloudWatch Logs

# ─── Secure Handler ───
secure_lambda = SecureLambda()

def handler(event, context):
    """Secure Lambda handler."""
    # 1. Validate input
    schema = {
        'type': 'object',
        'required': ['action', 'data'],
        'properties': {
            'action': {'type': 'string', 'enum': ['read', 'write', 'delete']},
            'data': {'type': 'object'},
        },
    }
    secure_lambda.validate_event(event, schema)

    # 2. Sanitize input
    event = secure_lambda.sanitize_input(event)

    # 3. Audit log
    secure_lambda.audit_log('function_invoked', {
        'action': event['action'],
        'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
    })

    # 4. Get secrets (from Secrets Manager, not env vars)
    secret = secure_lambda.get_secret('app/database')

    # 5. Process
    result = process_request(event, secret)

    # 6. Return (no sensitive data in response)
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Success',
            'request_id': context.aws_request_id,
            # Never return secrets or sensitive data
        }),
    }
```

### Event-Driven Security (EventBridge + Lambda)
```python
import boto3
import json

class EventDrivenSecurity:
    """Secure event-driven architecture."""

    def __init__(self):
        self.events = boto3.client('events')
        self.lambda_client = boto3.client('lambda')

    def create_secure_rule(self, rule_name, event_pattern, target_arn):
        """Create EventBridge rule with least privilege."""
        # 1. Create rule
        self.events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='Secure event rule with least privilege',
        )

        # 2. Add target with input transformer (sanitize event)
        self.events.put_targets(
            Rule=rule_name,
            Targets=[{
                'Id': '1',
                'Arn': target_arn,
                'InputTransformer': {
                    'InputPathsMap': {
                        'source': '$.source',
                        'detail_type': '$.detail-type',
                        'detail': '$.detail',
                    },
                    'InputTemplate': json.dumps({
                        'source': '<source>',
                        'type': '<detail_type>',
                        'data': '<detail>',
                        'sanitized': True,
                    }),
                },
                'RetryPolicy': {
                    'MaximumRetryAttempts': 3,
                    'MaximumEventAgeInSeconds': 3600,
                },
                'DeadLetterConfig': {
                    'Arn': 'arn:aws:sqs:us-east-1:123456789:dlq',
                },
            }],
        )

        # 3. Add resource-based policy (least privilege)
        self.lambda_client.add_permission(
            FunctionName=target_arn,
            StatementId=f'{rule_name}-invoke',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=f'arn:aws:events:us-east-1:123456789:rule/{rule_name}',
        )

    def validate_event_source(self, event):
        """Validate event came from trusted source."""
        expected_source = 'aws.events'
        actual_source = event.get('source')

        if actual_source != expected_source:
            raise PermissionError(f'Untrusted event source: {actual_source}')

        # Verify event signature (if using EventBridge with signing)
        # This is a simplified check — implement proper signature verification
        return True
```

### Cloud-Native Observability (Security)
```python
class CloudNativeSecurityObservability:
    """Security observability for cloud-native applications."""

    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch')
        self.xray = boto3.client('xray')

    def create_security_dashboard(self):
        """Create CloudWatch security dashboard."""
        dashboard_body = {
            'widgets': [
                # Lambda errors
                {
                    'type': 'metric',
                    'properties': {
                        'metrics': [
                            ['AWS/Lambda', 'Errors', {'stat': 'Sum'}],
                            ['AWS/Lambda', 'Throttles', {'stat': 'Sum'}],
                            ['AWS/Lambda', 'Duration', {'stat': 'Average'}],
                        ],
                        'period': 300,
                        'region': 'us-east-1',
                        'title': 'Lambda Security Metrics',
                    },
                },
                # API Gateway errors
                {
                    'type': 'metric',
                    'properties': {
                        'metrics': [
                            ['AWS/ApiGateway', '4XXError', {'stat': 'Sum'}],
                            ['AWS/ApiGateway', '5XXError', {'stat': 'Sum'}],
                        ],
                        'period': 300,
                        'region': 'us-east-1',
                        'title': 'API Gateway Security Metrics',
                    },
                },
                # IAM events
                {
                    'type': 'log',
                    'properties': {
                        'query': "SOURCE '/aws/lambda/security' | fields @timestamp, @message | filter @message like /ERROR|WARN|DENIED/",
                        'region': 'us-east-1',
                        'title': 'Security Events',
                    },
                },
            ],
        }

        self.cloudwatch.put_dashboard(
            DashboardName='cloud-native-security',
            DashboardBody=json.dumps(dashboard_body),
        )

    def create_security_alarms(self):
        """Create CloudWatch security alarms."""
        # Alarm: High error rate
        self.cloudwatch.put_metric_alarm(
            AlarmName='lambda-high-error-rate',
            MetricName='Errors',
            Namespace='AWS/Lambda',
            Statistic='Sum',
            Period=300,
            EvaluationPeriods=2,
            Threshold=10,
            ComparisonOperator='GreaterThanThreshold',
            AlarmActions=['arn:aws:sns:us-east-1:123456789:security-alerts'],
        )

        # Alarm: Unusual invocation pattern
        self.cloudwatch.put_metric_alarm(
            AlarmName='lambda-unusual-invocations',
            MetricName='Invocations',
            Namespace='AWS/Lambda',
            Statistic='Sum',
            Period=60,
            EvaluationPeriods=5,
            Threshold=1000,
            ComparisonOperator='GreaterThanThreshold',
            AlarmActions=['arn:aws:sns:us-east-1:123456789:security-alerts'],
        )
```

---

## AUDIT CHECKLIST

- [ ] Lambda functions in VPC (private subnet)
- [ ] IAM roles with least privilege (no wildcard actions)
- [ ] No secrets in environment variables (use Secrets Manager)
- [ ] Input validation on all events
- [ ] Input sanitization (null bytes, length limits)
- [ ] Dead letter queue for failed invocations
- [ ] Reserved concurrency (prevent runaway costs)
- [ ] X-Ray tracing enabled
- [ ] CloudWatch logging with retention
- [ ] Log encryption (KMS)
- [ ] Security alarms (errors, unusual patterns)
- [ ] Security dashboard (metrics, logs, alarms)
- [ ] Code signing for Lambda functions
- [ ] EventBridge rules with least privilege
- [ ] Event source validation
- [ ] Retry policy with DLQ
- [ ] API Gateway with authentication
- [ ] Rate limiting on API Gateway
- [ ] WAF on API Gateway
- [ ] Regular security review (quarterly)
