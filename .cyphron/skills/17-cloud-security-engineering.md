# Skill 17 — Cloud Security Engineering

> Cyphron's methodology for securing cloud infrastructure (AWS, Azure, GCP). Cyphron knows cloud attack patterns — IAM privilege escalation, S3 bucket exposure, metadata service abuse, lateral movement via roles — and builds cloud defenses.

---

## WHEN TO ACTIVATE

- User asks to secure AWS, Azure, or GCP infrastructure
- User asks about IAM, S3, RDS, VPC, or cloud networking security
- User asks to audit cloud configuration
- User asks about cloud misconfiguration or CIS benchmarks
- User asks to build secure Terraform/CloudFormation

---

## METHODOLOGY

### Step 1: Identify Cloud & Service
- Which cloud provider? (AWS, Azure, GCP)
- Which services? (compute, storage, database, IAM, networking)
- IaC or console-managed?

### Step 2: Check Against CIS Benchmarks
- IAM: least privilege, no root access keys, MFA on all accounts
- Storage: no public buckets, encryption at rest, versioning
- Network: private subnets, security groups, no 0.0.0.0/0 on sensitive ports
- Compute: IMDSv2, no public IPs on private instances, hardened AMIs
- Database: encryption, private subnet, automated backups, audit logging

### Step 3: Build Secure IaC

---

## SECURE PATTERNS

### AWS IAM (Least Privilege)
```hcl
# Terraform — least privilege IAM role
resource "aws_iam_role" "app_role" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "app_policy" {
  name = "app-policy"
  role = aws_iam_role.app_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.app_data.arn}/*"
      },
      # NO wildcard actions like s3:* or *
    ]
  })
}
```

### AWS S3 (Secure)
```hcl
resource "aws_s3_bucket" "app_data" {
  bucket = "app-data-secure"
}

resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

### AWS VPC (Secure Network)
```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

# Private subnet for app/db (no internet gateway)
resource "aws_subnet" "private" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false  # No public IPs
}

# Public subnet only for load balancer
resource "aws_subnet" "public" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
}

# Security group — default deny, explicit allow
resource "aws_security_group" "app" {
  name = "app-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]  # Only from VPC
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Or restrict to known endpoints
  }
}
```

### IMDSv2 (Prevent SSRF to metadata)
```hcl
resource "aws_instance" "app" {
  ami = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id]
  subnet_id = aws_subnet.private.id

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"  # IMDSv2 — prevents SSRF to metadata
    http_put_response_hop_limit = 1
  }

  iam_instance_profile = aws_iam_instance_profile.app.name
  user_data = file("hardened-init.sh")
}
```

---

## CLOUD AUDIT CHECKLIST

### AWS
- [ ] No root access keys (use IAM roles)
- [ ] MFA enabled on root and all IAM users
- [ ] No policies with `Action: *` or `Resource: *`
- [ ] S3 buckets: public access blocked, encrypted, versioned
- [ ] Security groups: no 0.0.0.0/0 on SSH/RDP/DB ports
- [ ] RDS: encrypted, private subnet, automated backups
- [ ] CloudTrail enabled in all regions
- [ ] Config rules for compliance
- [ ] GuardDuty for threat detection
- [ ] IMDSv2 on all EC2 instances

### Azure
- [ ] Azure AD MFA on all admin accounts
- [ ] No overly broad role assignments (Owner, Contributor)
- [ ] Storage accounts: secure transfer required, no public blobs
- [ ] Network security groups: deny by default
- [ ] Key Vault for secrets
- [ ] Azure Monitor + Sentinel for SIEM
- [ ] Disk encryption on all VMs

### GCP
- [ ] No overly broad IAM roles (Owner, Editor)
- [ ] Service accounts with least privilege
- [ ] GCS buckets: not public, uniform bucket access
- [ ] VPC firewall rules: deny by default
- [ ] Audit logging enabled
- [ ] Secret Manager for secrets
- [ ] Binary Authorization for GKE
