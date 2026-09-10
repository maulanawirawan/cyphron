# Security Tool Templates

> Reusable code templates for defensive security tools. Cyphron uses these as starting points when building security tools (Skill 04). All templates are defensive — they find, prevent, or detect vulnerabilities; they never exploit.

---

## 1. SAST SCANNER (Pattern-Based)

```python
#!/usr/bin/env python3
"""
Simple SAST scanner — scans source files for vulnerability patterns.
Defensive tool: finds vulnerabilities in code, doesn't exploit them.
"""
import re
import os
import sys
from pathlib import Path
from typing import List, Dict

# Vulnerability patterns
PATTERNS = {
    'sql_injection': {
        'patterns': [
            r'execute\s*\(\s*f["\'].*\{.*\}.*["\']',
            r'execute\s*\(\s*["\'].*["\']\s*\+\s*\w+',
            r'query\s*\(\s*f["\'].*\{.*\}.*["\']',
            r'\.format\s*\(\s*["\']SELECT.*["\']',
        ],
        'message': 'Possible SQL injection via string formatting/concatenation',
        'severity': 'CRITICAL',
        'cwe': 'CWE-89',
    },
    'command_injection': {
        'patterns': [
            r'os\.system\s*\(\s*f["\']',
            r'subprocess\.\w+\s*\(\s*.*shell\s*=\s*True',
            r'exec\s*\(\s*f["\']',
            r'eval\s*\(\s*\w+\s*\)',
        ],
        'message': 'Possible command injection via shell execution',
        'severity': 'CRITICAL',
        'cwe': 'CWE-78',
    },
    'hardcoded_secret': {
        'patterns': [
            r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\x27][^"\x27]{8,}["\x27]',
            r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*:\s*["\x27][^"\x27]{8,}["\x27]',
        ],
        'message': 'Possible hardcoded secret',
        'severity': 'HIGH',
        'cwe': 'CWE-798',
    },
    'weak_crypto': {
        'patterns': [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'createHash\s*\(\s*["\x27]md5["\x27]',
            r'createHash\s*\(\s*["\x27]sha1["\x27]',
            r'\.md5\s*\(',
        ],
        'message': 'Weak cryptographic hash algorithm',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327',
    },
    'xss': {
        'patterns': [
            r'innerHTML\s*=\s*[^"\x27]',
            r'dangerouslySetInnerHTML',
            r'document\.write\s*\(',
        ],
        'message': 'Possible XSS via unsafe DOM write',
        'severity': 'HIGH',
        'cwe': 'CWE-79',
    },
    'path_traversal': {
        'patterns': [
            r'open\s*\(\s*.*\+\s*\w+',
            r'readFile\s*\(\s*.*\+\s*\w+',
            r'join\s*\(\s*.*,\s*req\.',
        ],
        'message': 'Possible path traversal via user input in file path',
        'severity': 'HIGH',
        'cwe': 'CWE-22',
    },
}

def scan_file(filepath: str) -> List[Dict]:
    """Scan a single file for vulnerability patterns."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, PermissionError):
        return findings

    for line_num, line in enumerate(lines, 1):
        for vuln_type, config in PATTERNS.items():
            for pattern in config['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'file': filepath,
                        'line': line_num,
                        'type': vuln_type,
                        'severity': config['severity'],
                        'message': config['message'],
                        'cwe': config['cwe'],
                        'code': line.strip(),
                    })
    return findings

def scan_directory(directory: str, extensions: set = None) -> List[Dict]:
    """Scan all files in a directory for vulnerability patterns."""
    if extensions is None:
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb'}

    all_findings = []
    for root, dirs, files in os.walk(directory):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}]

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext in extensions:
                filepath = os.path.join(root, filename)
                all_findings.extend(scan_file(filepath))

    return all_findings

def print_report(findings: List[Dict]):
    """Print a formatted vulnerability report."""
    if not findings:
        print("✅ No vulnerabilities found!")
        return

    print("=" * 70)
    print(f"SAST SCAN REPORT — {len(findings)} findings")
    print("=" * 70)

    # Group by severity
    by_severity = {}
    for f in findings:
        by_severity.setdefault(f['severity'], []).append(f)

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in by_severity:
            print(f"\n{'!' if severity in ('CRITICAL', 'HIGH') else '?'} {severity}: {len(by_severity[severity])} findings")
            for f in by_severity[severity]:
                print(f"  {f['file']}:{f['line']} — {f['message']}")
                print(f"    [{f['cwe']}] {f['code'][:80]}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python sast_scanner.py <directory>")
        sys.exit(1)
    findings = scan_directory(sys.argv[1])
    print_report(findings)
```

---

## 2. SECRET SCANNER

```python
#!/usr/bin/env python3
"""
Secret scanner — finds hardcoded credentials in source code.
Defensive tool: prevents accidental secret exposure.
"""
import re
import os
import sys

SECRET_PATTERNS = {
    'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'AWS Secret Key': re.compile(r'(?i)aws_secret_access_key\s*=\s*["\x27]([A-Za-z0-9/+=]{40})["\x27]'),
    'Google API Key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'GitHub Token': re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),
    'Slack Token': re.compile(r'xox[baprs]-[A-Za-z0-9-]+'),
    'Stripe Key': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
    'Private Key': re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
    'Generic Password': re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\x27](?!{|\$|\s)([^"\x27]{8,})["\x27]'),
    'Generic API Key': re.compile(r'(?i)(api[_-]?key)\s*[:=]\s*["\x27][A-Za-z0-9]{20,}["\x27]'),
    'JWT Token': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    'Database URL': re.compile(r'(?i)(postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@'),
}

def scan_for_secrets(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern in SECRET_PATTERNS.items():
                    match = pattern.search(line)
                    if match:
                        # Mask the secret in output
                        secret = match.group(0)
                        masked = secret[:8] + '*' * (len(secret) - 12) + secret[-4:] if len(secret) > 12 else '***'
                        findings.append({
                            'file': filepath,
                            'line': line_num,
                            'type': name,
                            'masked_secret': masked,
                        })
    except (IOError, PermissionError):
        pass
    return findings

def scan_directory(directory):
    all_findings = []
    skip_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for filename in files:
            filepath = os.path.join(root, filename)
            all_findings.extend(scan_for_secrets(filepath))
    return all_findings

if __name__ == '__main__':
    findings = scan_directory(sys.argv[1] if len(sys.argv) > 1 else '.')
    if findings:
        print(f"🚨 Found {len(findings)} potential secrets:")
        for f in findings:
            print(f"  {f['file']}:{f['line']} — {f['type']}: {f['masked_secret']}")
    else:
        print("✅ No secrets found!")
```

---

## 3. HTTP SECURITY HEADER CHECKER

```python
#!/usr/bin/env python3
"""
HTTP security header checker — validates security headers on a URL.
Defensive tool: verifies security headers are properly configured.
"""
import sys
import urllib.request
import ssl

REQUIRED_HEADERS = {
    'Strict-Transport-Security': {
        'severity': 'HIGH',
        'message': 'HSTS missing — vulnerable to protocol downgrade',
    },
    'Content-Security-Policy': {
        'severity': 'HIGH',
        'message': 'CSP missing — vulnerable to XSS',
    },
    'X-Frame-Options': {
        'severity': 'MEDIUM',
        'message': 'X-Frame-Options missing — vulnerable to clickjacking',
    },
    'X-Content-Type-Options': {
        'severity': 'MEDIUM',
        'message': 'X-Content-Type-Options missing — MIME sniffing possible',
    },
    'Referrer-Policy': {
        'severity': 'LOW',
        'message': 'Referrer-Policy missing — referrer leakage possible',
    },
    'Permissions-Policy': {
        'severity': 'LOW',
        'message': 'Permissions-Policy missing — browser features not restricted',
    },
}

def check_headers(url):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={'User-Agent': 'SecurityHeaderChecker/1.0'})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            headers = dict(response.headers)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return

    print(f"Security Header Check: {url}")
    print("=" * 60)

    issues = []
    for header, config in REQUIRED_HEADERS.items():
        if header in headers:
            print(f"  ✅ {header}: {headers[header][:60]}")
        else:
            print(f"  ❌ {header}: MISSING — {config['message']}")
            issues.append({'header': header, 'severity': config['severity'], 'message': config['message']})

    # Check for insecure headers
    if 'X-Powered-By' in headers:
        print(f"  ⚠️  X-Powered-By: {headers['X-Powered-By']} — reveals technology")
        issues.append({'header': 'X-Powered-By', 'severity': 'LOW', 'message': 'Technology disclosure'})

    if 'Server' in headers and any(v in headers['Server'] for v in ['Apache', 'nginx', 'IIS']):
        print(f"  ⚠️  Server: {headers['Server']} — reveals server software")

    print(f"\n{'='*60}")
    print(f"Summary: {len(issues)} issues found")
    for issue in issues:
        print(f"  [{issue['severity']}] {issue['header']}: {issue['message']}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python header_checker.py <url>")
        sys.exit(1)
    check_headers(sys.argv[1])
```

---

## 4. DEPENDENCY VULNERABILITY CHECKER

```python
#!/usr/bin/env python3
"""
Dependency vulnerability checker — checks package manifests for known issues.
Defensive tool: identifies outdated/vulnerable dependencies.
"""
import json
import os
import sys
import re

# Known vulnerable version patterns (simplified — in production, use a CVE database)
KNOWN_VULNERABILITIES = {
    'npm': {
        'lodash': {'vulnerable': '<4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'HIGH'},
        'express': {'vulnerable': '<4.17.3', 'cve': 'CVE-2022-24999', 'severity': 'MEDIUM'},
        'minimist': {'vulnerable': '<1.2.6', 'cve': 'CVE-2021-44906', 'severity': 'CRITICAL'},
    },
    'pip': {
        'django': {'vulnerable': '<3.2.13', 'cve': 'CVE-2022-28346', 'severity': 'HIGH'},
        'flask': {'vulnerable': '<2.0.3', 'cve': 'CVE-2023-30861', 'severity': 'MEDIUM'},
        'pyyaml': {'vulnerable': '<5.4', 'cve': 'CVE-2020-14343', 'severity': 'HIGH'},
    },
}

def parse_version(version_str):
    """Parse version string into tuple of integers."""
    return tuple(int(x) for x in re.findall(r'\d+', version_str)[:3])

def is_vulnerable(installed, vulnerable_range):
    """Check if installed version is in vulnerable range."""
    installed_v = parse_version(installed)
    if vulnerable_range.startswith('<'):
        target = parse_version(vulnerable_range[1:])
        return installed_v < target
    return False

def check_npm(directory):
    findings = []
    pkg_path = os.path.join(directory, 'package.json')
    if not os.path.exists(pkg_path):
        return findings
    with open(pkg_path) as f:
        pkg = json.load(f)
    deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
    for name, version_spec in deps.items():
        if name in KNOWN_VULNERABILITIES['npm']:
            vuln = KNOWN_VULNERABILITIES['npm'][name]
            installed = version_spec.lstrip('^~>=<')
            if is_vulnerable(installed, vuln['vulnerable']):
                findings.append({
                    'package': name,
                    'installed': installed,
                    'vulnerable': vuln['vulnerable'],
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                })
    return findings

def check_pip(directory):
    findings = []
    req_path = os.path.join(directory, 'requirements.txt')
    if not os.path.exists(req_path):
        return findings
    with open(req_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'([a-zA-Z0-9_-]+)==([0-9.]+)', line)
            if match:
                name, version = match.groups()
                if name.lower() in KNOWN_VULNERABILITIES['pip']:
                    vuln = KNOWN_VULNERABILITIES['pip'][name.lower()]
                    if is_vulnerable(version, vuln['vulnerable']):
                        findings.append({
                            'package': name,
                            'installed': version,
                            'vulnerable': vuln['vulnerable'],
                            'cve': vuln['cve'],
                            'severity': vuln['severity'],
                        })
    return findings

if __name__ == '__main__':
    directory = sys.argv[1] if len(sys.argv) > 1 else '.'
    findings = check_npm(directory) + check_pip(directory)
    if findings:
        print(f"🚨 {len(findings)} vulnerable dependencies found:")
        for f in findings:
            print(f"  [{f['severity']}] {f['package']}@{f['installed']} — {f['cve']} (fix: {f['vulnerable']})")
    else:
        print("✅ No known vulnerable dependencies found!")
```

---

## 5. DOCKERFILE SECURITY LINTER

```python
#!/usr/bin/env python3
"""
Dockerfile security linter — checks Dockerfiles for security issues.
Defensive tool: prevents insecure container configurations.
"""
import re
import sys

CHECKS = [
    {
        'id': 'DS001',
        'pattern': r'^FROM\s+\S+:latest',
        'message': 'Using :latest tag — pin specific version for reproducibility',
        'severity': 'MEDIUM',
    },
    {
        'id': 'DS002',
        'pattern': r'^\s*USER\s+root',
        'message': 'Running as root user — use non-root user',
        'severity': 'HIGH',
    },
    {
        'id': 'DS003',
        'pattern': r'(password|secret|token|api_key)\s*=',
        'message': 'Possible hardcoded secret in Dockerfile',
        'severity': 'CRITICAL',
    },
    {
        'id': 'DS004',
        'pattern': r'^FROM\s+\S+\s*$',
        'message': 'No digest pinning — use @sha256: for immutability',
        'severity': 'LOW',
    },
    {
        'id': 'DS005',
        'pattern': r'apt-get\s+install\s+(?!.*--no-install-recommends)',
        'message': 'apt-get install without --no-install-recommends — larger attack surface',
        'severity': 'LOW',
    },
    {
        'id': 'DS006',
        'pattern': r'ADD\s+https?://',
        'message': 'ADD with URL — use curl/wget with checksum verification instead',
        'severity': 'MEDIUM',
    },
    {
        'id': 'DS007',
        'pattern': r'chmod\s+777',
        'message': 'chmod 777 — overly permissive file permissions',
        'severity': 'MEDIUM',
    },
]

def lint_dockerfile(filepath):
    findings = []
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            for check in CHECKS:
                if re.search(check['pattern'], line, re.IGNORECASE | re.MULTILINE):
                    findings.append({
                        'line': line_num,
                        'id': check['id'],
                        'severity': check['severity'],
                        'message': check['message'],
                        'code': line.strip(),
                    })

    # Check for missing USER instruction
    with open(filepath) as f:
        content = f.read()
    if not re.search(r'^USER\s+', content, re.MULTILINE):
        findings.append({
            'line': 0,
            'id': 'DS008',
            'severity': 'HIGH',
            'message': 'No USER instruction — container runs as root by default',
            'code': '',
        })

    return findings

if __name__ == '__main__':
    findings = lint_dockerfile(sys.argv[1])
    if findings:
        print(f"Dockerfile Security Lint: {len(findings)} issues")
        print("=" * 60)
        for f in sorted(findings, key=lambda x: x['line']):
            print(f"  [{f['severity']}] {f['id']} (line {f['line']}): {f['message']}")
            if f['code']:
                print(f"    {f['code']}")
    else:
        print("✅ No Dockerfile security issues found!")
```

---

## 6. INPUT VALIDATION LIBRARY

```javascript
/**
 * Input validation library — reusable validation functions.
 * Defensive tool: prevents injection by validating input at the boundary.
 */

const validator = {
  // String validation
  string(value, { min = 0, max = Infinity, pattern = null, allowHtml = false } = {}) {
    if (typeof value !== 'string') throw new Error('Expected string');
    if (value.length < min) throw new Error(`Minimum length: ${min}`);
    if (value.length > max) throw new Error(`Maximum length: ${max}`);
    if (pattern && !pattern.test(value)) throw new Error('Invalid format');
    if (!allowHtml && /<[^>]*>/.test(value)) throw new Error('HTML not allowed');
    return value;
  },

  // Integer validation
  integer(value, { min = -Infinity, max = Infinity } = {}) {
    const num = Number(value);
    if (!Number.isInteger(num)) throw new Error('Expected integer');
    if (num < min) throw new Error(`Minimum: ${min}`);
    if (num > max) throw new Error(`Maximum: ${max}`);
    return num;
  },

  // Email validation
  email(value) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!pattern.test(value)) throw new Error('Invalid email');
    if (value.length > 254) throw new Error('Email too long');
    return value.toLowerCase();
  },

  // URL validation (SSRF-safe)
  url(value, { allowedSchemes = ['http', 'https'] } = {}) {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error('Invalid URL');
    }
    if (!allowedSchemes.includes(parsed.protocol.slice(0, -1))) {
      throw new Error(`Scheme not allowed: ${parsed.protocol}`);
    }
    return parsed.href;
  },

  // UUID validation
  uuid(value) {
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!pattern.test(value)) throw new Error('Invalid UUID');
    return value.toLowerCase();
  },

  // Enum validation (allowlist)
  enum(value, allowedValues) {
    if (!allowedValues.includes(value)) {
      throw new Error(`Allowed values: ${allowedValues.join(', ')}`);
    }
    return value;
  },

  // File path validation (traversal-safe)
  filePath(value, baseDir) {
    const path = require('path');
    const resolved = path.resolve(baseDir, value);
    const normalizedBase = path.resolve(baseDir);
    if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
      throw new Error('Path traversal detected');
    }
    return resolved;
  },

  // Sanitize HTML (using DOMPurify if available)
  sanitizeHtml(value) {
    if (typeof DOMPurify !== 'undefined') {
      return DOMPurify.sanitize(value);
    }
    // Basic fallback — encode HTML entities
    return value
      .replace(/&/g, '&')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '"')
      .replace(/'/g, '&#x27;');
  },

  // Validate and return object or throw
  validate(data, schema) {
    const result = {};
    for (const [field, config] of Object.entries(schema)) {
      const value = data[field];
      if (value === undefined) {
        if (config.required) throw new Error(`Missing required field: ${field}`);
        if (config.default !== undefined) result[field] = config.default;
        continue;
      }
      result[field] = this[config.type](value, config.options || {});
    }
    return result;
  },
};

module.exports = validator;
```

---

## USAGE

When Cyphron builds a security tool, it:
1. Selects the appropriate template from this file
2. Customizes it for the user's specific needs
3. Adds any missing functionality
4. Includes tests and documentation
5. Delivers complete, working code

These templates are **starting points**, not final products. Cyphron adapts them to the user's language, framework, and specific requirements.
