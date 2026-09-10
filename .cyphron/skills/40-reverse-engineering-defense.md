# Skill 40 — Reverse Engineering for Defense

> Cyphron's methodology for reverse engineering binaries to understand vulnerabilities and build defenses. Cyphron uses RE to analyze how exploits work, find vulnerabilities in compiled code, and verify patches — never to create exploits or bypass protections.

---

## WHEN TO ACTIVATE

- User asks to reverse engineer a binary for vulnerability analysis
- User asks about buffer overflows, format strings, or memory corruption
- User asks about exploit mitigations (ASLR, DEP, stack canaries)
- User asks to analyze a patch diff to understand a vulnerability
- User asks about binary hardening (PIE, RELRO, stack canaries)

---

## ETHICAL BOUNDARY

- ✅ Reverse engineer to understand vulnerability mechanisms
- ✅ Analyze patches to identify what was fixed
- ✅ Build hardened binaries with exploit mitigations
- ✅ Create detection rules based on RE findings
- ❌ Create working exploits for specific targets
- ❌ Bypass DRM, license checks, or security products

---

## METHODOLOGY

### Step 1: Identify Analysis Goal
- Understand a vulnerability (CVE analysis)
- Verify a patch is effective
- Identify vulnerable code patterns in compiled binaries
- Build exploit mitigations

### Step 2: RE Tools

| Tool | Purpose |
|---|---|
| Ghidra | Disassembly + decompilation (free, NSA) |
| IDA Pro | Disassembly + decompilation (commercial) |
| radare2 | CLI disassembly + analysis |
| Binary Ninja | Disassembly + decompilation |
| objdump | Basic disassembly |
| checksec | Check binary security features |

### Step 3: Analysis Approach
1. Static analysis — disassemble, identify functions, find vulnerabilities
2. Dynamic analysis — debug, trace execution, observe behavior
3. Patch diffing — compare patched vs. unpatched to find the fix

---

## SECURE PATTERNS

### Binary Hardening (Compilation Flags)
```bash
#!/bin/bash
# Secure compilation flags — produce hardened binaries

# GCC / Clang hardening flags
SECURE_CFLAGS="-fstack-protector-strong"     # Stack canaries (buffer overflow detection)
SECURE_CFLAGS+=" -fPIE -pie"                 # Position Independent Executable (ASLR)
SECURE_CFLAGS+=" -D_FORTIFY_SOURCE=2"        # Buffer overflow checks in libc
SECURE_CFLAGS+=" -ftrapv"                    # Trap on integer overflow
SECURE_CFLAGS+=" -Wformat -Wformat-security" # Format string warnings
SECURE_CFLAGS+=" -Wl,-z,relro,-z,now"        # Full RELRO (GOT protection)
SECURE_CFLAGS+=" -Wl,-z,noexecstack"         # NX stack (DEP)
SECURE_CFLAGS+=" -Wl,-z,separate-code"       # Separate code/data segments

# Additional warnings for security
SECURE_CFLAGS+=" -Wall -Wextra -Werror"
SECURE_CFLAGS+=" -Wconversion -Wsign-conversion"
SECURE_CFLAGS+=" -Wformat=2 -Wformat-overflow=2"
SECURE_CFLAGS+=" -Wstringop-overflow=4 -Wstringop-truncation"

echo "Compiling with secure flags: $SECURE_CFLAGS"
gcc $SECURE_CFLAGS -o secure_app app.c

# Verify hardening
checksec --file=secure_app
```

### Checksec Verification
```bash
#!/bin/bash
# Verify binary security features

checksec --file=./app
# Expected output for hardened binary:
# RELRO        STACK CANARY  NX     PIE    FORTIFY
# Full RELRO   Canary found  NX enabled  PIE Enabled  Yes

# If any are missing, recompile with appropriate flags
```

### Vulnerability Pattern Analysis (Python + radare2)
```python
#!/usr/bin/env python3
"""
Binary analysis — find vulnerable code patterns.
Defensive: identify vulnerabilities to fix them.
"""
import r2pipe
import re

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.r2 = r2pipe.open(binary_path)
        self.r2.cmd('aaa')  # full analysis

    def find_dangerous_functions(self):
        """Find calls to dangerous functions."""
        dangerous = {
            'gets': 'Buffer overflow — no length check',
            'strcpy': 'Buffer overflow — no length check',
            'strcat': 'Buffer overflow — no length check',
            'sprintf': 'Buffer overflow — no length check',
            'vsprintf': 'Buffer overflow — no length check',
            'scanf': 'Buffer overflow — no length check',
            'sscanf': 'Buffer overflow — no length check',
            'system': 'Command injection — if input controlled',
            'exec': 'Command injection — if input controlled',
            'popen': 'Command injection — if input controlled',
        }

        findings = []
        for func, reason in dangerous.items():
            # Find cross-references to dangerous functions
            xrefs = self.r2.cmd(f'axt @ sym.imp.{func}')
            if xrefs.strip():
                for line in xrefs.strip().split('\n'):
                    findings.append({
                        'function': func,
                        'reason': reason,
                        'location': line.strip(),
                    })

        return findings

    def find_format_string_vulns(self):
        """Find potential format string vulnerabilities."""
        # Look for printf/scanf with user-controlled format string
        findings = []
        for func in ['printf', 'fprintf', 'sprintf', 'syslog']:
            xrefs = self.r2.cmd(f'axt @ sym.imp.{func}')
            for line in xrefs.strip().split('\n'):
                # Check if format string argument is a variable (not constant)
                if 'mov' in line and '[rbp' in line:
                    findings.append({
                        'function': func,
                        'reason': 'Format string may be user-controlled',
                        'location': line.strip(),
                    })
        return findings

    def check_security_features(self):
        """Check binary security features."""
        checksec = self.r2.cmd('iI')
        features = {}
        for line in checksec.split('\n'):
            if 'canary' in line.lower():
                features['stack_canary'] = 'yes' in line.lower()
            if 'nx' in line.lower():
                features['nx'] = 'yes' in line.lower()
            if 'pie' in line.lower():
                features['pie'] = 'yes' in line.lower()
            if 'relro' in line.lower():
                features['relro'] = line.split(':')[1].strip() if ':' in line else 'unknown'
        return features

    def generate_report(self):
        """Generate vulnerability analysis report."""
        dangerous = self.find_dangerous_functions()
        format_strings = self.find_format_string_vulns()
        security = self.check_security_features()

        print("=" * 60)
        print("BINARY SECURITY ANALYSIS REPORT")
        print("=" * 60)

        print(f"\n🔒 Security Features:")
        for feature, status in security.items():
            icon = '✅' if status and status != 'no' else '❌'
            print(f"  {icon} {feature}: {status}")

        print(f"\n⚠️  Dangerous Functions ({len(dangerous)}):")
        for f in dangerous:
            print(f"  {f['function']}: {f['reason']}")
            print(f"    at {f['location']}")

        print(f"\n⚠️  Format String Issues ({len(format_strings)}):")
        for f in format_strings:
            print(f"  {f['function']}: {f['reason']}")
            print(f"    at {f['location']}")

        self.r2.close()

# Usage
analyzer = BinaryAnalyzer('./target_binary')
analyzer.generate_report()
```

### Patch Diffing (Understanding CVE Fixes)
```python
#!/usr/bin/env python3
"""
Patch diffing — compare patched vs unpatched binary.
Defensive: understand what was fixed to build detection.
"""
import subprocess

class PatchDiffer:
    def diff_binaries(self, unpatched, patched):
        """Compare two binary versions to identify the fix."""
        # Extract functions from both
        unpatched_funcs = self._extract_functions(unpatched)
        patched_funcs = self._extract_functions(patched)

        # Find changed functions
        changed = []
        for func_name, func_data in patched_funcs.items():
            if func_name in unpatched_funcs:
                if func_data != unpatched_funcs[func_name]:
                    changed.append({
                        'function': func_name,
                        'unpatched': unpatched_funcs[func_name],
                        'patched': func_data,
                        'change_type': self._classify_change(
                            unpatched_funcs[func_name], func_data
                        ),
                    })

        return changed

    def _classify_change(self, old, new):
        """Classify what type of fix was applied."""
        if 'bound' in new.lower() or 'length' in new.lower():
            return 'bounds_check_added'
        if 'canary' in new.lower():
            return 'canary_added'
        if 'sanitize' in new.lower() or 'escape' in new.lower():
            return 'sanitization_added'
        if 'free' in new.lower() and 'free' not in old.lower():
            return 'memory_free_added'
        return 'logic_change'

    def _extract_functions(self, binary):
        """Extract function disassembly from binary."""
        result = subprocess.run(
            ['objdump', '-d', binary],
            capture_output=True, text=True
        )
        functions = {}
        current_func = None
        current_lines = []

        for line in result.stdout.split('\n'):
            if line.startswith('0') and '<' in line and '>:' in line:
                if current_func:
                    functions[current_func] = '\n'.join(current_lines)
                current_func = line.split('<')[1].split('>')[0]
                current_lines = [line]
            elif current_func:
                current_lines.append(line)

        if current_func:
            functions[current_func] = '\n'.join(current_lines)

        return functions
```

### Memory-Safe Coding Patterns (C/C++)
```c
// ❌ VULNERABLE — buffer overflow
void vulnerable_copy(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // no bounds check
}

// ✅ SECURE — bounds-checked
void secure_copy(const char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // ensure null-termination
}

// ❌ VULNERABLE — format string
void vulnerable_log(char *user_input) {
    printf(user_input);  // format string vulnerability
}

// ✅ SECURE — constant format string
void secure_log(const char *user_input) {
    printf("%s", user_input);  // user_input is data, not format
}

// ❌ VULNERABLE — integer overflow leading to small allocation
char *vulnerable_alloc(unsigned int size) {
    char *buf = malloc(size + 1);  // overflow if size = UINT_MAX
    return buf;
}

// ✅ SECURE — overflow check
char *secure_alloc(size_t size) {
    if (size > SIZE_MAX - 1) return NULL;  // overflow check
    char *buf = malloc(size + 1);
    if (!buf) return NULL;
    return buf;
}

// ❌ VULNERABLE — use-after-free
char *vulnerable_use() {
    char *ptr = malloc(64);
    free(ptr);
    return ptr;  // caller may use freed memory
}

// ✅ SECURE — null after free
char *secure_use() {
    char *ptr = malloc(64);
    // ... use ptr ...
    free(ptr);
    ptr = NULL;  // prevent use-after-free
    return ptr;  // caller gets NULL, not dangling pointer
}
```

---

## AUDIT CHECKLIST

- [ ] All binaries compiled with: -fstack-protector-strong, -fPIE, -D_FORTIFY_SOURCE=2
- [ ] Full RELRO enabled (-Wl,-z,relro,-z,now)
- [ ] NX/DEP enabled (-Wl,-z,noexecstack)
- [ ] No dangerous functions (gets, strcpy, sprintf) — use safe alternatives
- [ ] Format strings are constants (never user input)
- [ ] Integer overflow checks before arithmetic
- [ ] Memory freed and pointer set to NULL
- [ ] Input validation on all external input
- [ ] checksec verification in CI/CD
- [ ] Static analysis (CodeQL, Coverity) in CI/CD
- [ ] Fuzzing for critical parsing code
- [ ] AddressSanitizer/UBSan in test builds
