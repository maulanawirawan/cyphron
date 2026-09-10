# Skill 41 — Memory Safety & Buffer Overflow Defense

> Cyphron's methodology for preventing memory corruption vulnerabilities. Cyphron knows memory attack techniques — stack/heap overflows, use-after-free, double-free, type confusion, ROP chains — and builds memory-safe code and exploit mitigations.

---

## WHEN TO ACTIVATE

- User asks about buffer overflows, memory corruption, or use-after-free
- User asks about ASLR, DEP, stack canaries, or CFI
- User asks to write memory-safe C/C++ code
- User asks about Rust or memory-safe alternatives
- User asks about fuzzing or AddressSanitizer

---

## METHODOLOGY

### Step 1: Identify Memory Vulnerability Classes

| Class | Mechanism | Mitigation |
|---|---|---|
| Stack overflow | Write past stack buffer | Stack canaries, bounds check |
| Heap overflow | Write past heap allocation | Heap hardening, bounds check |
| Use-after-free | Access freed memory | Null pointer after free, ownership |
| Double-free | Free same memory twice | Track allocation state |
| Integer overflow | Arithmetic wraps around | Checked arithmetic |
| Type confusion | Cast to wrong type | Type-safe APIs |
| Format string | User controls format | Constant format strings |
| Race condition | TOCTOU on memory | Atomic operations, locks |

### Step 2: Apply Defense in Depth

```
1. Memory-safe language (Rust, Go) — eliminates entire classes
2. Safe libraries (strncpy, snprintf) — if C/C++ required
3. Compiler mitigations (canaries, ASLR, DEP, CFI)
4. Runtime sanitizers (ASan, UBSan, MSan) — testing
5. Fuzzing — find edge cases
```

---

## SECURE PATTERNS

### Memory-Safe C/C++ Patterns
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ─── Bounds-Checked String Operations ───

// ❌ VULNERABLE
// void copy_input(char *input) {
//     char buf[64];
//     strcpy(buf, input);  // no bounds check
// }

// ✅ SECURE
void copy_input(const char *input) {
    char buf[64];
    if (strlen(input) >= sizeof(buf)) {
        fprintf(stderr, "Input too long\n");
        return;
    }
    // strncpy with explicit null-termination
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
}

// ─── Safe Allocation with Overflow Check ───

// ❌ VULNERABLE — integer overflow
// char *alloc_buffer(unsigned int count, unsigned int size) {
//     return malloc(count * size);  // overflow if count * size > UINT_MAX
// }

// ✅ SECURE — checked multiplication
#include <inttypes.h>
char *alloc_buffer(size_t count, size_t size) {
    // Check for multiplication overflow
    if (count != 0 && count > SIZE_MAX / size) {
        return NULL;  // overflow detected
    }
    size_t total = count * size;
    char *buf = malloc(total);
    if (!buf) return NULL;
    return buf;
}

// ─── Safe Free (Prevent Use-After-Free) ───

// ❌ VULNERABLE
// void process_data(char *data) {
//     free(data);
//     // data is now dangling — caller may still use it
// }

// ✅ SECURE — double-pointer to null the caller's reference
void safe_free(char **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;  // caller's pointer is now NULL
    }
}

// Usage: safe_free(&data);  // data is now NULL

// ─── Format String Safety ───

// ❌ VULNERABLE
// void log_message(char *user_input) {
//     syslog(LOG_INFO, user_input);  // format string vuln
// }

// ✅ SECURE
void log_message(const char *user_input) {
    syslog(LOG_INFO, "%s", user_input);  // constant format string
}

// ─── Array Access with Bounds Checking ───

typedef struct {
    int *data;
    size_t size;
} SafeArray;

int safe_array_get(SafeArray *arr, size_t index) {
    if (index >= arr->size) {
        fprintf(stderr, "Array index out of bounds: %zu >= %zu\n", index, arr->size);
        abort();  // fail fast — don't return garbage
    }
    return arr->data[index];
}

// ─── Atomic Operations (Prevent Race Conditions) ───

#include <stdatomic.h>

typedef struct {
    _Atomic int ref_count;
    void *data;
} RefCounted;

RefCounted *ref_counted_new(void *data) {
    RefCounted *obj = malloc(sizeof(RefCounted));
    if (!obj) return NULL;
    atomic_init(&obj->ref_count, 1);
    obj->data = data;
    return obj;
}

void ref_counted_acquire(RefCounted *obj) {
    atomic_fetch_add(&obj->ref_count, 1);
}

void ref_counted_release(RefCounted *obj) {
    if (atomic_fetch_sub(&obj->ref_count, 1) == 1) {
        // Last reference — safe to free
        free(obj->data);
        free(obj);
    }
}
```

### Rust (Memory-Safe by Design)
```rust
// Rust eliminates memory vulnerabilities at compile time:
// - No null pointers (Option<T>)
// - No dangling pointers (ownership/borrowing)
// - No data races (Send/Sync traits)
// - No buffer overflows (bounds-checked indexing)
// - No use-after-free (lifetimes)

fn process_input(input: &str) -> String {
    // Bounds checking is automatic
    let buffer = [0u8; 64];

    // This would panic (safe) instead of overflowing:
    // buffer[100] = 1;  // panic: index out of bounds

    // Safe string handling
    if input.len() > 64 {
        return input[..64].to_string();  // truncation, not overflow
    }
    input.to_string()
}

// Ownership prevents use-after-free
fn ownership_example() {
    let data = String::from("hello");
    let reference = &data;
    // data is still valid here — reference is valid
    println!("{}", reference);

    // When data goes out of scope, memory is freed
    // No dangling pointer possible — compiler enforces this
}
```

### Fuzzing (Find Memory Bugs)
```python
#!/usr/bin/env python3
"""
Fuzzing harness — find memory corruption bugs.
Defensive: find bugs before attackers do.
"""
import subprocess
import os
import atheris

def fuzz_parser(data):
    """Fuzz target — parser that processes untrusted input."""
    try:
        # This is the function under test
        result = parse_input(data)
        # If we reach here, no crash — good
    except Exception:
        # Expected exceptions are fine
        pass
    # Crashes (segfault, abort) will be caught by the fuzzer

def parse_input(data):
    """Example parser to fuzz."""
    if len(data) < 4:
        return None
    length = int.from_bytes(data[:4], 'little')
    if length > 1024:  # bounds check
        return None
    payload = data[4:4+length]
    return payload

if __name__ == "__main__":
    # Compile target with: -fsanitize=address,undefined
    atheris.Setup(sys.argv, fuzz_parser)
    atheris.Fuzz()
```

### AddressSanitizer (Testing)
```bash
#!/bin/bash
# Compile with AddressSanitizer for testing (not production)

# ASan catches: buffer overflow, use-after-free, double-free, memory leaks
# UBSan catches: integer overflow, null dereference, type mismatch

gcc -fsanitize=address,undefined \
    -fno-sanitize-recover=all \
    -g -O1 \
    -fstack-protector-strong \
    -o app_asan app.c

# Run with ASan
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ./app_asan

# Expected output on bug:
# ==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
# READ of size 1 at 0x... thread T0
#     #0 0x... in vulnerable_function app.c:42
```

---

## EXPLOIT MITIGATION REFERENCE

| Mitigation | Flag | What It Prevents |
|---|---|---|
| Stack canary | `-fstack-protector-strong` | Stack buffer overflow detection |
| NX/DEP | `-Wl,-z,noexecstack` | Code execution on stack/heap |
| ASLR | `-fPIE -pie` | Fixed address exploitation |
| Full RELRO | `-Wl,-z,relro,-z,now` | GOT overwrite attacks |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=2` | libc buffer overflow checks |
| CFI | `-fsanitize=cfi` | Control flow hijacking |
| Stack clash | `-fstack-clash-protection` | Stack guard page bypass |

---

## AUDIT CHECKLIST

- [ ] Memory-safe language used where possible (Rust, Go, Swift)
- [ ] If C/C++: all compiler mitigations enabled
- [ ] No dangerous functions (gets, strcpy, sprintf) — use safe alternatives
- [ ] All allocations checked for integer overflow
- [ ] All freed pointers set to NULL
- [ ] All format strings are constants
- [ ] All array accesses bounds-checked
- [ ] AddressSanitizer/UBSan in test builds
- [ ] Fuzzing on all input parsers
- [ ] Static analysis (CodeQL, Coverity) in CI
- [ ] checksec verification in CI
- [ ] No VLAs (variable-length arrays) — use heap allocation
- [ ] Valgrind testing for memory leaks
