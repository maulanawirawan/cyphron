# Skill 71 — File Upload & Media Processing Abuse Testing

> Cyphron's methodology for testing upload/ingestion pipelines: magic bytes over
> declared MIME, bounded format matrices, corrupt/polyglot handling, resource
> limits before decode, and per-platform decoder capability maps.

---

## WHEN TO ACTIVATE

- User builds/tests image/file upload (profile photos, attachments, importers)
- User asks about EXIF, HEIC/HEIF support, corrupt files, or upload limits
- User asks "can someone upload a script and execute it?" / unrestricted upload
- User changes native image dependencies or base images

---

## METHODOLOGY

### Step 1: Never trust declared MIME or extension
Verify **magic bytes** server-side before any processing. A `.jpg` that is
really a PHP script, SVG with embedded script, or a polyglot must be rejected
(or transcode-neutralized) by content inspection alone.

### Step 2: Bounded format matrix
Test a finite matrix and record the result per cell:

| Dimension | Values |
|---|---|
| Formats | JPEG, PNG, WEBP (+ HEIC/HEIF where platforms require) |
| Orientation | EXIF-normal vs EXIF-rotated/flipped |
| Content | normal, text-heavy product photos |
| Size | tiny, near-limit bytes, near-limit pixels (pixel-bomb) |
| Health | valid, corrupt, truncated, unsupported |
| Name/extension | double extensions (`.jpg.php`), misleading types |
| Platform | each production platform/decoder version |

### Step 3: Record per cell
decoder availability · byte/pixel limits · processing result · retry category ·
user-facing state. The user-facing state must be **graceful** (clear message,
retry option) — never a stack trace or silent drop.

### Step 4: Resource limits BEFORE decode
- Enforce byte-size limit before buffering the whole file (`arrayBuffer()` /
  full read).
- Guard pixel bombs: width × height × bytes-per-pixel bound before decode.
- Decode in an isolated context with timeout; a malicious file must never hang
  or OOM the worker.

### Step 5: EXIF policy
Decide explicitly: strip, normalize-orientation-only, or keep. Privacy default
is strip (EXIF leaks GPS/device); orientation normalization must match visual
expectation across platforms.

### Step 6: Storage hygiene
Random server-generated names; no user influence on path; storage location is
non-executable and not directly interpreted (no server-side script engines on
the upload mount); served with fixed safe content types.

### Step 7: SBOM freshness
Refresh the exact image SBOM after native decoder or base-image changes —
decoders are C/C++ libraries; a bump is a supply-chain event.

---

## SECURE PATTERNS

- Magic-byte verification (`image-normalize` style: declared type is a claim)
- Normalize/transcode pipeline as the choke point (re-encode, never store raw)
- Per-platform decoder capability map; bounded retries; graceful unavailable state
- Limits before decode; isolated parsing; pixel-bomb arithmetic guard

---

## AUDIT CHECKLIST

- [ ] Magic bytes checked; declared MIME never trusted
- [ ] Size and pixel-dimension limits enforced before decode
- [ ] Corrupt/truncated files → graceful user-facing state, no crash
- [ ] HEIC/HEIF path defined per platform (or explicitly unsupported with message)
- [ ] Polyglot/double-extension files neutralized (re-encode strips payloads)
- [ ] EXIF policy applied (strip or documented keep)
- [ ] Upload storage non-executable, random names, fixed served types
- [ ] SBOM refreshed after decoder/base-image changes

> Provenance: harvested from the media matrix plan (§6.9 verbatim: bounded
> matrix, decoder/limits/retry/user-state recording) plus source-verified magic
> byte validation (image-normalize). Unit decoder tests exist; the per-platform
> matrix itself is DIUSULKAN — design real, execution pending.
