"""code_audit — WHITE-BOX SAST (Cyphron's own regex pack).
Walks a local repository and flags dangerous code patterns with file:line
evidence. Conservative patterns only — low false-positive by design; every
match is a candidate for human review, not an automatic verdict."""

from __future__ import annotations

import re
from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

RULES = [
    ("SQL built from f-string", re.compile(r"execute\s*\(\s*f[\"']"), "critical", "CWE-89",
     "SQL query built with an f-string — user input may be concatenated into the query.",
     "Use parameterized queries: db.query('... WHERE id = $1', [id])"),
    ("SQL string concatenation", re.compile(r"execute\s*\(\s*[\"'][^\"']*[\"']\s*\+"), "critical", "CWE-89",
     "SQL query built by string concatenation.", "Use parameter binding instead of concatenation."),
    ("eval() usage", re.compile(r"\beval\s*\("), "high", "CWE-95",
     "eval() executes arbitrary code from its input.", "Remove eval; parse data with JSON/AST APIs."),
    ("shell=True subprocess", re.compile(r"shell\s*=\s*True"), "critical", "CWE-78",
     "subprocess with shell=True interprets input through the shell.",
     "Pass argument lists (shell=False) and validate inputs."),
    ("os.system call", re.compile(r"\bos\.system\s*\("), "critical", "CWE-78",
     "os.system runs a shell command string.", "Use subprocess.run([...]) with argument lists."),
    ("Weak hash (MD5/SHA1)", re.compile(r"(createHash\s*\(\s*[\"'](md5|sha1)[\"']|hashlib\.(md5|sha1)\()"),
     "medium", "CWE-327",
     "MD5/SHA1 are broken for security purposes (signatures, passwords).",
     "Use SHA-256+ for integrity and bcrypt/argon2 for passwords."),
    ("TLS verification disabled", re.compile(r"verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"),
     "high", "CWE-295", "TLS certificate verification is disabled — MITM becomes trivial.",
     "Never disable verification in production code paths."),
    ("Insecure deserialization", re.compile(r"pickle\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader)"),
     "high", "CWE-502",
     "Deserializing untrusted data with pickle/yaml.load can execute code.",
     "Use yaml.safe_load / JSON; never unpickle untrusted input."),
    ("Dangerous DOM write", re.compile(r"innerHTML\s*=\s*[^=]|dangerouslySetInnerHTML"),
     "medium", "CWE-79",
     "Direct innerHTML/DangerouslySetInnerHTML assignment can inject markup.",
     "Prefer textContent/framework escaping; sanitize with DOMPurify if HTML is required."),
    ("Hardcoded credential shape", re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"][A-Za-z0-9+/_=-]{16,}['\"]"),
     "high", "CWE-798",
     "Credential-shaped literal assigned inline.", "Move to env/secret manager; rotate if real."),
    ("CORS wildcard origin", re.compile(r"(?i)(origin\s*[:=]\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*,\s*[\"']\*)"),
     "medium", "CWE-942",
     "CORS allows any origin — any site can read authenticated responses.",
     "Allow-list exact origins; never '*' on credentialed endpoints."),
    ("Deprecated cipher (createCipher)", re.compile(r"createCipher(iv)?\s*\("),
     "medium", "CWE-327",
     "crypto.createCipher uses legacy algorithms without auth (malleable).",
     "Use createCipheriv with GCM/CCM or a modern AEAD library."),
    ("Insecure randomness for token", re.compile(r"(?i)(token|secret|otp|nonce)\w*\s*[:=][^;\n]*Math\.random"),
     "medium", "CWE-338",
     "Security token derived from Math.random() — predictable.",
     "Use crypto.randomBytes / crypto.getRandomValues."),
    # (rule duplikat "SQL built from f-string" dihapus — dulu satu baris
    #  menghasilkan dua temuan identik dari dua label bertumpuk)
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 3000


class CodeAuditTool(Tool):
    name = "code_audit"
    description = "White-box SAST: regex pack over a local repo (file:line evidence)."
    risk_tags = {"local", "passive"}
    source_skill = "01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        root = Path(str(args.get("path", args.get("target", "."))))
        files = ([root] if root.is_file()
                 else [p for p in root.rglob("*") if p.is_file()
                       and not (set(p.parts) & SKIP_DIRS)][:MAX_FILES])
        if not root.exists():
            return ToolResult(tool=self.name, ok=False, error=f"no such path: {root}")
        findings: list[Finding] = []
        scanned = 0
        for file in files:
            try:
                if file.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for line_no, line in enumerate(text.splitlines(), start=1):
                for label, pattern, severity, cwe, desc, fix in RULES:
                    if pattern.search(line):
                        findings.append(Finding(
                            tool=self.name, title=f"{label} — {file.name}:{line_no}",
                            severity=severity, cwe=cwe,
                            description=f"{desc} Found at {file}:{line_no}: {line.strip()[:120]!r}",
                            recommendation=fix,
                            file_path=str(file), line_start=line_no, line_end=line_no,
                            request=None,
                            response=f"line: {line.strip()[:160]!r}",
                            confidence=0.65, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="code-line"))
        ctx.world.note(f"code_audit (white-box): {scanned} files, {len(findings)} pattern matches")
        return ToolResult(tool=self.name, ok=True, data={"files_scanned": scanned},
                          findings=findings)
