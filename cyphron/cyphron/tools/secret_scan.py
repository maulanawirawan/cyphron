"""secret_scan — Cyphron's own hardcoded-secret scanner (no gitleaks).
Walks a local repo/file target with a curated regex pack, redacts matches,
reports file+line evidence. Local + read-only."""

from __future__ import annotations

import re
from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

PATTERNS = [
    ("AWS access key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "critical", "CWE-798"),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical", "CWE-321"),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b"), "critical", "CWE-798"),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "high", "CWE-798"),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{30,})\b"), "high", "CWE-798"),
    ("JWT literal", re.compile(r"\b(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "high", "CWE-798"),
    ("generic credential assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]([A-Za-z0-9+/_=.-]{16,})['\"]"),
     "high", "CWE-798"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 2000


def _mask(match_text: str) -> str:
    return match_text[:4] + "***[redacted]" if len(match_text) > 4 else "***[redacted]"


class SecretScanTool(Tool):
    name = "secret_scan"
    description = "Scan a local repo/file for hardcoded secrets."
    risk_tags = {"local", "passive"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        root = Path(str(args.get("path", args.get("target", "."))))
        if root.is_file():
            files = [root]
        elif root.is_dir():
            files = [p for p in root.rglob("*")
                     if p.is_file() and not (set(p.parts) & SKIP_DIRS)][:MAX_FILES]
        else:
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
                for label, pattern, severity, cwe in PATTERNS:
                    m = pattern.search(line)
                    if m:
                        matched = m.group(0)
                        findings.append(Finding(
                            tool=self.name,
                            title=f"Hardcoded {label} in {file.name}",
                            severity=severity, cwe=cwe,
                            description=(
                                f"{label} found at {file}:{line_no}. Hardcoded credentials in source "
                                f"leak through repositories, builds, and artifacts."
                            ),
                            recommendation=(
                                "Revoke and rotate the credential immediately, move it to a secret "
                                "manager/env injection, and add history-cleaning + CI scanning. "
                                "See .kimchi/skills/20-secrets-management.md."
                            ),
                            file_path=str(file), line_start=line_no, line_end=line_no,
                            request=None,
                            response=f"matched {_mask(matched)} | line: {line.strip()[:160]!r}",
                            confidence=0.8 if label.startswith("generic") else 0.95,
                            source_skill=self.source_skill, status="confirmed",
                            evidence_kind="code-line",
                        ))
        ctx.world.note(f"secret_scan: {scanned} files scanned, {len(findings)} matches")
        return ToolResult(tool=self.name, ok=True, data={"files_scanned": scanned},
                          findings=findings)
