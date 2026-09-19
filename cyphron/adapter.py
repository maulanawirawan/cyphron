"""adapter — Engine Adapter Layer polyglot (Fullpower B1).

Engine non-Python dideklarasikan via manifest JSON:

    cyphron/adapters/<nama>/manifest.json

    {
      "name": "entropy_audit",
      "description": "...",
      "language": "cpp",
      "runtime": "cpp",              # cpp | c | node | go | rust | java
      "entry": "entropy_audit.cpp",  # relatif ke folder manifest
      "build": "{compiler} -O2 -std=c++17 -o {out} {src}",   # opsional
      "risk_tags": ["local"],
      "network": false,
      "timeout_s": 20
    }

Adapter menjalankannya lewat subprocess SATU PINTU: args dikirim sebagai
JSON lewat stdin, hasil WAJIB JSON di stdout:

    {"ok": true, "data": {...}, "findings": [ {...Finding fields...} ],
     "requests": 0}

Pagar tetap ditegakkan dari sisi Python (satu pintu): authorization gate +
rate-limit + budget lewat ToolRegistry; hasil temuan DIVALIDASI ketat
(severity sah, field lengkap) — hasil yang tidak sesuai kontrak dibuang,
bukan ditebak (zero-FP). Runtime yang tidak terpasang -> skipped secara
anggun, scan lain tetap jalan. Auto-detect environment: g++/clang++, gcc,
node, go, rustc, javac.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .findings import Finding, SEVERITY_ORDER
from .tools.base import Tool, ToolContext, ToolResult

ADAPTERS_DIR = Path(__file__).resolve().parent / "adapters"

RUNTIME_BINARIES: dict[str, tuple[str, ...]] = {
    "cpp": ("g++", "clang++"),
    "c": ("gcc", "clang"),
    "node": ("node",),
    "go": ("go",),
    "rust": ("rustc",),
    "java": ("javac",),
}

_REQUIRED_FIELDS = ("name", "description", "language", "runtime", "entry")
_KNOWN_RUNTIMES = set(RUNTIME_BINARIES)
_DETECT_CACHE: dict[str, str | None] | None = None


def detect_runtimes() -> dict[str, str | None]:
    """Runtime yang terpasang di mesin ini -> binary path (None = absen)."""
    global _DETECT_CACHE
    if _DETECT_CACHE is not None:
        return _DETECT_CACHE
    out: dict[str, str | None] = {}
    for runtime, candidates in RUNTIME_BINARIES.items():
        found = None
        for cand in candidates:
            p = shutil.which(cand)
            if p:
                found = p
                break
        out[runtime] = found
    _DETECT_CACHE = out
    return out


def load_manifests(root: Path | None = None) -> tuple[list[dict], list[str]]:
    """Muat semua manifest adapter; return (manifests, errors)."""
    root = root or ADAPTERS_DIR
    manifests: list[dict] = []
    errors: list[str] = []
    if not root.exists():
        return manifests, errors
    for mf in sorted(root.glob("*/manifest.json")):
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
            for field in _REQUIRED_FIELDS:
                if field not in data:
                    raise ValueError(f"field '{field}' wajib")
            if data["runtime"] not in _KNOWN_RUNTIMES:
                raise ValueError(f"runtime tak dikenal: {data['runtime']}")
            if not (mf.parent / data["entry"]).exists():
                raise ValueError(f"entry tidak ada: {data['entry']}")
            data["_dir"] = str(mf.parent)
            manifests.append(data)
        except Exception as exc:
            errors.append(f"{mf}: {exc}")
    return manifests, errors


class AdapterEngine(Tool):
    """Tool generik yang menjalankan engine non-Python via manifest."""

    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.name = str(manifest["name"])
        self.description = str(manifest.get("description", ""))
        self.risk_tags = {str(t) for t in (manifest.get("risk_tags")
                                           or ["local"])}
        self.source_skill = f"adapter-{manifest.get('language', 'x')}"

    # ------------------------------------------------------------- build
    def _binary_path(self) -> Path | None:
        """Kompilasi (bila manifest punya 'build') + path hasil; cache di
        temp dir yang dikunci hash sumber."""
        manifest = self.manifest
        build_cmd = manifest.get("build")
        src = Path(manifest["_dir"]) / manifest["entry"]
        key = hashlib.sha256(src.read_bytes()).hexdigest()[:10]
        cache_dir = Path(tempfile.gettempdir()) / "cyphron-adapters" \
            / f"{self.name}-{key}"
        suffix = ".exe" if sys_platform_windows() else ""
        out = cache_dir / f"{self.name}{suffix}"
        if out.exists():
            return out
        if not build_cmd:
            return src  # runtime skrip: tidak perlu build
        runtime_bin = detect_runtimes().get(manifest["runtime"])
        if not runtime_bin:
            return None
        cmd = (build_cmd.replace("{compiler}", _q(runtime_bin))
               .replace("{src}", _q(str(src)))
               .replace("{out}", _q(str(out))))
        cache_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(cmd, shell=True, capture_output=True,
                              timeout=120)
        if proc.returncode != 0 or not out.exists():
            alt = cache_dir / self.name
            if alt.exists():
                return alt
            return None
        return out

    # --------------------------------------------------------------- run
    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        manifest = self.manifest
        runtime_bin = detect_runtimes().get(manifest["runtime"])
        if not runtime_bin:
            ctx.world.note(
                f"adapter[{self.name}]: runtime '{manifest['runtime']}' "
                "tidak terpasang — dilewati (fallback anggun)")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "runtime-unavailable",
                                    "runtime": manifest["runtime"]})
        target = manifest["entry"]
        if manifest.get("build"):
            target_path = self._binary_path()
            if target_path is None:
                ctx.world.note(f"adapter[{self.name}]: build gagal — dilewati")
                return ToolResult(tool=self.name, ok=True,
                                  data={"skipped": "build-failed"})
            target = str(target_path)
        else:
            target = str(Path(manifest["_dir"]) / manifest["entry"])

        run_cmd = manifest.get("run") or "{compiler} {entry}"
        cmd = (run_cmd.replace("{compiler}", _q(runtime_bin))
               .replace("{entry}", _q(target)).replace("{out}", _q(target)))
        timeout = min(float(manifest.get("timeout_s", 20)),
                      max(float(ctx.timeout_s) * 4, 30.0))
        ctx.throttle()
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, timeout=timeout,
                input=json.dumps(args, default=str).encode("utf-8"))
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.name, ok=False,
                              error=f"adapter timeout ({timeout:.0f}s)")
        except OSError as exc:
            return ToolResult(tool=self.name, ok=False,
                              error=f"adapter exec gagal: {exc}")
        out = self._parse_output(proc.stdout.decode("utf-8",
                                                    errors="replace"))
        if out is None:
            return ToolResult(tool=self.name, ok=False,
                              error="output adapter bukan JSON kontrak")
        if proc.returncode != 0 and not out.get("ok"):
            return ToolResult(tool=self.name, ok=False,
                              error=str(out.get("error")
                                        or "adapter return non-zero"))
        findings = self._validate_findings(out.get("findings") or [])
        requests = int(out.get("requests") or 0)
        ctx.world.request_count += requests  # akuntansi jujur dari engine
        return ToolResult(tool=self.name, ok=True,
                          data=out.get("data") or {},
                          findings=findings,
                          raw_excerpt=out.get("raw_excerpt"))

    # ----------------------------------------------------------- kontrak
    def _parse_output(self, stdout: str) -> dict | None:
        text = (stdout or "").strip()
        if not text:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            # cari blok JSON terakhir (engine boleh mencetak log dulu)
            idx = text.rfind("\n{")
            if idx < 0:
                return None
            try:
                data = json.loads(text[idx + 1:])
            except ValueError:
                return None
        return data if isinstance(data, dict) else None

    def _validate_findings(self, rows: list) -> list[Finding]:
        """Validasi ketat kontrak temuan — yang tidak sah DIBUANG."""
        out: list[Finding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            title = str(row.get("title", "")).strip()
            severity = str(row.get("severity", "")).lower()
            if not title or severity not in SEVERITY_ORDER:
                continue  # tidak sesuai kontrak -> buang (zero-FP)
            try:
                f = Finding(
                    tool=self.name,
                    title=title,
                    severity=severity,
                    description=str(row.get("description", "")),
                    recommendation=str(row.get("recommendation", "")),
                    cwe=row.get("cwe") or None,
                    target_url=row.get("target_url") or None,
                    param=row.get("param") or None,
                    confidence=min(float(row.get("confidence", 0.5)), 1.0),
                    finding_class=str(row.get("finding_class", "weakness")),
                    status="unconfirmed",
                    evidence_kind="file",
                )
                f.attach_evidence("adapter", {
                    "adapter": self.name,
                    "language": self.manifest.get("language"),
                })
                out.append(f)
            except (TypeError, ValueError):
                continue
        return out


def sys_platform_windows() -> bool:
    import sys
    return sys.platform.startswith("win")


def _q(path: str) -> str:
    """Kutip path utk shell (compiler di Windows sering di 'Program Files')."""
    p = str(path)
    return p if not p or (p.startswith('"') and p.endswith('"')) else f'"{p}"'
