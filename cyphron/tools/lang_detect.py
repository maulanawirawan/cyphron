"""lang_detect — deteksi bahasa pemrograman otomatis (Fullpower B6).

Sumber: extension + fingerprint isi + shebang (registry 36 bahasa).
Zero-FP: dua kandidat terlalu berdekatan tanpa ekstensi = AMBIGU (dilabel,
bukan ditebak). Dipakai SAST (pilih rule pack) dan adapter (pilih runtime).
"""

from __future__ import annotations

from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding
from .. import languages


class LangDetectTool(Tool):
    name = "lang_detect"
    description = ("Deteksi bahasa pemrograman otomatis (36 bahasa): "
                   "ekstensi + fingerprint isi + shebang; ambigu ditolak.")
    risk_tags = {"local", "passive"}
    source_skill = "fleet-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        text = str(args.get("text") or "")
        filename = str(args.get("filename") or "") or None
        path = Path(str(args.get("path") or ""))
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                return ToolResult(tool=self.name, ok=False, error=str(exc))
            filename = filename or path.name
        if not text and not path.exists():
            return ToolResult(tool=self.name, ok=False,
                              error="args.text atau args.path wajib")
        result = languages.detect_language(text, filename)
        if path.is_dir():
            counts: dict[str, int] = {}
            for p in sorted(path.rglob("*")):
                if not p.is_file() or "kb/data" in str(p) \
                        or ".git" in p.parts or "__pycache__" in p.parts:
                    continue
                det = languages.detect_language("", str(p))
                if det["language"]:
                    counts[det["language"]] = counts.get(det["language"], 0) + 1
            result["directory_counts"] = dict(sorted(
                counts.items(), key=lambda kv: -kv[1]))
        ctx.world.note(
            f"lang_detect: {result['language'] or 'AMBIGU'} "
            f"(confidence {result['confidence']})")
        if result["ambiguous"] and result["candidates"]:
            f = Finding(
                tool=self.name,
                title="Bahasa tidak dapat ditentukan (ambigu ditolak)",
                severity="info",
                description=(
                    "Kandidat: " + ", ".join(
                        c["language"] for c in result["candidates"]) +
                    ". Tanpa ekstensi dan skor terlalu berdekatan — "
                    "dilabel ambigu, TIDAK ditebak (zero-FP)."),
                recommendation=(
                    "Perjelas ekstensi berkas atau berikan konteks lebih; "
                    "rule pack yang tepat butuh bahasa pasti."),
                confidence=0.9,
                finding_class="info",
                status="unconfirmed",
            )
            return ToolResult(tool=self.name, ok=True, data=result,
                              findings=[f])
        return ToolResult(tool=self.name, ok=True, data=result)
