"""fingerprint_to_cpe — penerjemah fingerprint teknologi -> CPE 2.3.

PASIF (nol request). Input default = WorldModel.technologies; boleh juga
args.texts manual. Output: data.cpe (daftar CpeMatch) + world.note.
Temuan TIDAK dibuat di sini — klaim CVE hanya lewat cve_matcher.
"""

from __future__ import annotations

from ..kb import fingerprint as _fp
from .base import Tool, ToolContext, ToolResult


class FingerprintToCpeTool(Tool):
    name = "fingerprint_to_cpe"
    description = ("Terjemahkan fingerprint teknologi (banner/generator/"
                   "census) menjadi CPE 2.3 — pasif, bahan untuk cve_matcher.")
    risk_tags = {"passive", "local"}
    source_skill = "kb-godtier-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        texts = list(args.get("texts") or [])
        if not texts:
            texts = _fp.fingerprints_from_world(ctx.world)
        if not texts:
            ctx.world.note("fingerprint_to_cpe: tidak ada sinyal teknologi "
                           "di world — jalankan census/banner dulu")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "tidak ada fingerprint"})
        try:
            matches = _fp.to_cpe(texts)
        except Exception as exc:  # cpe_map rusak -> jangan crash scan
            return ToolResult(tool=self.name, ok=True,
                              data={"error": f"{type(exc).__name__}: {exc}"})
        data = {"cpe": [
            {"cpe23": c.cpe23, "vendor": c.vendor, "product": c.product,
             "version": c.version, "versioned": c.versioned,
             "mapping": c.mapping_id, "source": c.source,
             "note_only": c.note_only} for c in matches],
            "total": len(matches),
            "versioned": sum(1 for c in matches if c.versioned)}
        ctx.world.note(
            "fingerprint_to_cpe: " + "; ".join(
                c.cpe23 for c in matches[:8]) +
            (f" (+{len(matches) - 8} lain)" if len(matches) > 8 else ""))
        return ToolResult(tool=self.name, ok=True, data=data)
