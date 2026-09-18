"""privesc_scan — engine read-only utk RTL-04 (privilege-escalation playbook).

Pemindaian kesalahan konfigurasi host yang MENINGKATKAN risiko privesc:
PATH directory writable, binary world-writable di PATH, SUID inventory
(POSIX). BACA SAJA — tidak ada upaya eskalasi nyata di engine ini; upaya
eksploitasi = tahap engagement terpisah dengan otorisasi tertulis terpisah.
Temuan berkelas posture; verdict jujur per objek konkret (zero-FP).
"""

from __future__ import annotations

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding
from .. import redteam_lab


class PrivescScanTool(Tool):
    name = "privesc_scan"
    description = ("Privesc playbook read-only: PATH writable, binary "
                   "world-writable, SUID inventory (host lab/engagement).")
    risk_tags = {"local", "passive"}
    source_skill = "rtl-04"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        result = redteam_lab.privesc_scan()
        findings: list[Finding] = []
        for row in result["findings"]:
            if row["severity"] == "info":
                continue  # SUID = observasi, bukan temuan otomatis
            findings.append(Finding(
                tool=self.name,
                title=f"Privesc risk: {row['check']} — {row['target']}",
                severity=row["severity"],
                description=(
                    f"Pemindaian read-only menemukan {row['check']} pada "
                    f"{row['target']}. {row['verdict']}. Mode: "
                    f"{result['mode']} — tidak ada upaya eskalasi yang "
                    f"dijalankan oleh engine."),
                recommendation=(
                    "Kunci izin direktori PATH (root-owned, non-writable); "
                    "turunkan izin binary; review SUID inventory manual."),
                cwe="CWE-428" if row["check"] == "path-dir-writable"
                else "CWE-276",
                file_path=row["target"],
                confidence=0.85,
                finding_class="posture",
                status="unconfirmed",
                evidence_kind="file",
            ))
        ctx.world.note(
            f"privesc_scan: {len(result['findings'])} temuan kandidat "
            f"(read-only)")
        return ToolResult(tool=self.name, ok=True, data=result,
                          findings=findings)
