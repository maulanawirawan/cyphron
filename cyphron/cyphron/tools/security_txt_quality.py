"""security_txt_quality — security.txt ADA tapi kualitasnya rusak
(CWE-1059-class, low posture). Lanjutan security_txt (yang mendeteksi
ada/tidaknya).

Kriteria rusak:
  - Contact rusak/invalid (bukan mailto: atau https://) atau duplikat;
  - Expires hilang ATAU sudah lewat;
  - file di root /security.txt TANPA padanan /.well-known/ (mirror setengah).
Guard: hanya file yang valid-parse yang dinilai; 404/catch-all HTML =
bukan domain engine ini (punya security_txt); maks 2 GET; posture.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_EXPIRES_RE = re.compile(r"(?im)^Expires:\s*(.+)$")
_CONTACT_RE = re.compile(r"(?im)^Contact:\s*(.+)$")


class SecurityTxtQualityTool(Tool):
    name = "security_txt_quality"
    description = ("security.txt ada tapi kualitasnya rusak (Contact "
                   "invalid/duplikat, Expires hilang/kadaluarsa).")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "").rstrip("/")
        if not base:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")

        def get(path: str):
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(base + path,
                                                     timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            return st, (body or "")

        st_w, body_w = get("/.well-known/security.txt")
        st_r, body_r = get("/security.txt")
        if st_w >= 400 and st_r >= 400:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": "security.txt tidak ada (domain security_txt)"})
        body = body_w if st_w < 400 else body_r
        location = (".well-known" if st_w < 400 else "root")
        problems: list[str] = []

        contacts = [c.strip() for c in _CONTACT_RE.findall(body)]
        if not contacts:
            problems.append("Contact hilang")
        else:
            invalid = [c for c in contacts
                       if not (c.lower().startswith("mailto:")
                               or c.lower().startswith("https://"))]
            if invalid:
                problems.append(f"Contact invalid: {invalid[:2]}")
            if len(contacts) > len(set(c.lower() for c in contacts)):
                problems.append("Contact duplikat")
        exp = _EXPIRES_RE.search(body)
        if not exp:
            problems.append("Expires hilang (wajib per RFC 9116)")
        else:
            try:
                exp_dt = datetime.fromisoformat(
                    exp.group(1).strip().replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    problems.append(f"Expires sudah lewat ({exp.group(1).strip()})")
            except ValueError:
                problems.append(f"Expires tidak bisa diparse ({exp.group(1).strip()})")
        if st_w < 400 and st_r >= 400:
            problems.append("hanya di root, tidak di /.well-known/")
        elif st_r < 400 and st_w < 400 and body_r.strip() != body_w.strip():
            problems.append("versi root dan .well-known berbeda")

        data = {"location": location, "contacts": len(contacts),
                "problems": problems}
        if not problems:
            data["note"] = "security.txt sehat"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"security.txt quality issues: {problems[0]}"
                  + (f" (+{len(problems)-1} lain)" if len(problems) > 1 else ""),
            severity="low", cwe="CWE-1059",
            description=(f"security.txt di {base} ({location}) ada tetapi "
                         f"bermasalah: {'; '.join(problems)}. Pelapor "
                         f"keamanan bisa tersesat — dugaan laporan tak "
                         f"sampai. finding_class=posture."),
            recommendation=("Perbaiki per RFC 9116: Contact mailto/https "
                            "valid & unik, Expires selalu ada (<=1 tahun), "
                            "mirror konsisten di /.well-known/ dan root."),
            target_url=base, request=f"GET /.well-known/security.txt",
            response=f"problems={problems}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="posture")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
