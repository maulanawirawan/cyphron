"""robots_sensitive_entry — robots.txt menyebut path sensitif (CWE-538,
info surface / intel lead).

Roadmap: "robots.txt menyebut path sensitif (intel lead)". Robots.txt yang
Disallow-kan /admin, /backup, /private = PETA ke penyerang. Guard:
  - hanya entri Disallow/Sitemap yang berisi kata sensitif (admin, backup,
    private, internal, secret, dump, .git, .env, panel) yang dicatat;
  - hasil = LEAD untuk dir_probe manual (bukan klaim); 1 GET per run.
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_SENSITIVE = ("admin", "backup", "private", "internal", "secret", "dump",
              ".git", ".env", "panel", "config", "phpmyadmin", "debug")


class RobotsSensitiveEntryTool(Tool):
    name = "robots_sensitive_entry"
    description = ("robots.txt menyebut path sensitif — intel lead untuk "
                   "dir_probe manual; surface info.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "").rstrip("/")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        ctx.throttle()
        st, _h, body, _ms = http_engine.http_get(url + "/robots.txt",
                                                 timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        if st >= 400:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"robots.txt tidak ada (status {st})"})
        low = (body or "").lower()
        if "<html" in low[:200]:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": "catch-all HTML — bukan robots.txt asli "
                           "(pelajaran security_txt)"})
        entries: list[str] = []
        for line in (body or "").splitlines():
            m = re.match(r"(?i)^\s*Disallow:\s*(/\S*)", line)
            if m and any(s in m.group(1).lower() for s in _SENSITIVE):
                entries.append(m.group(1))
        entries = sorted(set(entries))[:10]
        data = {"entries_sensitive": entries}
        if not entries:
            data["note"] = "tidak ada entri sensitif"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"robots.txt reveals {len(entries)} sensitive path(s): "
                  f"{entries[0]}" + (" (+" + str(len(entries) - 1) + " lain)"
                                     if len(entries) > 1 else ""),
            severity="info", cwe="CWE-538",
            description=(f"robots.txt mendaftar path sensitif "
                         f"({', '.join(entries[:5])}) — Disallow tidak "
                         f"melindungi apa pun, hanya memberi peta. Lead: "
                         f"verifikasi manual dengan dir_probe path ini "
                         f"(cease-on-data; bukan brute). surface intel."),
            recommendation=("Hapus path dari robots.txt; blokir di layer "
                            "auth; batasi akses jaringan; hapus backup/"
                            "dump dari webroot."),
            target_url=url + "/robots.txt",
            request="GET /robots.txt",
            response=f"entries={entries}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="surface")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
