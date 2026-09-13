"""tls_mismatch_leak — host internal/mentah terbocor di SAN sertifikat
publik (CWE-200, info surface). PASIF: hanya CT log (crt.sh), nol koneksi
ke host yang ditemukan.

Guard:
  - sumber tunggal crt.sh output=json; gagal/429 -> skipped (bukan error);
  - hanya SAN yang mengindikasikan NON-PUBLIK (internal, vpn, uat, staging,
    stg, dev, sbx, jira-, git-, localhost, IP literal) yang dicatat;
  - wildcard dan host publik = noise, dibuang;
  - SEMUA hasil = intel/surface (nama host, bukan kerentanan) — tidak
    menggurui program; nol probe lanjutan ke host internal.
"""

from __future__ import annotations

import json
import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_INTERNAL_HINTS = ("internal", "vpn", "uat", "staging", "stg", "dev", "sbx",
                   "sandbox", "test", "jira", "git", "grafana", "kibana",
                   "jenkins", "localhost", "intra")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CT_URL = ("https://crt.sh/?q=%25.{domain}&output=json")


class CtSanLeakTool(Tool):
    name = "tls_mismatch_leak"
    description = ("Pasif: host internal/mentah di SAN sertifikat publik "
                   "dari CT log. Nol koneksi ke host hasil. Intel/surface.")
    risk_tags = {"passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        domain = str(args.get("domain") or "").strip().lower().lstrip(".")
        if not domain or "." not in domain:
            return ToolResult(tool=self.name, ok=False,
                              error="args.domain wajib (mis. contoh.go.id)")
        try:
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(
                _CT_URL.format(domain=domain), timeout=max(ctx.timeout_s, 15.0))
            ctx.world.request_count += 1
            entries = json.loads(body or "[]")
        except Exception as e:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"ct-unavailable: {type(e).__name__}"})
        names: set[str] = set()
        for ent in entries:
            raw = str(ent.get("name_value") or "")
            for n in raw.splitlines():
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain) and n != domain:
                    names.add(n)
        flagged = sorted(n for n in names
                         if any(h in n for h in _INTERNAL_HINTS)
                         or _IP_RE.match(n))
        data = {"domain": domain, "ct_names": len(names),
                "flagged_internal": flagged[:10]}
        if not flagged:
            data["note"] = "tidak ada SAN non-publik terdeteksi"
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"CT certificates reveal {len(flagged)} non-public host "
                  f"names under {domain}",
            severity="info", cwe="CWE-200",
            description=(
                f"Sertifikat publik (CT log) menyebut host non-publik: "
                f"{', '.join(flagged[:5])}. Ini PETA infrastruktur untuk "
                f"penyerang (nama layanan internal/staging bocor). Intel/"
                f"surface: pasif, tanpa koneksi ke host; qualifying atau "
                f"tidak mengikuti rules program."),
            recommendation=("Jangan terbitkan sertifikat publik untuk host "
                            "internal; gunakan CA internal/DNS nama alias; "
                            "ganti nama host generik."),
            target_url=f"crt.sh?domain={domain}",
            request="crt.sh ?q=%.domain&output=json (pasif)",
            response=f"flagged={flagged[:5]}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="surface")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
