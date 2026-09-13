"""email_disclosure_pattern — pola email di halaman publik (CWE-200,
info surface).

Roadmap: intel untuk RANTAI berikutnya (pola firstname.lastname@domain
menjadi bahan reset_enum/register). Guard redaksi PII KERAS:
  - local part di-mask (huruf pertama + ***@domain) — email penuh TIDAK
    disimpan di data/finding;
  - temuan = POLA terdeteksi (>=2 email konsisten satu pola), bukan alamat;
  - maks 3 halaman publik per run, 1 GET per halaman.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_EMAIL_RE = re.compile(
    r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)


def _mask(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def _pattern_of(email: str) -> str:
    local, _, _d = email.partition("@")
    if re.fullmatch(r"[a-z]+\.[a-z]+", local, re.I):
        return "first.last"
    if re.fullmatch(r"[a-z]+[0-9]{2,}", local, re.I):
        return "name+number"
    if re.fullmatch(r"[a-z]\.[a-z]+", local, re.I):
        return "f.last"
    return "other"


class EmailPatternTool(Tool):
    name = "email_disclosure_pattern"
    description = ("Deteksi pola email di halaman publik; alamat di-mask "
                   "(PII redaksi keras); hasil = pola, bukan alamat.")
    risk_tags = {"passive"}
    source_skill = "bounty-medium-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        urls = [str(u) for u in (args.get("urls") or [])][:3]
        if not urls:
            return ToolResult(tool=self.name, ok=False,
                              error="args.urls (halaman publik) wajib")
        domain = (urlsplit(urls[0]).hostname or "").lower()
        seen: dict[str, str] = {}
        data: dict = {"pages": len(urls), "masked_emails": [],
                      "patterns": {}}
        for u in urls:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, _h, body, _ms = http_engine.http_get(
                    u, timeout=ctx.timeout_s)
            except Exception as e:
                data[f"error:{u}"] = type(e).__name__
                continue
            ctx.world.request_count += 1
            if st >= 400:
                continue
            for m in _EMAIL_RE.findall(body or ""):
                if domain and not m.lower().endswith(domain):
                    continue  # hanya email domain target
                seen.setdefault(m.lower(), _pattern_of(m.lower()))
        data["masked_emails"] = sorted(_mask(e) for e in seen)[:10]
        for email, pat in seen.items():
            data["patterns"].setdefault(pat, 0)
            data["patterns"][pat] += 1
        dominant = max(data["patterns"], key=data["patterns"].get) \
            if data["patterns"] else None
        if not dominant or data["patterns"][dominant] < 2:
            data.setdefault("note", "pola belum konsisten (<2 contoh)")
            return ToolResult(tool=self.name, ok=True, data=data)
        findings = [Finding(
            tool=self.name,
            title=f"Public pages reveal {len(seen)} emails with pattern "
                  f"'{dominant}' on {domain}",
            severity="info", cwe="CWE-200",
            description=(
                f"Halaman publik {domain} memaparkan {len(seen)} alamat "
                f"email dengan pola dominan '{dominant}' (contoh ter-mask: "
                f"{data['masked_emails'][:3]}). Pola ini memungkinkan "
                f"penyerang menebak alamat siapa pun di organisasi untuk "
                f"reset_enum/register — intel/surface, nilai akhir dari "
                f"rules program. Alamat penuh tidak disimpan (redaksi)."),
            recommendation=("Gunakan form kontak ber-layer, hapus mailto "
                            "bulk, konsider alias per-peran."),
            target_url=urls[0],
            request=f"GET {urls[0]} (+{len(urls)-1} halaman)",
            response=f"pattern={dominant}; count={len(seen)}; "
                     f"masked={data['masked_emails'][:3]}",
            confidence=0.8, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="surface")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
