"""cache_poison — web cache poisoning header -> respons cache teracuni
(CWE-444, high).

Rantai bukti (2 request, differential):
  1. POISON : request dengan header injeksi (X-Forwarded-Host) berisi host
     marker peneliti -> respons memuat marker;
  2. VERIFY : request URL SAMA tanpa header -> respons YANG MUNCUL DARI
     CACHE masih memuat marker = cache tersimpan teracuni.
Reflection pada request #1 saja = bukan temuan (server bisa mem-echo
header tanpa cache); hanya kondisi #2 yang membuktikan poisoning.

Doktrin: DAMPAK ke user lain nyata — args.acknowledge_impact=True wajib
(seperti allow_foreign_probe); marker tidak berbahaya; cease-on-data
(segera setelah verify hit, JANGAN mengulang/meracuni path lain); lapor
segera agar cache di-purge.
"""

from __future__ import annotations

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class CachePoisonTool(Tool):
    name = "cache_poison"
    description = ("Web cache poisoning bukti dua-langkah (poison + verify "
                   "dari cache). Wajib acknowledge_impact; cease-on-data.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "")
        header_name = str(args.get("header_name") or "X-Forwarded-Host")
        marker_host = str(args.get("marker_host") or "cyphron-oob.example")
        if not url:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        if not args.get("acknowledge_impact"):
            return ToolResult(
                tool=self.name, ok=False,
                error="cache poisoning memengaruhi user lain — set "
                      "acknowledge_impact=True hanya di program yang "
                      "mengizinkannya, dan lapor segera setelah bukti")
        marker = marker_host.lower()

        # ---- 1. POISON: kirim header teracuni
        ctx.throttle()
        p_st, p_hd, p_body, _ms = http_engine.http_get(
            url, timeout=ctx.timeout_s, headers={header_name: marker_host})
        ctx.world.request_count += 1
        data: dict = {"url": url, "header": header_name, "marker": marker_host,
                      "poison_status": p_st,
                      "poison_reflected": marker in p_body.lower()}

        # ---- 2. VERIFY: URL sama, TANPA header -> harus dari cache
        ctx.throttle()
        v_st, _h, v_body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        data["verify_status"] = v_st
        data["verify_cached_marker"] = marker in v_body.lower()
        if data["poison_reflected"] and data["verify_cached_marker"]:
            findings = [Finding(
                tool=self.name,
                title=f"Web cache poisoning confirmed via {header_name}",
                severity="high", cwe="CWE-444",
                description=(
                    f"Header '{header_name}' direfleksikan server DAN "
                    f"tersimpan di cache: request berikutnya TANPA header "
                    f"masih menyajikan konten teracuni (host '{marker_host}'). "
                    f"Pengunjung lain dapat menerima respons yang dikendalikan "
                    f"attacker (defacement/skrip). cease-on-data: satu path "
                    f"saja diracuni; laporkan segera agar purge."),
                recommendation=(
                    "Jangan refleksikan header non-standar ke respons; set "
                    "Vary/Cache-Key eksplisit; allowlist host X-Forwarded-*; "
                    "purge cache secepatnya."),
                target_url=url, param=header_name,
                request=f"1) GET {url} [{header_name}: {marker_host}]  "
                        f"2) GET {url} (tanpa header)",
                response=f"poison: status={p_st} (marker tampil); "
                         f"verify-tanpa-header: status={v_st} (marker "
                         f"MASIH tampil dari cache)",
                confidence=0.95, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair")]
            return ToolResult(tool=self.name, ok=True, data=data,
                              findings=findings)
        if data["poison_reflected"] and not data["verify_cached_marker"]:
            data["note"] = ("marker hanya tampil saat header dikirim = "
                            "reflection biasa, BUKAN cache poisoning")
        return ToolResult(tool=self.name, ok=True, data=data)
