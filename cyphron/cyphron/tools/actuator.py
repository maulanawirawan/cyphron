"""actuator — Spring Boot Actuator exposure (HIGH, CWE-200).

Klasik bug bounty: /actuator tanpa proteksi membuka /env (environment —
bisa memuat kredensial), /heapdump (memory dump — bisa memuat sesi/kred),
/mappings, /configprops. Semua cukup GET; engine hanya memeriksa
ketersediaan + metadata header (NOL pengunduhan isi heapdump — cease-on-data).

FP-guard:
  - /actuator wajib mengembalikan JSON dengan "_links" berisi "self";
  - /env temuan bila JSON punya key "propertySources" atau "properties";
  - heapdump: cukup Content-Type + Content-Length dari header (isi TIDAK
    diunduh/di-dump);
  - /actuator/health 200 saja = normal, BUKAN temuan.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding


class ActuatorTool(Tool):
    name = "actuator"
    description = ("Spring Boot Actuator exposure: env/mappings/heapdump. "
                   "Isi heapdump tidak pernah diunduh (header-only).")
    risk_tags = {"active"}
    source_skill = "manual-bb-17"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        data: dict = {"host": host, "checks": []}
        findings: list[Finding] = []

        def _get(path, max_body=8000):
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    urljoin(base + "/", path.lstrip("/")),
                    timeout=ctx.timeout_s, max_body=max_body)
            except Exception as e:
                return None, {}, type(e).__name__
            ctx.world.request_count += 1
            return st, hd, body

        # gate: /actuator harus JSON _links
        st0, _hd, body0 = _get("/actuator")
        gate_ok = False
        try:
            parsed = json.loads(body0 or "")
            links = parsed.get("_links") or {}
            gate_ok = isinstance(links, dict) and "self" in links
        except Exception:
            gate_ok = False
        data["checks"].append({"path": "/actuator", "status": st0,
                               "valid": gate_ok})
        if not gate_ok:
            return ToolResult(tool=self.name, ok=True, data=data)

        # /env — HIGH bila berisi propertySources/properties
        st1, _h1, body1 = _get("/actuator/env")
        env_ok = False
        try:
            p1 = json.loads(body1 or "")
            env_ok = bool(p1.get("propertySources") or p1.get("properties"))
        except Exception:
            env_ok = False
        data["checks"].append({"path": "/actuator/env", "status": st1,
                               "exposed": env_ok})
        if env_ok:
            findings.append(Finding(
                tool=self.name,
                title=f"Spring Boot Actuator /env exposed publicly on {host}",
                severity="high", cwe="CWE-200",
                description=(
                    "/actuator/env dapat diakses tanpa autentikasi dan "
                    "mengungkap konfigurasi/property aplikasi — sering memuat "
                    "kredensial database, API key, dan secret lain "
                    "(nilai sensitif di-redact dari bukti ini)."),
                recommendation=(
                    "Batasi /actuator/env,configprops,heapdump via "
                    "management.endpoint exposure + Spring Security, atau "
                    "pisahkan management port ke jaringan internal."),
                target_url=base,
                request="GET /actuator/env",
                response=f"HTTP {st1}; propertySources terbuka (nilai redacted)",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))

        # /heapdump — HIGH bila header menunjukkan dump besar; isi tidak diunduh
        st2, h2, _b2 = _get("/actuator/heapdump", max_body=1)
        ctype = ""
        clen = ""
        for k, v in (h2 or {}).items():
            if k.lower() == "content-type":
                ctype = v
            if k.lower() == "content-length":
                clen = v
        heap_ok = (isinstance(st2, int) and st2 == 200
                   and ("octet-stream" in ctype.lower()
                        or "gzip" in ctype.lower()))
        data["checks"].append({"path": "/actuator/heapdump", "status": st2,
                               "content_type": ctype, "content_length": clen,
                               "exposed": heap_ok})
        if heap_ok:
            findings.append(Finding(
                tool=self.name,
                title=f"Spring Boot Actuator /heapdump exposed publicly on {host}",
                severity="high", cwe="CWE-200",
                description=(
                    f"/actuator/heapdump dapat diakses tanpa autentikasi "
                    f"(HTTP {st2}, Content-Type={ctype or '?'}, "
                    f"Content-Length={clen or '?'}). Memory dump JVM lazim "
                    f"memuat kredensial, sesi, dan secret dalam memori. Isi "
                    f"dump TIDAK diunduh — pemeriksaan berhenti di header "
                    f"(cease-on-data)."),
                recommendation=(
                    "Nonaktifkan endpoint heapdump di produksi "
                    "(management.endpoints.web.exposure.exclude) dan batasi "
                    "management interface."),
                target_url=base,
                request="GET /actuator/heapdump (header-only)",
                response=f"HTTP {st2}; Content-Type={ctype}; Content-Length={clen}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="header"))

        # /mappings — medium (peta route internal)
        st3, _h3, body3 = _get("/actuator/mappings")
        map_ok = False
        try:
            p3 = json.loads(body3 or "")
            map_ok = bool(p3.get("contexts"))
        except Exception:
            map_ok = False
        data["checks"].append({"path": "/actuator/mappings", "status": st3,
                               "exposed": map_ok})
        if map_ok and not env_ok:
            findings.append(Finding(
                tool=self.name,
                title=f"Spring Boot Actuator /mappings exposed publicly on {host}",
                severity="medium", cwe="CWE-200",
                description=("/actuator/mappings terbuka tanpa auth — mengungkap "
                             "peta seluruh route internal aplikasi."),
                recommendation="Batasi exposure endpoint actuator di produksi.",
                target_url=base,
                request="GET /actuator/mappings",
                response=f"HTTP {st3}; contexts terbuka",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
