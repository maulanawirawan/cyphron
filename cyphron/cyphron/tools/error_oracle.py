"""error_oracle — klasifikasi bentuk error endpoint API untuk membedakan
model otorisasi vs kebocoran info (protokol lapangan Gojek BB 2026-09-13).

Teknik teruji: kirim varian kecil ke endpoint berbasis identifier —
(1) id milik sendiri (baseline), (2) id rusak/malformed, (3) id asing
HANYA dengan flag allow_foreign_probe — lalu bandingkan SHAPE error:
  - gRPC-style "5 NOT_FOUND: ..." / "7 PERMISSION_DENIED: ..." 
  - "Authorization failure" / "customer unauthorized"  -> authz fail-closed
  - error yang MENGUTIP status object asing ("Completed") -> status-oracle
    (info; di banyak program non-qualifying, tapi dicatat)
  - stack trace (Java/Clojure/Python) di error 5xx -> info-leak
FP-guard & keamanan:
  - cease-on-data: respons 200 berisi data untuk id ASING -> 1 temuan IDOR,
    nilai tidak disimpan (nama field saja), probing langsung berhenti;
  - maks 1 request per varian; tanpa brute force;
  - baseline id WAJIB milik peneliti (args.own_id).
"""

from __future__ import annotations

import json
import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_GRPC = re.compile(r"^\s*(\d{1,2})\s+([A-Z_]+):\s*(.+)$")
_STACK = re.compile(r"(Traceback \(most recent call last\)|"
                    r"at [\w$.]+\([\w.]+:\d+\)|File \"[^\"]+\", line \d+)")
_STATUS_LEAK = re.compile(
    r'\(not\s*\(#\{|"status"\s*:\s*"[A-Za-z][A-Za-z _-]{2,30}"', re.I)
_AUTHZ_DENY = re.compile(
    r"authorization failure|permission_denied|unauthorized|forbidden|"
    r"customer unauthorized|access denied", re.I)


def _classify(status: int, body: str) -> str:
    # PENTING: kasus nyata Gojek = HTTP 200 dengan error text di body
    # ("5 NOT_FOUND..." via 200). Pola error dicek DULU, baru status.
    if _STACK.search(body):
        return "STACK-TRACE-LEAK"
    g = _GRPC.match(body.strip())
    if g:
        code, name, msg = g.group(1), g.group(2), g.group(3)
        if code in ("7", "16") or _AUTHZ_DENY.search(msg):
            return f"AUTHZ-DENIED (gRPC {code} {name})"
        if code == "5":
            return "NOT-FOUND (gRPC 5)"
        return f"gRPC {code} {name}"
    if _AUTHZ_DENY.search(body):
        return "AUTHZ-DENIED"
    if _STATUS_LEAK.search(body):
        return "STATUS-ORACLE (status object bocor di pesan error)"
    if status == 200:
        return "DATA-OK"
    return "GENERIC-ERROR"


class ErrorOracleTool(Tool):
    name = "error_oracle"
    description = ("Klasifikasi shape error endpoint API (baseline id sendiri, "
                   "malformed, tanpa-auth, id asing opsional) — membedakan "
                   "authz fail-closed vs status-oracle vs kebocoran info.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base_url = str(args.get("url") or "").rstrip("/")
        id_param = str(args.get("id_template") or "{id}")
        own_id = str(args.get("own_id") or "")
        malformed_id = str(args.get("malformed_id") or "F-00000ZZZ999")
        foreign_id = str(args.get("foreign_id") or "")
        allow_foreign = bool(args.get("allow_foreign_probe", False))
        headers = dict(args.get("headers") or {})
        if not base_url or not own_id:
            return ToolResult(tool=self.name, ok=False,
                              error="args.url + args.own_id wajib (baseline "
                                    "harus milik peneliti sendiri)")
        if foreign_id and not allow_foreign:
            return ToolResult(tool=self.name, ok=False,
                              error="args.foreign_id diabaikan tanpa "
                                    "allow_foreign_probe=true (cease-on-data)")

        variants = [("own", own_id), ("malformed", malformed_id)]
        if foreign_id:
            variants.append(("foreign", foreign_id))

        shapes: list[dict] = []
        findings: list[Finding] = []
        stop = False
        for name, ident in variants:
            if stop:
                break
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            url = base_url + id_param.replace("{id}", ident)
            omit_auth = name == "foreign" and bool(args.get("foreign_omit_auth"))
            st, _h, body, _ms = http_engine.http_get(
                url, timeout=ctx.timeout_s, headers=headers or None)
            ctx.world.observe_response(url, st, _h, body, self.name)
            ctx.world.request_count += 1
            shape = _classify(st, body[:2000])
            entry = {"variant": name, "identifier": ident,
                     "omit_auth": omit_auth, "status": st, "shape": shape}
            if name == "foreign" and st == 200 and shape == "DATA-OK":
                # IDOR: data asing terbuka. cease-on-data — tidak ada nilai
                # yang disimpan, hanya struktur bukti. (200 berisi teks
                # error Gojek-style sudah terklasifikasi di atas.)
                try:
                    j = json.loads(body[:200000])
                    keys = list(j.keys())[:20] if isinstance(j, dict) else None
                except Exception:
                    keys = None
                entry["shape"] = "DATA-OK (foreign!)"
                entry["foreign_data_fields"] = keys
                findings.append(Finding(
                    tool=self.name,
                    title=f"IDOR: foreign object returned at {id_param}",
                    severity="high", cwe="CWE-639",
                    description=(f"Endpoint {base_url}{id_param} mengembalikan "
                                 f"objek milik pengguna lain untuk identifier "
                                 f"asing ({ident}). Ownership check tidak "
                                 f"di-enforce. Nilai data TIDAK disimpan."),
                    recommendation="Enforce ownership check per-session/per-user "
                                   "di endpoint object-level.",
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {ident} (foreign)",
                    response=f"status=200; fields={keys} (nilai redacted)",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="http-response",
                ))
                shapes.append(entry)
                stop = True  # cease-on-data
                break
            if shape == "STACK-TRACE-LEAK":
                findings.append(Finding(
                    tool=self.name,
                    title=f"Stack trace leaked in error at {id_param}",
                    severity="info", cwe="CWE-209",
                    description=(f"Pesan error pada {ident} memuat stack trace "
                                 f"(frame/line internal). Info-leak; di banyak "
                                 f"program non-qualifying tanpa exploit, tapi "
                                 f"intel kerangka kerja berharga."),
                    recommendation="Return generic error pages; log detail di server.",
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {ident}",
                    response=redact(body[:300]), confidence=0.8,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="http-response",
                ))
            shapes.append(entry)
            if name == "own" and "DATA-OK" in shape:
                baseline_ok = True

        verdict = "authz-fail-closed" if any(
            "AUTHZ-DENIED" in s["shape"] for s in shapes if s["variant"] == "foreign") \
            else ("status-oracle" if any("STATUS-ORACLE" in s["shape"] for s in shapes)
                  else "inconclusive")
        ctx.world.note(f"error_oracle: {len(shapes)} varian -> {verdict}")
        return ToolResult(tool=self.name, ok=True, data={
            "url": base_url + id_param,
            "shapes": shapes,
            "verdict": verdict,
            "cease_on_data": stop,
        }, findings=findings)
