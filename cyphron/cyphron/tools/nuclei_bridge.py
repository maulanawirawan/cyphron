"""nuclei_bridge — eksekutor template Nuclei TERKURASI (subset aman).

Eksekusi = aktif (risk_tags active), lewat gate otorisasi seperti engine
lain. Yang dijalankan HANYA template lolos nuclei_loader.is_safe:
- severity dalam izin (default info/low),
- whitelist tag + bebas blacklist (dos/bruteforce/overflow/fuzz/...),
- 1 request GET, path {{BaseURL}}+literal, matcher word/status,
- matcher wajib memeriksa ISI respons (anti catch-all 200, pelajaran SIPAS),
- tanpa interactsh/raw/body/payloads/DSL/host-header.
Satu request per template, throttle ctx, cap max_templates, redirect tidak
diikuti (atribusi lintas-host ditolak). Template agresif hanya jalan bila
izin severity dinaikkan eksplisit + user bilang gas di sesi.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..kb import nuclei_loader
from ..kb.paths import resolve_kb_dir
from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


def _matcher_group_matches(m: dict, status: int, body: str,
                           headers: dict[str, str]) -> bool | None:
    """True/False; None = matcher jenis luar duga (tidak dijalankan)."""
    mtype = str(m.get("type") or "").lower()
    if mtype == "status":
        want = m.get("status") or []
        if not isinstance(want, list):
            want = [want]
        return status in [int(x) for x in want if isinstance(x, (int, str))
                          and str(x).lstrip("-").isdigit()]
    if mtype == "word":
        part = str(m.get("part") or "body").lower()
        hay = body if part in ("body", "") else (
            "; ".join(f"{k}: {v}" for k, v in headers.items())
            if part in ("header", "headers") else None)
        if hay is None:
            return None
        words = [str(w) for w in (m.get("words") or [])]
        if not words:
            return False
        cond = str(m.get("condition") or "or").lower()
        low = hay.lower()
        if cond == "and":
            return all(w.lower() in low for w in words)
        return any(w.lower() in low for w in words)
    return None


def _template_matches(t: nuclei_loader.NucleiTemplate, status: int, body: str,
                      headers: dict[str, str]) -> bool | None:
    """Evaluasi semua matcher template (kondisi and/or antar-grup)."""
    verdicts: list[bool] = []
    for req in t.requests:
        for m in req.matchers:
            v = _matcher_group_matches(m, status, body, headers)
            if v is None:
                return None
            verdicts.append(v)
    if not verdicts:
        return False
    cond = (t.requests[0].matchers_condition if t.requests else "or")
    return all(verdicts) if cond == "and" else any(verdicts)


class NucleiBridgeTool(Tool):
    name = "nuclei_bridge"
    description = ("Jalankan template Nuclei subset aman (info/low, GET "
                   "sederhana) terhadap target berizin — 1 request/template.")
    risk_tags = {"active"}
    source_skill = "kb-godtier-04"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        kb_dir = resolve_kb_dir(args.get("kb_dir"))
        root = kb_dir / "nuclei"
        if not root.exists():
            note = ("nuclei_bridge: template nuclei belum tersinkron — "
                    "jalankan `python -m cyphron kb --source nuclei`")
            ctx.world.note(note)
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "kb-belum-tersedia"})
        url = str(args.get("url") or ctx.world.target or "").rstrip("/")
        if not url.startswith(("http://", "https://")):
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "url tidak valid"})
        host = urlsplit(url).hostname or ""

        severity_arg = str(args.get("severity") or "info,low")
        allow_severity = tuple(
            s.strip().lower() for s in severity_arg.split(",") if s.strip())
        dry_run = bool(args.get("dry_run"))
        cap = max(1, min(int(args.get("max_templates") or 25), 100))
        want_ids = {str(x) for x in (args.get("template_ids") or [])}

        stats = nuclei_loader.LoadStats()
        checked: list[dict] = []
        findings: list[Finding] = []
        sent = 0
        base_prefix = "{{BaseURL}}"
        for t in nuclei_loader.iter_safe_templates(root, allow_severity, stats):
            if len(checked) >= cap:
                break
            if want_ids and t.tid not in want_ids:
                continue
            req = t.requests[0]
            full = url + req.path[len(base_prefix):]
            row = {"id": t.tid, "severity": t.severity, "url": full,
                   "tags": sorted(t.tags)[:6]}
            if dry_run:
                row["would_send"] = True
                checked.append(row)
                continue
            if host and urlsplit(full).hostname != host:
                continue  # keamanan atribusi: path tak boleh lari ke host lain
            checked.append(row)
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    full, timeout=ctx.timeout_s, follow_redirects=False)
            except Exception as exc:
                row["error"] = type(exc).__name__
                ctx.errors.append(f"nuclei_bridge[{t.tid}]: {exc}")
                continue
            sent += 1
            ctx.world.request_count += 1
            status = st if isinstance(st, int) else -1
            row["status"] = status
            matched = _template_matches(t, status, body or "", hd or {})
            if not matched:
                continue
            top_score = t.cvss_score
            f = Finding(
                tool=self.name,
                title=f"[nuclei:{t.tid}] {t.name or t.tid}",
                severity=t.severity,
                cwe=t.cwe or None,
                description=(
                    f"Template Nuclei aman ({', '.join(sorted(t.tags))}) match "
                    f"terhadap {full}. {t.description[:220]}".strip()),
                recommendation=(
                    "Verifikasi manual ringan sebelum klaim; cek referensi "
                    f"template {t.tid} di repo nuclei-templates. "
                    + (f"CVSS {top_score:.1f} ({t.cvss_metrics})." if top_score else "")),
                target_url=full,
                request=f"GET {full}",
                response=(f"status={status} "
                          f"body_excerpt={(body or '')[:200]}"),
                confidence=0.9,
                source_skill=self.source_skill,
                status="confirmed",
                evidence_kind="request-response",
                finding_class=("surface" if t.severity == "info" else "weakness"))
            if top_score:
                f.attach_evidence("kb", {
                    "template": t.tid, "cve_ids": t.cve_ids,
                    "cvss_score": top_score, "cvss_metrics": t.cvss_metrics})
            findings.append(f)
        data = {"checked": checked, "requests_sent": sent, "stats": {
            "total": stats.total, "parsed": stats.parsed,
            "skipped_parse": stats.skipped_parse,
            "skipped_unsafe": stats.skipped_unsafe, "safe": stats.safe}}
        ctx.world.note(
            f"nuclei_bridge: {sent} request, {len(findings)} match, "
            f"template aman={stats.safe}/{stats.total} "
            f"(skip parse={stats.skipped_parse}, unsafe={stats.skipped_unsafe})")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
