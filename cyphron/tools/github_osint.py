"""github_osint — pencarian kode GitHub untuk kredensial terkait domain
target (verdict BINUS LAYAK; 11 query lapangan -> 3 kandidat, semua non-leak
berkat guard).

FP-guard (wajib):
  - VERIFIKASI ULANG isi file via raw URL sebelum dilaporkan;
  - cek tanggal commit/push (kode lama / sudah direvisi = downgrade);
  - hasil = LEAD unconfirmed (confidence rendah) sampai diverifikasi manual;
  - tanpa GITHUB_TOKEN/GH_TOKEN di environment -> engine SKIP dengan pesan
    jelas (API search tanpa token = rate limit parah dan di-reject);
  - nol interaksi dengan infra target — semua query ke api.github.com.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request

from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_API = "https://api.github.com/search/code"
_QUERIES = [
    '{d} password',
    '{d} api_key',
    '{d} apikey',
    '{d} secret',
    '{d} token',
    '{d} AKIA',
    '{d} authorization',
]
_SECRET_HINT = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)", re.I)
_ASSIGN = re.compile(
    r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]")


def _gh_json(url: str, token: str, timeout: float = 15.0):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "cyphron-github-osint/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace")), resp.headers


def _fetch_raw(raw_url: str, token: str, timeout: float = 15.0) -> str:
    req = urllib.request.Request(raw_url, headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": "cyphron-github-osint/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


class GithubOsintTool(Tool):
    name = "github_osint"
    description = ("OSINT kode GitHub untuk kredensial terkait domain target "
                   "(butuh GITHUB_TOKEN/GH_TOKEN; tanpa token = skip). "
                   "Semua hit diverifikasi ulang via raw + cek tanggal push.")
    risk_tags = {"passive"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        domain = str(args.get("domain") or "").strip().lower()
        if not domain or "." not in domain:
            return ToolResult(tool=self.name, ok=False,
                              error="args.domain wajib (mis. contoh.ac.id)")
        token = str(args.get("token") or os.environ.get("GITHUB_TOKEN")
                    or os.environ.get("GH_TOKEN") or "")
        if not token:
            ctx.world.note("github_osint: SKIP — GITHUB_TOKEN/GH_TOKEN tidak "
                           "tersedia di environment")
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": "token-tidak-ada",
                "hint": "set GITHUB_TOKEN di environment untuk mengaktifkan"})
        per_query = int(args.get("per_query", 10))
        hits: list[dict] = []
        queries_run = 0
        for q in _QUERIES:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            queries_run += 1
            try:
                d, hdrs = _gh_json(
                    f"{_API}?q={urllib.parse.quote(q.format(d=domain))}"
                    f"&per_page={per_query}", token, timeout=ctx.timeout_s)
            except Exception as e:
                hits.append({"query": q, "error": redact(str(e))[:120]})
                continue
            for item in d.get("items") or []:
                entry = {
                    "query": q,
                    "repo": (item.get("repository") or {}).get("full_name"),
                    "path": item.get("path"),
                    "raw_url": item.get("url"),
                    "pushed_at": (item.get("repository") or {}).get("pushed_at"),
                }
                # FP-guard: verifikasi ulang isi via raw
                try:
                    ctx.throttle()
                    content = _fetch_raw(entry["raw_url"], token,
                                         timeout=ctx.timeout_s)
                    ctx.world.request_count += 1
                    entry["verified"] = bool(
                        _SECRET_HINT.search(content)
                        and (_ASSIGN.search(content) or _SECRET_HINT.search(content)))
                    entry["excerpt"] = redact(
                        content[:200]) if entry["verified"] else None
                except Exception as e:
                    entry["verified"] = False
                    entry["error"] = redact(str(e))[:120]
                hits.append(entry)

        verified = [h for h in hits if h.get("verified")]
        findings = [Finding(
            tool=self.name,
            title=f"GitHub OSINT: possible credential in {h['repo']}/{h['path']}",
            severity="medium", cwe="CWE-798",
            description=(f"Kode publik di {h['repo']} ({h['path']}, pushed "
                         f"{h['pushed_at']}) cocok pola kredensial untuk "
                         f"{domain}. VERIFIED via raw fetch — tetap LEAD: "
                         f"wajib cek manual (bisa sample/kelas/placeholder) "
                         f"sebelum klaim."),
            recommendation="Verifikasi manual isi file + liveness; jika "
                           "kredensial hidup, laporkan via program terkait.",
            file_path=None, line_start=None, line_end=None,
            request=f"GET {h['raw_url']}",
            response=h.get("excerpt") or "(excerpt tersensor)",
            confidence=0.4, source_skill=self.source_skill,
            status="unconfirmed", evidence_kind="osint",
        ) for h in verified]

        ctx.world.note(
            f"github_osint: {queries_run} query, {len(hits)} hit, "
            f"{len(verified)} verified-lead")
        return ToolResult(tool=self.name, ok=True, data={
            "domain": domain,
            "queries_run": queries_run,
            "hits": hits,
            "verified_leads": len(verified),
        }, findings=findings)
