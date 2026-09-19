"""api_surface_probe — harvest endpoint API dari JS bundle + probe unauth
(Broken Function-Level Authorization, CWE-285/862).

Teknik terbukti lapangan (BINUS 2026-09, dari scratch/unauth_probe.py +
extract_probe.py): bundle JS publik membocorkan peta endpoint; sebagian
merespons DATA tanpa kredensial. Di Gojek (2026-09-13) varian yang sama
juga mengekstrak NAMA HEADER WAJIB (x-csrf-token/x-platform/x-appversion)
dari interceptor axios — pengetahuan yang membuka endpoint terproteksi
untuk pengujian sah dengan akun sendiri.

Keamanan & FP-guard:
  - GET saja, TANPA payload; skip path mutasi/auth (wilayah yang berbahaya
    atau milik reporter lain);
  - klasifikasi dari ISI RESPONS, bukan status (pelajaran BINUS: 90+
    endpoint "200" ternyata cuma halaman versi = bukan temuan);
  - data-hint sensif (password/token dump) -> langsung STOP semua probing;
  - cap ketat: maks 6 script, maks N probe (default 8) — bukan scanner;
  - semua bukti lewat redact(); PII value TIDAK disimpan, hanya nama field;
  - temuan hanya bila JSON berisi data-hint personal pada endpoint yang
    bisa diakses tanpa kredensial — sisanya intel (ToolResult.data).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_SCRIPT_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_PATH_RE = re.compile(
    r"""["'`](/(?:api|v\d{1,2}|[a-z][a-z0-9-]{2,30}/v\d{1,2})/[A-Za-z0-9._/~:?&=\[\]@!$'()*+,;%-]{2,90})["'`]""")
_HEADER_RE = re.compile(r"""["'`](x-[a-z][a-z0-9-]{2,30})["'`]""", re.I)
_HOST_RE = re.compile(r"https?://([a-z0-9.-]+\.[a-z]{2,})", re.I)

SKIP_PATH = re.compile(
    r"auth/token|logout|sign_up|signup|/login|password|create|update|delete|"
    r"save|submit|upload|import|approve|reject|verify|set/|toggle|cancel|"
    r"register|/me\b", re.I)
DATA_HINT = re.compile(
    r'"(nama|name|email|phone|mobile|alamat|address|nilai|grade|score|exam|'
    r'student|mahasiswa|dosen|nik|gender|dob|photo|gpa|krs|balance|amount)"'
    r'\s*:', re.I)
SENSITIVE_STOP = re.compile(
    r'"[^"]*(?:password|passwd|secret|private_key|access_token|refresh_token)"'
    r'\s*:\s*"[^"]{6,}"', re.I)

_MAX_SCRIPTS = 6
_MAX_BODY = 400_000
_JS_BODY = 600_000


class ApiSurfaceProbeTool(Tool):
    name = "api_surface_probe"
    description = ("Harvest endpoint API + custom header dari JS bundle, "
                   "lalu probe unauth GET terbatas (BFLA, CWE-285/862) — "
                   "klasifikasi dari isi respons, sensif-STOP.")
    risk_tags = {"active"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        url = str(args.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return ToolResult(tool=self.name, ok=False,
                              error="args.url wajib http(s)://")
        max_probe = max(1, min(int(args.get("max_probe", 8)), 12))
        parts = urlsplit(url)
        host = parts.netloc

        st, _hd, page, _ms = http_engine.http_get(url, timeout=ctx.timeout_s)
        ctx.world.request_count += 1
        if st != 200:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"halaman utama {st}"})

        scripts = [urljoin(url, s) for s in _SCRIPT_RE.findall(page)
                   if urlsplit(urljoin(url, s)).netloc in ("", host)][: _MAX_SCRIPTS]
        paths: set[str] = set()
        headers: set[str] = set()
        api_hosts: set[str] = set()
        for js in scripts:
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            jst, _jh, body, _ms = http_engine.http_get(js, timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            if jst != 200 or not body:
                continue
            body = body[:_JS_BODY]
            paths |= set(_PATH_RE.findall(body))
            headers |= set(_HEADER_RE.findall(body))
            api_hosts |= set(_HOST_RE.findall(body))

        probed: list[dict] = []
        findings: list[Finding] = []
        stop = False
        candidates = sorted(p for p in paths if not SKIP_PATH.search(p))
        for path in candidates:
            if stop or len(probed) >= max_probe:
                break
            if ctx.world.request_count >= ctx.max_requests:
                break
            ctx.throttle()
            pu, _ph, pbody, _ms = http_engine.http_get(
                urljoin(url, path), timeout=ctx.timeout_s)
            ctx.world.request_count += 1
            entry = {"path": path, "status": pu, "classified": None}
            try:
                j = json.loads(pbody[:_MAX_BODY])
                is_json = isinstance(j, (dict, list))
            except Exception:
                is_json = False
            if is_json and SENSITIVE_STOP.search(pbody):
                entry["classified"] = "SENSITIVE-STOP (credential dump terdeteksi)"
                findings.append(Finding(
                    tool=self.name,
                    title=f"Unauth API exposes sensitive credentials at {path}",
                    severity="critical", cwe="CWE-285",
                    description=(
                        f"Endpoint {path} merespons JSON tanpa kredensial dan "
                        f"berisi credential dump (password/token literal). "
                        f"Broken function-level authorization."),
                    recommendation=(
                        "Enforce authentication + function-level authorization "
                        "di server; rotasi kredensial yang terekspos."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {path} (unauthenticated)",
                    response=redact(pbody[:400]), confidence=0.9,
                    source_skill=self.source_skill, status="confirmed",
                    evidence_kind="http-response",
                ))
                probed.append(entry)
                stop = True  # sensif-STOP
                break
            if is_json and DATA_HINT.search(pbody):
                entry["classified"] = "data-hint (nama field saja, nilai disensor)"
                fields = sorted(set(DATA_HINT.findall(pbody)))[:12]
                findings.append(Finding(
                    tool=self.name,
                    title=f"Unauth API returns personal data at {path}",
                    severity="high", cwe="CWE-285",
                    description=(
                        f"Endpoint {path} merespons JSON tanpa kredensial "
                        f"berisi field personal: {', '.join(fields)}. "
                        f"Broken function-level authorization (BFLA)."),
                    recommendation=(
                        "Terapkan authorization per-endpoint; minimal alami "
                        "anonymous access; audit fungsi-level authz."),
                    file_path=None, line_start=None, line_end=None,
                    request=f"GET {path} (unauthenticated)",
                    response=f"fields: {fields} (nilai PII tidak disimpan)",
                    confidence=0.75, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="http-response",
                ))
            elif is_json:
                entry["classified"] = "json-tanpa-data-personal (bukan temuan)"
            else:
                entry["classified"] = "non-json (halaman/error)"
            probed.append(entry)

        ctx.world.note(
            f"api_surface_probe: {len(scripts)} JS, {len(paths)} path, "
            f"{len(probed)} probe, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={
            "url": url,
            "scripts_fetched": len(scripts),
            "paths_total": len(paths),
            "paths_sample": candidates[:40],
            "custom_headers": sorted(headers),
            "api_hosts": sorted(api_hosts),
            "probed": probed,
            "stopped_early": stop,
        }, findings=findings)
