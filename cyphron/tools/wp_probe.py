"""wp_probe — WordPress hardening check: REST user enumeration & friends.

Teknik dari lapangan (2026-09): /wp-json/wp/v2/users yang merespons
200 dengan array user (slug = username login) memungkinkan panenan username
untuk credential attack + phishing tertarget.

FP-guard (wajib sebelum predikat "user enumeration"):
  - respons WAJIB JSON array (diawali '[') dan memuat field '"slug"';
  - halaman HTML soft-404 / konten non-JSON TIDAK dihitung;
  - nama user di evidence DIREDAKSI (2 huruf pertama + '***') — data pihak
    ketiga tidak di-dump ke laporan;
  - xmlrpc.php 200 saja BUKAN temuan (info); debug.log butuh marker PHP.

Pemeriksaan (maks 4 request):
  1. GET /wp-json/wp/v2/users            -> enumeration (primary)
  2. GET /?rest_route=/wp/v2/users       -> bypass permalinks (bila #1 gagal)
  3. GET /wp-content/debug.log           -> log exposure (marker PHP)
  4. GET /xmlrpc.php                     -> posture note (bukan temuan)
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_USERS_JSON = re.compile(r"^\s*\[")
_SLUG = re.compile(r'"slug"\s*:\s*"([^"]*)"')
_PHP_LOG = re.compile(r"PHP (Notice|Warning|Fatal error|Parse error)")
_XMLRPC = re.compile(r"XML-RPC server accepts POST requests", re.I)


def _redact_name(name: str) -> str:
    return (name[:2] + "***" + name[-1]) if len(name) > 3 else "***"


class WpProbeTool(Tool):
    name = "wp_probe"
    description = ("WordPress hardening check: REST user enumeration (2 path), "
                   "debug.log exposure, xmlrpc posture. JSON-slug guard wajib.")
    risk_tags = {"active", "external"}
    source_skill = "manual-bb-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        findings: list[Finding] = []
        data: dict = {"host": host}
        users_path = "/wp-json/wp/v2/users"

        def _fetch(path: str, max_body: int = 120_000, follow: bool = True):
            ctx.throttle()
            st, hd, body, _ms = http_engine.http_get(urljoin(base + "/", path.lstrip("/")),
                                                     timeout=ctx.timeout_s,
                                                     max_body=max_body,
                                                     follow_redirects=follow)
            ctx.world.request_count += 1
            if isinstance(st, int) and st < 500:
                ctx.world.observe_response(urljoin(base + "/", path.lstrip("/")),
                                           st, hd, body, self.name)
            return st, body or "", hd or {}

        def _fetch_same_host(path: str, max_body: int = 120_000):
            """Fetch yang menolak mengatribusikan respons dari host lain.
            FP lapangan 2026-09: host redirect 302 ke WP lain — temuan
            user-enum "milik" host tujuan redirect, bukan target."""
            st, body, hd = _fetch(path, max_body, follow=False)
            if isinstance(st, int) and st in (301, 302, 303, 307, 308):
                loc = ""
                for k, v in (hd or {}).items():
                    if k.lower() == "location":
                        loc = v or ""
                        break
                target_host = urlsplit(urljoin(base + "/", loc)).hostname
                if target_host and target_host != host:
                    ctx.world.note(f"wp_probe: {host}{path} redirect ke host lain "
                                   f"({target_host}) — tidak diatribusikan ke target")
                    data["redirected_to_other_host"] = target_host
                    return None, ""
                return _fetch(urljoin(base + "/", loc), max_body, follow=True)[:2]
            return st, body

        # 1. primary path
        st, body = _fetch_same_host(users_path)
        enumerated = bool(isinstance(st, int) and st == 200
                          and _USERS_JSON.match(body) and _SLUG.search(body))
        # 2. bypass path bila primary tidak jelas
        via_bypass = False
        if not enumerated and (st is None or st in (400, 404) or not _SLUG.search(body)):
            st2, body2 = _fetch_same_host("/?rest_route=/wp/v2/users")
            if isinstance(st2, int) and st2 == 200 and _USERS_JSON.match(body2) \
                    and _SLUG.search(body2):
                enumerated, via_bypass, st, body = True, True, st2, body2

        if enumerated:
            slugs = _SLUG.findall(body)
            data["wp_users"] = {"count": len(slugs), "path": "?rest_route=" if via_bypass
                                else users_path}
            sample = "; ".join(_redact_name(s) for s in slugs[:4])
            findings.append(Finding(
                tool=self.name,
                title=(f"WordPress REST API user enumeration on {host} "
                       f"({len(slugs)} users, {'?rest_route= bypass' if via_bypass else 'wp-json'})"),
                severity="medium", cwe="CWE-200",
                description=(
                    f"{users_path if not via_bypass else '/?rest_route=/wp/v2/users'} pada "
                    f"{host} merespons HTTP 200 tanpa autentikasi dengan daftar lengkap "
                    f"user terdaftar ({len(slugs)} akun) termasuk display name dan field "
                    f"'slug' yang pada WordPress identik dengan username login. "
                    f"wp-login.php yang dapat dijangkau publik menjadikan daftar ini "
                    f"bahan langsung credential attack dan phishing tertarget. "
                    f"Contoh (teredaksi): {sample}. Nama lengkap tidak di-dump."),
                recommendation=(
                    "Blokir /wp-json/wp/v2/users untuk request tanpa otentikasi "
                    "(filter rest_endpoints atau plugin disable user enumeration), "
                    "tutup bypass ?rest_route= dengan aturan yang sama, dan tambahkan "
                    "rate-limit/lockout pada wp-login.php."),
                target_url=host, request=f"GET {users_path} (tanpa auth)",
                response=f"HTTP 200; {len(slugs)} user; fields: id/name/slug (teredaksi)",
                poc=f"curl -s https://{host}{users_path}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        elif isinstance(st, int) and st in (401, 403):
            data["wp_users"] = f"protected (HTTP {st})"
            ctx.world.note(f"wp_probe: REST users terproteksi di {host} (HTTP {st})")
        else:
            data["wp_users"] = "not-applicable / not-wordpress"

        # 3. debug.log exposure
        st3, body3, _hd3 = _fetch("/wp-content/debug.log", 60_000)
        if isinstance(st3, int) and st3 == 200 and _PHP_LOG.search(body3):
            findings.append(Finding(
                tool=self.name,
                title=f"WordPress debug.log exposed publicly on {host}",
                severity="medium", cwe="CWE-532",
                description=("wp-content/debug.log dapat diakses publik dan berisi "
                             "log error PHP (path internal, query, kadang data). "
                             "WP_DEBUG seharusnya mati di produksi dan log tidak "
                             "boleh dilayani web server."),
                recommendation="Set WP_DEBUG=false, hapus debug.log, blok akses web ke *.log.",
                target_url=host, request="GET /wp-content/debug.log",
                response=f"HTTP 200; marker: {_PHP_LOG.search(body3).group(0)}",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        else:
            data["debug_log"] = f"not-exposed (HTTP {st3})"

        # 4. xmlrpc posture (info saja - bukan temuan)
        st4, body4, _hd4 = _fetch("/xmlrpc.php", 20_000)
        data["xmlrpc"] = (f"open (HTTP {st4})"
                          if isinstance(st4, int) and st4 == 200 and _XMLRPC.search(body4)
                          else f"blocked/absent (HTTP {st4})")

        ctx.world.note(f"wp_probe: {host} users={data.get('wp_users')} "
                       f"debuglog={data.get('debug_log', 'n/a')}")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
