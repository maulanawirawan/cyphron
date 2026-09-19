"""browser_scout — CDP headless scout untuk halaman JS-heavy (Unity U4).

Formalisasi alur yang terbukti di lapangan: browser Edge/Chrome headless
dengan ``--remote-debugging-port`` + profil terisolasi sekali-pakai, lalu
jembatan node (subprocess, WebSocket CDP) yang:

- menavigasi halaman dalam scope (GET/navigation saja dari sisi scout),
- menangkap trafik jaringan (Network domain: URL/status/method/mime/
  Set-Cookie),
- menarik DOM final (Runtime.evaluate ``outerHTML``) untuk diparse link/form
  ke world model,
- menarik cookie via ``Network.getAllCookies``.

Pagar (tanpa kompromi):
- Scope per-destination ditegakkan DI DALAM browser: semua request ke host
  di luar target diblokir via ``Fetch.requestPaused`` -> ``BlockedByClient``
  (pihak ketiga tidak pernah dihubungi).
- Bounded: max_pages 1-8 (default 5), timeout per halaman, deadline total
  subprocess, rate-limit ``ctx.throttle()`` antar halaman, budget request
  dunia dihormati.
- Authorization gate tetap memutus lewat registry (risk_tags ``active``).
- Zero-FP: temuan HANYA fakta header deterministik (atribut cookie dari
  Network.getAllCookies) berkelas posture; sisanya data/observasi.
- Graceful degrade: tanpa browser/node, engine me-return skipped (bukan
  crash) — scan lain tetap jalan.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

from .base import Tool, ToolContext, ToolResult
from .browser_engine import KEY_PATHS, _find_browser
from ..findings import Finding

_BRIDGE = Path(__file__).with_name("browser_scout_bridge.js")
_MAX_PAGES = 8
_PER_PAGE_TIMEOUT_MS = 10_000
_SETTLE_MS = 1_200
_CDP_WAIT_S = 12.0
_DOM_MAX = 2_000_000
_REQ_ACCOUNT_CAP = 25  # request same-host yang dihitung ke budget per halaman


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_cdp(port: int, deadline_s: float) -> bool:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            with urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1.5) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _cookie_findings(cookies: list[dict], page_url: str) -> list[Finding]:
    """Temuan posture DETERMINISTIK dari atribut cookie yang ditangkap."""
    out: list[Finding] = []
    for c in cookies:
        name = str(c.get("name", ""))
        if not name:
            continue
        missing = []
        if not c.get("secure"):
            missing.append("Secure")
        if not c.get("http_only"):
            missing.append("HttpOnly")
        if c.get("same_site") == "unspecified":
            missing.append("SameSite")
        if not missing:
            continue
        out.append(Finding(
            tool="browser_scout",
            title=f"Cookie '{name}' tanpa atribut {', '.join(missing)}",
            severity="low",
            description=(
                f"Cookie bersesi (domain {c.get('domain', '-')}) diverifikasi "
                f"lewat CDP Network.getAllCookies pada halaman JS-heavy "
                f"{page_url}: atribut {', '.join(missing)} tidak diset. "
                f"Cookie tanpa Secure bisa bocor lewat kanal teks-samar; "
                f"tanpa HttpOnly bisa dibaca skrip; tanpa SameSite terbuka "
                f"pada lintas-situs."),
            recommendation=(
                "Set atribut Secure; HttpOnly; dan SameSite (Lax/Strict) "
                "pada semua cookie bersesi."),
            cwe="CWE-1004",
            target_url=page_url,
            param=name,
            confidence=0.9,
            finding_class="posture",
            status="unconfirmed",
            evidence_kind="header",
        ))
    return out


class BrowserScoutTool(Tool):
    name = "browser_scout"
    description = ("CDP headless scout: DOM/trafik/cookie halaman JS-heavy "
                   "dalam scope (profil terisolasi, bounded, GET-only).")
    risk_tags = {"active"}
    source_skill = "23"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        browser = _find_browser()
        if not browser:
            ctx.world.note("browser_scout: Edge/Chrome tidak ditemukan — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-browser"})
        node = shutil.which("node")
        if not node or not _BRIDGE.exists():
            ctx.world.note("browser_scout: bridge node tidak tersedia — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-node-bridge"})

        base = str(args.get("url") or ctx.world.target).rstrip("/")
        host = _host_of(base)
        if not host:
            return ToolResult(tool=self.name, ok=False, error="target tanpa host")
        max_pages = max(1, min(int(args.get("max_pages", 5)), _MAX_PAGES))
        paths = [str(p) for p in (args.get("paths") or KEY_PATHS)]
        urls: list[str] = []
        for p in paths[:max_pages]:
            u = urljoin(base + "/", p.lstrip("/"))
            if _host_of(u) == host and u not in urls:
                urls.append(u)
        if not urls:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-in-scope-pages"})

        # budget: 1 navigation per halaman + capture same-host (diperkirakan)
        if ctx.world.request_count + len(urls) >= ctx.max_requests:
            ctx.world.note("browser_scout: budget request nyaris habis — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "budget"})

        port = _free_port()
        profile = tempfile.mkdtemp(prefix="cyphron-bscout-")
        proc = None
        try:
            proc = subprocess.Popen(
                [browser,
                 "--headless=new",
                 "--disable-gpu",
                 "--no-first-run",
                 "--no-default-browser-check",
                 "--disable-extensions",
                 f"--remote-debugging-port={port}",
                 f"--user-data-dir={profile}",
                 "--window-size=1280,1024",
                 "about:blank"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not _wait_cdp(port, _CDP_WAIT_S):
                ctx.world.note("browser_scout: CDP tidak siap (timeout) — dilewati")
                return ToolResult(tool=self.name, ok=True,
                                  data={"skipped": "cdp-timeout"})
            report = self._run_bridge(node, port, urls, host)
            return self._ingest(report, ctx, host)
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            shutil.rmtree(profile, ignore_errors=True)

    # ------------------------------------------------------------- bridge
    def _run_bridge(self, node: str, port: int, urls: list[str],
                    host: str) -> dict:
        timeout_s = (len(urls) * (_PER_PAGE_TIMEOUT_MS + _SETTLE_MS) / 1000.0) + 20.0
        completed = subprocess.run(
            [node, str(_BRIDGE),
             "--cdp-port", str(port),
             "--urls", "|".join(urls),
             "--max-pages", str(len(urls)),
             "--timeout-ms", str(_PER_PAGE_TIMEOUT_MS),
             "--settle-ms", str(_SETTLE_MS),
             "--target-host", host],
            capture_output=True, timeout=timeout_s)
        return json.loads(completed.stdout.decode("utf-8", errors="replace")
                          or "{}")

    # ------------------------------------------------------------- ingest
    def _ingest(self, report: dict, ctx: ToolContext, host: str) -> ToolResult:
        from ..world.model import Endpoint  # hindari siklus impor modul

        pages = report.get("pages", []) or []
        data = {"pages": [], "third_party_blocked": 0, "new_links": 0,
                "new_forms": 0, "cookie_findings": 0}
        findings: list[Finding] = []
        rendered = 0

        for page in pages:
            page_url = str(page.get("final_url") or page.get("url") or "")
            if _host_of(page_url) != host:
                continue  # redirect keluar scope: tidak dicatat
            rendered += 1
            status = page.get("status")
            in_scope_reqs = [r for r in page.get("requests", [])
                             if r.get("in_scope") and not r.get("failed")]
            data["third_party_blocked"] += int(page.get("third_party_blocked", 0))

            # DOM final -> endpoint link/form (parser sama dengan browser_engine)
            dom = str(page.get("dom") or "")[:_DOM_MAX]
            new_links = new_forms = 0
            if dom:
                from .crawler import _PageParser
                parser = _PageParser()
                try:
                    parser.feed(dom)
                except Exception:
                    parser = None
                if parser is not None:
                    before = len(ctx.world.endpoints)
                    for link in parser.links:
                        absolute = urljoin(page_url, link.split("#", 1)[0])
                        if (_host_of(absolute) == host
                                and absolute not in ctx.world.endpoints):
                            ctx.world.endpoints[absolute] = Endpoint(
                                url=absolute, discovered_by=self.name)
                            new_links += 1
                    for form in parser.forms:
                        action = urljoin(page_url, form["action"] or page_url)
                        if _host_of(action) == host:
                            ctx.world.observe_endpoint(
                                action, params=[], method=form["method"],
                                form_fields=form["fields"],
                                discovered_by=self.name)
                            new_forms += 1
                    if len(ctx.world.endpoints) > before:
                        ctx.world.note(
                            f"browser_scout: {page_url} membuka "
                            f"{len(ctx.world.endpoints) - before} endpoint baru")
            data["new_links"] += new_links
            data["new_forms"] += new_forms

            # halaman utama + subresource same-host -> world (hanya yang dalam scope)
            hdr_map: dict[str, dict] = {}
            for r in in_scope_reqs[:_REQ_ACCOUNT_CAP]:
                if not r.get("url"):
                    continue
                st = r.get("status")
                if st is not None:
                    hdr_map[r["url"]] = {"set-cookie": r.get("set_cookie", "")} \
                        if r.get("set_cookie") else {}
                    ctx.world.observe_endpoint(r["url"], params=[],
                                               method=r.get("method", "GET"),
                                               discovered_by=self.name)
                    ep = ctx.world.endpoints.get(r["url"])
                    if ep is not None and isinstance(st, int):
                        ep.status = st
                    ctx.world.request_count += 1

            main = page_url
            ctx.world.observe_response(
                main, status if isinstance(status, int) else None,
                hdr_map.get(main) or None, dom or None, self.name)

            cookies = [c for c in page.get("cookies", [])
                       if str(c.get("domain", "")).lstrip(".").endswith(host)]
            cookie_f = _cookie_findings(cookies, page_url)
            findings.extend(cookie_f)
            data["cookie_findings"] += len(cookie_f)

            data["pages"].append({
                "url": page_url, "status": status,
                "requests_in_scope": len(in_scope_reqs),
                "third_party_blocked": int(page.get("third_party_blocked", 0)),
                "cookies": len(cookies), "errors": page.get("errors", []),
            })
            ctx.throttle()

        for err in (report.get("errors", []) or []):
            ctx.world.note(f"browser_scout: {err}")
        ctx.world.note(
            f"browser_scout: {rendered}/{len(pages)} halaman JS-heavy dipindai "
            f"(+{data['new_links']} link, +{data['new_forms']} form, "
            f"{data['third_party_blocked']} request pihak ketiga diblokir di "
            f"dalam browser)")
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
