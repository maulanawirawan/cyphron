"""browser_engine — JS-rendered DOM capture using the browser already
installed on the machine (Edge/Chrome headless --dump-dom). Zero installs.
Bounded: a small set of key pages per run. Passive GETs only."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .base import Tool, ToolContext, ToolResult
from .crawler import _PageParser

BROWSER_CANDIDATES = [
    # chrome first: msedge.exe frequently ignores --dump-dom when another
    # instance/policy holds the profile — chrome headless is the reliable path
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]

KEY_PATHS = ["/", "/login", "/register", "/signup", "/dashboard"]


def _find_browser() -> str | None:
    for cand in BROWSER_CANDIDATES:
        if Path(cand).exists():
            return cand
    for name in ("msedge", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    return None


class BrowserEngineTool(Tool):
    name = "browser_engine"
    description = "Render key pages with headless Edge/Chrome; parse the JS-rendered DOM."
    risk_tags = {"passive"}
    source_skill = "23"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        browsers = [b for b in BROWSER_CANDIDATES if Path(b).exists()]
        if not browsers:
            ctx.world.note("browser_engine: no Edge/Chrome found — SPA rendering unavailable")
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-browser"})
        base = str(args["url"]).rstrip("/")
        host = urlparse(base).hostname or ""
        profiles = {b: tempfile.mkdtemp(prefix="cyphron-browser-") for b in browsers}
        parsed_pages = 0
        new_links = 0
        new_forms = 0
        seen_pages: list[str] = []
        used_browser = None

        def dump(browser: str, url: str) -> str:
            try:
                ctx.throttle()
                proc = subprocess.run(
                    [browser,
                     "--headless=new",
                     "--disable-gpu",
                     "--no-first-run",
                     "--no-default-browser-check",
                     "--disable-extensions",
                     f"--user-data-dir={profiles[browser]}",
                     "--virtual-time-budget=6000",
                     "--timeout=15000",
                     "--dump-dom", url],
                    capture_output=True, timeout=30)
            except (subprocess.TimeoutExpired, OSError):
                return ""
            return proc.stdout.decode("utf-8", errors="replace")

        for path in KEY_PATHS[: int(args.get("max_pages", 5))]:
            url = urljoin(base + "/", path.lstrip("/"))
            if urlparse(url).hostname != host:
                continue
            dom = ""
            for browser in browsers:  # fallback across browsers per page
                dom = dump(browser, url)
                if dom.strip():
                    used_browser = used_browser or browser
                    break
            if not dom.strip():
                ctx.world.note(f"browser_engine: {path} produced no DOM from any browser")
                continue
            seen_pages.append(path)
            ctx.world.request_count += 1
            parser = _PageParser()
            try:
                parser.feed(dom)
            except Exception:
                continue
            before = len(ctx.world.endpoints)
            for link in parser.links:
                absolute = urljoin(url, link.split("#", 1)[0])
                if urlparse(absolute).hostname == host and absolute not in ctx.world.endpoints:
                    ctx.world.endpoints[absolute] = __import__(
                        "cyphron.world.model", fromlist=["Endpoint"]).Endpoint(
                        url=absolute, discovered_by=self.name)
                    new_links += 1
            for form in parser.forms:
                action = urljoin(url, form["action"] or url)
                if urlparse(action).hostname == host:
                    ctx.world.observe_endpoint(action, params=[], method=form["method"],
                                               form_fields=form["fields"],
                                               discovered_by=self.name)
                    new_forms += 1
            parsed_pages += 1
            if len(ctx.world.endpoints) > before:
                ctx.world.note(f"browser_engine: {path} revealed {len(ctx.world.endpoints) - before} new endpoints")

        for profile in profiles.values():
            shutil.rmtree(profile, ignore_errors=True)
        ctx.world.note(f"browser_engine: rendered {parsed_pages}/{len(seen_pages)} pages "
                       f"(+{new_links} links, +{new_forms} forms) via "
                       f"{Path(used_browser).name if used_browser else 'none'}")
        return ToolResult(tool=self.name, ok=True, data={
            "browser": Path(used_browser).name if used_browser else None,
            "pages_rendered": parsed_pages,
            "new_links": new_links, "new_forms": new_forms,
        })
