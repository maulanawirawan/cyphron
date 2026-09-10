"""crawler — Cyphron's own deep crawler (html.parser): links, forms, params,
HTML comments, emails, asset fingerprints, robots.txt/sitemap.xml ingestion,
and security.txt discovery. Same-host only. Passive."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl

from . import http_engine
from .base import Tool, ToolContext, ToolResult

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
STATIC_ASSET_RE = re.compile(r'/(?:_next/static|assets?|static)/[^"\'\s>]+\.(?:js|css)')


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.comments: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "get").upper(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if not name and tag == "input" and a.get("type") in ("email", "password", "text", "tel"):
                # Next.js/React forms often omit name attributes; key on type instead
                name = f"input[type={a.get('type')}]"
            if name:
                self._form["fields"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip()[:300])


class CrawlerTool(Tool):
    name = "crawler"
    description = "Deep crawl same-host: endpoints, forms, params, comments, emails, sitemap."
    risk_tags = {"passive"}
    source_skill = "02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        max_pages = int(args.get("max_pages", 15))
        host = urlparse(base).hostname or ""
        queue: list[str] = [base + "/"]
        seen: set[str] = set()
        pages_fetched = 0
        forms_found = 0
        comments: list[str] = []
        emails: set[str] = set()
        assets: list[str] = []

        # --- lead ingestion: robots.txt + sitemap.xml (same host only) ---
        robots_status, _h, robots_body, _ms = http_engine.http_get(
            base + "/robots.txt", timeout=ctx.timeout_s)
        ctx.world.observe_response(base + "/robots.txt", robots_status, _h, robots_body, self.name)
        if robots_status == 200:
            for line in (robots_body or "").splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        queue.append(urljoin(base + "/", path))
                elif line.lower().startswith("sitemap:"):
                    queue.append(line.split(":", 1)[1].strip())
        else:
            ctx.world.note("robots.txt not present (404)")

        sm_status, _h, sm_body, _ms = http_engine.http_get(
            base + "/sitemap.xml", timeout=ctx.timeout_s)
        ctx.world.observe_response(base + "/sitemap.xml", sm_status, _h, sm_body, self.name)
        if sm_status == 200 and "<loc>" in (sm_body or ""):
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm_body)[:80]:
                if urlparse(loc).hostname == host:
                    queue.append(loc)
            ctx.world.note(f"sitemap.xml ingested ({sm_body.count('<loc>')} urls)")

        # --- main walk ---
        while queue and pages_fetched < max_pages:
            url = queue.pop(0)
            norm = url.split("#", 1)[0]
            if not norm or norm in seen:
                continue
            if urlparse(norm).hostname != host:
                continue
            if norm.startswith("mailto:"):
                continue
            seen.add(norm)
            status, _headers, body, _ms = http_engine.http_get(norm, timeout=ctx.timeout_s)
            ctx.world.observe_response(norm, status, _headers, body, self.name)
            pages_fetched += 1
            if status >= 400 or not body:
                continue
            parser = _PageParser()
            parser.feed(body)
            for link in parser.links:
                absolute = urljoin(norm, link.split("#", 1)[0])
                if any(k in absolute.lower() for k in ("logout", "signout", "sign-out")):
                    continue  # never kill the grey-box session
                if urlparse(absolute).hostname == host and absolute not in seen:
                    queue.append(absolute)
            for form in parser.forms:
                action = urljoin(norm, form["action"] or norm)
                if urlparse(action).hostname == host:
                    ctx.world.observe_endpoint(
                        action, params=[], method=form["method"],
                        form_fields=form["fields"], discovered_by=self.name)
                    forms_found += 1
            if "?" in norm:
                params = [k for k, _ in parse_qsl(urlparse(norm).query)]
                ctx.world.observe_endpoint(norm, params=params, discovered_by=self.name)
            for c in parser.comments:
                if len(comments) < 12 and len(c) > 8:
                    comments.append(c)
            for m in EMAIL_RE.findall(body):
                if not m.endswith(("example.com", "w3.org", "sentry.io")):
                    emails.add(m)
            for a in STATIC_ASSET_RE.findall(body)[:3]:
                if a not in assets and len(assets) < 6:
                    assets.append(a)

        for c in comments:
            ctx.world.note(f"HTML comment: {c[:180]}")
        if emails:
            ctx.world.note(f"emails found: {', '.join(sorted(emails)[:8])}")
        if assets:
            ctx.world.note(f"static assets fingerprinted: {assets[0]}")

        sec_status, _h, sec_body, _ms = http_engine.http_get(
            base + "/.well-known/security.txt", timeout=ctx.timeout_s)
        ctx.world.observe_response(base + "/.well-known/security.txt", sec_status, _h, sec_body, self.name)
        if sec_status != 200:
            ctx.world.note("security.txt (RFC 9116) not present")

        ctx.world.note(f"crawler visited {pages_fetched} pages, {forms_found} forms, "
                       f"{len(seen)} unique URLs queued")
        return ToolResult(tool=self.name, ok=True, data={
            "pages": pages_fetched, "forms": forms_found, "unique": len(seen),
            "comments": comments[:8], "emails": sorted(emails)[:8], "assets": assets,
        })
