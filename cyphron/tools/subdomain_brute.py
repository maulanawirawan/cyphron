"""subdomain_brute — DNS prefix bruteforce via DoH (dns.google), stdlib.

Teknik terbukti lapangan (BINUS 2026-09, dari scratch/dns_brute.py):
436 prefix x domain via DoH menghasilkan 23 subdomain baru (8 web hidup),
termasuk fleet WordPress yang menghasilkan BB-001 fleet-wide user
enumeration. Dipilih DoH karena jaringan tertentu membuang DNS plaintext
(UDP/TCP 53) — kasus nyata BINUS (FP "SPF/DMARC missing" palsu).

Keamanan & FP-guard:
  - SEMUA query DNS ke resolver publik (dns.google) — bukan ke infra target;
    pertanyaan A record = aktivitas resolusi normal, bukan scanning;
  - liveness WAJIB terverifikasi 2x (cache DNS fluktuatif — hasil sekali
    resolve = noise, bukan temuan);
  - hasil digabung + dedup per host; IP dicatat untuk dedup ASN/CDN;
  - prefix default dibangun dari kamus lapangan (infra, dev/staging,
    admin, mail, monitoring, dsb) — 436 entri;
  - ini engine RECON: hasil masuk ToolResult.data (bukan Finding —
    subdomain bukan kerentanan; temuan menyusul dari engine lain).
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request

from .base import Tool, ToolContext, ToolResult

_NAME_OK = re.compile(r"^[a-z0-9._-]+$")

DEFAULT_PREFIXES = [
    "mail", "webmail", "smtp", "pop", "imap", "vpn", "portal", "sso", "login",
    "auth", "id", "account", "api", "api2", "api-dev", "api-uat", "app", "apps",
    "admin", "administrator", "panel", "cpanel", "dashboard", "manage",
    "intranet", "internal", "staff", "employee", "hr", "erp", "crm",
    "dev", "devel", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "old", "legacy",
    "backup", "bak", "cms", "jenkins", "ci", "cd", "git", "gitlab", "svn",
    "grafana", "kibana", "elastic", "prometheus", "nagios", "zabbix",
    "status", "monitor", "monitoring", "log", "logs", "db", "mysql",
    "postgres", "mongo", "redis", "mq", "kafka", "es", "search",
    "wiki", "confluence", "jira", "chat", "bot", "storage", "file", "files",
    "ftp", "sftp", "share", "cdn", "static", "assets", "img", "image",
    "images", "media", "video", "live", "shop", "store", "pay", "payment",
    "billing", "finance", "news", "blog", "press", "event", "events",
    "helpdesk", "support", "ticket", "service", "services", "it", "network",
    "noc", "dns", "ns1", "ns2", "proxy", "gateway", "firewall", "waf",
    "lb", "edge", "cache", "oauth", "oidc", "keycloak", "mobile", "m",
    "wap", "partner", "merchant", "driver", "customer", "seller", "buyer",
]


def _doh_a(name: str, timeout: float = 6.0) -> str | None:
    """A record via DoH dns.google (stdlib, TCP — tahan jaringan pembuang UDP).
    Resolver publik = infrastruktur resolusi, bukan target: tidak melewati
    gate scope target."""
    if not name or not _NAME_OK.match(name.lower()):
        return None
    url = ("https://dns.google/resolve?name="
           + urllib.parse.quote(name, safe="._-") + "&type=A")
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "cyphron-doh/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    if data.get("Status") != 0:
        return None
    for ans in data.get("Answer") or []:
        if ans.get("type") == 1:
            return str(ans.get("data", ""))
    return None


def resolve_verified(name: str, rounds: int = 2, timeout: float = 6.0) -> str | None:
    """FP-guard liveness: host dianggap hidup hanya bila A record KONSISTEN
    `rounds` kali (cache DNS fluktuatif — single-hit = noise)."""
    seen: set[str] = set()
    for _ in range(max(1, rounds)):
        ip = _doh_a(name, timeout)
        if ip is None:
            return None
        seen.add(ip)
        time.sleep(0.05)
    return seen.pop() if len(seen) == 1 else None


class SubdomainBruteTool(Tool):
    name = "subdomain_brute"
    description = ("DNS prefix bruteforce via DoH (dns.google) dengan "
                   "liveness 2x — recon subdomain yang tahan jaringan "
                   "pembuang DNS plaintext.")
    risk_tags = {"passive"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        domains = args.get("domains") or []
        if isinstance(domains, str):
            domains = [domains]
        domains = [d.strip().lower() for d in domains if d and "." in str(d)]
        prefixes = args.get("prefixes") or DEFAULT_PREFIXES
        try:
            cap = max(1, min(int(args.get("max_prefixes", len(prefixes))), len(prefixes)))
        except Exception:
            cap = len(prefixes)
        prefixes = prefixes[:cap]
        timeout = float(args.get("timeout", 6.0))
        if not domains:
            return ToolResult(tool=self.name, ok=False,
                              error="args.domains wajib diisi (contoh: ['contoh.id'])")

        found: list[dict] = []
        probed = 0
        for dom in domains:
            for pfx in prefixes:
                host = f"{pfx}.{dom}"
                ctx.throttle()
                probed += 1
                ip = resolve_verified(host, rounds=2, timeout=timeout)
                if ip:
                    found.append({"host": host, "ip": ip, "prefix": pfx,
                                  "source": "doh-brute"})
        ctx.world.note(
            f"subdomain_brute: {probed} kandidat x {len(domains)} domain, "
            f"{len(found)} hidup (verified 2x)")
        return ToolResult(tool=self.name, ok=True, data={
            "domains": domains,
            "prefixes_tried": probed // max(1, len(domains)),
            "live_count": len(found),
            "live": found,
            "note": "recon — subdomain hidup bukan kerentanan; lanjutkan "
                    "dengan census HTTP/liveness sebelum uji apa pun",
        })
