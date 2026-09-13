"""passive_dns — census subdomain pasif via OTX (AlienVault) + verifikasi DoH.

Teknik terbukti lapangan (Gojek/DANA/GoTo Financial census 2026-09-13):
kombinasi OTX passive DNS + verifikasi A-record via DoH menghasilkan 819
nama untuk Gojek (199 live) dan 298 untuk GoTo Financial (182 live) —
semuanya NOL trafik ke infra target (query hanya ke OTX/dns.google).

Keamanan & FP-guard:
  - sumber = layanan intel publik (otx.alienvault.com, dns.google);
    infra target TIDAK disentuh sama sekali (patuh aturan program
    "no automated scanners" yang mengatur trafik ke target);
  - liveness = A record via DoH, konsisten 2x (cache fluktuatif);
  - klasifikasi staging eksplisit: host yang cocok pola staging Ditandai
    OUT-OF-SCOPE (pelajaran Gojek: "staging indicated by test/integration/
    staging etc" — termasuk varian stg/sbx yang sering lolos regex);
  - hasil = recon (ToolResult.data), bukan Finding;
  - rate sopan + throttle ctx.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request

from .base import Tool, ToolContext, ToolResult

_STAGING = re.compile(
    r"(^|[-.])(test|testing|integration|staging|stage|dev|devel|development"
    r"|uat|qa|sandbox|demo|preprod|pre|alpha|stg|sbx|mock|mocks)([-.])", re.I)
_UA = {"Accept": "application/json", "User-Agent": "cyphron-passivedns/1.0"}


def _http_json(url: str, timeout: float = 30.0):
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def otx_hostnames(domain: str, timeout: float = 30.0) -> set[str]:
    """Hostname historis untuk domain dari OTX passive DNS (publik)."""
    try:
        d = _http_json(
            "https://otx.alienvault.com/api/v1/indicators/domain/"
            + urllib.parse.quote(domain, safe=".") + "/passive_dns", timeout)
    except Exception:
        return set()
    out = set()
    for rec in d.get("passive_dns") or []:
        n = (rec.get("hostname") or "").lower().lstrip("*.")
        if n.endswith(domain):
            out.add(n)
    return out


def _doh_a(name: str, timeout: float = 6.0) -> str | None:
    url = ("https://dns.google/resolve?name="
           + urllib.parse.quote(name, safe="._-") + "&type=A")
    try:
        req = urllib.request.Request(url, headers=_UA)
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


def resolve_verified(name: str, rounds: int = 2, timeout: float = 6.0):
    seen: set[str] = set()
    for _ in range(max(1, rounds)):
        ip = _doh_a(name, timeout)
        if ip is None:
            return None
        seen.add(ip)
        time.sleep(0.05)
    return seen.pop() if len(seen) == 1 else None


class PassiveDnsTool(Tool):
    name = "passive_dns"
    description = ("Census subdomain pasif via OTX + verifikasi DoH 2x + "
                   "klasifikasi staging — nol trafik ke infra target.")
    risk_tags = {"passive"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        domains = args.get("domains") or []
        if isinstance(domains, str):
            domains = [domains]
        domains = [d.strip().lower() for d in domains if d and "." in str(d)]
        if not domains:
            return ToolResult(tool=self.name, ok=False,
                              error="args.domains wajib diisi")
        timeout = float(args.get("timeout", 30.0))
        names: dict[str, dict] = {}
        for dom in domains:
            ctx.throttle()
            for n in otx_hostnames(dom, timeout):
                names.setdefault(n, {"domain": dom, "sources": ["otx"]})
        live: dict[str, str] = {}
        for n in sorted(names):
            ctx.throttle()
            ip = resolve_verified(n, rounds=2)
            if ip:
                live[n] = ip
        live_in_scope: list[dict] = []
        staging: list[str] = []
        for n, ip in live.items():
            if _STAGING.search(n):
                staging.append(n)
            else:
                live_in_scope.append({"host": n, "ip": ip})
        ctx.world.note(
            f"passive_dns: {len(names)} nama dari OTX, {len(live)} live, "
            f"{len(staging)} flag staging")
        return ToolResult(tool=self.name, ok=True, data={
            "domains": domains,
            "names_total": len(names),
            "live_total": len(live),
            "live_in_scope": live_in_scope,
            "staging_flagged": staging,
            "note": "recon — verifikasi scope program sebelum menyentuh "
                    "host mana pun; host staging = out-of-scope umum program",
        })
