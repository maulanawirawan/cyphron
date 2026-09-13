"""admin_panel — management console exposure fingerprint (HIGH).

Pelajaran lapangan (2026-09, UMS): konsol manajemen yang terjangkau publik
(Keycloak Administration Console, Gitea, UniFi Network) ditemukan cukup dari
judul halaman — satu GET per fingerprint. Engine ini memfingerprint panel
manajemen populer lewat judul/marker, lalu melaporkan exposure.

FP-guard:
  - fingerprint WAJIB unik per produk (judul/marker spesifik, bukan kata
    generik "admin"/"login");
  - path yang 401/403 = TERPROTEKSI (bukan temuan — malah catatan positif);
  - halaman publik memang disengaja (mis. portal perizinan) tidak termasuk
    daftar fingerprint.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# (path, fingerprint regex pada body, nama produk)
FINGERPRINTS = (
    ("/admin/master/console/", r"Keycloak", "Keycloak Admin Console"),
    ("/admin/", r"Keycloak", "Keycloak Admin Console"),
    ("/login", r"<title>[^<]*Jenkins", "Jenkins CI"),
    ("/whoAmI/", r'"authenticatedUser"', "Jenkins CI"),
    ("/login", r"Grafana", "Grafana Dashboard"),
    ("/api/health", r'"database"\s*:\s*"ok"', "Grafana API"),
    ("/app/kibana", r"Kibana", "Kibana"),
    ("/api/status", r'"name"\s*:', "Kibana API"),
    ("/manager/html", r"Tomcat Web Application Manager", "Tomcat Manager"),
    ("/browser/", r"pgAdmin", "pgAdmin"),
    ("/#/login", r"Portainer", "Portainer"),
    ("/sessions/new", r"SonarQube", "SonarQube"),
    ("/admin/airflow/login", r"Airflow", "Apache Airflow"),
    ("/graph", r"Prometheus", "Prometheus"),
    ("/login", r"UniFi Network", "UniFi Network Controller"),
    ("/api/session/properties", r'"setupAllowed"', "Metabase"),
)


class AdminPanelTool(Tool):
    name = "admin_panel"
    description = ("Management console exposure fingerprinting (Keycloak/Jenkins/"
                   "Grafana/Kibana/Tomcat/pgAdmin/UniFi/dll) — GET-only, "
                   "fingerprints spesifik, 401/403 = terproteksi.")
    risk_tags = {"active"}
    source_skill = "manual-bb-15"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        data: dict = {"host": host, "probed": []}
        findings: list[Finding] = []
        seen_products: set[str] = set()

        for path, pattern, product in FINGERPRINTS:
            if product in seen_products:
                continue
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    urljoin(base + "/", path.lstrip("/")), timeout=ctx.timeout_s,
                    follow_redirects=False)
            except Exception as e:
                data["probed"].append({"path": path, "error": type(e).__name__})
                continue
            ctx.world.request_count += 1
            # FP-guard: redirect/catch-all tidak dihitung exposed (lapangan
            # 2026-09: SPA fallback/cross-vhost memuat kata fingerprint)
            if not isinstance(st, int) or st in (301, 302, 303, 307, 308, 401,
                                                 403, 404):
                data["probed"].append({"path": path, "status": st,
                                       "product": product,
                                       "protected": st in (401, 403)})
                continue
            title_m = re.search(r"<title[^>]*>([^<]{1,120})", body or "", re.I)
            title = title_m.group(1) if title_m else ""
            hit = bool(re.search(pattern, title, re.I)) or                 bool(re.search(pattern, (body or "")[:2000], re.I))
            data["probed"].append({"path": path, "status": st,
                                   "product": product, "exposed": hit})
            if hit:
                seen_products.add(product)
                ctx.world.note(f"admin_panel: {product} terjangkau publik di {host}")
                findings.append(Finding(
                    tool=self.name,
                    title=f"Management console exposed publicly: {product} on {host}{path}",
                    severity="high", cwe="CWE-284",
                    description=(
                        f"Konsol manajemen {product} dapat dijangkau dari internet "
                        f"tanpa autentikasi jaringan (halaman merespons HTTP {st} "
                        f"dengan fingerprint spesifik '{product}'). Konsol "
                        f"manajemen adalah titik kendali infrastruktur/aplikasi — "
                        f"terjangkaunya publik memperluas permukaan credential "
                        f"attack dan exploit CVE terkait produk. Verifikasi: buka "
                        f"{urljoin(base + '/', path.lstrip('/'))} di browser."),
                    recommendation=(
                        f"Batasi akses {product} ke jaringan kampus/VPN (IP "
                        f"allowlist / Cloudflare Access), aktifkan 2FA, dan "
                        f"perbarui ke versi terbaru."),
                    target_url=base,
                    request=f"GET {path}",
                    response=f"HTTP {st}; fingerprint '{product}' ditemukan",
                    confidence=0.95, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="header"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
