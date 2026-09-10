"""liveness_probe — precision layer: app-liveness classification (2026-09-08).

Menjawab kasus lapangan "nginx live != app live": host terlihat hidup (DNS
resolve, TLS valid, server merespons) padahal aplikasi di belakangnya sudah
dihapus. Engine ini memisahkan empat lapis liveness dan menulis SEMUANYA
eksplisit di data temuan:

  1. host liveness      - DNS/HTTP merespons (terukur, objektif)
  2. server fingerprint - header Server/X-Powered-By/X-Generator
  3. application liveness - fingerprint framework/formulir/konten diharapkan
  4. backend liveness   - TIDAK dapat dikonfirmasi dari luar; tidak pernah diklaim

FP-guard (wajib sebelum predikat "stale"):
  - minimal 1 respons HTTP sukses (2xx/3xx) dari host; tanpa itu tidak ada
    kesimpulan apa pun,
  - fingerprint aplikasi dicek dulu (world model crawler + N path umum +
    baseline) sebelum menyimpulkan,
  - halaman login/formulir dihitung APLIKASI HIDUP (bukan "app tidak ada"),
  - predikat HANYA "app fingerprint not established" - bukan klaim backend
    mati (backend liveness tidak teramati dari black-box).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# Halaman default/blank web server: sinyal kuat tidak ada aplikasi di belakangnya.
_DEFAULT_PAGE_MARKERS = (
    "welcome to nginx", "it works!", "apache2 default page",
    "welcome to apache", "internet information services",
    "iis windows server", "test page for the http server",
    "this page is used to test the proper operation",
)

# Marker framework/konten aplikasi: salah satu saja = aplikasi hidup.
_APP_MARKERS = (
    "__next_data__", "/_next/static", "wp-content", "wp-json",
    'id="root"', "id='root'", 'id="app"', "id='app'",
    "ng-version", "data-reactroot", "<form", "csrf",
    "laravel_session", "django", "js/chunk", "assets/index",
)

_APP_PATHS = ("/login", "/signin", "/api", "/api/v1", "/home",
              "/dashboard", "/index.php", "/admin", "/status", "/health")
_MAX_PATH_CHECKS = 6


def _app_markers_in(body: str) -> str | None:
    low = (body or "").lower()
    for m in _APP_MARKERS:
        if m in low:
            return m
    return None


def _default_page_in(body: str) -> bool:
    low = (body or "").lower()
    if any(m in low for m in _DEFAULT_PAGE_MARKERS):
        return True
    # halaman generik: body nyaris kosong tanpa marker aplikasi apa pun
    return len((body or "").strip()) < 120


class LivenessProbeTool(Tool):
    name = "liveness_probe"
    description = ("Klasifikasi 4 lapis liveness: host vs server vs aplikasi vs "
                   "backend. Kandidat 'stale/orphaned surface' bila server hidup "
                   "tetapi fingerprint aplikasi tidak terbentuk.")
    risk_tags = {"active"}
    source_skill = "t2-low-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        layers = {"host": "unknown", "server": "", "app": "unknown",
                  "backend": "unverifiable-from-outside"}
        try:
            ctx.throttle()
            st, hd, body, _ms = http_engine.http_get(base, timeout=ctx.timeout_s)
        except Exception as exc:
            ctx.world.note(f"liveness_probe: host {host} tidak merespons "
                           f"({type(exc).__name__}) - liveness tidak dinilai")
            return ToolResult(tool=self.name, ok=True, data={"host_liveness": "down"})
        ctx.world.observe_response(base, st, hd, body, self.name)
        ctx.world.request_count += 1
        # FP-guard 1: minimal satu respons sukses sebelum kesimpulan apa pun.
        if not isinstance(st, int) or st >= 400:
            ctx.world.note(f"liveness_probe: host {host} tidak memberi respons "
                           f"sukses (status {st}) - liveness tidak dinilai")
            return ToolResult(tool=self.name, ok=True,
                              data={"host_liveness": "no-success-response"})
        layers["host"] = f"responsive (HTTP {st})"

        # LAPIS 2: server fingerprint dari header + world model.
        server_bits = []
        for name, val in (hd or {}).items():
            if name.lower() in ("server", "x-powered-by", "x-generator"):
                server_bits.append(f"{name}: {val}")
        for key in ctx.world.technologies:
            if key.lower().startswith(("server:", "x-powered-by:", "generator:")):
                if key not in server_bits:
                    server_bits.append(key)
        layers["server"] = "; ".join(server_bits[:3]) or "tidak ada header server"

        # LAPIS 3: application liveness - FP-guard 2: cek fingerprint dulu.
        app_evidence: list[str] = []
        # (a) world model: crawler/browser sudah melihat interaksi aplikasi
        if any(e.form_fields for e in ctx.world.endpoints.values()):
            app_evidence.append("formulir teramati crawler di world model")
        if ctx.world.has_param(("q", "search", "id", "page")):
            app_evidence.append("endpoint berparameter teramati (app interaktif)")
        for key in ctx.world.technologies:
            if key.lower().startswith("generator:") or "framework" in key.lower():
                app_evidence.append(f"teknologi aplikasi: {key}")
        bodies: list[tuple[str, str]] = [(base, body or "")]
        if _app_markers_in(body or ""):
            app_evidence.append(f"marker aplikasi pada halaman utama "
                                f"({_app_markers_in(body or '')})")
        # (b) FP-guard 3: halaman login = aplikasi hidup (cek path umum).
        checked_paths: list[str] = []
        default_seen = _default_page_in(body or "")
        for path in _APP_PATHS:
            if len(checked_paths) >= _MAX_PATH_CHECKS:
                break
            if path in {urlsplit(e.url).path for e in ctx.world.endpoints.values()
                        if e.status and e.status < 400}:
                # sudah teramati hidup oleh crawler: cukup satu pengecekan langsung
                pass
            probe_url = urljoin(base + "/", path.lstrip("/"))
            try:
                ctx.throttle()
                pst, _ph, pbody, _m = http_engine.http_get(probe_url,
                                                           timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.request_count += 1
            checked_paths.append(f"{path}={pst}")
            if not isinstance(pst, int) or pst >= 400 or not pbody:
                continue
            bodies.append((probe_url, pbody))
            marker = _app_markers_in(pbody)
            if marker:
                app_evidence.append(f"marker aplikasi di {path} ({marker})")
            if "<form" in pbody.lower():
                app_evidence.append(f"formulir HTML di {path} (halaman login/app hidup)")
            if _default_page_in(pbody):
                default_seen = True
        # (c) JSON API yang menjawab = aplikasi hidup
        for probe_url, pbody in bodies:
            if (pbody or "").lstrip().startswith(("{", "[")) and len(pbody) > 20:
                app_evidence.append(f"respons JSON API di {probe_url}")
                break

        layers["app"] = ("established (" + "; ".join(sorted(set(app_evidence))[:3]) + ")"
                         if app_evidence else "not established")
        if app_evidence:
            ctx.world.note(f"liveness_probe: {host} - fingerprint aplikasi TERBENTUK "
                           f"({len(app_evidence)} bukti); bukan kandidat stale")
            return ToolResult(tool=self.name, ok=True,
                              data={"layers": layers,
                                    "app_evidence": sorted(set(app_evidence))[:6]})

        # Predikat: app fingerprint not established (kandidat stale/orphaned).
        sev = "low" if default_seen else "info"
        conf = 0.75 if default_seen else 0.55
        default_note = (" Halaman default/generik web server terdeteksi pada "
                        "respons." if default_seen else "")
        layers_text = (f"LAPIS 1 host liveness: AKTIF - {host} merespons "
                       f"({layers['host']}). LAPIS 2 server fingerprint: "
                       f"{layers['server']}. LAPIS 3 application liveness: TIDAK "
                       f"TERBENTUK - fingerprint aplikasi (framework, formulir, "
                       f"konten diharapkan) tidak teramati setelah baseline + "
                       f"{len(checked_paths)} path umum dicek "
                       f"({'; '.join(checked_paths) or 'tidak ada yang bisa dicek'})"
                       f".{default_note} LAPIS 4 backend liveness: TIDAK DAPAT "
                       f"DIKONFIRMASI dari pengujian eksternal dan tidak diklaim. "
                       f"Predikat temuan hanya 'app fingerprint not established' - "
                       f"bukan klaim backend mati.")
        finding = Finding(
            tool=self.name,
            title=(f"Stale/orphaned surface candidate: {host} (server hidup, "
                   f"fingerprint aplikasi tidak terbentuk)"),
            severity=sev, cwe=None,
            description=(f"Server merespons tetapi fingerprint aplikasi tidak "
                         f"terbentuk. {layers_text} Kandidat surface tidak "
                         f"terkelola: server tanpa aplikasi tetap menambah attack "
                         f"surface (pemeliharaan sertifikat, patching, eksposur). "
                         f"Status: KANDIDAT - perlu konfirmasi pemilik sebelum "
                         f"dinyatakan stale."),
            recommendation=("Konfirmasi ke pemilik apakah vhost masih dipakai. "
                            "Bila aplikasinya memang sudah dihapus: matikan vhost "
                            "di web server dan hapus/arahkan ulang record DNS, "
                            "sehingga tidak ada server tanpa aplikasi yang "
                            "terekspos publik."),
            target_url=base,
            request=f"GET baseline + {len(checked_paths)} path umum",
            response=(f"layers: host={layers['host']}; server={layers['server']}; "
                      f"app=not established; backend=unverifiable-from-outside; "
                      f"paths: {'; '.join(checked_paths)}"),
            confidence=conf, source_skill=self.source_skill,
            status="unconfirmed", evidence_kind="baseline-diff",
            finding_class="surface")
        ctx.world.note(f"liveness_probe: {host} - server hidup, fingerprint "
                       f"aplikasi TIDAK terbentuk -> kandidat stale/orphaned surface")
        return ToolResult(tool=self.name, ok=True,
                          data={"layers": layers, "paths": checked_paths},
                          findings=[finding])
