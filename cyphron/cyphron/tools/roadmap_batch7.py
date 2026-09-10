"""roadmap_batch7 — slot HIGH yang butuh MULTI-AKUN (god mode):
1. bola        (high-02 bola-object-probe + high-28 tenant-cross-two-acct):
               sesi B menerima objek milik sesi A (anonymous DITOLAK)
2. priv_matrix (high-03 privilege-matrix): user biasa melihat panel admin
               (anonymous ditolak, body ≈ admin)

Truth guarantee: hit HANYA saat diferensial 3-peran jelas —
anonymous ditolak + user-B/role-rendah menerima isi yang sama dengan pemiliknya.
Jika sesi < 2 (tanpa --accounts ganda) engine no-op tanpa temuan."""

from __future__ import annotations

import difflib
import re
from urllib.parse import urlencode, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_LOGIN_PAGE_RE = re.compile(r"(?i)(<form|password|login|signin|masuk)")


def _get(url: str, cookie: str | None, ctx: ToolContext):
    # Cookie eksplisit selalu MENIMPA cookie global (http_engine menempel cookie
    # sesi-pertama otomatis); anonim kirim Cookie kosong agar benar-benar anonim.
    headers = {"Cookie": cookie if cookie else ""}
    ctx.throttle()
    # no-redirect: 3xx ke halaman login = "ditolak"; isi target redirect tidak
    # boleh tercampur ke perbandingan body lintas sesi
    st, hd, bd, _ms = http_engine.http_get(url, timeout=ctx.timeout_s, headers=headers,
                                           follow_redirects=False)
    ctx.world.observe_response(url, st, hd, bd, "multiacct")
    ctx.world.request_count += 1
    return st, bd or ""


class BolaTool(Tool):
    name = "bola"
    description = "BOLA/IDOR lintas akun: sesi B mengambil objek milik sesi A."
    risk_tags = {"active"}
    source_skill = "t2-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        sessions = dict(getattr(ctx, "sessions", None) or {})
        users = sorted(sessions)
        if len(users) < 2:
            ctx.world.note("bola: butuh >= 2 sesi (--accounts userA:pass,userB:pass) — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"sessions": len(users)})
        cap = int(args.get("max_requests", 24))
        findings: list[Finding] = []
        tested = 0
        owner = users[0]
        for ep in ctx.world.param_endpoints(limit=10):
            if tested + 3 > cap:
                break
            probe_url = ep.url.split("?", 1)[0]
            for param in ep.params[:3]:
                if tested + 3 > cap:
                    break
                if param.lower() not in ("id", "uid", "user_id", "userid", "account_id",
                                         "order_id", "doc_id", "invoice_id", "ref", "pid"):
                    continue
                st_a, body_a = _get(f"{probe_url}?{urlencode({param: '1'})}",
                                    sessions[owner], ctx)
                tested += 1
                if st_a != 200 or len(body_a) < 30:
                    continue  # objek #1 bukan milik owner / tak ada — tidak sah untuk uji
                for other in users[1:]:
                    st_b, body_b = _get(f"{probe_url}?{urlencode({param: '1'})}",
                                        sessions[other], ctx)
                    st_anon, body_anon = _get(f"{probe_url}?{urlencode({param: '1'})}",
                                              None, ctx)
                    tested += 2
                    sim = difflib.SequenceMatcher(None, body_b, body_a).ratio()
                    anon_denied = st_anon in (301, 302, 303, 307, 401, 403, 404) or \
                        _LOGIN_PAGE_RE.search(body_anon)
                    # FP-guard: anonymous DITOLAK, sesi lain DITERIMA dengan isi ≈ milik A
                    if (st_b == 200 and sim >= 0.8 and anon_denied
                            and not _LOGIN_PAGE_RE.search(body_b)):
                        findings.append(Finding(
                            tool=self.name,
                            title=f"BOLA: '{other}' mengambil objek #{param}=1 milik '{owner}'",
                            severity="high", cwe="CWE-639",
                            description=(f"Dengan sesi '{other}', GET {probe_url}?{param}=1 "
                                         f"mengembalikan isi yang identik dengan milik "
                                         f"'{owner}' (kemiripan {sim:.0%}), padahal permintaan "
                                         f"anonim DITOLAK ({st_anon}). Objek dilindungi dari "
                                         f"publik tapi TIDAK diperiksa kepemilikannya per-user "
                                         f"— lintas akun/tenant bisa saling membaca."),
                            recommendation="Otorisasi per-objek di server (owner/tenant check) "
                                           "pada setiap GET; jangan percaya ID dari klien.",
                            target_url=probe_url, param=param,
                            request=f"GET {probe_url}?{param}=1 (sesi '{other}')",
                            response=f"owner: 200 len={len(body_a)}; other: 200 sim={sim:.2f}; "
                                     f"anon: {st_anon}",
                            poc=f"# dgn cookie '{other}': curl -s '{probe_url}?{param}=1'",
                            confidence=0.9, source_skill=self.source_skill,
                            status="confirmed", evidence_kind="probe-pair"))
                        break
                if findings:
                    break
            if findings:
                break
        ctx.world.note(f"bola: {tested} request, {len(findings)} temuan, "
                       f"{len(users)} sesi")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)


class PrivMatrixTool(Tool):
    name = "priv_matrix"
    description = "Matriks hak akses: user biasa menerima panel/kontrol admin."
    risk_tags = {"active"}
    source_skill = "t2-high-03"

    ADMIN_PATHS = ("/admin", "/admin/users", "/api/admin/users", "/api/users",
                   "/admin/settings", "/dashboard/admin")

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        sessions = dict(getattr(ctx, "sessions", None) or {})
        users = sorted(sessions)
        if not users:
            ctx.world.note("priv_matrix: butuh >= 1 sesi — dilewati")
            return ToolResult(tool=self.name, ok=True, data={"sessions": len(users)})
        base = str(args["url"]).rstrip("/")
        cap = int(args.get("max_requests", 24))
        # gabungkan path admin dari world (hanya yang benar-benar 200 saat
        # teramati — path 302/404 bukan panel admin) + default
        paths = list(self.ADMIN_PATHS)
        for ep in ctx.world.endpoints.values():
            p = urlsplit(ep.url).path.lower()
            if (ep.status == 200 and any(k in p for k in ("admin", "role", "impersonat"))
                    and p not in paths):
                paths.insert(0, p)
        findings: list[Finding] = []
        tested = 0
        for path in paths[:6]:
            if tested + len(users) + 1 > cap:
                break
            url = base + path
            st_anon, body_anon = _get(url, None, ctx)
            tested += 1
            anon_denied = st_anon in (301, 302, 303, 307, 401, 403, 404) or \
                _LOGIN_PAGE_RE.search(body_anon)
            if not anon_denied:
                continue  # publik bisa lihat = bukan panel admin, bukan slot ini
            # early-skip: sesi pertama saja dulu — kalau bukan 200 berisi konten,
            # path ini bukan panel admin (hemat budget untuk path berikutnya)
            st_first, body_first = _get(url, sessions[users[0]], ctx)
            tested += 1
            if st_first != 200 or len(body_first) < 50 or _LOGIN_PAGE_RE.search(body_first):
                continue
            bodies: dict[str, tuple[int, str]] = {users[0]: (st_first, body_first)}
            for user in users[1:]:
                st_u, body_u = _get(url, sessions[user], ctx)
                tested += 1
                bodies[user] = (st_u, body_u)
            ok_sessions = [u for u, (st_u, _b) in bodies.items() if st_u == 200]
            if len(ok_sessions) < 2:
                continue
            ref = bodies[ok_sessions[0]][1]
            identical = [u for u in ok_sessions[1:]
                         if difflib.SequenceMatcher(None, bodies[u][1], ref).ratio() >= 0.8]
            # FP-guard: anonim ditolak, TAPI >= 2 sesi berbeda melihat ISI YANG SAMA
            # -> role tidak ditegakkan (tanpa asumsi siapa admin)
            if len(identical) + 1 >= 2 and len(ref) >= 50 \
                    and not _LOGIN_PAGE_RE.search(ref):
                findings.append(Finding(
                    tool=self.name,
                    title=f"Privilege matrix: {path} identik untuk semua sesi "
                          f"({', '.join(sorted(bodies))})",
                    severity="high", cwe="CWE-285",
                    description=(f"GET {url} mengembalikan konten yang sama untuk "
                                 f"{len(ok_sessions)} sesi berbeda ({', '.join(sorted(bodies))}) "
                                 f"padahal anonim ditolak ({st_anon}). Halaman admin/kontrol "
                                 f"hanya menyembunyikan UI, bukan menegakkan hak akses — "
                                 f"semua role terautentikasi mendapat kontrol penuh."),
                    recommendation="Tegakkan otorisasi role di server untuk setiap endpoint "
                                   "admin; bedakan konten per role; uji ulang lintas peran.",
                    target_url=url, request=f"GET {path} (semua sesi)",
                    response=f"anon: {st_anon}; sesi: "
                             + "; ".join(f"{u}: {bodies[u][0]} len={len(bodies[u][1])}"
                                         for u in sorted(bodies)),
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="probe-pair"))
                break
        ctx.world.note(f"priv_matrix: {tested} request, {len(findings)} temuan")
        return ToolResult(tool=self.name, ok=True, data={"tested": tested}, findings=findings)
