"""identity_matrix — Matriks Multi-Identitas (Unity U5).

Membandingkan respons SATU endpoint lintas identitas (anonymous + sesi-sesi
uji dari --accounts) dan menguji tabel expected-behavior:

    identitas \ akses   objek privat milik A    objek publik
    anonymous           DENIED (kontrol)        ALLOW
    sesi A (pemilik)    ALLOW (isi milik A)     ALLOW
    sesi B (lain)       DENIED                  ALLOW

DEVIASI yang dilaporkan (differential kuat, zero-FP):
- sesi B menerima isi yang identik dengan objek privat milik A
  (similarity >= 0.8) SEMENTARA kontrol anonymous DITOLAK ->
  broken access control antar identitas (high, weakness).
- anonymous menerima isi objek privat milik A -> objek privat terbuka
  (critical, weakness).

Tanpa >= 2 identitas, engine hanya membangun MATRIKS observasi (tanpa
temuan) — deviasi tidak bisa dibuktikan tanpa kontrol. Semua uji GET-only,
rate-limit via ctx.throttle, dedup per endpoint, bounded cap endpoint.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import urlencode

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_LOGIN_RE = re.compile(r"(?i)(<form|password|login|signin|masuk)")
_ID_PARAMS = ("id", "uid", "user_id", "userid", "account_id", "order_id",
              "doc_id", "invoice_id", "ref", "pid")
_ADMIN_HINTS = ("admin", "dashboard", "manage", "panel", "console")
_MAX_ENDPOINTS = 12
_SIM_THRESHOLD = 0.8
_MIN_BODY = 30


def _get(url: str, cookie: str | None, ctx: ToolContext):
    """GET dengan Cookie eksplisit; anonim kirim Cookie kosong agar
    benar-benar anonim (cookie global tidak bocor ke baris anonymous)."""
    headers = {"Cookie": cookie if cookie else ""}
    ctx.throttle()
    st, _h, body, _ms = http_engine.http_get(url, timeout=ctx.timeout_s,
                                             headers=headers,
                                             follow_redirects=False)
    ctx.world.observe_response(url, st, None, None, "identity_matrix")
    ctx.world.request_count += 1
    return st, body or ""


def _denied(status: int, body: str) -> bool:
    return status in (301, 302, 303, 307, 401, 403, 404) or bool(
        _LOGIN_RE.search(body))


class IdentityMatrixTool(Tool):
    name = "identity_matrix"
    description = ("Matriks identitas: expected-behavior anonymous/A/B per "
                   "endpoint; deviasi differential = weakness terverifikasi.")
    risk_tags = {"active"}
    source_skill = "t2-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        sessions = dict(getattr(ctx, "sessions", None) or {})
        users = sorted(sessions)
        target = str(args.get("url") or ctx.world.target).rstrip("/")

        # endpoint kandidat: berparam id-like (objek per-user) + path admin-hint
        candidates: list[str] = []
        for ep in ctx.world.param_endpoints(limit=20):
            has_id = any(p.lower() in _ID_PARAMS for p in ep.params)
            path = ep.url
            if has_id or any(h in path.lower() for h in _ADMIN_HINTS):
                if ep.url not in candidates:
                    candidates.append(ep.url)
        for url in ctx.world.endpoints:
            if url not in candidates and any(
                    h in url.lower() for h in _ADMIN_HINTS):
                candidates.append(url)
        candidates = candidates[:_MAX_ENDPOINTS]
        if not candidates:
            ctx.world.note("identity_matrix: tidak ada endpoint kandidat "
                           "(param id-like / path admin)")
            return ToolResult(tool=self.name, ok=True,
                              data={"matrix": [], "endpoints": 0})

        matrix: list[dict] = []
        findings: list[Finding] = []
        tested = 0

        for url in candidates:
            if tested >= _MAX_ENDPOINTS:
                break
            rows: dict[str, tuple[int, str]] = {}
            # anonymous dulu (kontrol paling penting)
            st_a, body_a = _get(url, None, ctx)
            rows["anonymous"] = (st_a, body_a)
            for u in users:
                st_u, body_u = _get(url, sessions[u], ctx)
                rows[u] = (st_u, body_u)
            tested += 1

            # satu endpoint = satu temuan (defect yang sama tidak dihitung
            # dua kali dari arah identitas berbeda); anonim dulu (paling
            # parah), lalu lintas-sesi
            def _report(f: Finding, row: dict) -> None:
                matrix.append(row)
                findings.append(f)

            st_an, body_an = rows["anonymous"]
            anon_denied = _denied(st_an, body_an)
            reported = False
            for u in users:
                st_u, body_u = rows[u]
                if reported or st_u != 200 or len(body_u) < _MIN_BODY \
                        or _LOGIN_RE.search(body_u):
                    continue
                # deviasi 2: anonymous menerima isi objek privat
                if (st_an == 200 and len(body_an) >= _MIN_BODY
                        and not _LOGIN_RE.search(body_an)):
                    sim = difflib.SequenceMatcher(None, body_an,
                                                  body_u).ratio()
                    if sim >= _SIM_THRESHOLD:
                        _report(Finding(
                            tool=self.name,
                            title=(f"Objek privat dapat diakses anonim pada "
                                   f"{url}"),
                            severity="critical",
                            description=(
                                f"Endpoint {url} merespons 200 dengan konten "
                                f"identik milik sesi '{u}' (similaritas "
                                f"{sim:.0%}) TANPA autentikasi apa pun. "
                                f"Objek privat terekspos ke publik; uji "
                                f"differential GET-only, reproduktif."),
                            recommendation=(
                                "Wajibkan autentikasi pada endpoint; tolak "
                                "akses anonim ke objek privat (default-deny)."),
                            cwe="CWE-306",
                            target_url=url,
                            confidence=0.9,
                            finding_class="weakness",
                            status="confirmed",
                            evidence_kind="differential",
                        ), {"endpoint": url, "identity": "anonymous",
                            "status": st_an, "verdict": "ALLOW",
                            "expected": "DENIED",
                            "similarity_to_owner": round(sim, 3),
                            "control": f"{u} 200 (pemilik)"})
                        f = findings[-1]
                        f.attach_evidence("probe-pair", {
                            "endpoint": url, "owner": u,
                            "accessor": "anonymous",
                            "similarity": round(sim, 3),
                        })
                        reported = True
                        continue
            if not reported:
                for u in users:
                    st_u, body_u = rows[u]
                    if st_u != 200 or len(body_u) < _MIN_BODY \
                            or _LOGIN_RE.search(body_u):
                        continue
                    for other in users:
                        if other == u:
                            continue
                        st_o, body_o = rows[other]
                        sim = difflib.SequenceMatcher(None, body_o,
                                                      body_u).ratio()
                        if (st_o == 200 and sim >= _SIM_THRESHOLD
                                and anon_denied
                                and not _LOGIN_RE.search(body_o)):
                            _report(Finding(
                                tool=self.name,
                                title=(f"Akses lintas identitas pada {url}: "
                                       f"sesi '{other}' menerima objek milik "
                                       f"'{u}'"),
                                severity="high",
                                description=(
                                    f"Endpoint {url} merespons 200 dengan "
                                    f"konten identik milik sesi '{u}' ketika "
                                    f"diakses sesi '{other}' (similaritas "
                                    f"{sim:.0%}), sementara kontrol anonymous "
                                    f"DITOLAK ({st_an}). Expected-behavior "
                                    f"matriks: objek privat hanya boleh "
                                    f"diakses pemilik. Uji differential "
                                    f"GET-only, reproduktif."),
                                recommendation=(
                                    "Terapkan otorisasi object-level: cek "
                                    "kepemilikan objek terhadap identitas "
                                    "sesi di server pada setiap akses; uji "
                                    "ulang tiap endpoint baru."),
                                cwe="CWE-639",
                                target_url=url,
                                confidence=0.9,
                                finding_class="weakness",
                                status="confirmed",
                                evidence_kind="differential",
                            ), {"endpoint": url, "identity": other,
                                "status": st_o, "verdict": "ALLOW",
                                "expected": "DENIED",
                                "similarity_to_owner": round(sim, 3),
                                "control": f"anonymous {st_an}"})
                            f = findings[-1]
                            f.attach_evidence("probe-pair", {
                                "endpoint": url, "owner": u,
                                "accessor": other,
                                "similarity": round(sim, 3),
                                "control": "anonymous-denied",
                                "control_status": st_an,
                            })
                            reported = True
                            break
                    if reported:
                        break

        if not users:
            ctx.world.note(
                "identity_matrix: hanya identitas anonymous tersedia "
                "(butuh >= 2 sesi --accounts untuk deviasi lintas akun) — "
                "matriks observasi tanpa temuan")
            return ToolResult(tool=self.name, ok=True,
                              data={"matrix": [], "endpoints": tested,
                                    "note": "butuh >= 2 identitas untuk "
                                            "differential"})
        ctx.world.note(
            f"identity_matrix: {tested} endpoint uji GET-only lintas "
            f"{len(users) + 1} identitas; {len(findings)} deviasi "
            f"expected-behavior")
        return ToolResult(tool=self.name, ok=True,
                          data={"matrix": matrix, "endpoints": tested},
                          findings=findings)
