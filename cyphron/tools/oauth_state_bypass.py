"""oauth_state_bypass — OAuth state tidak divalidasi + redirect_uri longgar
(CWE-352, high). Akun & session MILIK SENDIRI (cookie session global
http_engine yang sudah di-set via auth_login).

Dua bukti terpisah:
  1. STATE : GET authorize_url dengan state sampah -> halaman consent tetap
     tampil (marker consent ada, tanpa error state) = state tidak
     divalidasi; kalau redirect_uri varian juga lolos (302 Location ke
     varian) = bukti penuh code leakage.
  2. REDIRECT_URI : varian redirect_uri (host peneliti) di-allow -> 302
     Location ke varian = high.

FP-guard: halaman login (belum sesi) = skipped; error 'invalid state'
= postur baik; Location harus benar-benar berawalan varian (bukan cuma
menyebut); akun sendiri; maks 4 request; cease-on-data (code TIDAK
ditukar jadi token — cukup 302 sebagai bukti).
"""

from __future__ import annotations

from urllib.parse import quote as _q, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


class OAuthStateBypassTool(Tool):
    name = "oauth_state_bypass"
    description = ("OAuth: state sampah diterima + redirect_uri varian di-"
                   "allow (akun sendiri). Bukti = consent tanpa error / 302 "
                   "ke host peneliti. Code tidak ditukar.")
    risk_tags = {"active"}
    source_skill = "bounty-high-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        authorize_url = str(args.get("authorize_url") or "")
        if "{state}" not in authorize_url or "{redirect_uri}" not in \
                authorize_url:
            return ToolResult(
                tool=self.name, ok=False,
                error="authorize_url wajib memuat {state} dan "
                      "{redirect_uri} (mis. ...&state={state}&"
                      "redirect_uri={redirect_uri})")
        marker_host = str(args.get("marker_host") or "cyphron-oob.example")
        consent_marker = str(args.get("consent_marker") or "authorize")
        uri_variants = [str(v) for v in (args.get("redirect_uri_variants") or
                                         [f"https://{marker_host}/cb"])][:2]

        def auth(state: str, redirect_uri: str):
            u = authorize_url.replace("{state}", state) \
                             .replace("{redirect_uri}",
                                      _q(redirect_uri, safe=""))
            ctx.throttle()
            st, hd, body, _ms = http_engine.http_get(
                u, timeout=ctx.timeout_s, follow_redirects=False)
            ctx.world.request_count += 1
            return st, hd, body

        data: dict = {"marker_host": marker_host, "probes": []}
        findings: list[Finding] = []

        # ---- 1: state sampah
        st1, hd1, body1 = auth("cyphron-junk-state-000",
                               "https://app.legit.invalid/cb")
        low1 = body1.lower()
        state_error = any(s in low1 for s in ("invalid state", "state mismatch",
                                              "state tidak valid"))
        consent_shown = st1 == 200 and consent_marker.lower() in low1 and \
            not state_error
        data["probes"].append({"probe": "junk-state", "status": st1,
                               "state_error": state_error,
                               "consent_shown": consent_shown})
        if st1 in (301, 302, 303) and "login" in (hd1 or {}).get(
                "Location", "").lower():
            data["skipped"] = "belum login (akun sendiri diperlukan)"
            return ToolResult(tool=self.name, ok=True, data=data)
        if consent_shown:
            data["mode"] = "state-not-validated"

        # ---- 2: redirect_uri varian (cease-on-data)
        for variant in uri_variants:
            st2, hd2, _b2 = auth("cyphron-junk-state-000", variant)
            loc = (hd2 or {}).get("Location", "")
            host_ok = loc.startswith(variant) or \
                urlsplit(loc).hostname == urlsplit(variant).hostname
            data["probes"].append({"probe": "redirect-uri", "status": st2,
                                   "location": loc[:120]})
            if st2 in (301, 302, 303) and host_ok:
                state_note = (" DAN menerima state sampah (CSRF OAuth)"
                              if consent_shown else "")
                findings.append(Finding(
                    tool=self.name,
                    title="OAuth authorization code leaks to attacker "
                          "redirect_uri",
                    severity="high", cwe="CWE-352",
                    description=(
                        f"authorize endpoint menerima redirect_uri varian "
                        f"'{variant}' dan me-redirect 302 ke sana "
                        f"(Location terbukti){state_note} — authorization "
                        f"code pengirim dapat dikirim ke host attacker "
                        f"(code interception). cease-on-data: code TIDAK "
                        f"ditukar jadi token; tidak ada akses akun orang "
                        f"lain."),
                    recommendation=(
                        "Enforce exact-match redirect_uri per client; wajibkan "
                        "state acak server-side + verifikasi; PKCE untuk "
                        "public client."),
                    target_url=authorize_url.split("?")[0],
                    request=f"GET authorize?...&state=junk&redirect_uri="
                            f"{variant}",
                    response=f"status={st2}; Location={loc[:120]}",
                    confidence=0.9, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
                break  # cease-on-data

        # state-only (tanpa redirect varian lolos) = medium lead-evidence
        if not findings and consent_shown:
            findings.append(Finding(
                tool=self.name,
                title="OAuth state parameter not validated",
                severity="medium", cwe="CWE-352",
                description=(
                    "Halaman consent tetap tampil dengan state sampah (tanpa "
                    "error) — proteksi CSRF OAuth tidak aktif. Dampak penuh "
                    "(code interception) belum dibuktikan karena redirect_uri "
                    "ketat; catat dan laporkan sesuai rules program."),
                recommendation=("Wajibkan dan verifikasi state server-side."),
                target_url=authorize_url.split("?")[0],
                request="GET authorize?...&state=cyphron-junk-state-000",
                response=f"status={st1}; consent tampil tanpa error state",
                confidence=0.6, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response"))
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
