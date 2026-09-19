"""username_osint — enumerasi username di platform publik (pasif, LEAD).

Satu GET per platform pada pola URL profil publik yang dikenal; hasil =
LEAD "profil dengan username ini ada/tidak" — BUKAN resolusi identitas.
Ambiguitas diakui jujur: 403/429/redirect/timeout = TIDAK PASTI, bukan
"tidak ada" (zero-FP: tidak menebak dari sinyal lemah).

Guard:
  - nama username divalidasi ketat (hanya [A-Za-z0-9._-], 2-32);
  - default 10 platform per run (deterministik, urut abjad), 1 GET max
    per platform, rate-limit via ctx.throttle();
  - platform dengan marker (halaman exists & tidak-exists sama-sama 200)
    diverifikasi konten, bukan status saja;
  - semua temuan = LEAD (unconfirmed, finding_class surface);
  - bukan tool doxxing: yang dicari adalah keberadaan profil publik,
    identitas orang tetap jalur resmi (skill 81-playbook-fraud).
"""

from __future__ import annotations

import re
from urllib.parse import quote as _urlquote

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")

# marker = substring yang hanya ada bila profil TIDAK ada (platform yang
# membalas 200 untuk profil bohong). Platform yang statusnya tak bisa
# dipercaya TIDAK ikut daftar (steam: 200 untuk profil tak ada; IG/TikTok:
# redirect login) — jujur daripada temuan palsu.
_PLATFORMS = {
    "github": "https://github.com/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "keybase": "https://keybase.io/{u}",
    "medium": "https://medium.com/@{u}",
    "soundcloud": "https://soundcloud.com/{u}",
    "vimeo": "https://vimeo.com/{u}",
    "dribbble": "https://dribbble.com/{u}",
    "behance": "https://www.behance.net/{u}",
    "chess": "https://www.chess.com/member/{u}",
    "hackernews": "https://news.ycombinator.com/user?id={u}",
    "kaggle": "https://www.kaggle.com/{u}",
    "pinterest": "https://www.pinterest.com/{u}/",
    "replit": "https://replit.com/@{u}",
}
_NO_SUCH_MARKERS = {
    "hackernews": "No such user",
}
_DEFAULT_MAX = 10


class UsernameOsintTool(Tool):
    name = "username_osint"
    description = ("enumerasi username di platform publik — satu GET per "
                   "platform, hasil = LEAD keberadaan profil (bukan "
                   "resolusi identitas).")
    risk_tags = {"passive", "external"}
    source_skill = "82-recon-eksternal"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        username = str(args.get("username") or "").strip()
        if not _USERNAME_RE.match(username):
            return ToolResult(
                tool=self.name, ok=False,
                error="args.username wajib [A-Za-z0-9._-], panjang 2-32 "
                      "(bukan email, bukan nomor telepon)")
        platforms = sorted(_PLATFORMS)
        want = args.get("platforms")
        if want:
            missing = [p for p in want if p not in _PLATFORMS]
            if missing:
                return ToolResult(tool=self.name, ok=False,
                                  error=f"platform tidak dikenal: {missing}")
            platforms = sorted(want)
        platforms = platforms[:int(args.get("max_platforms", _DEFAULT_MAX))]

        found: list[dict] = []
        not_found: list[str] = []
        ambiguous: list[dict] = []
        for p in platforms:
            ctx.throttle()
            url = _PLATFORMS[p].format(u=_urlquote(username))
            st, _h, body, _ms = http_engine.http_get(url,
                                                     timeout=ctx.timeout_s)
            marker = _NO_SUCH_MARKERS.get(p)
            if marker and marker in (body or ""):
                not_found.append(p)          # 200 tapi halaman "no such user"
            elif st == 200:
                found.append({"platform": p, "url": url})
            elif st in (401, 403, 429) or 500 <= st < 600:
                ambiguous.append({"platform": p, "status": st,
                                  "note": "dibatasi/blokir — tidak pasti"})
            elif st >= 400:
                not_found.append(p)
            else:
                ambiguous.append({"platform": p, "status": st,
                                  "note": "respon tak terduga"})
            if len(found) + len(not_found) + len(ambiguous) >= len(platforms):
                break

        ctx.world.note(
            f"username_osint: {username} -> {len(found)} ada, "
            f"{len(not_found)} tidak ada, {len(ambiguous)} tidak pasti")

        findings = [Finding(
            tool=self.name,
            title=f"profil publik '{username}' ada di {f['platform']}",
            severity="info", cwe=None,
            description=(f"Username '{username}' terdaftar sebagai profil "
                         f"publik di {f['platform']} ({f['url']}). LEAD "
                         f"recon — verifikasi manual sebelum dipakai "
                         f"menyusun permukaan social engineering "
                         f"(dengan otorisasi)."),
            recommendation=("Catat sebagai permukaan awal engagement; "
                            "jangan hubungi pemilik akun di luar jalur "
                            "engagement yang diizinkan."),
            target_url=f["url"], request=f"GET {f['url']}",
            response="status 200", confidence=0.65,
            source_skill=self.source_skill, status="unconfirmed",
            evidence_kind="header", finding_class="surface")
            for f in found]

        return ToolResult(tool=self.name, ok=True, data={
            "username": username,
            "platforms_checked": len(platforms),
            "found": found,
            "not_found": not_found,
            "ambiguous": ambiguous,
            "note": ("LEAD keberadaan profil publik; ambiguitas "
                     "(403/429) dilaporkan jujur, bukan dianggap "
                     "tidak ada"),
        }, findings=findings)
