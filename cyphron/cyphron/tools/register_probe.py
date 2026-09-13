"""register — Open registration probe (CWE-284 posture).

Teknik lapangan (2026-09, gitea.ums.ac.id): tool internal (git server,
panel, helpdesk) yang halaman registrasinya terbuka publik memperluas
permukaan serangan — siapa pun bisa membuat akun di dalam dinding.

FP-guard:
  - hanya path yang eksplisit bernama register/signup yang diuji (bukan
    menebak acak);
  - form HARUS memuat input password (halaman login juga punya password —
    FP utama!): halaman login ditolak bila action-nya login dan tidak ada
    field konfirmasi password kedua;
  - posture (low), bukan klaim breach — konteks (tool internal vs publik)
    dinilai di atas engine.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PATHS = ("/register", "/signup", "/register.html", "/wp-login.php?action=register")
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.I)
_TYPE_RE = re.compile(r'type=["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
_ID_RE = re.compile(r'id=["\']([^"\']+)["\']', re.I)


def _register_form(html: str) -> dict | None:
    """Form dengan password + identitas, BUKAN halaman login (FP-guard)."""
    for attrs, form in _FORM_RE.findall(html or ""):
        inputs = _INPUT_RE.findall(form)
        pw_fields, id_field = [], None
        for inp in inputs:
            itype = (_TYPE_RE.search(inp) or [None, "text"])[1].lower() \
                if _TYPE_RE.search(inp) else "text"
            nm = _NAME_RE.search(inp) or _ID_RE.search(inp)
            name = (nm.group(1).lower() if nm else "")
            if itype == "password":
                pw_fields.append(name)
            elif itype in ("email", "text") and any(
                    k in name for k in ("email", "user", "username", "login")):
                id_field = name
        if not pw_fields or not id_field:
            continue
        action_m = _ACTION_RE.search(attrs) or _ACTION_RE.search(form)
        action = (action_m.group(1).lower() if action_m else "")
        # FP-guard halaman login: action login + tidak ada field konfirmasi
        confirm = any(("confirm" in p or "retype" in p or "ulang" in p or "re-" in p)
                      for p in pw_fields)
        if "login" in action and len(pw_fields) < 2 and not confirm:
            continue
        if "login" in (form or "").lower() and not confirm and len(pw_fields) < 2 \
                and "register" not in action and "signup" not in action \
                and "daftar" not in action:
            continue
        return {"action": action, "id_field": id_field, "passwords": len(pw_fields)}
    return None


class RegisterProbeTool(Tool):
    name = "register"
    description = ("Open registration probe pada path register/signup eksplisit "
                   "— posture exposure (field-driven: gitea.ums.ac.id).")
    risk_tags = {"active"}
    source_skill = "manual-bb-10"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        data: dict = {"host": host, "probed": []}
        hits: list[str] = []
        for path in _PATHS:
            if ctx.world.request_count >= ctx.max_requests:
                break
            try:
                ctx.throttle()
                st, hd, body, _ms = http_engine.http_get(
                    urljoin(base + "/", path.lstrip("/")), timeout=ctx.timeout_s)
            except Exception:
                continue
            ctx.world.request_count += 1
            form = _register_form(body or "") if st == 200 else None
            data["probed"].append({"path": path, "status": st,
                                   "register_form": bool(form)})
            if form:
                hits.append(path)
                ctx.world.note(f"register: form registrasi terbuka di {host}{path}")
        if hits:
            findings = [Finding(
                tool=self.name,
                title=f"Open registration endpoint on {host} ({', '.join(hits)})",
                severity="low", cwe="CWE-284", finding_class="posture",
                description=(
                    f"Endpoint registrasi dapat diakses publik dan menampilkan "
                    f"form pendaftaran berfungsi. Pada tool internal (git "
                    f"server/panel/helpdesk), ini memperluas permukaan serangan: "
                    f"siapa pun bisa membuat akun di dalam lingkungan. Nilai "
                    f"risiko bergantung konteks — untuk situs publik memang "
                    f"disengaja; untuk tool internal = exposure."),
                recommendation=(
                    "Bila tool hanya untuk internal: matikan registrasi mandiri "
                    "atau batasi via SSO/allowlist; tambahkan persetujuan admin "
                    "untuk akun baru."),
                target_url=base,
                request="GET " + " / GET ".join(hits),
                response="HTTP 200 dengan form registrasi berfungsi",
                confidence=0.9, source_skill=self.source_skill,
                status="confirmed", evidence_kind="request-response")]
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
        return ToolResult(tool=self.name, ok=True, data=data)
