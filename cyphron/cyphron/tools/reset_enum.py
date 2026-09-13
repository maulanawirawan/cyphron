"""reset_enum — password-reset user enumeration via response diff
(CWE-204/200).

Teknik terbukti lapangan (BINUS BB-003, 2026-09): POST password-reset untuk
email yang TERDAFTAR vs email FIKTIF menghasilkan respons berbeda (mis.
existing -> 500 vs nonexistent -> 302) — sinyal enumerasi akun.

Keamanan & FP-guard:
  - email fiktif memakai TLD .invalid (RFC 2606) -> tidak ada email yang
    pernah terkirim ke pihak ketiga;
  - wajib args known_email milik peneliti sendiri (akun uji);
  - diff harus KONSISTEN 3 putaran — perbedaan sekali = noise, bukan temuan;
  - respons identik = tidak ada temuan (postur baik, dicatat saja).
"""

from __future__ import annotations

import re
import statistics
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.I)
_TYPE_RE = re.compile(r'type=["\']([^"\']+)["\']', re.I)
_VALUE_RE = re.compile(r'value=["\']([^"\']*)["\']', re.I)
_CSRF = ("_token", "csrf_token", "csrftoken", "_csrf", "authenticity_token")
_ROUNDS = 3


def _reset_form(html: str) -> dict | None:
    for attrs, form in _FORM_RE.findall(html or ""):
        fields: list[tuple[str, str]] = []
        email_field = None
        for inp in _INPUT_RE.findall(form):
            nm = _NAME_RE.search(inp)
            if not nm:
                continue
            name = nm.group(1)
            low = name.lower()
            itype = (_TYPE_RE.search(inp) or [None, "text"])[1].lower() \
                if _TYPE_RE.search(inp) else "text"
            if itype == "password":
                return None  # ini form login, bukan reset
            if any(c == low for c in _CSRF) or low.endswith("token"):
                val = _VALUE_RE.search(inp)
                fields.append((name, val.group(1) if val else ""))
            elif email_field is None and (itype == "email" or "email" in low
                                          or "user" in low):
                email_field = name
        if email_field:
            action_m = re.search(r'action=["\']([^"\']+)["\']', attrs, re.I)
            return {"action": action_m.group(1) if action_m else "",
                    "email_field": email_field, "csrf": fields}
    return None


def _signature(st, body: str) -> tuple:
    """Sidik jari respons: (status, ada pesan sent/error umum)."""
    low = (body or "").lower()
    marker = "sent" if ("sent" in low or "kirim" in low) else \
        "error" if ("error" in low or "tidak" in low) else "other"
    return (st, marker)


class ResetEnumTool(Tool):
    name = "reset_enum"
    description = ("Password-reset user enumeration via differential response "
                   "(known vs fictional .invalid email, 3 rounds, consistent "
                   "diff required). Wajib known_email milik peneliti.")
    risk_tags = {"active"}
    source_skill = "manual-bb-11"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        known = str(args.get("known_email") or "").strip()
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        if not known:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "known_email-required",
                                    "note": "diff butuh email akun uji milik "
                                            "peneliti; tanpa itu tidak dijalankan"})
        reset_path = str(args.get("reset_path") or "/password/reset")
        fictional = str(args.get("fictional_email")
                        or "cyphron-nonexist@invalid.cyphron-probe")

        try:
            ctx.throttle()
            st0, hd0, body0, _ms = http_engine.http_get(
                urljoin(base + "/", reset_path.lstrip("/")),
                timeout=ctx.timeout_s)
        except Exception as e:
            return ToolResult(tool=self.name, ok=True,
                              data={"error": type(e).__name__})
        ctx.world.request_count += 1
        form = _reset_form(body0 or "") if st0 == 200 else None
        if not form:
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-reset-form", "host": host})
        action = urljoin(base + "/", (form["action"] or reset_path).lstrip("/")
                         if not form["action"].startswith("http")
                         else form["action"])

        sig_known, sig_fake = [], []
        for rnd in range(_ROUNDS):
            for email, sink in ((known, sig_known), (fictional, sig_fake)):
                if ctx.world.request_count >= ctx.max_requests:
                    break
                payload = list(form["csrf"]) + [(form["email_field"], email)]
                body_data = "&".join(f"{k}={v}" for k, v in payload)
                try:
                    ctx.throttle()
                    st, _hd, body, _ms = http_engine.http_get(
                        action, method="POST", data=body_data.encode("utf-8"),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=ctx.timeout_s)
                except Exception as e:
                    return ToolResult(tool=self.name, ok=True,
                                      data={"error": type(e).__name__})
                ctx.world.request_count += 1
                sink.append(_signature(st, body))
        data = {"host": host,
                "known_redacted": (known[:2] + "***" + known.split("@")[-1]),
                "signatures_known": sig_known, "signatures_fictional": sig_fake}

        if len(set(sig_known)) == 1 and len(set(sig_fake)) == 1 \
                and sig_known[0] != sig_fake[0]:
            findings = [Finding(
                tool=self.name,
                title=f"Password reset reveals account existence on {host}",
                severity="medium", cwe="CWE-204",
                description=(
                    f"POST {action} membalas BERBEDA secara konsisten ({_ROUNDS} "
                    f"putaran) antara email terdaftar (teredaksi "
                    f"'{data['known_redacted']}') dan email fiktif domain "
                    f".invalid: known={sig_known} vs nonexistent={sig_fake}. "
                    f"Attacker dapat memetakan akun mana yang ada sebelum "
                    f"menyerang — dikombinasikan enumerasi username menjadi "
                    f"targeting presisi. Email fiktif memakai TLD .invalid "
                    f"(RFC 2606) — tidak ada email terkirim ke pihak ketiga."),
                recommendation=(
                    "Samakan respons reset untuk semua email (pesan generik "
                    "'jika email terdaftar, link akan dikirim') dan samakan "
                    "status/timing."),
                target_url=base,
                request=f"POST {action} x{_ROUNDS * 2} (2 identitas, 3 putaran)",
                response=f"known={sig_known} vs fictional={sig_fake} (konsisten)",
                confidence=1.0, source_skill=self.source_skill,
                status="confirmed", evidence_kind="probe-pair")]
            return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
        data["note"] = "respons identik/inkonsisten — tidak ada sinyal enumerasi"
        return ToolResult(tool=self.name, ok=True, data=data)
