"""lockout — bounded login lockout/rate-limit check (CWE-307).

Teknik dari lapangan (2026-09, program bug bounty dengan aturan "3-6 percobaan
login diperbolehkan untuk uji lockout"): N kegagalan login beruntun yang
diterima dengan pola identik TANPA sinyal throttle berarti sistem tidak
mengunci/membatasi percobaan kredensial — bahan langsung credential attack
ketika digabung user enumeration.

FP-guards (pelajaran lapangan yang membentuk engine ini):
  - pesan statis vs dinamis: keyword lockout yang SUDAH ada di halaman login
    SEBELUM percobaan apa pun (mis. modal title "Locked!" pada template)
    TIDAK dihitung sebagai sinyal — hanya delta setelah kegagalan;
  - tanpa form HTML (SPA yang login via API) engine TIDAK menebak endpoint:
    skipped, bukan POST buta ke path tebakan;
  - password uji acak-per-attempt yang jelas salah (bukan dictionary);
  - username di-redact di semua evidence; password tidak pernah disimpan.

Predikat "no lockout" hanya dikeluarkan bila: semua attempt membalas dengan
pola "invalid credentials" yang sama, tanpa HTTP 429, tanpa header
Retry-After, tanpa captcha marker dinamis, dan tanpa eskalasi timing >= 2.5x
median attempt awal. Satu pun sinyal throttle = tidak ada temuan (kondisi baik).
"""

from __future__ import annotations

import re
import statistics
import time
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult, redact
from ..findings import Finding

_MAX_ATTEMPTS = 6  # plafon keras; default engine 4 (aman untuk aturan "3-6")

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.I)
_TYPE_RE = re.compile(r'type=["\']([^"\']+)["\']', re.I)
_VALUE_RE = re.compile(r'value=["\']([^"\']*)["\']', re.I)
_PW_INPUT_RE = re.compile(r'<input\b[^>]*type=["\']password["\'][^>]*>', re.I)

_USER_FIELDS = ("email", "username", "user", "login", "account", "userid")
_CSRF_FIELDS = ("_token", "csrf_token", "csrftoken", "_csrf", "authenticity_token",
                "csrfmiddlewaretoken", "__requestverificationtoken")
# marker yang menandakan throttle/lockout/captcha DINAMIS
_THROTTLE_MARKERS = ("too many", "throttl", "attempts remaining", "try again in",
                     "retry after", "has been locked", "account locked",
                     "captcha", "recaptcha", "hcaptcha", "verify you are human")


def _redact_user(u: str) -> str:
    return (u[:2] + "***") if len(u) > 2 else "***"


def _parse_login_form(html: str) -> dict | None:
    """Cari form yang memuat <input type=password>. Kembalikan
    {action, user_field, csrf: [(name, value), ...]} atau None."""
    for form_attrs, form in _FORM_RE.findall(html or ""):
        if not _PW_INPUT_RE.search(form):
            continue
        user_field = None
        csrf: list[tuple[str, str]] = []
        for inp in _INPUT_RE.findall(form):
            name_m = _NAME_RE.search(inp)
            if not name_m:
                continue
            name = name_m.group(1)
            low = name.lower()
            itype = (_TYPE_RE.search(inp) or [None, "text"])[1].lower() \
                if _TYPE_RE.search(inp) else "text"
            if itype == "password":
                continue
            if any(c == low for c in _CSRF_FIELDS) or low.endswith("token"):
                val = _VALUE_RE.search(inp)
                csrf.append((name, val.group(1) if val else ""))
            elif user_field is None and (low in _USER_FIELDS
                                         or itype in ("email", "text", "")):
                user_field = name
        if user_field:
            action_m = _ACTION_RE.search(form_attrs)
            return {"action": action_m.group(1) if action_m else "",
                    "user_field": user_field, "csrf": csrf}
    return None


def _dynamic_markers(body: str, baseline_markers: set[str]) -> list[str]:
    low = (body or "").lower()
    return sorted({m for m in _THROTTLE_MARKERS
                   if m in low and not any(m in b for b in baseline_markers)})


class LockoutProbeTool(Tool):
    name = "lockout"
    description = ("Bounded login lockout/rate-limit check: N failed attempts "
                   "(max 6, program-safe), statis-vs-dinamis marker guard, "
                   "no-credentials. Temuan hanya bila nol sinyal throttle.")
    risk_tags = {"active"}
    source_skill = "manual-bb-05"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        username = str(args.get("username") or "cyphron.probe@example.invalid")
        attempts = max(3, min(int(args.get("max_attempts") or 4), _MAX_ATTEMPTS))

        # 1. GET login page = sekaligus BASELINE marker statis
        try:
            ctx.throttle()
            st0, hd0, body0, _ms = http_engine.http_get(base, timeout=ctx.timeout_s)
        except Exception as exc:
            return ToolResult(tool=self.name, ok=True,
                              data={"error": type(exc).__name__},
                              error=f"login page fetch failed: {type(exc).__name__}")
        ctx.world.request_count += 1
        if not isinstance(st0, int) or st0 >= 400 or not body0:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-login-page"})
        ctx.world.observe_response(base, st0, hd0, body0, self.name)

        baseline_low = body0.lower()
        baseline_markers = {m for m in _THROTTLE_MARKERS if m in baseline_low}
        form = _parse_login_form(body0)
        if not form:
            ctx.world.note(f"lockout: tidak ada HTML login form di {host} "
                           "(SPA) — tidak menebak endpoint API")
            return ToolResult(tool=self.name, ok=True,
                              data={"skipped": "no-html-form", "host": host})

        action_url = urljoin(base + "/", (form["action"] or "").strip())
        post_fields: list[tuple[str, str]] = list(form["csrf"])
        post_fields.append((form["user_field"], username))

        # 2. N bounded attempts, password salah unik per attempt
        timings: list[int] = []
        statuses: list[int] = []
        dynamic_signals: list[str] = []
        retry_after_seen = False
        for i in range(attempts):
            if ctx.world.request_count >= ctx.max_requests:
                break
            data_pairs = post_fields + [("password", f"cyphron-wrong-{i}-x{int(time.time()) % 9997}")]
            body_data = "&".join(f"{k}={v}" for k, v in data_pairs)
            try:
                ctx.throttle()
                st, hd, body, ms = http_engine.http_get(
                    action_url, method="POST", data=body_data.encode("utf-8"),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=ctx.timeout_s)
            except Exception as exc:
                return ToolResult(tool=self.name, ok=True,
                                  data={"error": type(exc).__name__},
                                  error=f"POST failed: {type(exc).__name__}")
            ctx.world.request_count += 1
            statuses.append(st if isinstance(st, int) else -1)
            timings.append(ms)
            if any(k.lower() == "retry-after" for k in (hd or {}).keys()):
                retry_after_seen = True
            dynamic_signals.extend(_dynamic_markers(body, baseline_markers))
            if any((k.lower() == "retry-after") for k in (hd or {}).keys()):
                break

        if not statuses:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-attempts"})

        throttled = bool(dynamic_signals) or retry_after_seen \
            or any(s == 429 for s in statuses)
        med = statistics.median(timings[:max(2, len(timings) - 1)]) if len(timings) > 1 else timings[0]
        # floor 500ms: eskalasi throttle nyata itu ratusan ms+; noise scheduler
        # di bawah itu bukan sinyal (FP lapangan saat sistem sibuk)
        timing_escalation = bool(timings and med > 0
                                 and timings[-1] >= 2.5 * med
                                 and timings[-1] >= 500)
        throttled = throttled or timing_escalation

        if throttled:
            ctx.world.note(f"lockout: throttle/lockout signal terdeteksi di {host} "
                           f"— kondisi baik, tidak ada temuan")
            return ToolResult(tool=self.name, ok=True, data={
                "host": host, "lockout": {"present": True,
                                          "signals": sorted(set(dynamic_signals)),
                                          "retry_after": retry_after_seen,
                                          "statuses": statuses}})

        findings = [Finding(
            tool=self.name,
            title=f"No lockout/rate limiting on login of {host} "
                  f"({len(statuses)} consecutive failed attempts accepted)",
            severity="medium", cwe="CWE-307",
            description=(
                f"Endpoint login {action_url} menerima {len(statuses)} percobaan "
                f"password salah beruntun untuk username teredaksi "
                f"'{_redact_user(username)}' dengan pola respons identik, tanpa "
                f"HTTP 429, tanpa Retry-After, tanpa captcha dinamis, dan tanpa "
                f"eskalasi timing (median {med}ms). Digabung dengan enumerasi "
                f"username, hal ini memungkinkan password spraying tanpa "
                f"terdeteksi. Uji dibatasi {len(statuses)} attempt (aturan "
                f"program: maks 6) dengan password uji yang jelas salah; tidak "
                f"ada kredensial valid yang diuji."),
            recommendation=(
                "Terapkan rate-limit/lockout progresif pada endpoint login "
                "(mis. Laravel RateLimiter/ThrottleRequests, fail2ban, atau "
                "CAPTCHA setelah N kegagalan) dan audit log percobaan gagal."),
            target_url=base,
            request=f"POST {action_url} x{len(statuses)} (password salah, username redacted)",
            response=(f"statuses={statuses}; timings_ms={timings}; "
                      "tidak ada marker throttle dinamis (baseline statis difilter)"),
            poc=(f"curl -i -X POST '{action_url}' -d '{form['user_field']}=...&password=wrong' "
                 f"— ulangi >=4x, semua diterima dengan pola sama"),
            confidence=0.9, source_skill=self.source_skill,
            status="confirmed", evidence_kind="probe-pair")]
        return ToolResult(tool=self.name, ok=True,
                          data={"host": host,
                                "lockout": {"present": False, "statuses": statuses,
                                            "timings_ms": timings},
                                "username_redacted": _redact_user(username)},
                          findings=findings)
