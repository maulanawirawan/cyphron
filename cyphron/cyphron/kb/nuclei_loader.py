"""Loader template Nuclei — HANYA subset aman, via yamlite (no PyYAML).

Prinsip fail-safe:
- Template yang gagal diparse = SKIP (dihitung di statistik, bukan error).
- Template di luar kelas aman = SKIP dengan alasan eksplisit:
  * whitelist tag (wajib punya >=1) dan blacklist tag (satu hit = buang),
  * severity dibatasi (default info/low; medium+ butuh izin eksplisit),
  * HTTP sederhana: 1 request, method GET, 1 path {{BaseURL}}+literal,
    tanpa body/raw/payload/variabel/DSL/interactsh/host-header,
  * matcher hanya word/status/description — dan match wajib memeriksa ISI
    respons (anti catch-all 200, pelajaran SIPAS).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import yamlite

WHITELIST_TAGS = {
    "cve", "info", "misconfig", "config", "exposure", "token", "redirect",
    "panel", "tech", "default-login", "detect",
}
BLACKLIST_TAGS = {
    "dos", "bruteforce", "brute", "overflow", "fuzz", "intrusive",
    "password", "stealth", "destruction", "credential-stuffing", "nologin",
    "lua",
}
SAFE_MATCHER_TYPES = {"word", "status", "description"}
ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
# kunci workload non-HTTP yang tidak boleh dieksekusi bridge
_NON_HTTP_KEYS = {"code", "javascript", "network", "dns", "file", "headless",
                  "ssl", "workflow"}


@dataclass
class NucleiRequest:
    method: str = "GET"
    path: str = ""
    matchers: list[dict] = field(default_factory=list)
    matchers_condition: str = "or"
    headers: dict = field(default_factory=dict)


@dataclass
class NucleiTemplate:
    tid: str = ""
    name: str = ""
    author: str = ""
    severity: str = "info"
    tags: set[str] = field(default_factory=set)
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cwe: str = ""
    cvss_score: float | None = None
    cvss_metrics: str = ""
    requests: list[NucleiRequest] = field(default_factory=list)
    source_file: str = ""


@dataclass
class LoadStats:
    total: int = 0
    parsed: int = 0
    skipped_parse: int = 0
    skipped_unsafe: int = 0
    safe: int = 0
    reasons: dict[str, int] = field(default_factory=dict)


def _reason(stats: LoadStats | None, why: str) -> None:
    if stats is not None:
        stats.reasons[why] = stats.reasons.get(why, 0) + 1


def parse_template(text: str, source: str = "") -> tuple[NucleiTemplate | None, str | None]:
    """YAML template -> NucleiTemplate (None, alasan) bila tidak layak."""
    lowered = text.lower()
    if "interactsh" in lowered:
        return None, "pakai interactsh (OOB) — tidak didukung"
    try:
        data = yamlite.parse(text)
    except yamlite.YamliteError as exc:
        return None, f"yamlite: {exc}"
    if not isinstance(data, dict):
        return None, "bukan mapping YAML"
    for key in _NON_HTTP_KEYS:
        if key in data:
            return None, f"workload {key!r} tidak dieksekusi bridge"
    tid = data.get("id")
    info = data.get("info")
    if not isinstance(tid, str) or not tid or not isinstance(info, dict):
        return None, "id/info hilang"
    http = data.get("http")
    if not isinstance(http, list) or not http:
        return None, "bukan template http"
    t = NucleiTemplate(
        tid=tid,
        name=str(info.get("name") or ""),
        author=str(info.get("author") or ""),
        severity=str(info.get("severity") or "info").lower(),
        description=str(info.get("description") or ""),
        source_file=source,
    )
    raw_tags = info.get("tags") or ""
    if isinstance(raw_tags, str):
        t.tags = {x.strip().lower() for x in raw_tags.split(",") if x.strip()}
    elif isinstance(raw_tags, list):
        t.tags = {str(x).strip().lower() for x in raw_tags if str(x).strip()}
    cls = info.get("classification") or {}
    if isinstance(cls, dict):
        cve = cls.get("cve-id") or ""
        if isinstance(cve, str) and cve:
            t.cve_ids = [cve]
        elif isinstance(cve, list):
            t.cve_ids = [str(x) for x in cve if str(x)]
        t.cwe = str(cls.get("cwe-id") or "")
        score = cls.get("cvss-score")
        if isinstance(score, (int, float)):
            t.cvss_score = float(score)
        t.cvss_metrics = str(cls.get("cvss-metrics") or "")
    for entry in http:
        if not isinstance(entry, dict):
            return None, "entri http bukan mapping"
        if "raw" in entry or "body" in entry or "payloads" in entry \
                or "variables" in entry:
            return None, "request kompleks (raw/body/payloads/variables)"
        path_list = entry.get("path")
        if not isinstance(path_list, list) or len(path_list) != 1 \
                or not isinstance(path_list[0], str):
            return None, "path bukan tepat satu string"
        req = NucleiRequest(
            method=str(entry.get("method") or "GET").upper(),
            path=path_list[0],
            matchers_condition=str(entry.get("matchers-condition") or "or").lower(),
        )
        headers = entry.get("headers")
        if isinstance(headers, dict):
            if any(str(k).lower() == "host" for k in headers):
                return None, "override Host header — tidak aman"
            req.headers = {str(k): str(v) for k, v in headers.items()}
        matchers = entry.get("matchers")
        if isinstance(matchers, list):
            for m in matchers:
                if not isinstance(m, dict) \
                        or str(m.get("type") or "").lower() not in SAFE_MATCHER_TYPES:
                    return None, "matcher di luar kelas aman"
            req.matchers = matchers
        t.requests.append(req)
    return t, None


def is_safe(t: NucleiTemplate,
            allow_severity: tuple[str, ...] = ("info", "low")) -> str | None:
    """None = aman; string = alasan tolak (fail-closed)."""
    if t.severity not in ALLOWED_SEVERITIES:
        return f"severity tak dikenal: {t.severity}"
    if t.severity not in allow_severity:
        return f"severity {t.severity} di luar izin {allow_severity}"
    if not (t.tags & WHITELIST_TAGS):
        return "tanpa tag whitelist"
    if t.tags & BLACKLIST_TAGS:
        return "ada tag blacklist"
    for req in t.requests:
        if req.method != "GET":
            return f"method {req.method} != GET"
        if not req.path.startswith("{{BaseURL}}"):
            return "path tidak berawal {{BaseURL}}"
        rest = req.path[len("{{BaseURL}}"):]
        if "{{" in rest or ".." in rest or "%" in rest:
            return "path memuat placeholder/karakter berisiko"
        if req.matchers and req.matchers_condition not in ("and", "or"):
            return f"matchers-condition aneh: {req.matchers_condition}"
        if not req.matchers:
            return "tanpa matcher (wajib cek isi respons)"
        if all(str(m.get("type") or "").lower() == "status"
               for m in req.matchers):
            return "matcher status-only (wajib cek isi respons)"
    return None


def iter_templates(root: Path, stats: LoadStats | None = None):
    """Walk folder template; yield (NucleiTemplate|None, alasan|None)."""
    for p in sorted(Path(root).rglob("*.yaml")):
        if stats is not None:
            stats.total += 1
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _reason(stats, f"baca file: {type(exc).__name__}")
            if stats is not None:
                stats.skipped_parse += 1
            yield None, f"baca file gagal: {exc}"
            continue
        t, why = parse_template(text, source=str(p))
        if stats is not None:
            if t is None:
                stats.skipped_parse += 1
                _reason(stats, why or "parse gagal")
            else:
                stats.parsed += 1
        yield t, why


def iter_safe_templates(root: Path,
                        allow_severity: tuple[str, ...] = ("info", "low"),
                        stats: LoadStats | None = None):
    """Yield hanya template lolos pemeriksaan keamanan (fail-closed)."""
    for t, why in iter_templates(root, stats):
        if t is None:
            continue
        unsafe = is_safe(t, allow_severity)
        if unsafe is not None:
            _reason(stats, unsafe)
            if stats is not None:
                stats.skipped_unsafe += 1
            continue
        if stats is not None:
            stats.safe += 1
        yield t
