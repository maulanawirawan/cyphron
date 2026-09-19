"""escalation — Adaptive Escalation Mode: probe -> pelajari pola -> ofensif.

Cyphron tidak langsung ofensif. Dari Evidence Graph, fungsi ini membaca pola
yang menarik dan menentukan FASE eskalasi berikutnya:

  FASE 1 PROBE    : graph masih tipis -> lanjutkan census/rekon pasif.
  FASE 2 PATTERN  : pola menarik terdeteksi -> buka hypothesis ringan.
  FASE 3 ESCALATE : pola kaya + mode otorisasi mengizinkan offensive ->
                    buka antrian engine ofensif yang cocok (budget tetap).
  FASE 4 PROVE    : temuan kandidat ada -> serahkan ke verdict ladder
                    (bukti minimal -> cease).

Deterministik: keputusan dari isi graph saja; tanpa LLM. Tanpa otorisasi
offensive, eskalasi BERHENTI DI FASE 2 selamanya (fail-closed).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

FASE_PROBE = "PROBE"
FASE_PATTERN = "PATTERN"
FASE_ESCALATE = "ESCALATE"
FASE_PROVE = "PROVE"

# pola -> antrian engine ofensif yang cocok (nama registry)
_UNLOCK: list[tuple[str, tuple[str, ...]]] = [
    ("login-form", ("auth_login", "lockout", "register", "reset_enum",
                    "auth_bypass_matrix")),
    ("json-api-params", ("bola", "idor_mass_endpoint", "mass_assign",
                         "api_version_diff", "variant_sweep")),
    ("session-cookie", ("session_probe", "cookie_audit", "priv_matrix")),
    ("admin-panel", ("admin_panel", "laravel_panel", "actuator",
                     "header_variant_matrix")),
    ("wp-signature", ("wp_probe", "wp_dataexp", "xmlrpc_probe")),
    ("upload-endpoint", ("traversal", "lfi_read")),
    ("many-params", ("param_miner", "sqli_probe", "xss_probe", "variant_sweep")),
]

_ADMIN_HINTS = ("admin", "dashboard", "manage", "panel", "console")
_UPLOAD_HINTS = ("upload", "media", "file", "attachment")

_API_PATH_RE = re.compile(r"/api(/|\.|$)", re.IGNORECASE)


def _url_path(url: str) -> str:
    """Path dari URL node (bisa absolut atau relatif)."""
    if url.startswith(("http://", "https://")):
        return urlsplit(url).path
    return url


def _segment_match(path: str, hints: tuple[str, ...]) -> bool:
    """Cocokkan hint per SEGMENT path — substring bebas terlalu salah sasaran
    (mis. "file" kena /profile)."""
    for seg in path.lower().split("/"):
        seg = seg.strip()
        if seg and seg.split(".", 1)[0].startswith(hints):
            return True
    return False


def _patterns_in_graph(g) -> dict[str, list[str]]:
    """Deteksi pola dari isi graph; return {pola: [bukti ringkas]}."""
    patterns: dict[str, list[str]] = {}

    for n in g.nodes("ENDPOINT"):
        url = n["id"].split(":", 1)[-1]
        props = n["props"] or {}
        fields = [str(f).lower() for f in (props.get("form_fields") or [])]
        if any("password" in f for f in fields):
            patterns.setdefault("login-form", []).append(url)

    params_by_ep: dict[str, list[str]] = {}
    for e in g.edges("HAS_PARAM"):
        params_by_ep.setdefault(e["src"], []).append(e["dst"])
    for ep_id, params in params_by_ep.items():
        url = ep_id.split(":", 1)[-1]
        if _API_PATH_RE.search(_url_path(url)):
            patterns.setdefault("json-api-params", []).append(url)
        if len(params) >= 3:
            patterns.setdefault("many-params", []).append(url)

    for t in g.nodes("TECHNOLOGY"):
        name = t["id"].split(":", 1)[-1].lower()
        if "session cookie" in name or "jwt" in name:
            patterns.setdefault("session-cookie", []).append(name)
        if "wordpress" in name or "wp-json" in name:
            patterns.setdefault("wp-signature", []).append(name)

    for n in g.nodes("ENDPOINT"):
        url = n["id"].split(":", 1)[-1].lower()
        path = _url_path(url)
        if _segment_match(path, _ADMIN_HINTS):
            patterns.setdefault("admin-panel", []).append(url)
        if _segment_match(path, _UPLOAD_HINTS):
            patterns.setdefault("upload-endpoint", []).append(url)
    return patterns


def escalation_plan(g, offensive_allowed: bool,
                    has_vuln_candidates: bool = False) -> dict:
    """Fase eskalasi berikutnya + antrian engine, dari isi graph saja.

    ``unlocked_by_pattern`` memetakan pola -> engine yang dibukanya (dipakai
    planner untuk menjadwalkan sekali per pola; ``unlocked_engines`` tetap
    gabungan datar untuk konsumsi umum)."""
    patterns = _patterns_in_graph(g)
    n_nodes = len(g.nodes())
    vuln_nodes = len(g.nodes("VULNERABILITY")) + (1 if has_vuln_candidates else 0)
    unlock_by_pattern: dict[str, list[str]] = {}

    if vuln_nodes:
        fase = FASE_PROVE
        unlocked: list[str] = []
    elif not offensive_allowed:
        fase = FASE_PATTERN if patterns else FASE_PROBE
        unlocked = []
    elif patterns and n_nodes >= 3:
        fase = FASE_ESCALATE
        unlocked = []
        for pola in sorted(patterns):
            for eng in _UNLOCK:
                if eng[0] == pola:
                    unlocked.extend(eng[1])
                    unlock_by_pattern[pola] = sorted(eng[1])
        unlocked = sorted(set(unlocked))
    else:
        fase = FASE_PROBE
        unlocked = []
    return {
        "fase": fase,
        "patterns": {k: sorted(set(v))[:8] for k, v in sorted(patterns.items())},
        "unlocked_engines": unlocked,
        "unlocked_by_pattern": unlock_by_pattern,
        "graph_nodes": n_nodes,
        "offensive_allowed": bool(offensive_allowed),
    }
