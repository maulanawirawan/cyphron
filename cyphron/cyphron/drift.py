"""drift — Attack Surface Drift (Cyphron Intelligence Fabric).

Continuous pentesting bukan "scan ulang semuanya tiap minggu": mesin harus
memahami APA YANG BERUBAH sejak baseline dan menyaring perubahan itu menurut
relevansi keamanan, sehingga re-scan tertarget mengejar perubahan berisiko,
bukan dunia penuh.

diff_surface(old, new) menerima dua snapshot permukaan (list of dicts dengan
minimal {"url"}, opsional {"status", "params": [...]}) — sumbernya bisa
world-model dump, census JSON, atau hasil engine apapun. Output:

  added   : url baru          -> klasifikasi relevansi (auth/admin/config/...)
  removed : url hilang
  changed : status berubah    -> potensi regresi kontrol atau fitur baru
  counts  + priority queue (added/changed urut relevansi)

Deterministik, stdlib-only, tanpa I/O (pemanggil memuat snapshot sendiri).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

__all__ = ["classify_relevance", "diff_surface", "prioritize"]

# path keyword -> (tag, relevance)
_RULES: list[tuple[str, str, str]] = [
    ("admin", "admin-panel", "high"),
    ("logout", "auth-action", "medium"),
    ("login", "auth", "high"),
    ("signin", "auth", "high"),
    ("auth", "auth", "high"),
    ("register", "auth", "medium"),
    ("password", "auth", "high"),
    ("token", "identity", "high"),
    ("oauth", "identity", "high"),
    ("jwt", "identity", "high"),
    ("session", "identity", "medium"),
    ("export", "data-exfil", "high"),
    ("dump", "data-exfil", "high"),
    ("backup", "data-exfil", "high"),
    ("upload", "upload", "high"),
    ("config", "config", "high"),
    (".env", "config", "high"),
    (".git", "config", "high"),
    ("debug", "config", "medium"),
    ("bucket", "storage", "medium"),
    ("s3", "storage", "medium"),
    ("graphql", "api", "medium"),
    ("api", "api", "low"),
    ("swagger", "api-docs", "low"),
    ("openapi", "api-docs", "low"),
]


def classify_relevance(url: str) -> tuple[str, list[str]]:
    """Return (relevance, tags). 'high' menang bila >1 kelas peka muncul."""
    path = urlsplit(url).path.lower() if "//" in url or urlsplit(url).path else url.lower()
    tags: list[str] = []
    relevance = "low"
    for kw, tag, rel in _RULES:
        if kw in path:
            tags.append(tag)
            if rel == "high":
                relevance = "high"
            elif rel == "medium" and relevance != "high":
                relevance = "medium"
    if len([t for t in tags if t in ("auth", "admin-panel", "config", "data-exfil")]) >= 2:
        relevance = "high"
    return relevance, tags


def diff_surface(old: list[dict], new: list[dict]) -> dict:
    """Bandingkan dua snapshot permukaan. Deterministik (urut url)."""
    def index(rows: list[dict]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in rows or []:
            url = (r or {}).get("url")
            if url:
                out[url] = r
        return out

    old_i, new_i = index(old), index(new)
    added, removed, changed = [], [], []
    for url in sorted(set(new_i) - set(old_i)):
        rel, tags = classify_relevance(url)
        row = dict(new_i[url])
        row.update({"relevance": rel, "tags": tags})
        added.append(row)
    for url in sorted(set(old_i) - set(new_i)):
        rel, _tags = classify_relevance(url)
        removed.append({"url": url, "relevance": rel})
    for url in sorted(set(old_i) & set(new_i)):
        o, n = old_i[url], new_i[url]
        os_, ns_ = o.get("status"), n.get("status")
        if os_ is not None and ns_ is not None and os_ != ns_:
            rel, tags = classify_relevance(url)
            changed.append({"url": url, "old_status": os_, "new_status": ns_,
                            "relevance": rel, "tags": tags,
                            "note": _status_note(os_, ns_)})
    return {
        "added": added, "removed": removed, "changed": changed,
        "counts": {"added": len(added), "removed": len(removed),
                   "changed": len(changed)},
        "high_priority": [r for r in (added + changed) if r.get("relevance") == "high"],
    }


def prioritize(drift: dict, limit: int = 10) -> list[dict]:
    """Antrian re-scan tertarget: high dulu, lalu medium/low, urut url."""
    rows = [r for r in drift.get("added", []) + drift.get("changed", [])]
    rank = {"high": 0, "medium": 1, "low": 2}
    rows.sort(key=lambda r: (rank.get(r.get("relevance", "low"), 3), r.get("url", "")))
    return rows[:limit]


def _status_note(old: int, new: int) -> str:
    if old in (401, 403) and new == 200:
        return "kontrol akses HILANG (dulu terproteksi, sekarang terbuka)"
    if old == 200 and new in (401, 403, 404):
        return "permukaan ditutup/berpindah (bukan risiko)"
    if old == 404 and new == 200:
        return "fitur/endpoint baru menyala"
    if new >= 500:
        return "endpoint baru sehat? error 5xx saat census"
    return "status berubah"
