"""blind — Blind Re-producer: validator independen level-5.

Prinsip: penemu tidak boleh menjadi satu-satunya sumber kebenaran. Fungsi
ini mereproduksi temuan dari EVIDENCE SAJA (claim + request tersimpan),
tanpa reasoning penemunya:

- GET-only: hanya temuan ber-request GET yang direplay otomatis (aman —
  tanpa POST/payload ulang).
- Marker = potongan unik respons lama; lulus bila marker muncul kembali
  pada respons baru DENGAN status sama (anti catch-all: status + isi).
- Hasil di-attach sebagai evidence kind "blind" -> verdict naik ke
  BLIND_VALIDATED. Kegagalan replay TIDAK menolak temuan (catat saja);
  penolakan tetap hak quorum.
"""

from __future__ import annotations

import re

from .findings import Finding
from .tools import http_engine

_MARKER_LEN = 24
_MARKER_MIN_BODY = 12


def _request_url(finding: Finding) -> str | None:
    req = (getattr(finding, "request", "") or "")
    m = re.match(r"GET\s+(\S+)", req, re.I)
    if m:
        return m.group(1)
    url = getattr(finding, "target_url", "") or ""
    return url or None


def _old_status(finding: Finding) -> int | None:
    """Status HTTP asli dari field response (format umum engine: 'HTTP 200; ...')."""
    resp = (getattr(finding, "response", "") or "").strip()
    m = re.match(r"HTTP/?[\d.]*\s*(\d{3})", resp, re.I)
    return int(m.group(1)) if m else None


def _old_marker(finding: Finding) -> str | None:
    resp = (getattr(finding, "response", "") or "")
    body = resp.strip()
    if len(body) < _MARKER_MIN_BODY:
        return None
    # ambil potongan tengah respons lama: lebih khas daripada awal/akhir
    start = max(0, (len(body) // 2) - (_MARKER_LEN // 2))
    return body[start:start + _MARKER_LEN]


def replay(finding: Finding, ctx, timeout: float | None = None) -> dict:
    """Coba reproduksi buta satu temuan GET. Return laporan replay.

    `ctx` hanya dipakai untuk throttle/request_count/redaksi — bukan untuk
    mengambil reasoning penemu (itu inti "blind")."""
    result = {"attempted": False, "match": False, "reason": ""}
    if (getattr(finding, "request", "") or "").upper().startswith(("POST", "PUT", "PATCH", "DELETE")):
        result["reason"] = "non-GET: blind replay otomatis tidak dijalankan"
        return result
    url = _request_url(finding)
    marker = _old_marker(finding)
    old_status = _old_status(finding)
    if not url or not marker or old_status is None:
        result["reason"] = ("evidence tidak cukup (butuh request GET + respons lama "
                            "dengan status HTTP terekam)")
        return result
    try:
        ctx.throttle()
        st, hd, body, _ms = http_engine.http_get(
            url, timeout=timeout or ctx.timeout_s, follow_redirects=False)
    except Exception as exc:
        result["reason"] = f"replay gagal: {type(exc).__name__}"
        return result
    result["attempted"] = True
    result["status"] = st if isinstance(st, int) else -1
    result["marker"] = marker
    marker_found = marker in (body or "")
    # anti catch-all: marker + status HARUS sama (docstring: "status + isi")
    if result["status"] != old_status:
        result["reason"] = (f"status berubah (asli {old_status}, replay "
                            f"{result['status']}) — kemungkinan catch-all/error")
    elif marker_found:
        result["match"] = True
        finding.attach_evidence("blind", {
            "replayed_url": url, "marker": marker,
            "status": result.get("status"), "mode": "GET-blind",
        })
        ctx.world.note(f"blind re-producer: {finding.id} reproduksi ulang "
                       f"(marker cocok, status {old_status}) -> BLIND_VALIDATED")
    else:
        result["reason"] = "marker tidak muncul pada replay (state berubah?)"
    return result


def replay_all(findings: list[Finding], ctx, cap: int = 10) -> list[dict]:
    out = []
    for f in findings:
        if len(out) >= cap:
            break
        req = (getattr(f, "request", "") or "").upper()
        if req.startswith(("POST", "PUT", "PATCH", "DELETE")):
            continue  # non-GET tidak memakan jatah cap
        out.append({"id": getattr(f, "id", ""), **replay(f, ctx)})
    return out
