"""favicon_hash — fingerprint favicon (murmur3 gaya Shodan http.favicon.hash)
(CWE-200, info surface, pasif).

Roadmap: "hash favicon -> pemetaan infrastruktur shodan-style (pasif)".
Engine: GET /favicon.ico (atau args.path) 1x, hitung murmur3(base64(body))
+ md5 — hash dipakai manual di shodan/fofa untuk menemukan host lain
milik infra yang sama. TIDAK ada query ke shodan (pasif penuh; kredensial
API tidak diminta).
Guard: favicon 404/catch-all = skipped; body >= 32 bytes; hasil = surface
intel (hash saja — tidak ada akses ke hasil pencarian).
"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import urljoin

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | \
            (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 2**32 if h1 >= 2**31 else h1


class FaviconHashTool(Tool):
    name = "favicon_hash"
    description = ("Fingerprint favicon (mmh3 gaya Shodan + md5) untuk "
                   "pemetaan infrastruktur manual — pasif, surface intel.")
    risk_tags = {"passive"}
    source_skill = "bounty-low-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "").rstrip("/")
        path = str(args.get("path") or "/favicon.ico")
        if not base:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            ctx.throttle()
            st, _h, body, _ms = http_engine.http_get(url,
                                                     timeout=ctx.timeout_s)
        except Exception as e:
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"fetch-error: {type(e).__name__}"})
        ctx.world.request_count += 1
        if st >= 400 or len(body or "") < 32 or "<html" in (body or "")[:200].lower():
            return ToolResult(tool=self.name, ok=True, data={
                "skipped": f"favicon tidak tersedia (status {st})"})
        b64 = base64.encodebytes(body.encode("latin-1") if
                                 isinstance(body, str) else body)
        mmh3_hash = _mmh3_32(b64)
        md5_hash = hashlib.md5(
            body.encode("latin-1") if isinstance(body, str) else body
        ).hexdigest()
        data = {"favicon_url": url, "mmh3_shodan": mmh3_hash, "md5": md5_hash,
                "bytes": len(body)}
        findings = [Finding(
            tool=self.name,
            title=f"Favicon fingerprint: mmh3={mmh3_hash} on {base}",
            severity="info", cwe="CWE-200",
            description=(f"Favicon {url} memberi fingerprint mmh3 "
                         f"(gaya Shodan http.favicon.hash)={mmh3_hash}, "
                         f"md5={md5_hash}. Cari hash ini di mesin pencari "
                         f"IoT/asset (shodan/fofa) untuk menemukan host lain "
                         f"bertanda sama — mungkin staging/non-publik yang "
                         f"terkait. Pasif: TIDAK ada query API yang dikirim; "
                         f"hasil = lead untuk direview manual."),
            recommendation=("Tidak ada mitigasi wajib — gunakan sebagai OSINT "
                            "untuk inventaris aset sendiri; konsider favicon "
                            "unik per-aplikasi bila ingin menyulitkan "
                            "pemetaan."),
            target_url=url, request=f"GET {path}",
            response=f"mmh3={mmh3_hash}; md5={md5_hash}; bytes={len(body)}",
            confidence=1.0, source_skill=self.source_skill,
            status="confirmed", evidence_kind="file",
            finding_class="surface")]
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
