"""cache_deception_probe — Web Cache Deception dua-langkah (tervalidasi
lapangan 2026-09-19 saat hunting RedStorm, metode: langkah-1 & 2 di bawah).

Web Cache Deception (WCD): halaman terautentikasi dapat di-cache CDN/proxy
bila diakses lewat path yang tampak seperti file statis
(`/dashboard/x.css`). Korban (bersesi) membuka path itu -> cache menyimpan
KONTEN TERAUTENTIKASI -> penyerang tanpa sesi meminta path sama dan menerima
konten tersebut.

Kontrak bukti (zero-FP): temuan hanya bila KEDUA langkah terpenuhi,
  langkah 1: GET path .css DENGAN sesi -> 200 + konten member + header cache
             yang memungkinkan penyimpanan (tanpa no-store/private);
  langkah 2: GET path sama TANPA sesi -> 200 + konten member (dari cache).
Tanpa langkah 2 = bukan temuan (kebanyakan app menyetel no-store — benar).
"""

from __future__ import annotations

import re

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_PROBE_SUFFIXES = ("/cx-zz.css", "/cx-zz.js")
_NOT_CACHEABLE = ("no-store", "private")


def _cacheable(headers: dict) -> tuple[bool, str]:
    cc = ""
    cfc = ""
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk == "cache-control":
            cc = v.lower()
        elif lk == "cf-cache-status":
            cfc = v.lower()
    if any(t in cc for t in _NOT_CACHEABLE):
        return False, f"cache-control: {cc}"
    if cfc in ("dynamic",):
        return False, f"cf-cache-status: {cfc}"
    return True, f"cache-control: {cc or '(kosong)'}; cf-cache-status: {cfc or '(tidak ada)'}"


class CacheDeceptionProbeTool(Tool):
    name = "cache_deception_probe"
    description = ("Web Cache Deception dua-langkah: halaman terautentikasi "
                   "ter-cache lewat path statis lalu terbaca tanpa sesi.")
    risk_tags = {"active", "passive"}
    source_skill = "80"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args.get("url") or "").rstrip("/")
        if not base:
            return ToolResult(tool=self.name, ok=False, error="args.url wajib")
        cookie = str(args.get("session_cookie")
                     or next(iter(ctx.sessions.values()), "") or "")
        marker = str(args.get("member_marker") or "")
        probes = [_PROBE_SUFFIXES[0], _PROBE_SUFFIXES[1]]
        candidates: list[dict] = []
        confirmed: list[dict] = []
        note_extra = ""

        if not cookie:
            # tanpa sesi, kedua langkah adalah dua GET anonim yang sama —
            # halaman publik apa pun (atau SPA catch-all) bakal "terkonfirmasi"
            # palsu. WCD hanya bermakna pada halaman TERAUTENTIKASI.
            return ToolResult(tool=self.name, ok=True, data={
                "base": base, "candidates": [], "confirmed": [],
                "note": "dilewati: butuh session_cookie/ctx.sessions — "
                        "tanpa sesi probe tidak valid (anti-FP)",
            }, findings=[])

        # kontrol: konten anonim di path ASLI — jadi pembanding diferensial.
        # Situs yang membalas halaman yang sama untuk SEMUA path (catch-all)
        # tidak boleh lolos sebagai "konten member".
        ctx.throttle()
        st_k, h_k, b_k, _ = http_engine.http_get(base, timeout=ctx.timeout_s)
        ctx.world.observe_response(base, st_k, h_k, b_k, self.name)
        generic_body = (st_k == 200 and b_k and b_k[:400] is not None)

        for suffix in probes:
            url = base + suffix
            ctx.throttle()
            # langkah 1: DENGAN sesi
            hdrs = {"Cookie": cookie} if cookie else {}
            st1, h1, b1, _ = http_engine.http_get(url, timeout=ctx.timeout_s,
                                                  headers=hdrs)
            ctx.world.observe_response(url, st1, h1, b1, self.name)
            if st1 >= 400:
                continue
            ok1, why1 = _cacheable(h1)
            memberish = (len(b1) > 200 and "<html" in b1.lower())
            if marker:
                memberish = memberish and marker.lower() in b1.lower()
            # diferensial: halaman sesi HARUS berbeda dari konten publik
            if generic_body and b1[:400] == b_k[:400]:
                continue
            if not (ok1 and memberish):
                continue
            candidates.append({"url": url, "why": why1, "len": len(b1)})
            ctx.throttle()
            # langkah 2: TANPA sesi — bukti cache tersimpan lintas klien
            st2, h2, b2, _ = http_engine.http_get(url, timeout=ctx.timeout_s)
            ctx.world.observe_response(url, st2, h2, b2, self.name)
            same = (st2 == 200 and len(b2) == len(b1)
                    and b2[:400] == b1[:400])
            if marker and same:
                same = marker.lower() in b2.lower()
            if same:
                confirmed.append({"url": url, "len": len(b2),
                                  "has_marker": bool(marker)})

        findings = [Finding(
            tool=self.name,
            title=f"Web Cache Deception terkonfirmasi: {c['url']}",
            severity="high", cwe="CWE-524",
            description=("Halaman terautentikasi ter-cache pada path statis "
                         "dan konten member terbaca TANPA sesi (dua-langkah "
                         "divalidasi: dengan sesi 200 + cacheable + konten "
                         "berbeda dari halaman publik; tanpa sesi "
                         "mengembalikan konten identik"
                         + (", marker member ada di kedua langkah" if c["has_marker"]
                            else "; TANPA member_marker — verifikasi manual "
                                 "konten member wajib sebelum dipakai")
                         + "). Penyerang bisa membaca cache korban bila korban "
                           "membuka link berakhiran ekstensi statis."),
            recommendation=("Set Cache-Control: private, no-store pada semua "
                            "respons terautentikasi; jangan meng-cache path "
                            "member berdasarkan ekstensi."),
            target_url=c["url"], request="GET " + c["url"],
            response=f"len={c['len']} (identik dengan sesi)",
            confidence=0.9 if c["has_marker"] else 0.55,
            source_skill=self.source_skill,
            status="confirmed" if c["has_marker"] else "unconfirmed",
            evidence_kind="request-response",
        ) for c in confirmed]

        return ToolResult(tool=self.name, ok=True, data={
            "base": base,
            "candidates": candidates,
            "confirmed": confirmed,
            "note": ("tanpa langkah-2 identik = bukan temuan (no-store benar); "
                     "tanpa member_marker temuan tetap kandidat")
                     + note_extra,
        }, findings=findings)
