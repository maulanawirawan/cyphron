"""wp_dataexp — WordPress comments/media PII exposure sweep (cease-on-data).

Teknik dari lapangan (2026-09): fleet WordPress sering membiarkan REST
collection comments/media terbuka. /wp/v2/users (wp_probe) membocorkan
username; /wp/v2/comments dan /wp/v2/media bisa membocorkan LEBIH —
author email, nomor telepon, isi komentar pribadi — tanpa autentikasi.
Kalau temuan ini ada di host yang sama dengan user enumeration, severity
naik dari "username-only" menjadi "data exposure".

FP-guards (pelajaran lapangan):
  - author_email TIDAK di-serve WordPress core ke unauth — field itu hanya
    muncul bila plugin/konfigurasi salah; klaim "email exposed" WAJIB karena
    field atau isi, bukan asumsi;
  - pattern image@2x.png / foto@3x.jpg di filename (source_url, guid, slug)
    BUKAN email — domain mirip ekstensi file difilter, field URL-ish skip;
  - semua nilai PII di-mask sebelum masuk evidence (tidak ada dump data user);
  - cease-on-data: begitu PII terbukti, pengambilan data dihentikan.
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urljoin, urlsplit

from . import http_engine
from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_FILELOOKALIKE = re.compile(r"^[0-9]+x(\.[a-z0-9]{2,4})?$", re.I)
_EXT_TAIL = re.compile(r"\.(png|jpe?g|gif|webp|svg|css|js|ico|woff2?|ttf|eot|"
                       r"mp4|mp3|pdf|docx?|xlsx?|zip)\b", re.I)
_PHONE = re.compile(r"(?<![\w.\-])(\+62|62|0)8[1-9][0-9]{6,10}(?![\w.\-])")
_SENSITIVE_FIELDS = {"author_email", "email", "user_email", "phone",
                     "telephone", "no_hp", "alamat", "address", "nik", "dob"}
_URLISH_FIELDS = {"guid", "source_url", "slug", "link", "_links", "url", "href"}


def _mask_email(e: str) -> str:
    local, _, dom = e.partition("@")
    return f"{local[:1]}***@{dom[0] if dom else '?'}***"


def _mask_phone(p: str) -> str:
    return p[:4] + "***" + p[-2:]


def _strip_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s)
    return html.unescape(s)


def _scan_strings(obj, path: str = ""):
    """Yield (field_path, text) untuk semua string, kecuali field URL-ish."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _scan_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _scan_strings(v, path)
    elif isinstance(obj, str):
        if path.split(".")[0] not in _URLISH_FIELDS:
            yield path, obj


def _analyze(body: str) -> dict:
    """Ringkasan ter-redact dari satu collection. Tidak pernah menyimpan PII."""
    out: dict = {"count_items": 0, "fields": [], "sensitive_fields": [],
                 "emails": [], "phones": []}
    if not body.lstrip().startswith(("[", "{")):
        out["note"] = "not-json-collection"
        return out
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            if isinstance(data.get("data"), dict) and "status" in data["data"]:
                out["wp_error"] = data["data"]["status"]
                return out
            data = data.get("data", [])
    except Exception:
        out["note"] = "json-parse-failed"
        return out
    if not isinstance(data, list):
        out["note"] = "unexpected-shape"
        return out
    out["count_items"] = len(data)
    keys: set[str] = set()
    for it in data:
        if isinstance(it, dict):
            keys.update(it.keys())
    out["fields"] = sorted(keys)[:30]
    out["sensitive_fields"] = sorted(keys & _SENSITIVE_FIELDS)
    for i, it in enumerate(data[:20]):
        if not isinstance(it, dict):
            continue
        for fpath, text in _scan_strings(it):
            text = _strip_html(text)
            for m in _EMAIL.finditer(text):
                e = m.group(0)
                dom = e.partition("@")[2]
                if _FILELOOKALIKE.match(dom) or _EXT_TAIL.search(e):
                    continue
                out["emails"].append({"item": i, "field": fpath,
                                      "masked": _mask_email(e)})
            for m in _PHONE.finditer(text):
                out["phones"].append({"item": i, "field": fpath,
                                      "masked": _mask_phone(m.group(0))})
    out["emails"] = out["emails"][:10]
    out["phones"] = out["phones"][:10]
    return out


class WpDataExposureTool(Tool):
    name = "wp_dataexp"
    description = ("WP comments/media PII exposure (email/phone) dengan mask "
                   "wajib + cease-on-data; FP-guard filename lookalike.")
    risk_tags = {"active", "external"}
    source_skill = "manual-bb-06"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        base = str(args["url"]).rstrip("/")
        host = urlsplit(base).hostname or ""
        if not host:
            return ToolResult(tool=self.name, ok=True, data={"skipped": "no-host"})
        findings: list[Finding] = []
        data: dict = {"host": host, "collections": {}}

        def _fetch(path: str, max_body: int = 200_000):
            ctx.throttle()
            st, hd, body, _ms = http_engine.http_get(
                urljoin(base + "/", path.lstrip("/")), timeout=ctx.timeout_s,
                max_body=max_body)
            ctx.world.request_count += 1
            if isinstance(st, int) and st < 500:
                ctx.world.observe_response(urljoin(base + "/", path.lstrip("/")),
                                           st, hd, body, self.name)
            return st, body or ""

        for label, path in (("comments", "/wp-json/wp/v2/comments?per_page=20"),
                            ("media", "/wp-json/wp/v2/media?per_page=20")):
            st, body = _fetch(path)
            if st is None or st in (301, 302, 403, 404, 405):
                st, body = _fetch(f"/?rest_route=/wp/v2/{label}&per_page=20")
            res = _analyze(body)
            data["collections"][label] = res
            pii_fields = res["sensitive_fields"]
            pii_content = res["emails"] or res["phones"]
            if not pii_fields and not pii_content:
                continue
            # CEASE-ON-DATA: bukti cukup — hentikan pengambilan data sekarang
            ctx.world.note(f"wp_dataexp: PII terbukti di {host} {label} — "
                           f"pengambilan data dihentikan")
            if pii_fields:
                findings.append(Finding(
                    tool=self.name,
                    title=f"WordPress {label} REST API serves sensitive fields "
                          f"({', '.join(pii_fields)}) without auth on {host}",
                    severity="high", cwe="CWE-359",
                    description=(
                        f"Collection /wp/v2/{label} pada {host} menyertakan field "
                        f"peka {pii_fields} pada {res['count_items']} item tanpa "
                        f"autentikasi. Nilai di-mask dalam evidence ini dan "
                        f"pengujian dihentikan sesuai cease-on-data; penyerang "
                        f"bisa mengunduh seluruh collection tanpa batasan."),
                    recommendation=(
                        f"Filter field sensitif dari REST response unauth "
                        f"(rest_prepare_{'comment' if label == 'comments' else 'attachment'} "
                        f"filter) dan batasi collection dengan autentikasi."),
                    target_url=host,
                    request=f"GET /wp-json/wp/v2/{label}",
                    response=f"HTTP 200; sensitive fields: {pii_fields} (nilai teredaksi)",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
            if pii_content:
                kind = "email" if res["emails"] else "phone"
                sample = (res["emails"] or res["phones"])[0]
                findings.append(Finding(
                    tool=self.name,
                    title=f"WordPress {label} content exposes {kind} addresses "
                          f"({len(res['emails']) or len(res['phones'])} hits) "
                          f"without auth on {host}",
                    severity="medium", cwe="CWE-359",
                    description=(
                        f"{res['count_items']} item /wp/v2/{label} pada {host} "
                        f"memuat {kind} di konten/caption (contoh teredaksi: "
                        f"{sample['masked']} di field {sample['field']}). Data "
                        f"pihak ketiga terpapar publik tanpa autentikasi; "
                        f"pengujian dihentikan setelah bukti (cease-on-data)."),
                    recommendation=(
                        "Moderasi konten media/komentar, sembunyikan collection "
                        "publik, dan bersihkan PII historis."),
                    target_url=host,
                    request=f"GET /wp-json/wp/v2/{label}",
                    response=f"HTTP 200; hits teredaksi (max 10 disimpan)",
                    confidence=1.0, source_skill=self.source_skill,
                    status="confirmed", evidence_kind="request-response"))
            break  # cease-on-data: satu bukti cukup, hentikan sweep
        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
