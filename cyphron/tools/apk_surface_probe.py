"""apk_surface_probe — recon statis APK Android, stdlib-only.

Teknik terbukti lapangan (DANA 2.143/2.144 + Gojek 5.75.2, 2026-09-13):
unzip APK -> sapu dex/assets/resources dengan pola secret Cyphron ->
ekstrak host API ter-hardcode -> (opsional) androguard untuk versi,
sertifikat signing, dan komponen exported. Hasil DANA: intel mgs-gw/
billers/sec.m.dana.id + Firebase tertutup + 4 FP tersaring.

Keamanan & FP-guard:
  - LOKAL + read-only terhadap target (nol trafik ke infra vendor);
  - pola secret dari cyphron.tools.secret_scan.PATTERNS + guard:
    * FILELOOKALIKE: match berbentuk filename (logo.png) dibuang;
    * PEM marker di DEX string-pool = template formatter (blok kosong)
      -> kunci wajib punya body >= 60 char (lesson 13 Sep);
    * kredensial ter-decode wajib printable & mengandung ':' (lesson
      "Basic protection");
  - Google API key/Firebase id = config publik by-design -> dicatat
    sebagai NON-CLAIM, bukan temuan;
  - APK dari mirror = LEAD saja; klaim butuh verifikasi silang ke app
    resmi (versi + fingerprint sertifikat);
  - IP private (10./172.16-31./192.168.) dicatat sebagai dev-leftover,
    bukan temuan.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

try:  # pola resmi Cyphron
    from .secret_scan import PATTERNS as _SECRET_PATTERNS
except Exception:  # pragma: no cover
    _SECRET_PATTERNS = []

_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|id|io|co|net|org|dev|app|cloud|ai)(?:\.[a-z]{2})?)\b", re.I)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")
_FILELOOKALIKE = re.compile(r"\.(png|jpe?g|gif|webp|svg|woff2?|ttf|mp4|ico)\b", re.I)
_PRIV_IP = re.compile(r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b")
_PEM_REAL = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
    r"[\s\S]{60,}?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
_BASIC_LOOSE = re.compile(r"[\"'`]Basic ([A-Za-z0-9+/=]{16,})[\"'`]")
_VENDOR_HOST = re.compile(
    r"(?:gojek|gofood|gobiz|gopay|dana|goto|midtrans|alipay|tokopedia|golabs)", re.I)
_PRIVATE_KEY_LABEL = "private key block"


def _is_printable_cred(decoded: str) -> bool:
    """Guard 'Basic protection' (lesson 14 Sep): kredensial valid harus
    printable dan mengandung pemisah ':' — bukan kata biasa."""
    return bool(decoded) and decoded.isprintable() and ":" in decoded


def _base64_body_len(block: str) -> int:
    """Panjang body PEM di luar marker. DEX string-pool menyimpan '\n'
    sebagai literal backslash-n dalam SATU baris (kasus DANA classes6.dex),
    jadi marker dan newline literal keduanya dibuang sebelum menghitung.
    Template kosong (marker bersebelahan) = body ~0-1 char -> ditolak."""
    body = re.sub(r"-----BEGIN [A-Z ]*KEY-----", "", block)
    body = re.sub(r"-----END [A-Z ]*KEY-----", "", body)
    body = body.replace("\\n", "").replace("\n", "").replace("\r", "")
    return len(body.strip())


class ApkSurfaceProbeTool(Tool):
    name = "apk_surface_probe"
    description = ("Recon statis APK Android (lokal, read-only): host API "
                   "ter-hardcode, kandidat secret dengan FP-guard, "
                   "dev-leftover IP; androguard opsional untuk identitas/"
                   "sertifikat/exported components.")
    risk_tags = {"local", "passive"}
    source_skill = "20"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = Path(str(args.get("path") or ""))
        if not path.is_file():
            return ToolResult(tool=self.name, ok=False,
                              error=f"APK tidak ditemukan: {path}")
        max_bytes = int(args.get("max_entry_bytes", 60 * 1024 * 1024))
        hosts: dict[str, int] = {}
        candidates: list[dict] = []
        urls_sample: set[str] = set()
        scanned = 0

        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith((".png", ".jpg", ".jpeg", ".webp",
                                  ".gif", ".so", ".woff", ".woff2")):
                    continue
                try:
                    data = z.read(name)
                except Exception:
                    continue
                if len(data) > max_bytes:
                    continue
                scanned += 1
                text = data.decode("latin-1", "replace")
                rel = name.rsplit("/", 1)[-1]

                for m in _HOST_RE.finditer(text):
                    h = m.group(1).lower()
                    if _VENDOR_HOST.search(h) or len(h) > 12:
                        hosts[h] = hosts.get(h, 0) + 1
                for m in list(_URL_RE.finditer(text))[:3]:
                    if len(urls_sample) < 25:
                        urls_sample.add(m.group(0)[:140])
                if _PRIV_IP.search(text):
                    candidates.append({"file": rel, "label": "private IP hardcoded",
                                       "severity": "info",
                                       "verdict": "dev-leftover — non-claim (aturan umum)"})
                for label, pattern, severity, _cwe in _SECRET_PATTERNS:
                    if _PRIVATE_KEY_LABEL in label:
                        continue  # ditangani pass khusus di bawah
                    m = pattern.search(text)
                    if not m:
                        continue
                    matched = m.group(0)
                    if _FILELOOKALIKE.search(matched):
                        continue
                    verdict = ("NON-CLAIM (public API key — by design)"
                               if "Google" in label else
                               "LEAD — verifikasi silang app resmi dulu")
                    candidates.append({"file": rel, "label": label,
                                       "severity": severity,
                                       "match": matched[:6] + "***",
                                       "verdict": verdict})
                for m in _BASIC_LOOSE.finditer(text):
                    import base64 as _b64
                    raw = m.group(1)
                    try:
                        dec = _b64.b64decode(
                            raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
                    except Exception:
                        continue
                    if _is_printable_cred(dec):
                        candidates.append({"file": rel, "label": "basic-auth literal",
                                           "severity": "high",
                                           "match": dec[:4] + "***",
                                           "verdict": "LEAD — liveness 1x dulu"})
                for m in _PEM_REAL.finditer(text):
                    block = m.group(0)
                    if _base64_body_len(block) >= 60:
                        candidates.append({"file": rel, "label": _PRIVATE_KEY_LABEL,
                                           "severity": "critical",
                                           "verdict": "LEAD — cek penggunaan kunci"})

        # dedup kandidat per (file, label, match-prefix)
        seen: set[tuple] = set()
        uniq = []
        for c in candidates:
            key = (c["file"], c["label"], c.get("match", ""))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(c)

        top_hosts = sorted(hosts.items(), key=lambda kv: -kv[1])[:30]
        ctx.world.note(
            f"apk_surface_probe: {scanned} entri, {len(uniq)} kandidat, "
            f"{len(hosts)} host")

        # findings HANYA untuk kandidat kritis non-trivial (private key asli)
        findings = [Finding(
            tool=self.name,
            title=f"Hardcoded private key in APK ({c['file']})",
            severity="critical", cwe="CWE-321",
            description="Private key PEM tertanam di artefak APK. "
                        "Kunci dalam binary dapat diekstrak siapa pun.",
            recommendation="Pindahkan operasi kunci ke server/keystore; "
                           "rotasi kunci yang terekspos.",
            file_path=str(path), line_start=None, line_end=None,
            request=None, response=f"block {c.get('match', '')} (redacted)",
            confidence=0.85, source_skill=self.source_skill,
            status="confirmed", evidence_kind="code-line",
        ) for c in uniq if c["label"] == _PRIVATE_KEY_LABEL]

        return ToolResult(tool=self.name, ok=True, data={
            "apk": str(path),
            "entries_scanned": scanned,
            "top_hosts": top_hosts,
            "urls_sample": sorted(urls_sample),
            "candidates": uniq,
            "private_ip_dev_leftover": sum(
                1 for c in uniq if c["label"] == "private IP hardcoded"),
            "note": "recon statis — APK mirror = LEAD; klaim butuh "
                    "verifikasi silang versi+sertifikat ke app resmi",
        }, findings=findings)
