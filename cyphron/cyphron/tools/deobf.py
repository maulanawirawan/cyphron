"""deobf — Deobfuscation & attribution kit (Fullpower B2, pola kasus lapangan).

Formalisasi alur intel yang terbukti: blob terobfuscate (base64/hex/RC4/XOR/
rot berantai) -> teks asli -> ekstraksi kit phishing -> validasi wallet
anti-FP (base58check WAJIB — regex murni menghasilkan miliaran false
positive) -> pemetaan afiliasi. Pihak sisi-DOM (render + capture) ada di
engine browser_scout; kit ini sisi konten.

Empat engine:
- chain_decoder       : dekoder rantai b64/hex/url/rot13/xor/rc4 (data),
                        marker kit pada hasil = LEAD info.
- wallet_fp_guard     : hanya alamat valid-checksum (base58check BTC/TRON)
                        yang dilaporkan — anti-FP ketat.
- phishing_kit_extract: ekstraksi indikator kit (konfig webhook/telegram/
                        mailer, panel, template) — surface, tanpa klaim.
- affiliate_mapper    : klaster ID afiliasi/kampanye dari URL/konten — data.

Semua deterministik, pasif (tanpa request), zero-FP: tidak ada klaim
"penipuan" — hanya indikator + atribusi teknis.
"""

from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# ----------------------------------------------------------------- decoder


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 standar (klasik, test vector tersedia)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


def _b64_decode(text: str) -> bytes:
    text = re.sub(r"\s+", "", text)
    pad = "=" * (-len(text) % 4)
    return base64.b64decode(text + pad, validate=False)


def _b58_decode(text: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in text:
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError("karakter di luar alphabet base58")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip(alphabet[0]))
    return b"\x00" * pad + raw


def base58check_valid(addr: str) -> bool:
    """Validasi checksum base58check (BTC P2PKH/P2SH, TRON)."""
    try:
        raw = _b58_decode(addr)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] \
        == checksum


def chain_decode(blob: str, chain: list[str], key: str = "") -> bytes:
    """Dekode berantai; urutan = urutan penerapan. rc4/xor pakai key."""
    data = blob.encode("utf-8", errors="replace")
    for step in chain:
        step = step.strip().lower()
        if step in ("b64", "base64"):
            data = _b64_decode(data.decode("utf-8", errors="replace"))
        elif step == "hex":
            clean = re.sub(r"^(?:[0-9a-fA-F]{2})+$", "",
                           data.decode("utf-8", errors="replace")) or \
                data.decode("utf-8", errors="replace")
            data = bytes.fromhex(re.sub(r"\s+", "", clean))
        elif step == "url":
            data = urllib.parse.unquote(
                data.decode("utf-8", errors="replace")).encode("utf-8")
        elif step == "rot13":
            data = data.decode("utf-8", errors="replace")
            data = "".join(
                chr((ord(c) - (65 if c.isupper() else 97) + 13) % 26
                    + (65 if c.isupper() else 97))
                if c.isalpha() else c for c in data).encode("utf-8")
        elif step == "rc4":
            if not key:
                raise ValueError("step rc4 butuh key")
            data = rc4(key.encode("utf-8"), data)
        elif step == "xor":
            if not key:
                raise ValueError("step xor butuh key")
            k = key.encode("utf-8")
            data = bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
        else:
            raise ValueError(f"step tidak dikenal: {step}")
    return data


_KIT_MARKERS = (
    ("eval(", "eval runtime"),
    ("document.write(unescape(", "unescape loader"),
    ("atob(", "atob loader"),
    ("fromCharCode", "charcode builder"),
    ("window.location.replace", "redirector"),
    ("webdriver", "anti-sandbox check"),
)


class ChainDecoderTool(Tool):
    name = "chain_decoder"
    description = ("Dekoder rantai b64/hex/url/rot13/xor/rc4 + marker kit "
                   "pada hasil (pasif, tanpa request).")
    risk_tags = {"passive", "local"}
    source_skill = "deobf-01"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        blob = str(args.get("blob") or "")
        key = str(args.get("key") or "")
        chain = [str(c) for c in (args.get("chain") or ["b64"])]
        if not blob:
            return ToolResult(tool=self.name, ok=False, error="args.blob wajib")
        try:
            data = chain_decode(blob, chain, key)
        except Exception as exc:
            return ToolResult(tool=self.name, ok=False,
                              error=f"decode gagal: {type(exc).__name__}: {exc}")
        try:
            text = data.decode("utf-8")
            decode_ok = True
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")
            decode_ok = False
        markers = [label for pat, label in _KIT_MARKERS if pat in text]
        findings: list[Finding] = []
        if markers:
            f = Finding(
                tool=self.name,
                title=f"Blob terobfuscate memuat loader kit: {', '.join(markers[:4])}",
                severity="info",
                description=(
                    "Setelah didekode rantai " + " -> ".join(chain) + ", "
                    "konten memuat pola loader khas kit phishing/malware: "
                    + ", ".join(markers) + ". Ini INDIKATOR untuk analisis "
                    "lanjutan (LEAD), bukan kesimpulan."),
                recommendation=(
                    "Lanjutkan ekstraksi indikator (phishing_kit_extract) dan "
                    "verifikasi infrastruktur; simpan salinan ter-redaksi."),
                confidence=0.6,
                finding_class="surface",
                status="unconfirmed",
            )
            findings.append(f)
        ctx.world.note(f"chain_decoder: {' -> '.join(chain)} ok "
                       f"({len(data)} byte, {len(markers)} marker)")
        return ToolResult(tool=self.name, ok=True,
                          data={"decoded": text[:20000],
                                "decode_ok": decode_ok, "markers": markers},
                          findings=findings)


# ------------------------------------------------------------ wallet guard
_BTC_RE = re.compile(r"\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,39}\b")
_TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")


class WalletFpGuardTool(Tool):
    name = "wallet_fp_guard"
    description = ("Ekstraksi alamat kripto dengan WAJIB validasi checksum "
                   "base58check (anti-FP) — pasif.")
    risk_tags = {"passive", "local"}
    source_skill = "deobf-02"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        texts = [str(t) for t in (args.get("texts") or [])]
        if args.get("text"):
            texts.append(str(args["text"]))
        if not texts:
            return ToolResult(tool=self.name, ok=False, error="args.texts wajib")
        body = "\n".join(texts)
        candidates = set(_BTC_RE.findall(body)) | set(_TRON_RE.findall(body))
        valid = sorted(a for a in candidates if base58check_valid(a))
        rejected = sorted(candidates - set(valid))
        findings: list[Finding] = []
        if valid:
            f = Finding(
                tool=self.name,
                title=f"Alamat kripto valid-checksum terekspos: {len(valid)} alamat",
                severity="info",
                description=(
                    "Alamat lolos validasi checksum base58check (bukan sekadar "
                    "pola regex — pola saja menghasilkan miliaran false "
                    "positive). Alamat (ter-redaksi sebagian): "
                    + "; ".join(a[:8] + "..." + a[-6:] for a in valid[:5])
                    + ". Konteks: atribusi keuangan indikator."),
                recommendation=(
                    "Laporkan alamat ke pemantau rantai/penyedia intel; "
                    "jangan klaim pemilik tanpa bukti tambahan."),
                confidence=0.9,
                finding_class="surface",
                status="unconfirmed",
            )
            findings.append(f)
        ctx.world.note(f"wallet_fp_guard: {len(valid)} valid, "
                       f"{len(rejected)} kandidat dibuang checksum")
        return ToolResult(tool=self.name, ok=True,
                          data={"valid": valid, "rejected_by_checksum": rejected},
                          findings=findings)


# ------------------------------------------------------------- kit extract
_WEBHOOK_RE = re.compile(
    r"(?i)(?:https?://)?(?:discord(?:app)?\.com/api/webhooks/[\d/[\w\-]+"
    r"|hooks\.slack\.com/services/[\w/]+|api\.telegram\.org/bot"
    r"(\d+):([\w\-]+))")
_TELEGRAM_CHAT_RE = re.compile(r"(?i)chat[ _-]?id['\"]?\s*[:=]\s*['\"]?(-?\d+)")
_MAIL_RE = re.compile(r"(?i)\b(mailto:|smtp[._-]?(?:host|server|user|pass)"
                      r"|sendmail|phpmailer)[^\s]{0,40}")
_PANEL_RE = re.compile(r"(?i)(admin[_-]?(?:panel|area|login)|cpanel|"
                       r"panel[_-]?(?:login|admin))")
_AFF_RE = re.compile(
    r"(?i)[?&](?:ref|aff|affiliate|agent|campaign|utm_campaign|cid|aid|promo)"
    r"=([\w\-]{3,64})")


class PhishingKitExtractTool(Tool):
    name = "phishing_kit_extract"
    description = ("Ekstraksi indikator kit phishing dari konten HTML/JS: "
                   "webhook/telegram, mailer, panel, marker loader — pasif.")
    risk_tags = {"passive", "local"}
    source_skill = "deobf-03"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        texts = [str(t) for t in (args.get("texts") or [])]
        if args.get("html"):
            texts.append(str(args["html"]))
        if args.get("js"):
            texts.append(str(args["js"]))
        if not texts:
            return ToolResult(tool=self.name, ok=False, error="args.texts wajib")
        body = "\n".join(texts)
        webhooks = sorted(set(m.group(0) for m in _WEBHOOK_RE.finditer(body)))
        tg_chats = sorted(set(m.group(1) for m in _TELEGRAM_CHAT_RE.finditer(body)))
        mailers = sorted(set(m.group(1) for m in _MAIL_RE.finditer(body)))[:10]
        panels = sorted(set(m.group(1) for m in _PANEL_RE.finditer(body)))[:10]
        markers = [label for pat, label in _KIT_MARKERS if pat in body]
        redacted = [_redact_url(w) for w in webhooks]
        data = {
            "webhooks_redacted": redacted,
            "webhook_count": len(webhooks),
            "telegram_chat_ids": tg_chats[:10],
            "mailer_hints": mailers,
            "panel_hints": panels,
            "loader_markers": markers,
        }
        findings: list[Finding] = []
        if webhooks or tg_chats:
            f = Finding(
                tool=self.name,
                title=(f"Kit mengirim hasil ke kanan-luar: {len(webhooks)} "
                       f"webhook, {len(tg_chats)} telegram chat-id"),
                severity="info",
                description=(
                    "Konten memuat konfigurasi pengiriman korbannya ke kanal "
                    "penyerang (webhook/telegram). Detail diredaksi (token "
                    "bocor separuh). Ini bukti mekanisme exfil kandungan kit, "
                    "atribusi akun tetap butuh laporan platform."),
                recommendation=(
                    "Laporkan bot/webhook ke platform terkait (Telegram "
                    "@notoscam, Discord trust&safety); sertakan timestamp."),
                confidence=0.75,
                finding_class="surface",
                status="unconfirmed",
            )
            findings.append(f)
        ctx.world.note(f"phishing_kit_extract: {len(webhooks)} webhook, "
                       f"{len(tg_chats)} chat-id, {len(markers)} marker")
        return ToolResult(tool=self.name, ok=True, data=data,
                          findings=findings)


def _redact_url(url: str) -> str:
    return url[:28] + "...[redacted]" if len(url) > 34 else url


class AffiliateMapperTool(Tool):
    name = "affiliate_mapper"
    description = ("Klaster ID afiliasi/kampanye dari URL/konten — atribusi "
                   "jaringan afiliasi (pasif, data).")
    risk_tags = {"passive", "local"}
    source_skill = "deobf-04"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        urls = [str(u) for u in (args.get("urls") or [])]
        body = "\n".join([str(args.get("text") or "")] + urls)
        found: dict[str, list[str]] = {}
        for m in _AFF_RE.finditer(body):
            found.setdefault(m.group(1).lower(), []).append(m.group(0))
        clusters = {k: sorted(set(v))[:5] for k, v in sorted(found.items())}
        ctx.world.note(f"affiliate_mapper: {len(clusters)} ID afiliasi unik")
        return ToolResult(tool=self.name, ok=True,
                          data={"affiliate_ids": clusters,
                                "unique": len(clusters)})
