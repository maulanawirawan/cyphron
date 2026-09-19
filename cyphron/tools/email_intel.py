"""email_intel — triage header email phishing/BEC (offline, pasif).

Membaca pesan mentah (.eml) yang diberikan user dan memeriksa header
secara deterministik:
  - hasil autentikasi seperti yang dilaporkan header (SPF/DKIM/DMARC) —
    klaim infrastruktur penerima, tidak diverifikasi ulang (tanpa jaringan);
  - ketidakcocokan Reply-To / Return-Path vs domain From;
  - display-name impersonasi (token organisasi/jabatan + domain freemail);
  - domain punycode/IDN (xn--) di alamat;
  - kata dorong urgensi/kerahasiaan di subject (sinyal lemah);
  - brand lookalike bila user memberi daftar domain/brand sah.

Semua keluaran = LEAD (status unconfirmed, finding_class info). Keputusan
akhir tetap di tangan analisis (skill 78-deteksi-phishing-bec). Engine ini
TIDAK melakukan koneksi jaringan apa pun.
"""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from email.utils import getaddresses

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

_FREEMAIL_SUFFIX = (
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.id", "ymail.com",
    "hotmail.com", "hotmail.co.id", "outlook.com", "outlook.co.id",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mail.com",
    "proton.me", "protonmail.com", "zoho.com", "yandex.com", "gmx.com",
    "gmx.de", "ymail.co.id",
)

_ORG_ROLE_TOKENS = (
    "pt", "cv", "bank", "corp", "corporation", "company", "ltd", "limited",
    "inc", "llc", "enterprise", "group",
    "ceo", "cfo", "coo", "cto", "director", "direktur", "direksi",
    "president", "komisaris", "owner", "pemilik",
    "finance", "keuangan", "accounting", "akunting", "payroll", "treasury",
    "hr", "hrd", "personalia", "procurement", "purchasing", "pengadaan",
    "manajer", "manager", "pimpinan", "admin", "administrator",
)

_URGENT_PATTERNS = (
    "segera", "mendesak", "urgent", "rahasia", "confidential", "sensitive",
    "jangan beri tahu", "jangan beritahu", "perubahan rekening",
    "rekening baru", "no. rekening baru", "transfer sekarang",
    "pembayaran segera", "wire transfer", "immediately", "last chance",
    "verify your account", "verifikasi akun anda", "akun akan diblokir",
)

_LABEL_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)")


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in addr else ""


def _is_freemail(domain: str) -> bool:
    return domain in _FREEMAIL_SUFFIX


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


class EmailIntelTool(Tool):
    name = "email_intel"
    description = ("triage header email phishing/BEC — offline, pasif; "
                   "semua hasil = LEAD untuk analisis manual.")
    risk_tags = {"passive"}
    source_skill = "78-deteksi-phishing-bec"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw = args.get("raw_email") or ""
        path = args.get("path") or ""
        if not raw and path:
            try:
                raw = open(path, "r", encoding="utf-8", errors="replace").read()
            except OSError as e:
                return ToolResult(tool=self.name, ok=False,
                                  error=f"gagal baca {path}: {e}")
        if not raw.strip():
            return ToolResult(tool=self.name, ok=False,
                              error="args.raw_email / args.path wajib")

        try:
            msg = Parser(policy=policy.default).parsestr(raw)
        except Exception as e:
            return ToolResult(tool=self.name, ok=False,
                              error=f"pesan tidak ter-parse: {e}")
        if not msg.get("From"):
            return ToolResult(tool=self.name, ok=False,
                              error="header From tidak ada")

        from_addrs = getaddresses(msg.get_all("From") or [])
        from_addr = from_addrs[0][1] if from_addrs else ""
        from_domain = _domain_of(from_addr)
        if not from_domain:
            return ToolResult(tool=self.name, ok=False,
                              error="alamat From tidak terbaca")

        replytos = getaddresses(msg.get_all("Reply-To") or [])
        return_path = (msg.get("Return-Path") or "").strip().strip("<>")
        rp_domain = _domain_of(return_path)
        subject = str(msg.get("Subject") or "")
        received = msg.get_all("Received") or []
        ar_values = msg.get_all("Authentication-Results") or []

        leads: list[dict] = []

        # 1. hasil autentikasi yang dilaporkan header
        auth: dict[str, str] = {}
        for val in ar_values:
            for mech, res in _LABEL_RE.findall(val):
                cur = auth.get(mech.lower())
                if cur is None or res in ("fail", "softfail", "none"):
                    auth[mech.lower()] = res
        if auth.get("dmarc") == "fail" or auth.get("spf") == "fail":
            leads.append({
                "kind": "auth_fail",
                "confidence": 0.75,
                "detail": f"Authentication-Results melaporkan gagal: {auth}",
            })

        # 2. Reply-To domain beda dengan From
        rt_domains = {_domain_of(a) for _n, a in replytos if a}
        rt_foreign = {d for d in rt_domains if d and d != from_domain}
        if rt_foreign:
            leads.append({
                "kind": "replyto_mismatch",
                "confidence": 0.8,
                "detail": (f"Reply-To mengarah ke domain lain "
                           f"({', '.join(sorted(rt_foreign))}) padahal From "
                           f"{from_domain} — balasan akan lewat ke sana."),
            })

        # 3. Return-Path (envelope) beda domain dengan From
        if rp_domain and rp_domain != from_domain and not _is_freemail(rp_domain):
            leads.append({
                "kind": "returnpath_mismatch",
                "confidence": 0.5,
                "detail": (f"Return-Path domain {rp_domain} ≠ From "
                           f"{from_domain} — perlu penjelasan di hop pertama."),
            })

        # 4. display-name impersonasi
        display = (from_addrs[0][0] if from_addrs else "").strip()
        dtok = _tokens(display)
        org_hits = [t for t in _ORG_ROLE_TOKENS if t in dtok]
        if display and org_hits and _is_freemail(from_domain):
            leads.append({
                "kind": "displayname_impersonation",
                "confidence": 0.8,
                "detail": (f"display name '{display}' membawa token "
                           f"organisasi/jabatan ({', '.join(org_hits[:4])}) "
                           f"tapi dikirim dari freemail ({from_domain})."),
            })

        # 5. punycode / IDN
        all_domains = {from_domain} | rt_foreign | ({rp_domain} if rp_domain else set())
        puny = sorted(d for d in all_domains if "xn--" in d)
        if puny:
            leads.append({
                "kind": "punycode_domain",
                "confidence": 0.85,
                "detail": ("domain IDN/punycode terdeteksi "
                           f"({', '.join(puny)}) — periksa homograf."),
            })

        # 6. brand lookalike (butuh daftar sah dari user)
        brand_words = [str(w).lower() for w in (args.get("brand_words") or [])]
        brand_domains = [str(d).lower() for d in (args.get("brand_domains") or [])]
        if brand_words:
            fd_tokens = set(_tokens(from_domain.replace(".", " ")))
            brand_hit = [w for w in brand_words if w in fd_tokens]
            if brand_hit and from_domain not in brand_domains:
                leads.append({
                    "kind": "brand_lookalike",
                    "confidence": 0.75,
                    "detail": (f"domain pengirim memuat brand "
                               f"'{', '.join(brand_hit)}' tapi bukan domain "
                               f"sah yang diberikan."),
                })

        # 7. urgensi/kerahasiaan di subject (sinyal lemah)
        slow = subject.lower()
        urg = [p for p in _URGENT_PATTERNS if p in slow]
        if urg:
            leads.append({
                "kind": "urgency_subject",
                "confidence": 0.35,
                "detail": f"subject memuat frasa dorong: {urg[:4]}",
            })

        # 8. brand word di display name tapi domain asing
        if brand_words and display:
            dn_hits = [w for w in brand_words if w in dtok]
            if dn_hits and from_domain not in brand_domains and not _is_freemail(from_domain):
                leads.append({
                    "kind": "brand_lookalike",
                    "confidence": 0.6,
                    "detail": (f"display name memuat brand "
                               f"'{', '.join(dn_hits)}' tapi domain "
                               f"{from_domain} bukan domain sah."),
                })

        first_hop = ""
        if received:
            m = re.search(r"(?i)from\s+([a-z0-9._-]+\.[a-z]{2,})", received[-1])
            if m:
                first_hop = m.group(1)

        data = {
            "from": f"{display} <{from_addr}>" if display else from_addr,
            "from_domain": from_domain,
            "reply_to": [a for _n, a in replytos],
            "return_path": return_path or None,
            "auth_reported": auth or None,
            "received_hops": len(received),
            "first_hop": first_hop or None,
            "leads": leads,
            "note": ("header-only; autentikasi = klaim infrastruktur "
                     "penerima, tidak diverifikasi ulang (pasif)"),
        }

        findings = [Finding(
            tool=self.name,
            title=f"email lead: {ld['kind']}",
            severity="info",
            cwe="CWE-290" if ld["kind"] != "urgency_subject" else None,
            description=(f"{ld['detail']} Sinyal dari header pesan — "
                         f"butuh validasi manual (skill "
                         f"{self.source_skill})."),
            recommendation=("Validasi silang: verifikasi kanal kedua ke "
                            "pengirim sah, karantina pesan sejenis, cek "
                            "penerima lain; jangan konfrontasi pengirim."),
            request="header-only",
            response=ld["detail"][:200],
            confidence=ld["confidence"],
            source_skill=self.source_skill,
            status="unconfirmed",
            evidence_kind="header",
            finding_class="info",
        ) for ld in leads]

        return ToolResult(tool=self.name, ok=True, data=data, findings=findings)
