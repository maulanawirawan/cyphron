"""[SAFETY: 1-request] Email sender surface — kanonik keluarga email.

Skill kanonik hasil konsolidasi F18 (menggantikan spf-strictness-checker,
dkim-selector-checker, mta-sts-checker, dnssec-checker, dns-caa-checker —
semua jadi sub-check di dalam skill ini).

Murni DNS via DoH (dns.google JSON API): NOL trafik ke domain target
untuk seluruh sub-check KECUALI MTA-STS yang butuh SATU GET ke
mta-sts.<domain>/.well-known/mta-sts.txt (inilah 1-request pada safety
class; bila tidak diinginkan, jalankan --no-mta-sts untuk kembali
nol-request). Data publik yang dilihat internet sehari-hari.

Yang dipetakan:
  - SPF (includes vendor, qualifier -all/~all/none) + ketat/tidaknya
  - DMARC (p/sp, warisan org domain RFC 7489 §6.6.3)
  - DKIM selector vendor aktif + sinkron tidaknya dengan SPF
  - MTA-STS (kebijakan TLS SMTP) — 1 GET
  - DNSSEC (flag AD DoH)
  - CAA (type 257 — CA mana yang boleh terbit)

Temuan (verdict ladder — lihat core/findings.py):
  DMARC p=none              -> L1 lead (spoofing tidak ditolak receiver)
  DMARC p=quarantine/reject -> AMAN L0 (baseline teruji)
  DMARC absent              -> L1 lead
  SPF ~all / absent         -> L1 lead; -all -> dicatat sebagai AMAN info
  DKIM selector vendor aktif tapi TIDAK ada di SPF include -> L1 lead
    (kanal terverifikasi di luar inventaris SPF — inkonsistensi)
  Vendor kanal aktif        -> L0 info (inventaris permukaan)
  MTA-STS valid             -> AMAN L0; partial/absent -> L1 lead
  DNSSEC AD=true            -> AMAN L0; AD=false -> SURFACE L0
  CAA absent                -> L1 lead (CWE-306)

Pemakaian:
  python skills/email_sender_surface.py --domain example.go.id \\
      --out findings/tier0-xxx/findings.json
  python skills/email_sender_surface.py --domain example.go.id \\
      --no-mta-sts --out findings.json   # mode nol-request penuh

Semua output TERSIMPAN LOKAL (local-only). Tidak ada pengiriman data ke
mana pun selain query DoH publik + opsi 1 GET MTA-STS.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings
from ua import user_agent  # noqa: E402  # noqa: E402

DOH = "https://dns.google/resolve?name={name}&type={rtype}"
UA = user_agent()
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed
TOOL = "email-sender-surface"

SPF_VENDOR_MAP = [
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("_spf.google.com", "Google Workspace"),
    ("mcsv.net", "MailChimp"),
    ("mlsend.com", "MailerLite"),
    ("mailendo.com", "Mailendo (ESP)"),
    ("_spf.salesforce.com", "Salesforce"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("mailjet.com", "Mailjet"),
    ("sendinblue.com", "Brevo"),
    ("brevo.com", "Brevo"),
    ("amazonses.com", "AWS SES"),
    ("hubspotemail.net", "HubSpot"),
    ("zendesk.com", "Zendesk"),
    ("protonmail", "Proton Mail"),
    ("zohomail", "Zoho Mail"),
]

DKIM_SELECTORS = ["k1", "k2", "k3", "s1", "s2", "selector1", "selector2",
                  "google", "default", "mte1", "mte2", "ml", "ml1",
                  "brevo1", "brevo2", "zoho", "zimbra", "zm", "mail"]

DKIM_VENDOR_HINTS = [
    ("sendgrid.net", "SendGrid"),
    ("mcsv.net", "MailChimp"),
    ("onmicrosoft.com", "Microsoft 365"),
    ("mlsend.com", "MailerLite"),
    ("mailerlite", "MailerLite"),
    ("sendinblue", "Brevo"),
    ("brevo", "Brevo"),
    ("protonmail", "Proton Mail"),
    ("zoho", "Zoho Mail"),
]


def doh(name: str, rtype: str = "TXT",
        timeout: float = 20.0) -> list[tuple[int, str]]:
    """DoH resolve; balikin SEMUA answer sebagai (type, data) — caller
    yang memfilter. CNAME (type 5) dipertahankan karena target CNAME
    selector DKIM adalah bukti vendor (mis. dkim.mcsv.net = MailChimp).
    Kegagalan jaringan dilaporkan apa adanya (fail-closed, bukan kosong
    senyap): dikembalikan sebagai (0, "__doh_error__ ...")."""
    url = DOH.format(name=urllib.parse.quote(name), rtype=rtype)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return [(0, f"__doh_error__ response over "
                            f"{MAX_RESPONSE_BYTES}-byte cap — fail-closed")]
            doc = json.loads(raw.decode())
        return [(a.get("type", 0), a.get("data", ""))
                for a in doc.get("Answer", [])]
    except Exception as exc:
        return [(0, f"__doh_error__ {type(exc).__name__}: {exc}")]


def doh_doc(name: str, rtype: str, extra: str = "",
            timeout: float = 20.0) -> dict | None:
    """DoH resolve — balikin DOKUMEN penuh (butuh flag AD untuk DNSSEC)
    atau None bila gagal (fail-closed: caller tidak boleh membuat klaim)."""
    url = DOH.format(name=urllib.parse.quote(name), rtype=rtype) + extra
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return None
            return json.loads(raw.decode())
    except Exception:
        return None


def txt_records(name: str) -> list[str]:
    """Hanya record TXT (type 16) — CNAME di node _dmarc jangan ikut jadi
    'record' (mencegah FP 'No DMARC' pada domain ber-CNAME)."""
    return [d.replace('"', "")
            for t, d in doh(name, "TXT")
            if t == 16 and not d.startswith("__doh_error__")]


def parse_spf(record: str) -> dict:
    mechs = record.split()[1:] if record.lower().startswith("v=spf1") else []
    includes, ips, other = [], [], []
    for m in mechs:
        low = m.lower()
        if low.startswith("include:"):
            includes.append(m.split(":", 1)[1])
        elif low.startswith(("ip4:", "ip6:")):
            ips.append(m)
        elif low in ("a", "mx") or low.startswith("a:") or low.startswith("mx:"):
            other.append(m)
    qualifier = "-all" if record.rstrip().endswith("-all") else \
        ("~all" if record.rstrip().endswith("~all") else "none")
    return {"includes": includes, "ips": ips, "other": other,
            "qualifier": qualifier}


def parse_dmarc(record: str) -> dict:
    out = {}
    for tag in record.split(";"):
        if "=" in tag:
            k, v = tag.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def classify_include(host: str) -> str:
    low = host.lower()
    for pat, vendor in SPF_VENDOR_MAP:
        if pat in low:
            return vendor
    return "unmapped"


# Suffix TLD ganda yang umum (registrable domain = 3 label). Bukan daftar
# Public Suffix lengkap — cukup untuk kasus .go.id/.co.id/.ac.id dsb; domain
# di luar daftar jatuh ke aturan dua label (aman untuk uji DNS email karena
# query tetap fail-closed bila org domain salah).
MULTI_LABEL_SUFFIXES = {
    "go.id", "co.id", "or.id", "ac.id", "sch.id", "web.id", "my.id",
    "biz.id", "desa.id", "co.uk", "gov.uk", "ac.uk", "com.au", "net.au",
    "co.nz", "co.jp", "or.jp", "ne.jp", "co.in", "com.sg", "com.my",
}


def suffix_len(domain: str) -> int:
    """Jumlah LABEL public-suffix (1 atau 2): 'go.id' = 2, 'com' = 1."""
    labels = domain.split(".")
    tail2 = ".".join(labels[-2:]).lower()
    return 2 if tail2 in MULTI_LABEL_SUFFIXES else 1


def org_domain(domain: str) -> str | None:
    """Registrable/org domain (untuk fallback DMARC RFC 7489 §6.6.3):
    mail.example.go.id -> example.go.id;
    example.go.id -> None (sudah apex)."""
    labels = domain.split(".")
    reg = suffix_len(domain) + 1  # panjang registrable domain dalam label
    if len(labels) <= reg:
        return None
    return ".".join(labels[-reg:])


def org_dmarc_policy(domain: str) -> tuple[str | None, dict | None]:
    """Cari record DMARC org domain (fallback DMARC RFC 7489 §6.6.3):
    untuk subdomain, policy org domain (termasuk tag sp) tetap berlaku.
    Balikin (domain_sumber, parsed) atau (None, None)."""
    org = org_domain(domain)
    if org is None:
        return None, None
    for t in txt_records(f"_dmarc.{org}"):
        if t.lower().startswith("v=dmarc1"):
            return org, parse_dmarc(t)
    return None, None


def finding(domain: str, title: str, sev: str, desc: str, rec: str = "",
            cwe: str | None = None, category: str = "MISC",
            verdict: int = 1, fclass: str = "posture",
            **extra_more) -> dict:
    extra = {"category": category, "safety_class": "1-request"}
    extra.update(extra_more)
    return make_finding(
        tool=TOOL, title=title, severity=sev, description=desc,
        recommendation=rec, cwe=cwe, target_url=domain,
        response=json.dumps({"domain": domain})[:200],
        evidence_kind="dns", finding_class=fclass, confidence=1.0,
        status="confirmed", verdict=verdict, extra=extra)


# --- Sub-check SPF ketat (dulu spf-strictness-checker) ---------------------

def spf_strictness(domain: str, spf_rec: str | None) -> list[dict]:
    rows: list[dict] = []
    if spf_rec is None:
        return rows  # kasus "No SPF" sudah dilaporkan pemanggil
    if spf_rec.rstrip().endswith("-all"):
        rows.append(finding(domain, f"SPF strict on {domain}: -all", "info",
                            f"SPF hard-fail (-all): {spf_rec[:200]} — pengirim "
                            "tak terdaftar ditolak. AMAN.",
                            category="AMAN", verdict=0))
    elif spf_rec.rstrip().endswith("?all"):
        rows.append(finding(domain, f"SPF neutral (?all) on {domain}", "low",
                            f"SPF berakhir ?all: {spf_rec[:200]} — hasil "
                            "pemeriksaan dianggap netral, bukan hard-fail.",
                            rec="Ganti ke -all atau ~all.", cwe="CWE-290"))
    return rows


# --- Sub-check MTA-STS (dulu mta-sts-checker; 1 GET) -----------------------

def fetch_mta_sts(domain: str, timeout: float = 15.0) -> dict:
    """SATU GET ke https://mta-sts.<domain>/.well-known/mta-sts.txt."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status,
                    "body": r.read(4096).decode(errors="replace")}
    except Exception as exc:
        return {"status": None, "error": f"{type(exc).__name__}: {exc}"}


def mta_sts_posture(domain: str, fetched: dict | None = None
                    ) -> tuple[list[dict], int]:
    """Postur MTA-STS: policy via 1 GET + fallback TXT DoH bila fetch
    gagal. Return (rows, jumlah_get_ke_target)."""
    rows: list[dict] = []
    f = fetched if fetched is not None else fetch_mta_sts(domain)
    st, body = f.get("status"), (f.get("body") or "")
    low = body.lower()
    if st == 200:
        has_version = "version:" in low and "sts" in low
        has_mode = any(k in low for k in ("mode: enforce", "mode: testing",
                                          "mode: none"))
        if has_version and has_mode:
            rows.append(finding(domain, f"MTA-STS valid on {domain}", "info",
                                f"mta-sts.txt valid (version+mode) — kebijakan "
                                f"TLS SMTP ditegakkan. Preview: {body[:200]}",
                                category="AMAN", verdict=0))
        elif has_version or "mx:" in low:
            rows.append(finding(domain, f"MTA-STS present on {domain} (partial)",
                                "low",
                                f"mta-sts.txt 200 tapi tidak lengkap (lead): "
                                f"{body[:200]}",
                                rec="Pastikan version: STSv1 + mode: "
                                    "enforce/testing/none + mx:",
                                cwe="CWE-319"))
        else:
            rows.append(finding(domain, f"MTA-STS unexpected body on {domain}",
                                "low",
                                f"mta-sts.txt 200 tapi body tidak sesuai "
                                f"MTA-STS (lead): {body[:200]}",
                                cwe="CWE-319"))
    elif st is None:
        # zero-FP (pelajaran wildcard DNS apple.com): subdomain bisa
        # dijawab record WILDCARD yang bukan MTA-STS — "TXT exists" hanya
        # sah kalau recordnya cocok skema resmi (v=STSv1, RFC 8460)
        sts_txts = [x for x in txt_records(f"_mta-sts.{domain}")
                    if x.strip('"').lower().startswith("v=stsv1")]
        raw_txts = txt_records(f"_mta-sts.{domain}")
        has_txt = bool(sts_txts)
        if not has_txt and raw_txts:
            rows.append(make_finding(
                tool=TOOL, title=f"MTA-STS not determinable on {domain} "
                                 f"(wildcard DNS)",
                severity="info",
                description=f"_mta-sts.{domain} menjawab TXT wildcard "
                            f"({raw_txts[0][:60]}...) yang BUKAN skema "
                            "MTA-STS — status MTA-STS tidak dapat dinilai "
                            "dari DNS (tanpa klaim, fail-closed).",
                target_url=domain,
                evidence_kind="dns", finding_class="posture",
                confidence=1.0, status="unconfirmed", verdict=1,
                extra={"category": "MISC", "safety_class": "1-request"}))
        elif has_txt:
            rows.append(finding(
                domain, f"MTA-STS TXT exists but mta-sts.txt fetch failed "
                        f"on {domain}", "low",
                f"_mta-sts TXT ada tapi mta-sts.txt tidak terambil: "
                f"{str(f.get('error', ''))[:200]} (lead).",
                rec="Pastikan mta-sts.txt dapat diakses via HTTPS.",
                cwe="CWE-319"))
        else:
            rows.append(finding(domain, f"No MTA-STS on {domain}", "low",
                                "Tidak ada MTA-STS (lead): SMTP tanpa "
                                "kebijakan TLS — downgrade STARTTLS "
                                "mungkin.",
                                rec="Publikasikan MTA-STS + TLSRPT.",
                                cwe="CWE-319"))
    else:
        rows.append(finding(domain, f"MTA-STS not found on {domain}: {st}",
                            "info",
                            f"GET {st} — tidak ada MTA-STS (SURFACE).",
                            category="SURFACE", verdict=0))
    return rows, 1


# --- Sub-check DNSSEC (dulu dnssec-checker) --------------------------------

def dnssec_posture(domain: str) -> list[dict]:
    """Postur DNSSEC via flag AD pada DoH (type A, do=1)."""
    doc = doh_doc(domain, "A", extra="&do=1")
    if doc is None:
        return [finding(domain, f"DNSSEC check inconclusive on {domain}",
                        "info",
                        "DoH gagal — tidak ada klaim (fail-closed).",
                        category="MISC", verdict=1)]
    if doc.get("AD"):
        return [finding(domain, f"DNSSEC validated on {domain} (AD=true)",
                        "info",
                        "DoH AD flag true — rantai DNSSEC valid (AMAN).",
                        category="AMAN", verdict=0)]
    return [finding(domain, f"DNSSEC not validated on {domain} (AD=false)",
                    "info",
                    "DoH AD flag false — tidak ada validasi DNSSEC "
                    "(SURFACE, bukan klaim kerentanan).",
                    category="SURFACE", verdict=0)]


# --- Sub-check CAA (dulu dns-caa-checker) ----------------------------------

def caa_posture(domain: str) -> list[dict]:
    """Postur CAA (type 257): CA mana yang boleh menerbitkan sertifikat."""
    answers = doh(domain, "257")
    if answers and str(answers[0][1]).startswith("__doh_error__"):
        return [finding(domain, f"CAA check inconclusive on {domain}",
                        "info",
                        f"DoH gagal: {answers[0][1][:200]} — tidak ada klaim "
                        "(fail-closed).",
                        category="MISC", verdict=1)]
    caa = [d for t, d in answers
           if t == 257 and not str(d).startswith("__doh_error__")]
    if caa:
        txt = " ".join(caa)
        return [finding(domain, f"CAA present on {domain}: {txt[:80]}",
                        "info",
                        f"CAA record ada: {txt[:200]} — penerbitan "
                        "sertifikat dibatasi CA terdaftar. AMAN.",
                        category="AMAN", verdict=0)]
    return [finding(domain, f"No CAA on {domain}", "low",
                    "Tidak ada CAA — CA mana pun bisa menerbitkan "
                    "sertifikat untuk domain ini (lead).",
                    rec='Tambah CAA: 0 issue "letsencrypt.org"',
                    cwe="CWE-306")]


def audit(domain: str, mta_sts: bool = True) -> tuple[list[dict], int]:
    rows: list[dict] = []
    target_gets = 0

    # Warisan org domain (anti-FP): "No DMARC/No SPF pada subdomain" TIDAK
    # boleh dilaporkan sebagai risiko kalau policy org domain (tag sp=,
    # atau p= yang diwarisi subdomain) tetap menolak spoof dari subdomain
    # ini (RFC 7489 §6.6.3). Dihitung SEKALI di awal, dipakai semua seksi.
    org_src, org_d = org_dmarc_policy(domain)
    org_policy = None
    if org_d:
        org_policy = org_d.get("sp") or org_d.get("p") or "<absen>"

    # --- SPF
    spf_rec = None
    for t in txt_records(domain):
        if t.lower().startswith("v=spf1"):
            spf_rec = t
            break
    vendors = {}
    if spf_rec is None:
        mitigasi = ""
        sev_nosspf = "medium"
        if org_policy in ("quarantine", "reject"):
            mitigasi = (f" DMARC org domain ({org_src}) p={org_policy} "
                        "tetap menolak spoof From domain ini karena "
                        "alignment gagal — risiko dimitigasi.")
            sev_nosspf = "low"
        rows.append(finding(domain, f"No SPF record on {domain}", sev_nosspf,
                            "Domain tanpa SPF: server mana pun bisa mengirim "
                            "email dengan From domain ini tanpa melanggar SPF "
                            "(DMARC tetap bisa menutup bila p=reject)."
                            + mitigasi,
                            rec="Publikasikan SPF dengan inventaris sender "
                                "resmi.",
                            cwe="CWE-290"))
    else:
        spf = parse_spf(spf_rec)
        for inc in spf["includes"]:
            vendor = classify_include(inc)
            vendors.setdefault(vendor, []).append(inc)
            rows.append(finding(domain, f"SPF authorizes third-party sender "
                                       f"on {domain}: {vendor} ({inc})",
                                "info",
                                "Kanal kirim email resmi via pihak ketiga — "
                                "setiap kanal adalah akun yang bisa mengirim "
                                "email yang lolos alignment atas nama "
                                "domain.",
                                verdict=0))
        if spf["qualifier"] == "~all":
            rows.append(finding(domain, f"SPF soft-fail (~all) on {domain}",
                                "low",
                                "SPF berakhir ~all: pengirim tak terdaftar "
                                "hanya soft-fail — penerima cenderung tidak "
                                "menolak.",
                                rec="Pertimbangkan -all setelah inventaris "
                                    "sender lengkap dan DMARC enforcement.",
                                cwe="CWE-290"))
        elif spf["qualifier"] == "none":
            rows.append(finding(domain,
                                f"SPF tanpa qualifier all on {domain}", "low",
                                "SPF tidak diakhiri mechanism all — perilaku "
                                "default netral (dianggap neutral), bukan "
                                "hard-fail.",
                                cwe="CWE-290"))
    rows.extend(spf_strictness(domain, spf_rec))

    # --- DMARC
    dmarc_rec = None
    for t in txt_records(f"_dmarc.{domain}"):
        if t.lower().startswith("v=dmarc1"):
            dmarc_rec = t
            break
    if dmarc_rec is None:
        if org_policy in ("quarantine", "reject"):
            tag_src = (f"sp={org_policy}" if "sp" in (org_d or {})
                       else f"p={org_policy} (diwarisi subdomain)")
            rows.append(finding(domain, f"No DMARC record on {domain} "
                                        f"(covered by org domain {org_src}: "
                                        f"{tag_src})", "info",
                                f"Subdomain {domain} tidak punya record DMARC "
                                f"sendiri, tetapi evaluasi DMARC jatuh ke org "
                                f"domain {org_src} yang menetapkan {tag_src} "
                                "— spoof From domain ini TETAP ditolak "
                                "penerima yang menghormati DMARC. Bukan "
                                "risiko aktif.",
                                rec="Opsional: publikasikan DMARC eksplisit "
                                    "per subdomain bila ingin laporan rua "
                                    "terpisah.",
                                category="AMAN", verdict=0))
        else:
            rows.append(finding(domain, f"No DMARC record on {domain}",
                                "medium",
                                "Domain tanpa DMARC: penerima yang menghormati "
                                "DMARC tidak punya instruksi apa pun atas "
                                "email yang gagal SPF/DKIM — spoofing brand "
                                "tidak ditolak.",
                                rec="Publikasikan DMARC mulai p=none + rua, "
                                    "lalu naikkan bertahap ke quarantine/"
                                    "reject.",
                                cwe="CWE-290"))
    else:
        d = parse_dmarc(dmarc_rec)
        policy = d.get("p", "<absen>")
        if policy == "none":
            rows.append(finding(domain, f"DMARC policy p=none on {domain}",
                                "medium",
                                f"DMARC {dmarc_rec[:80]} — policy "
                                "monitor-only: email spoof yang gagal SPF/"
                                "DKIM TIDAK ditolak penerima yang menghormati "
                                "DMARC. Spoofing brand bebas dijalankan.",
                                rec="Roadmap enforcement: p=quarantine lalu "
                                    "p=reject setelah inventaris sender + "
                                    "monitoring rua.",
                                cwe="CWE-290"))
        elif policy in ("quarantine", "reject"):
            rows.append(finding(domain, f"DMARC enforcement active on "
                                        f"{domain}: p={policy}", "info",
                                f"DMARC {dmarc_rec[:80]} — spoof gagal "
                                "alignment ditolak/dikarantina penerima yang "
                                "menghormati DMARC.",
                                category="AMAN", verdict=0))
        if "sp" not in d:
            rows.append(finding(domain, f"DMARC tanpa tag sp (subdomain ikut "
                                        f"p={policy}) on {domain}", "info",
                                "Subdomain mewarisi policy apex — inventaris "
                                "sender subdomain perlu cakup sama.",
                                verdict=0))

    # --- DKIM selector vendor umum (bukti sender aktif)
    # record selector bisa TXT langsung ATAU CNAME ke host vendor
    dkim_active = []
    for sel in DKIM_SELECTORS:
        answers = doh(f"{sel}._domainkey.{domain}", "TXT")
        answers = [a for a in answers if not str(a[1]).startswith("__doh_error__")]
        if not answers:
            continue
        cname = [d for t, d in answers if t == 5]
        txts = [d for t, d in answers if t == 16]
        # Fp6: kunci DKIM yang REVOKED (p= kosong) bukan sender aktif —
        # hanya p= dengan materi kunci non-trivial yang dihitung
        valid_txt = [d for d in txts if re.search(r"p=[A-Za-z0-9+/]{8,}", d, re.I)]
        if not cname and not valid_txt:
            continue
        hint_text = " ".join(cname + valid_txt).lower()
        vendor = next((v for pat, v in DKIM_VENDOR_HINTS if pat in hint_text),
                      f"selector:{sel}")
        sample = (cname[0] if cname else (valid_txt[0] if valid_txt else ""))[:60]
        dkim_active.append((sel, vendor, sample))
    for sel, vendor, sample in dkim_active:
        rows.append(finding(domain, f"Active DKIM sender on {domain}: {vendor} "
                                    f"({sel}._domainkey)", "info",
                            f"Selector DKIM terpasang ({sample}...) — vendor "
                            "ini sedang/tersedia untuk mengirim atas nama "
                            "domain.",
                            verdict=0))
        in_spf = any(vendor.lower() in v.lower() for v in vendors)
        if not in_spf and vendor != f"selector:{sel}":
            rows.append(finding(domain, f"DKIM-verified sender NOT in SPF on "
                                        f"{domain}: {vendor} "
                                        f"({sel}._domainkey)", "low",
                                "Vendor terverifikasi DKIM di domain ini "
                                "tetapi tidak terdaftar di SPF — inventaris "
                                "sender tidak sinkron; kanal bisa lolos DMARC "
                                "via DKIM alignment di luar daftar resmi.",
                                rec="Sinkronkan inventaris sender (SPF "
                                    "include atau hapus verifikasi yang tak "
                                    "dipakai).",
                                cwe="CWE-290"))

    # --- Sub-check MTA-STS (1 GET per domain — safety class 1-request)
    if mta_sts:
        sts_rows, gets = mta_sts_posture(domain)
        rows.extend(sts_rows)
        target_gets += gets

    # --- Sub-check DNSSEC + CAA (DoH murni, 0 trafik ke target)
    rows.extend(dnssec_posture(domain))
    rows.extend(caa_posture(domain))

    return rows, target_gets


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", action="append", required=True,
                    help="domain yang diaudit; boleh diulang")
    ap.add_argument("--out", default="findings.json")
    ap.add_argument("--no-mta-sts", action="store_true",
                    help="lewati sub-check MTA-STS (nol request ke target)")
    args = ap.parse_args()
    rows: list[dict] = []
    total_gets = 0
    for dom in args.domain:
        dom_rows, gets = audit(dom, mta_sts=not args.no_mta_sts)
        rows.extend(dom_rows)
        total_gets += gets
    write_findings(args.out, rows, {"domains": args.domain, "method": "DoH",
                                    "requests": total_gets,
                                    "safety_class": "1-request"})
    aman = sum(1 for r in rows if r.get("category") == "AMAN")
    mode = "nol-request" if args.no_mta_sts else f"{total_gets} GET MTA-STS"
    print(f"{TOOL}: {len(rows)} temuan ({aman} AMAN, {mode}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
