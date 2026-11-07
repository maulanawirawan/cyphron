"""[AUDIT: read-only] ioc_defang — ekstraksi, normalisasi, dedup, dan
defang/refang IOC dari teks + render pola indikator STIX 2.1.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/building-ioc-defanging-and-sharing-pipeline' (#0289) — atribusi
ide; lisensi sumber Apache-2.0. Dibangun from scratch TANPA menyalin
kode sumber itu. NOL jaringan: input teks/hasil feed dibaca lokal;
panggilan reputasi (VT/URLScan/sandbox) dan pengiriman ke TAXII/MISP
TIDAK dilakukan tool ini — outputnya bahan baku untuk pipeline itu.

Kemampuan (deterministik, terurut, nol jaringan):
  refang      kembalikan bentuk ter-defang umum: hxxp(s):// -> http(s),
              [.] (.) [dot] (dot) -> '.', [:] -> ':', [@] [at] (at) ->
              '@' — supaya ekstraksi menemukan IOC yang sudah dikutip
              dari laporan lain.
  extract     klasifikasi multi-tipe dari teks bebas: url, ipv4, domain,
              email, md5, sha1, sha256. Domain milik host URL dan domain
              email TIDAK diulang di bucket domain (dedup lintas tipe).
              Hash di-validasi panjang persis (32/40/64 hex) dan
              di-lowercase; domain di-lowercase + titik akhir dibuang;
              URL dibuang tanda baca penutup kalimat yang menempel.
  defang      render aman untuk dibaca manusia: skema http(s) -> hxxp(s),
              titik pada host/domain/IP -> [.], '@' email -> [@]. Hash
              tidak aktif — dibiarkan apa adanya. Penggantian host pakai
              batas kata (tidak merusak kata lain yang mengandungnya);
              sisa skema aktif di-defang catch-all di akhir sehingga
              TIDAK ADA skema http(s):// yang tertinggal aktif.
  stix        pola indikator STIX 2.1 per IOC (pattern_type 'stix'):
              ipv4-addr / domain-name / url / email-addr / file:hashes;
              quote tunggal pada nilai di-escape gaya STIX.

Fail-closed & disiplin keluaran:
  - tanpa --text/--file                       -> exit 2
  - file tidak ada / melebihi 8 MB            -> exit 2
  - biner dibaca errors='replace' dan dicatat di meta
  - output JSON terurut deterministik (setiap list sorted)
  - allowlist (--allowlist, domain per baris) hanya membuang domain
    EXACT/ber-suffix — tidak pernah menyembunyikan tipe lain

Pemakaian:
  python tools/ioc_defang.py --file laporan.txt --out iocs.json
  python tools/ioc_defang.py --text "kontak admin[@]evil[.]com" --stix
  python tools/ioc_defang.py --file laporan.txt --emit-defanged
Exit: 0 selesai; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "cyphron.ioc-defang/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

IOC_TYPES = ("url", "ipv4", "domain", "email", "md5", "sha1", "sha256")

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`\[\]{}|\\^]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE)
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")


def refang_text(text: str) -> str:
    """Kembalikan defang umum ke bentuk aktif (untuk ekstraksi).

    Pair 'xx' WAJIB pada protokol (hxxp/hXXps) — token normal seperti
    'hp' atau 'php' tidak pernah tersentuh.
    """
    out = re.sub(r"\bh(?:xx)(ps?)\b",
                 lambda m: "ht" + ("tps" if m.group(1) == "ps" else "tp"),
                 text, flags=re.IGNORECASE)
    out = re.sub(r"h(?:tt)?p\s*:\s*/\s*/", "http://", out,
                 flags=re.IGNORECASE)
    for dot in ("[.]", "(.)", "[dot]", "(dot)"):
        out = out.replace(dot, ".")
    out = out.replace("[:]", ":")
    for at in ("[@]", "[at]", "(at)"):
        out = out.replace(at, "@")
    return out


# ------------------------------------------------------------ normalisasi
def _normalize_url(u: str) -> str:
    u = u.strip().rstrip(".,;:!?)\"'")
    # port kosong (sisa refang 'host[:]/') dibuang; port terisi dibiarkan
    m = re.match(r"^([a-z]+://)([^/?#\s]*)(.*)$", u, re.IGNORECASE)
    if m:
        u = m.group(1) + m.group(2).rstrip(":") + m.group(3)
    return u


def _normalize_host(h: str) -> str:
    return h.strip().lower().rstrip(".")


def _host_of(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/@\s]+)", url, re.IGNORECASE)
    return m.group(1) if m else ""


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str:
    """Pola indikator STIX 2.1 untuk satu IOC."""
    v = _stix_escape(value)
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{v}']"
    if ioc_type == "md5":
        return f"[file:hashes.'MD5' = '{v}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{v}']"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{v}']"
    raise ValueError(f"tipe IOC tak dikenal: {ioc_type}")


# ------------------------------------------------------------ defang
def defang_value(ioc_type: str, value: str) -> str:
    """Render aman satu IOC untuk konsumsi manusia."""
    if ioc_type == "url":
        m = re.match(r"^(https?)://([^/@\s]+)(.*)$", value,
                     re.IGNORECASE | re.DOTALL)
        if not m:
            return value
        scheme, host, rest = m.groups()
        new_scheme = "hxxps" if scheme.lower() == "https" else "hxxp"
        return f"{new_scheme}://{host.replace('.', '[.]')}{rest}"
    if ioc_type in ("ipv4", "domain"):
        return value.replace(".", "[.]")
    if ioc_type == "email":
        local, _, dom = value.rpartition("@")
        return f"{local}[@]{dom.replace('.', '[.]')}"
    return value  # hash tidak aktif


def defang_text(text: str, iocs: dict[str, list[str]] | None = None
                ) -> str:
    """Defang semua IOC di dalam teks.

    Urutan: URL utuh -> email -> host (domain+IP+host URL+domain email,
    batas kata, terpanjang dulu) -> catch-all skema agar tak ada
    http(s):// aktif tersisa. Teks di-refang dulu agar bentuk ter-defang
    tidak ter-defang dua kali.
    """
    raw = refang_text(text)
    if iocs is None:
        iocs = extract_iocs(raw)
    out = raw
    for v in sorted(iocs.get("url", ()), key=len, reverse=True):
        out = out.replace(v, defang_value("url", v))
    for e in sorted(iocs.get("email", ()), key=len, reverse=True):
        out = out.replace(e, defang_value("email", e))
    hosts = set(iocs.get("domain", ())) | set(iocs.get("ipv4", ()))
    for u in iocs.get("url", ()):
        h = _normalize_host(_host_of(u))
        if h:
            hosts.add(h)
    for e in iocs.get("email", ()):
        d = _normalize_host(e.rpartition("@")[2])
        if d:
            hosts.add(d)
    for h in sorted(hosts, key=len, reverse=True):
        pat = re.compile(r"(?<![a-z0-9.\-])" + re.escape(h) +
                         r"(?![a-z0-9\-])", re.IGNORECASE)
        out = pat.sub(h.replace(".", "[.]"), out)
    out = out.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return out


# ------------------------------------------------------------ ekstraksi
def _mask_url_paths(text: str, raw_urls: list[str]) -> str:
    """Tutup PATH URL dengan spasi (host tetap) supaya komponen path
    seperti 'gate.php' tidak terdeteksi sebagai 'domain' (anti-FP).
    Bekerja pada substring MENTAH hasil regex — bukan URL ternormalisasi.
    """
    masked = text
    for u in raw_urls:
        pre = re.match(r"[a-z]+://[^/?#\s]+", u, re.IGNORECASE)
        keep = pre.end() if pre else 0
        masked = masked.replace(u, u[:keep] + " " * (len(u) - keep), 1)
    return masked


def extract_iocs(text: str,
                 allowlist: set[str] | None = None
                 ) -> dict[str, list[str]]:
    """Ekstraksi + normalisasi + dedup IOC lintas tipe dari teks."""
    raw = refang_text(text)
    raw_urls = [m.group(0) for m in _URL_RE.finditer(raw)]
    urls = {u for u in (_normalize_url(x) for x in raw_urls) if _host_of(u)}
    url_hosts = {_normalize_host(_host_of(u)) for u in urls}
    masked = _mask_url_paths(raw, raw_urls)

    emails = {m.group(0).lower() for m in _EMAIL_RE.finditer(masked)}
    email_domains = {_normalize_host(e.rpartition("@")[2]) for e in emails}

    domains = {_normalize_host(m.group(0))
               for m in _DOMAIN_RE.finditer(masked)}
    domains -= url_hosts
    domains -= email_domains
    if allowlist:
        domains = {d for d in domains
                   if not any(d == a or d.endswith("." + a)
                              for a in allowlist)}

    ips = {m.group(0) for m in _IPV4_RE.finditer(masked)}
    # IP tetap masuk bucket ipv4 meski jadi host URL — indikator IP
    # berdiri sendiri untuk sharing; dedup hanya berlaku domain.

    sha256s = {m.group(0).lower() for m in _SHA256_RE.finditer(masked)}
    sha1s = {m.group(0).lower() for m in _SHA1_RE.finditer(masked)}
    md5s = {m.group(0).lower() for m in _MD5_RE.finditer(masked)}

    return {t: sorted(v) for t, v in
            (("url", urls), ("ipv4", ips), ("domain", domains),
             ("email", emails), ("md5", md5s), ("sha1", sha1s),
             ("sha256", sha256s))}


# ------------------------------------------------------------ CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ioc_defang — ekstraksi/normalisasi/defang-refang "
                    "IOC + pola STIX 2.1 (offline, nol jaringan).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="teks langsung di baris perintah")
    src.add_argument("--file", help="file teks sumber IOC")
    ap.add_argument("--allowlist",
                    help="file domain pengecualian (satu per baris)")
    ap.add_argument("--stix", action="store_true",
                    help="sertakan pola indikator STIX 2.1")
    ap.add_argument("--emit-defanged", action="store_true",
                    help="sertakan teks utuh ter-defang")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"[ioc-defang] file tidak ada: {p}", file=sys.stderr)
            return 2
        raw = p.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            print(f"[ioc-defang] file melebihi {MAX_FILE_BYTES} byte",
                  file=sys.stderr)
            return 2
        text = raw.decode("utf-8", errors="replace")
        binary = b"\x00" in raw[:4096]
    else:
        text = args.text
        binary = False

    allowlist: set[str] | None = None
    if args.allowlist:
        pa = Path(args.allowlist)
        if not pa.exists():
            print(f"[ioc-defang] allowlist tidak ada: {pa}", file=sys.stderr)
            return 2
        allowlist = {x.strip().lower().rstrip(".")
                     for x in pa.read_text(encoding="utf-8").splitlines()
                     if x.strip()}

    iocs = extract_iocs(text, allowlist)
    counts = {t: len(v) for t, v in iocs.items() if v}
    result: dict = {
        "schema": SCHEMA,
        "source": "file" if args.file else "text",
        "counts": counts,
        "iocs": {t: iocs[t] for t in IOC_TYPES},
    }
    if binary:
        result["meta"] = {"note": "input mengandung NUL byte — dibaca "
                                  "dengan errors='replace'"}
    if args.stix:
        result["stix_patterns"] = [stix_pattern(t, v)
                                   for t in IOC_TYPES for v in iocs[t]]
    if args.emit_defanged:
        result["defanged_text"] = defang_text(text, iocs)

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    total = sum(counts.values())
    print(f"[ioc-defang] IOC unik: {total} "
          f"({', '.join(f'{t}={n}' for t, n in counts.items()) or '-'})")
    for t in IOC_TYPES:
        for v in iocs[t][:5]:
            print(f"  {t:7} {defang_value(t, v)}")
    if args.out:
        print(f"[ioc-defang] hasil -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
