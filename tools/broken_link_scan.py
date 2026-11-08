"""[SAFETY: read-only, NOL jaringan] broken_link_scan — inventaris referensi
eksternal isi halaman + penanda referensi tergantung (broken link hijacking).

Port konsep dari antrean SKILL-PORT-QUEUE-G6 #1010 (mukul975/
Anthropic-Cybersecurity-Skills, skill 'exploiting-broken-link-hijacking' —
spider situs, ekstraksi referensi eksternal, cek DNS/status registrasi
domain pihak ketiga yang mati; lisensi sumber Apache-2.0, atribusi konsep,
kode dibangun from scratch TANPA menyalin kode sumber).

Skill sumber melakukan spidering live + DNS live (Burp Spider/Scrapy/dig).
secai memilih artefak OFFLINE — tool ini TIDAK PERNAH melakukan jaringan.
Input:
  1. artefak konten halaman (HTML/JS/CSS/SVG/teks) hasil crawl berizin;
  2. OPSIONAL --resolutions JSON jawaban resolver untuk hostname eksternal
     (peta {host: <nilai>}; nilai bisa: "nxdomain", angka rcode DoH
     (3 = NXDOMAIN, 0 = OK), atau objek DoH dns.google {"Status": ..,
     "Answer": [..]} — diproduksi operator dengan resolver apa pun).
Ceruk vs takeover-cname-hygiene / takeover-fingerprint-checker (keduanya
mulai dari hostname yang sudah diketahui lalu mengecek CNAME/fingerprint
layanan): tool ini MULAI DARI ISI HALAMAN — inventaris referensi pihak
ketiga yang dipakai halaman (script/img/link/import/fetch/XHR), lalu
menandai referensi ke domain yang (menurut jawaban resolver milik
operator) tidak terdaftar lagi. Siapa pun yang mendaftarkan domain mati
itu mengendalikan konten yang dieksekusi/dirender halaman target.

Input -> mekanisme -> output:
  - Input : --file/--dir artefak (teks; biner/oversize di-skip TERCATAT),
            --base-domain (domain target; referensi ke domain ini dan
            subdomainnya dihitung internal, bukan eksternal),
            --resolutions (opsional).
  - Mekanisme: ekstraksi referensi — atribut HTML (src/href/action/
            poster/data/srcset/cite/formaction) via html.parser + URL
            http(s) dan protocol-relative "//host" di JS/CSS/teks via
            regex (termasuk url(...) CSS); dedup per (file, baris, url);
            host jelas-bukan-publik DILEWATI TERCATAT (IP literal,
            localhost, TLD reserved RFC 2606/6761: test/example/invalid/
            localhost, konvensi internal local/internal, label-tunggal).
            Liveness DINILAI HANYA dari --resolutions:
              * rcode 3 / "nxdomain" -> HIGH external-ref-unregistered
                (LEAD L1 unconfirmed — konfirmasi tunggalnya mendaftarkan
                domain itu, TIDAK PERNAH dilakukan tool ini);
              * rcode 0 + CNAME ber-marker layanan -> INFO
                external-ref-dangling-note (hygiene; klaim takeover =
                wilayah takeover-cname-hygiene/fingerprint-checker);
              * rcode 0 tanpa marker -> bukan temuan;
              * SERVFAIL/rcode lain/tak ada data -> INFO
                external-ref-unresolved (jujur: SERVFAIL BUKAN bukti
                domain mati);
              * referensi via http:// (bukan https) -> LOW
                external-script-cleartext (konten bisa disisipkan MITM).
  - Output: JSON {schema, stats, findings} satu-pintu (semua temuan di
            sini maks L1 LEAD unconfirmed), --out file opsional (bungkus
            findings.json kontrak), --fail-on none|any|high|medium|low
            (default none = laporan murni). Exit 0 bersih/laporan, 1 ada
            temuan >= ambang --fail-on, 2 input error fail-closed (file
            tak-ada, nol artefak ter-parse, resolutions rusak,
            base-domain tak valid, >500 file).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.broken-link-scan/1"
TOOL = "broken-link-scan"
MAX_FILE_BYTES = 4 * 1024 * 1024        # 4 MB per artefak — lebih besar skip tercatat
MAX_FILES = 500                         # lebih banyak -> input error fail-closed
MAX_FINDINGS = 5000
MAX_EVIDENCE_PER_HOST = 50

# TLD reserved (RFC 2606 / 6761) + konvensi internal — host di bawah ini
# TIDAK bisa didaftarkan siapa pun, jadi bukan permukaan broken-link.
RESERVED_TLDS = frozenset({
    "test", "example", "invalid", "localhost", "local", "internal",
})
DANGLING_MARKERS = (
    # penanda layanan hosting yang lazim dipakai CNAME — KEPERCIAYAAN RENDAH:
    # keberadaan marker bukan bukti dangling (distribusi hidup juga memakai)
    "azurewebsites.net", "azureedge.net", "blob.core.windows.net",
    "cloudfront.net", "github.io", "herokuapp.com", "web.app",
    "firebaseapp.com", "s3.amazonaws.com", "storage.googleapis.com",
    "netlify.app", "vercel.app", "pages.dev", "ghost.io", "pantheon.io",
    "readme.io", "fastly.net",
)
_ATTR_URLS = ("src", "href", "action", "poster", "data", "cite", "formaction")
_RE_URL = re.compile(
    r"""(?:https?:)?//[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?(?::\d{2,5})?(?:[/?#][^\s"'`<>()\\]*)?""")  # noqa: E501
_RE_CSS_URL = re.compile(
    r"url\(\s*['\"]?((?:https?:)?//[^'\")\s]+)['\"]?\s*\)", re.I)
_IP4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-f:]+:[0-9a-f:.]+$", re.I)

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class _HtmlRefs(HTMLParser):
    """Kumpulkan URL dari atribut HTML + baris kemunculannya."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hits: list[tuple[str, int]] = []  # (url, line)

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        line = self.getpos()[0]
        for k, v in attrs:
            if k.lower() in _ATTR_URLS and v and v.strip():
                val = v.strip()
                if k.lower() == "srcset":  # kandidat pertama saja (tercatat)
                    val = val.split(",")[0].strip().split(" ")[0]
                self.hits.append((val, line))


def _split_host(raw: str) -> str | None:
    """URL/authority -> hostname lowercase tanpa port; None bila bukan URL
    jaringan yang valid."""
    s = raw.strip()
    if s.startswith("//"):
        s = "http:" + s
    try:
        parts = urlsplit(s)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    return host or None


def _host_class(host: str) -> str | None:
    """None = host publik yang dinilai; string = alasan dilewati (tercatat)."""
    if _IP4_RE.match(host) or _IPV6_RE.match(host):
        return "ip-literal"
    labels = host.split(".")
    if host == "localhost" or len(labels) == 1:
        return "single-label"
    if labels[-1].lower() in RESERVED_TLDS:
        return "reserved-tld"
    return None


def _norm_resolution(val) -> dict:
    """Normalisasi SATU nilai resolusi (string/bool/angka/objek DoH/peta)
    -> {"rcode": int|None, "cname": str, "note": str?}."""
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("nxdomain", "nx", "rcode3", "status3"):
            return {"rcode": 3}
        if v in ("ok", "resolved", "status0"):
            return {"rcode": 0}
        return {"rcode": None, "note": "teks resolusi tak dikenal"}
    if isinstance(val, bool):
        return {"rcode": 3 if val is False else 0,
                "note": "boolean (false=NXDOMAIN)"}
    if isinstance(val, (int, float)):
        return {"rcode": int(val)}
    if isinstance(val, dict):
        entry: dict = {}
        rcode = val.get("Status", val.get("status"))
        if isinstance(rcode, int) and not isinstance(rcode, bool):
            entry["rcode"] = rcode
        cname_parts = []
        for ans in val.get("Answer") or []:
            if isinstance(ans, dict) and ans.get("data"):
                cname_parts.append(str(ans["data"]).lower())
        if val.get("cname"):
            cname_parts.append(str(val["cname"]).lower())
        entry["cname"] = " ".join(cname_parts)
        return entry
    return {"rcode": None, "note": "tipe nilai resolusi tak dikenal"}


def _load_resolutions(path: str | None) -> dict[str, dict]:
    """Muat JSON resolusi (validasi bentuk) — normalisasi dilakukan di
    scan() agar API modul dan CLI berperilaku identik."""
    if not path:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("resolutions harus objek {host: nilai}")
    return {str(h).lower().rstrip("."): v for h, v in raw.items()}


def _classify_resolution(host: str, res: dict | None) -> tuple[str, str, str]:
    """-> (kelas, severity, deskripsi keadaan)."""
    if res is None:
        return ("external-ref-unresolved", "info", "tanpa data resolusi")
    rcode = res.get("rcode")
    if rcode == 3:
        return ("external-ref-unregistered", "high",
                "resolver melaporkan NXDOMAIN (rcode 3)")
    if rcode == 0:
        cname = str(res.get("cname") or "")
        if any(m in cname for m in DANGLING_MARKERS):
            return ("external-ref-dangling-note", "info",
                    "CNAME ber-marker layanan (%s) — hygiene note, bukan "
                    "klaim dangling/takeover" % cname[:80])
        return ("external-ref-resolved", "info", "resolver OK (rcode 0)")
    return ("external-ref-unresolved", "info",
            "resolusi tak-menentukan (rcode %s) — SERVFAIL BUKAN bukti "
            "domain mati" % (rcode if rcode is not None else "?"))


def _mk_finding(cls: str, host: str, ev: list, res: dict | None,
                state: str) -> dict:
    """Satu temuan untuk (kelas, host). Bukti = referensi pertama."""
    first_file, first_line, first_url = ev[0]
    where = "%s:%d" % (Path(first_file).name, first_line)
    if cls == "external-ref-unregistered":
        title = "Referensi eksternal ke domain tak-terdaftar: %s" % host
        desc = ("Halaman mereferensikan %s (%d referensi; contoh %s) dan "
                "resolusi operator = %s — domain bisa didaftarkan siapa pun "
                "sehingga mengendalikan konten yang dieksekusi/dirender "
                "halaman. LEAD: konfirmasi tunggal = mendaftarkan domain "
                "(tidak pernah dilakukan tool ini)."
                % (host, len(ev), where, state))
        rec = ("Pantau registrasi domain; hapus/ganti referensi; "
               "pertimbangkan defensive registration.")
        cwe: str | None = "CWE-350"
        extra = {"ref_count": len(ev), "resolution": {
            "rcode": (res or {}).get("rcode"),
            "cname": ((res or {}).get("cname") or "")[:200]}}
    elif cls == "external-script-cleartext":
        title = "Referensi eksternal via http:// (cleartext): %s" % host
        desc = ("Konten pihak ketiga dimuat via http:// (%d referensi; "
                "contoh %s) — bisa diganti pihak yang menempatkan MITM, "
                "efek akhir sama dengan referensi domain mati."
                % (len(ev), where))
        rec = "Gunakan https:// (atau hapus bila tak terpakai)."
        cwe = "CWE-311"
        extra = {"ref_count": len(ev)}
    elif cls == "external-ref-dangling-note":
        title = "CNAME marker layanan pada referensi eksternal: %s" % host
        desc = ("Referensi eksternal %s; resolusi OK dengan CNAME "
                "ber-marker layanan hosting (%s). Hygiene note — verifikasi "
                "dangling/fingerprint = wilayah takeover-cname-hygiene + "
                "takeover-fingerprint-checker."
                % (host, ((res or {}).get("cname") or "")[:120]))
        rec = "Cek klaim kepemilikan layanan bila host ini kritikal."
        cwe = None
        extra = {"ref_count": len(ev), "resolution": {
            "rcode": 0, "cname": ((res or {}).get("cname") or "")[:200]}}
    else:  # external-ref-unresolved
        title = "Referensi eksternal tanpa resolusi: %s" % host
        desc = ("Referensi eksternal %s (%d; contoh %s) tidak punya jawaban "
                "resolver di --resolutions (%s) — liveness tak bisa dinilai: "
                "tidak dianggap aman, tidak dianggap mati."
                % (host, len(ev), where, state))
        rec = "Sertakan jawaban resolver utk host ini di --resolutions."
        cwe = None
        extra = {"ref_count": len(ev)}

    f = make_finding(
        tool=TOOL, title=title,
        severity={"external-ref-unregistered": "high",
                  "external-script-cleartext": "low",
                  "external-ref-dangling-note": "info",
                  "external-ref-unresolved": "info"}[cls],
        description=desc, recommendation=rec, cwe=cwe,
        target_url=first_url, file_path=first_file, line_start=first_line,
        evidence_kind="dns" if cls == "external-ref-unregistered"
        else "content",
        confidence=1.0 if cls == "external-ref-unregistered" else 0.9,
        status="unconfirmed", extra=extra,
    )
    if cls == "external-ref-unregistered":
        f["response"] = json.dumps(res or {}, sort_keys=True)[:400]
    return f


def scan(artifacts: list[tuple[str, str]], base_domain: str | None,
         resolutions: dict) -> dict:
    """artifacts = [(nama_file, isi_teks)]. Deterministik, nol jaringan.
    resolutions: peta mentah {host: "nxdomain"|rcode|objek DoH} — dinorma-
    lisasi di sini sehingga CLI dan pemanggil modul identik."""
    base = (base_domain or "").lower().rstrip(".")
    if base and _host_class(base):
        raise ValueError("base-domain bukan host publik: %r" % base_domain)
    resolutions = {str(h).lower().rstrip("."): _norm_resolution(v)
                   for h, v in (resolutions or {}).items()}
    refs: dict[str, dict] = {}   # host -> {"evidence": [(file, line, url)]}
    skipped_hosts: dict[str, str] = {}
    internal_refs = 0
    notes: list[str] = []
    for fname, text in artifacts:
        if "\x00" in text[:8192]:
            notes.append("biner dilewati: %s" % fname)
            continue
        if len(text.encode("utf-8", errors="replace")) > MAX_FILE_BYTES:
            notes.append("melebihi %d byte, dilewati: %s"
                         % (MAX_FILE_BYTES, fname))
            continue
        pairs: list[tuple[str, int]] = []
        if fname.lower().endswith((".html", ".htm", ".svg", ".xhtml")):
            try:
                p = _HtmlRefs()
                p.feed(text)
                p.close()
                pairs.extend(p.hits)
            except Exception as exc:  # parser korup → jujur, lanjut regex
                notes.append("html parse gagal %s: %s" % (fname, exc))
        for m in _RE_URL.finditer(text):          # JS string / plain text
            pairs.append((m.group(0), text.count("\n", 0, m.start()) + 1))
        for m in _RE_CSS_URL.finditer(text):      # CSS url(...)
            pairs.append((m.group(1), text.count("\n", 0, m.start()) + 1))
        seen: set[tuple[str, int]] = set()
        for raw, line in pairs:
            key = (raw[:200], line)
            if key in seen:
                continue
            seen.add(key)
            host = _split_host(raw)
            if not host:
                continue
            if base and (host == base or host.endswith("." + base)):
                internal_refs += 1
                continue
            cls = _host_class(host)
            if cls:
                skipped_hosts.setdefault(host, cls)
                continue
            ev = refs.setdefault(host, {"evidence": []})
            if len(ev["evidence"]) < MAX_EVIDENCE_PER_HOST:
                ev["evidence"].append((fname, line, raw[:200]))

    findings = []
    for host in sorted(refs):
        ev = refs[host]["evidence"]
        first_file, first_line, first_url = ev[0]
        res = resolutions.get(host)
        cls, sev, state = _classify_resolution(host, res)
        scheme_http = first_url.lower().startswith("http://")

        # fakta cleartext (http://) = temuan TERPISAH, tidak menimpa
        # klasifikasi liveness — kecuali host sudah tak-terdaftar (high
        # mendominasi; cleartext pada domain mati redundan).
        if scheme_http and cls != "external-ref-unregistered":
            findings.append(_mk_finding(
                "external-script-cleartext", host, ev, None, state))

        if cls == "external-ref-resolved":
            continue  # OK via https (atau cleartext-nya sudah dicatat)

        findings.append(_mk_finding(cls, host, ev, res, state))
        if len(findings) >= MAX_FINDINGS:
            notes.append("capai MAX_FINDINGS, sisanya tidak dinilai")
            break

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]],
                                 f["file_path"] or "", f["line_start"] or 0,
                                 f["target_url"] or ""))
    stats = {
        "artifacts": len(artifacts),
        "external_hosts": len(refs),
        "internal_refs": internal_refs,
        "skipped_hosts": len(skipped_hosts),
        "findings": len(findings),
        "by_severity": {},
    }
    for f in findings:
        stats["by_severity"][f["severity"]] = \
            stats["by_severity"].get(f["severity"], 0) + 1
    return {
        "schema": SCHEMA,
        "tool": TOOL,
        "stats": stats,
        "skipped_hosts": dict(sorted(skipped_hosts.items())),
        "notes": notes,
        "findings": findings,
    }


def _collect(paths: list[str], dirs: list[str]) -> list[tuple[str, str]]:
    files: list[Path] = []
    for p in paths:
        fp = Path(p)
        if not fp.is_file():
            raise ValueError("file tidak ada: %s" % fp)
        files.append(fp)
    for d in dirs:
        dp = Path(d)
        if not dp.is_dir():
            raise ValueError("direktori tidak ada: %s" % dp)
        got = sorted(x for x in dp.rglob("*")
                     if x.is_file() and x.stat().st_size <= MAX_FILE_BYTES)
        files.extend(got)
    if len(files) > MAX_FILES:
        raise ValueError("terlalu banyak file (%d > %d)"
                         % (len(files), MAX_FILES))
    if not files:
        raise ValueError("nol artefak input")
    return [(str(fp), fp.read_text(encoding="utf-8", errors="replace"))
            for fp in files]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Inventaris referensi eksternal isi halaman + penanda "
                    "broken link hijacking — offline, nol jaringan, "
                    "fail-closed.")
    ap.add_argument("--file", action="append", default=[],
                    help="artefak halaman (HTML/JS/CSS/teks), diulang")
    ap.add_argument("--dir", action="append", default=[],
                    help="direktori artefak crawl, diulang")
    ap.add_argument("--base-domain",
                    help="domain target; referensi ke sini = internal")
    ap.add_argument("--resolutions",
                    help="JSON peta jawaban resolver "
                         "{host: nxdomain|rcode|objek DoH}")
    ap.add_argument("--out", help="tulis findings.json kontrak ke file")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"],
                    help="ambang exit 1 (default none = laporan murni)")
    args = ap.parse_args(argv)
    if not args.file and not args.dir:
        print("[broken-link-scan] input error: --file/--dir wajib",
              file=sys.stderr)
        return 2
    try:
        artifacts = _collect(args.file, args.dir)
        resolutions = _load_resolutions(args.resolutions)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("[broken-link-scan] input error: %s" % exc, file=sys.stderr)
        return 2

    try:
        result = scan(artifacts, args.base_domain, resolutions)
    except ValueError as exc:
        print("[broken-link-scan] scan error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "skipped_hosts": result["skipped_hosts"],
            "notes": result["notes"], "requests": 0,
        })
    print(rendered)
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if result["findings"] else 0
    need = {"high": {"high"}, "medium": {"high", "medium"},
            "low": {"low", "medium", "high"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
