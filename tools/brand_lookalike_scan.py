r"""[AUDIT: read-only] brand_lookalike_scan — klasifikasi OFFLINE domain
lookalike/impersonasi merek dari daftar domain TERAMATI vs watchlist
merek (T1583.001 / T1593 — sisi klasifikasi nama, bukan klaim phishing).

Ranah eksplisit (kontras tool lain):
  - skills/typosquat_watch : pemantauan CT 1-seed + GENERATOR kandidat
    (perm untuk satu domain) — output-nya jadi input bagus tool ini.
  - tools/eml_phish_triage : lookalike HANYA pada domain From email.
  - tools/pkg_typosquat_check : nama PAKET npm/PyPI, bukan domain.
  - skills/rdap_enrichment + rdap-whois : verifikasi kepemilikan/umur
    REGISTRASI live — langkah lanjutan setelah tool ini mengklasifikasi.
Gap yang diisi: klasifikasi DAFTAR domain teramati apa pun (ekspor CT
log, feed registrar, output dnstwist, hasil scan) terhadap DAFTAR merek.

Input -> mekanisme -> output:
  - Input : --observed FILE (domain teramati: teks 1 domain/baris ATAU
            JSON array string ATAU array objek dgn kunci "domain" +
            metadata opsional "created" (ISO tanggal) dan "mx" (bool)
            — metadata hanya dipakai kalau ADA, tidak pernah diasumsikan),
            --brands FILE (JSON {"brands":[{name, domains, keywords}]})
            ATAU --brand domain (repeatable, quick path).
  - Mekanisme: normalisasi (lowercase, NFKC, buang trailing dot/wildcard,
            dekode label punycode xn--, skel confusable) -> klasifikasi
            per kandidat vs tiap merek, urutan paling spesifik menang:
            subdomain-embed (brand.com.evil.io), homoglyph/punycode
            (skeleton sama, raw beda), typo-distance-1 dgn kelas operasi
            (omission/insertion/transposition/substitution/repetition),
            exact-other-tld (core sama, TLD beda), brand-plus-token
            (core merek + token curiga: login/secure/verify/pay/...),
            typo-distance-2. Faktor risiko dari metadata input: registrasi
            baru (created <= 90 hari) dan mx=true menaikkan severity satu
            tingkat (cap high) — TANPA metadata, tidak ada uplift dan
            itu dicatat (fail-closed, bukan dianggap aman).
  - Output: findings.json kontrak secai (status confirmed, verdict L2
            REPRODUCED — fakta aritmetika klasifikasi; klaim
            "impersonasi/phishing" TIDAK dibuat di sini) + meta
            (hitungan per teknik, excluded legit, idn-unparseable,
            dedup, keterbatasan).

Keterbatasan (jujur, ditulis di meta):
  - Public Suffix List TIDAK di-bundle: cukup suffix multi-label umum
    (co.uk/com.au/co.id/...) — TLD aneh di luar daftar bisa salah potong.
  - Tidak ada jaringan: kepemilikan domain TIDAK diperiksa (registrasi
    pertahanan merek seperti acme.net sah pun masuk kandidat — verifikasi
    via rdap-whois/rdap_enrichment sebelum tindakan takedown).
  - Klasifikasi bukan niat: temuan = kandidat lookalike, bukan bukti
    phishing (setara kelas pkg_typosquat_check: korpus terbatas).

Fail-closed: --observed tidak ada / nol domain ter-parse -> exit 2;
tanpa watchlist merek (--brands dan --brand kosong) -> exit 2; label
IDN gagal dekode dicatat di meta (idn-unparseable) dan kandidatnya
tetap dilaporkan sbg punycode-unparsed (tidak dibuang diam-diam);
duplikat didedup dan dihitung; baris sampah dicetak di meta (maks 20).

Pemakaian:
  python tools/brand_lookalike_scan.py --observed ct_names.txt \
      --brands watchlist.json --out f.json
  python tools/brand_lookalike_scan.py --observed d.json \
      --brand acme.com --brand acme.co.id --fail-on medium
Exit: 0 bersih; 1 ada temuan >= --fail-on; 2 error input.
"""
from __future__ import annotations

import argparse
import codecs
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "secai.brand-lookalike-scan/1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_OBSERVED = 5000
MAX_BRANDS = 50
MAX_JUNK_SAMPLES = 20
RECENT_REGISTRATION_DAYS = 90

# Suffix multi-label umum (subset PSL yang sering muncul di korporat/
# Indonesia) — dipakai untuk memotong registrable domain. BUKAN PSL
# penuh (keterbatasan ditulis di meta).
MULTI_PART_SUFFIX = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.id", "or.id", "web.id", "ac.id", "go.id", "sch.id", "my.id",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "net.br", "org.br",
    "co.nz", "net.nz", "org.nz",
    "co.in", "net.in", "org.in",
    "com.tr", "com.mx", "com.sg", "com.my", "com.ph", "com.vn",
    "co.za", "com.ar", "com.hk", "co.kr",
})

# Kamus confusable -> huruf kanonik ASCII (ditulis sendiri; kelas yang
# sama dipakai typosquat/eml triase: Latin-Greek-Cyrillic + digit +
# fullwidth via NFKC). Skeleton = bentuk setelah normalisasi ini.
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h",
    "ј": "j", "қ": "k", "ӏ": "l", "м": "m", "но": "no",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "κ": "k", "ν": "v", "ι": "i", "ѕ": "s",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b",
    "8": "b", "9": "g", "|": "l", "!": "i", "$": "s",
}

SUSPICIOUS_TOKENS = (
    "login", "secure", "security", "account", "accounts", "verify",
    "verification", "support", "help", "service", "auth", "sso",
    "portal", "signin", "sign-in", "password", "reset", "update",
    "billing", "payment", "payments", "pay", "invoice", "wallet",
    "confirm", "alert", "notice", "warning", "recover", "unlock",
    "id", "my", "mail", "email", "webmail", "docs", "app", "online",
    "site", "team", "official", "customer", "client", "user",
)

RE_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _uplift(severity: str, steps: int) -> str:
    """Naikkan severity `steps` tingkat menuuk critical, cap high."""
    order = ["low", "medium", "high"]
    if severity not in order:
        return severity
    idx = min(len(order) - 1, order.index(severity) + max(0, steps))
    return order[idx]


def skeleton(text: str) -> str:
    """Skeleton confusable: NFKC + peta confusable + bigram rn->m."""
    out = unicodedata.normalize("NFKC", text.lower())
    # bigram dulu: "rn" dan "vv" sering dipakai meniru "m"/"w"
    out = out.replace("rn", "m").replace("vv", "w")
    return "".join(_CONFUSABLE.get(ch, ch) for ch in out)


def damerau_osa(a: str, b: str) -> int:
    """Jarak Damerau-Levenshtein (OSA — transposisi tetangga, tanpa
    loop forbidden). Implementasi sendiri, stdlib murni."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev2: list[int] | None = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                best = min(best, prev2[j - 2] + 1)  # type: ignore[index]
            cur[j] = best
        prev2, prev = prev, cur
    return prev[lb]


def distance_ops(a: str, b: str) -> str | None:
    """Kelas operasi utk jarak-1 (omission/insertion/transposition/
    substitution/repetition); None bila jarak != 1."""
    if damerau_osa(a, b) != 1:
        return None
    if len(a) == len(b):
        diffs = [(x, y) for x, y in zip(a, b) if x != y]
        if len(diffs) == 1:
            return "substitution"
        return "transposition"  # pasangan tertukar = 2 posisi beda
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    # insertion ke short / omission dari long_; huruf ganda (repetition)
    # dideteksi di SEMUA posisi sebelum fallback (urutan posisi jangan
    # menutupi kelas 'repetition' — "acmee" vs "acme" = repetition).
    for i in range(len(long_)):
        if (i > 0 and long_[i] == long_[i - 1]
                and long_[:i] + long_[i + 1:] == short):
            return "repetition"
    for i in range(len(long_)):
        if long_[:i] + long_[i + 1:] == short:
            if len(a) > len(b):
                return "omission"  # a lebih panjang: huruf hilang di a
            return "insertion"
    return "omission"


def decode_domain(raw: str) -> tuple[str, bool, bool]:
    """Lowercase + NFKC + buang trailing dot/wildcard/scheme; dekode
    label punycode. Return (domain, idn_ok, had_punycode)."""
    dom = unicodedata.normalize("NFKC", raw.strip().lower())
    dom = dom.split("//")[-1]  # buang scheme bila ada
    dom = dom.split("/")[0].split("@")[-1]
    dom = dom.split(":")[0]  # port
    dom = dom.strip(".")
    if dom.startswith("*."):
        dom = dom[2:]
    labels: list[str] = []
    ok = True
    had_puny = False
    for lab in dom.split("."):
        if not lab:
            ok = False
            continue
        if lab.startswith("xn--"):
            had_puny = True
            try:
                labels.append(codecs.decode(lab[4:], "punycode"))
            except (UnicodeDecodeError, ValueError):
                ok = False
                labels.append(lab)
        else:
            labels.append(lab)
    return ".".join(labels), ok, had_puny


def registrable(domain: str) -> str:
    """Registrable domain heuristik: 2 label terakhir, 3 bila suffix
    multi-label dikenal. Tanpa PSL penuh (lihat keterbatasan)."""
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def label_core(domain: str) -> str:
    """Label kiri registrable domain (brand 'core')."""
    reg = registrable(domain)
    return reg.rsplit(".", 2)[0] if reg.count(".") >= 2 else reg.split(".")[0]


def classify(candidate: str, brand: dict, had_puny: bool = False) -> \
        dict | None:
    """Klasifikasi satu kandidat vs satu merek. Return dict teknik atau
    None (bukan kandidat / sah). Kandidat sudah ter-dekode."""
    c_core = label_core(candidate)
    c_reg = registrable(candidate)
    b_core = brand["core"]
    b_regs = set(brand["registrables"])
    if candidate in b_regs or c_reg in b_regs:
        return None  # domain merek sendiri / subdomainnya — sah
    # homoglyph: skeleton kandidat == skeleton core merek, raw beda
    sk_c, sk_b = skeleton(c_core), skeleton(b_core)
    raw_nonascii = any(ord(ch) > 127 for ch in c_core) or had_puny
    if sk_c == sk_b and c_core != b_core:
        tech = "homoglyph" if raw_nonascii else "homoglyph-ascii"
        return {"technique": tech, "severity": "high",
                "detail": f"skeleton '{sk_c}' identik dengan core "
                          f"merek '{b_core}' setelah normalisasi "
                          f"confusable (raw '{c_core}')"}
    if c_core == b_core:
        return {"technique": "exact-other-tld", "severity": "medium",
                "detail": f"core '{b_core}' sama persis di TLD lain "
                          f"({c_reg}) — bisa registrasi pertahanan "
                          f"merek; verifikasi kepemilikan"}
    # subdomain-embed: domain merek utuh jadi PREFIX host lain
    # (acme.com.evil.io) — remainder multi-label, BUKAN satu TLD
    # (acme.com.br = exact-other-tld, sudah tertangani di atas)
    for r in sorted(b_regs):
        if candidate.startswith(r + ".") and "." in \
                candidate[len(r) + 1:]:
            return {"technique": "subdomain-embed", "severity": "medium",
                    "detail": f"domain merek {r} di-hosting di bawah "
                              f"suffix lain ({candidate})"}
    # brand-plus-token: core/keyword menyusup di label dgn token curiga;
    # sisa >= 3 char (sisa pendek = typo kelas distance, bukan combo)
    for kw in {b_core, *brand["keywords"]}:
        if kw and kw in c_core and c_core != kw:
            remainder = c_core.replace(kw, "", 1)
            if len(remainder) < 3:
                continue  # "acmee"/"acmes" = kelas typo, cek distance
            hit = [t for t in SUSPICIOUS_TOKENS
                   if t in remainder.replace("-", "") and t not in kw]
            if hit:
                return {"technique": "brand-plus-token", "severity": "high",
                        "detail": f"'{kw}' + token curiga {hit[:3]} "
                                  f"di '{c_core}'"}
            return {"technique": "brand-plus-token", "severity": "medium",
                    "detail": f"'{kw}' menyusup di '{c_core}' tanpa "
                              f"token curiga jelas"}
    dist = damerau_osa(sk_c, sk_b)
    if dist == 1:
        return {"technique": "typo-distance-1", "severity": "high",
                "op": distance_ops(sk_c, sk_b),
                "detail": f"skeleton '{sk_c}' jarak-1 dari '{sk_b}' "
                          f"({distance_ops(sk_c, sk_b)})"}
    if dist == 2:
        return {"technique": "typo-distance-2", "severity": "low",
                "detail": f"skeleton '{sk_c}' jarak-2 dari '{sk_b}'"}
    return None


def parse_observed(path: Path) -> tuple[list[dict], dict, list[str]]:
    """Parse file domain teramati: teks per baris / JSON array string /
    JSON array objek dgn kunci 'domain'. Metadata (created/mx) hanya
    dipakai bila ada. Return (entries, meta, junk_samples)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    entries: list[dict] = []
    junk: list[str] = []
    src = "text"
    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        src = "json"
        data = json.loads(stripped)
        items = data if isinstance(data, list) else [data]
        for it in items:
            if isinstance(it, str):
                entries.append({"raw": it})
            elif isinstance(it, dict) and it.get("domain"):
                entries.append({
                    "raw": str(it["domain"]),
                    "created": it.get("created") or it.get("creation_date"),
                    "mx": it.get("mx"),
                })
            elif len(junk) < MAX_JUNK_SAMPLES:
                junk.append(json.dumps(it)[:100])
    else:
        for idx, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if _looks_like_domain_line(s):
                entries.append({"raw": s})
            elif len(junk) < MAX_JUNK_SAMPLES:
                junk.append(f"L{idx}:{s[:100]}")
    meta = {"observed_source": src, "observed_lines": len(entries),
            "junk": junk}
    return entries, meta, junk


def _looks_like_domain_line(s: str) -> bool:
    dom, _, _ = decode_domain(s)
    if not dom or "." not in dom or " " in dom:
        return False
    return all(
        RE_LABEL.match(lab)
        or lab.startswith("xn--")
        or any(ord(ch) > 127 for ch in lab)  # label homoglyph Unicode
        for lab in dom.split(".")
    )


def load_brands(brands_path: Path | None,
                brand_args: list[str]) -> tuple[list[dict], dict]:
    """Muat watchlist merek: JSON file ATAU --brand (repeatable).
    Return (brands, meta). Setiap brand: core (label kiri registrable
    pertama), registrables (set), keywords (list)."""
    brands: list[dict] = []
    if brands_path:
        data = json.loads(brands_path.read_text(encoding="utf-8",
                                                errors="replace"))
        for b in data.get("brands", []):
            doms = [d.lower().strip(".") for d in b.get("domains", []) if d]
            if not doms:
                continue
            brands.append({
                "name": str(b.get("name") or doms[0]),
                "registrables": {registrable(d) for d in doms},
                "core": label_core(doms[0]),
                "keywords": [k.lower() for k in b.get("keywords", [])],
            })
    for d in brand_args:
        dom = d.lower().strip(".")
        brands.append({
            "name": dom,
            "registrables": {registrable(dom)},
            "core": label_core(dom),
            "keywords": [],
        })
    # dedup by registrables union
    uniq: list[dict] = []
    seen: set[frozenset] = set()
    for b in brands:
        key = frozenset(b["registrables"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(b)
    meta = {"brands_loaded": len(brands), "brands_unique": len(uniq)}
    return uniq, meta


def days_since(date_str: str) -> float | None:
    """Umur registrasi (hari) dari string tanggal ISO; None bila tak
    terurai — TIDAK pernah diasumsikan."""
    s = str(date_str).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Klasifikasi OFFLINE domain lookalike merek dari "
                    "daftar domain teramati — nol jaringan (#0783)")
    ap.add_argument("--observed", required=True,
                    help="file domain teramati (teks/JSON/dnstwist-ish)")
    ap.add_argument("--brands", help="JSON watchlist merek "
                                     "{'brands':[{name,domains,keywords}]}")
    ap.add_argument("--brand", action="append", default=[],
                    help="domain merek tunggal (repeatable, quick path)")
    ap.add_argument("--legit", action="append", default=[],
                    help="domain sah tambahan (repeatable) — dikecualikan")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"],
                    default="medium",
                    help="ambang exit-1: temuan >= severity ini "
                         "(semantik sama dgn pkg_typosquat_check)")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args(argv)

    obs_path = Path(args.observed)
    if not obs_path.exists():
        print(f"ERROR: {args.observed}: file tidak ada", file=sys.stderr)
        return 2
    if obs_path.stat().st_size > MAX_FILE_BYTES:
        print(f"ERROR: {args.observed} > {MAX_FILE_BYTES} byte",
              file=sys.stderr)
        return 2
    brands_path: Path | None = None
    if args.brands:
        brands_path = Path(args.brands)
        if not brands_path.exists():
            print(f"ERROR: {args.brands}: file tidak ada", file=sys.stderr)
            return 2
        if brands_path.stat().st_size > MAX_FILE_BYTES:
            print(f"ERROR: {args.brands} > {MAX_FILE_BYTES} byte",
                  file=sys.stderr)
            return 2
    if not brands_path and not args.brand:
        print("[brand_lookalike_scan] tanpa watchlist merek (--brands/"
              "--brand) tidak ada pembanding -> tidak ada kesimpulan "
              "(fail-closed)", file=sys.stderr)
        return 2

    try:
        entries, obs_meta, junk = parse_observed(obs_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {args.observed}: {exc}", file=sys.stderr)
        return 2
    if not entries:
        print("[brand_lookalike_scan] nol domain ter-parse dari "
              "--observed (fail-closed)", file=sys.stderr)
        return 2

    try:
        brands, brand_meta = load_brands(brands_path, args.brand)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: --brands: {exc}", file=sys.stderr)
        return 2
    if not brands:
        print("[brand_lookalike_scan] watchlist merek kosong "
              "(fail-closed)", file=sys.stderr)
        return 2
    if len(brands) > MAX_BRANDS:
        print(f"ERROR: watchlist > {MAX_BRANDS} merek (potong di sumber)",
              file=sys.stderr)
        return 2

    legit: set[str] = set()
    for b in brands:
        legit |= b["registrables"]
    for d in args.legit:
        legit.add(registrable(d.lower().strip(".")))

    seen: set[str] = set()
    dup = 0
    idn_fail = 0
    truncated = max(0, len(entries) - MAX_OBSERVED)
    tech_counts: dict[str, int] = {}
    findings: list[dict] = []
    for ent in entries[:MAX_OBSERVED]:
        raw = ent["raw"]
        dom, idn_ok, had_puny = decode_domain(raw)
        if not idn_ok:
            idn_fail += 1
        if not dom or "." not in dom:
            if len(junk) < MAX_JUNK_SAMPLES:
                junk.append(f"bad:{raw[:80]}")
            continue
        if dom in seen:
            dup += 1
            continue
        seen.add(dom)
        if registrable(dom) in legit:
            continue  # suffix milik domain sah yang dikenal (anti-FP)
        for brand in brands:
            res = classify(dom, brand, had_puny=had_puny)
            if res is None:
                continue
            sev = res["severity"]
            uplift_note = ""
            created = ent.get("created")
            age = days_since(created) if created else None
            steps = 0
            if age is not None and age <= RECENT_REGISTRATION_DAYS:
                steps += 1
                uplift_note += " registrasi-baru"
            if ent.get("mx") is True:
                steps += 1
                uplift_note += " mx-aktif"
            if steps and sev != "high":
                sev = _uplift(sev, steps)
                uplift_note = f"(uplift:{uplift_note.strip()} -> {sev})"
            elif steps:
                uplift_note = f"(faktor risiko:{uplift_note.strip()})"
            tech_counts[res["technique"]] = \
                tech_counts.get(res["technique"], 0) + 1
            findings.append(make_finding(
                tool="brand_lookalike_scan",
                title=f"Lookalike {res['technique']}: {dom} ~ {brand['name']}",
                severity=sev,
                description=f"{dom} diklasifikasi '{res['technique']}' "
                            f"terhadap merek {brand['name']} — "
                            f"{res['detail']}{uplift_note}",
                recommendation="Verifikasi kepemilikan via rdap-whois/"
                               "rdap_enrichment sebelum tindakan; "
                               "klasifikasi nama BUKAN klaim phishing.",
                cwe="CWE-290",
                target_url=dom,
                param=res["technique"],
                poc=f"skeleton('{label_core(dom)}') vs "
                    f"skeleton('{brand['core']}') = "
                    f"{skeleton(label_core(dom))} vs "
                    f"{skeleton(brand['core'])}",
                evidence_kind="arithmetic",
                status="confirmed",
                verdict=2,
                extra={"technique": res["technique"],
                       "brand": brand["name"],
                       "registrable": registrable(dom),
                       "age_days": round(age, 1) if age is not None else None,
                       "mx": ent.get("mx")},
            ))
            break  # teknik paling spesifik pertama yang menang

    meta = {
        "schema": SCHEMA,
        "observed_total": len(entries),
        "observed_unique": len(seen),
        "duplicates": dup,
        "truncated": truncated,
        "idn_unparseable": idn_fail,
        "brands": brand_meta,
        "legit_suffixes": sorted(legit),
        "technique_counts": tech_counts,
        "junk_samples": junk[:MAX_JUNK_SAMPLES],
        "recent_registration_days": RECENT_REGISTRATION_DAYS,
        "limitations": [
            "PSL subset (MULTI_PART_SUFFIX) — TLD aneh bisa salah potong",
            "tanpa jaringan: kepemilikan/tanggal registrasi nyata tidak "
            "dicek (verifikasi rdap; metadata hanya bila ada di input)",
            "klasifikasi nama = kandidat, bukan klaim phishing",
        ],
    }
    write_findings(args.out, findings, meta)

    threshold = SEV_RANK[args.fail_on]
    hits = [f for f in findings if SEV_RANK[f["severity"]] <= threshold]
    print(f"[brand_lookalike_scan] teramati={len(entries)} "
          f"unik={len(seen)} merek={len(brands)} "
          f"temuan={len(findings)} (>= {args.fail_on}: {len(hits)})")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
