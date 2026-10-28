"""[F41] CVE-Matcher — pemetaan product/version -> CVE dari intel_sync.

Konsumen KEV (CISA) + KB operator + watchlist breaking-CVE [F61b] +
indeks template nuclei; NOL request (read-only). Desain fail-closed:
docs/CVE-MATCHER.md — KEV TIDAK membawa version-range, maka match KEV
= SELALU lead L1 product-level "verifikasi manual paparan versi"; klaim
terikat versi hanya dari KB operator (assets/intel/cve-kb.json, entri
tanpa source_url ditolak). Watchlist (assets/intel/watchlist.json,
seed kurasi) menutup celah CVE kritis yang BELUM terkonfirmasi KEV —
lead product-level maks L1, tanpa klaim versi. Verdict maksimum L1 di
semua jalur — ladder tidak dilonggar.

Pemakaian:
  python tools/cve_matcher.py --findings f.json --out cve.json
  python tools/cve_matcher.py --findings f.json --kb kb.json \\
      --with-templates --out cve.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

from findings import make_finding, write_findings  # noqa: E402

KEV_PATH = ROOT / "assets" / "intel" / "kev.json"
KB_PATH = ROOT / "assets" / "intel" / "cve-kb.json"
# [F61b] Watchlist breaking-CVE (seed kurasi operator): CVE kritis di
# LUAR KEV — celah konfirmasi KEV adalah masa paling berbahaya.
WATCHLIST_PATH = ROOT / "assets" / "intel" / "watchlist.json"
TPL_INDEX_PATH = ROOT / "assets" / "intel" / "cve-template-index.json"
TPL_CORPUS_DIR = ROOT / "assets" / "intel" / "nuclei-templates"

# Tool yang barisnya boleh jadi sumber fakta product/version (anti-noise;
# baris dari tool lain tidak pernah dipakai — docs/CVE-MATCHER.md §2).
ALLOWED_SOURCE_TOOLS = frozenset({
    "server-version-disclosure", "banner-posture",
    "banner-posture-evidence", "js-library-version-checker",
    "tech-fingerprint", "port-banner-consistency-checker",
    "litellm-posture",
    "wp-posture",
    "gitlab-posture",
    "beyondtrust-posture",
    "ollama-posture",
    "vllm-posture",
    "openwebui-posture",
    # [F66] batch agresif pasca-Black October: runtime PHP, stack
    # Brotli/Node, plugin WordPress, Adobe Commerce/Magento.
    "php-posture", "brotli-stack-surface", "wp-plugin-surface",
    "magento-surface",
})

# Token produk generik yang TIDAK PERNAH boleh jadi direct-match
# sendirian (entri KEV semacam "TrueConf :: Server" mencemari teks apa
# pun berisi "server"). Keluarga ini hanya boleh lewat alias kurasi
# vendor+product (docs/CVE-MATCHER.md §3).
GENERIC_PRODUCT_TOKENS = frozenset({
    "server", "service", "manager", "client", "portal", "gateway",
    "appliance", "plugin", "module", "desktop", "mobile", "support",
    "remote", "secure", "system", "network", "security", "kernel",
    "office", "exchange", "webmail", "web", "api", "cloud", "edge",
})

# Alias kurasi: token banner pendek -> identitas KEV (vendor, product),
# keduanya wajib cocok pada entri (docs/CVE-MATCHER.md §3). Hanya
# pasangan TIDAK ambigu; yang ambigu sengaja tidak ada (miss > FP).
ALIASES = {
    "apache": [("apache", "http server"), ("apache", "apache")],
    "apache-coyote": [("apache", "tomcat")],
    "tomcat": [("apache", "tomcat")],
    "log4j": [("apache", "log4j")],
    "log4j2": [("apache", "log4j")],
    "struts": [("apache", "struts")],
    "iis": [("microsoft", "internet information services")],
    "microsoft-iis": [("microsoft", "internet information services")],
    "exchange": [("microsoft", "exchange")],
    "sharepoint": [("microsoft", "sharepoint")],
    "outlook": [("microsoft", "outlook")],
    "zimbra": [("synacor", "zimbra")],
    "wordpress": [("wordpress", "core")],
    "drupal": [("drupal", "core")],
    "joomla": [("joomla", "joomla")],
    "confluence": [("atlassian", "confluence")],
    "jira": [("atlassian", "jira")],
    "weblogic": [("oracle", "weblogic")],
    "websphere": [("ibm", "websphere")],
    "coldfusion": [("adobe", "coldfusion")],
    "pan-os": [("palo alto networks", "pan-os")],
    "fortios": [("fortinet", "fortios")],
    "vcenter": [("vmware", "vcenter"), ("broadcom", "vcenter")],
    "esxi": [("vmware", "esxi")],
    "netscaler": [("citrix", "netscaler")],
    "big-ip": [("f5", "big-ip")],
    "pulse-connect-secure": [("pulse", "pulse connect secure"),
                             ("ivanti", "pulse connect secure")],
    "openssl": [("openssl", "openssl")],
    "php": [("php", "php")],
    "jquery": [("jquery", "jquery")],
    "phpmyadmin": [("phpmyadmin", "phpmyadmin")],
    "phpmailer": [("php", "phpmailer")],
    "thinkphp": [("thinkphp", "thinkphp")],
    # [F61] Black October 2026: GitLab self-managed, BeyondTrust
    # (Remote Support / PRA — dulu Bomgar), Node.js.
    "gitlab": [("gitlab", "gitlab")],
    "beyondtrust": [("beyondtrust", "remote support"),
                    ("beyondtrust", "privileged remote access")],
    "bomgar": [("beyondtrust", "remote support"),
               ("beyondtrust", "privileged remote access")],
    "nodejs": [("nodejs", "node.js"), ("openjs foundation", "node.js")],
    "ollama": [("ollama", "ollama")],
    "vllm": [("vllm", "vllm")],
    "open-webui": [("open webui", "open webui")],
}

_RE_NONALNUM = re.compile(r"[^a-z0-9.]+")
_RE_VERSION = re.compile(r"(\d+(?:\.\d+)+)")


def norm_text(s: str) -> str:
    """Lowercase + non-alnum/dot -> spasi + rapatkan (dipakai utk semua
    sisi pencocokan, alias kunci ikut dinormalisasi)."""
    s = (s or "").lower().replace("_", " ")
    return _RE_NONALNUM.sub(" ", s).strip()


def parse_version(v: str) -> tuple[int, ...] | None:
    """Versi -> tuple segmen numerik; gagalurai = None (dilewati,
    bukan dianggap rentan)."""
    if not v:
        return None
    parts = v.strip().split(".")
    if not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def version_in_range(v: tuple[int, ...], introduced: tuple[int, ...] | None,
                     fixed: tuple[int, ...]) -> bool:
    """introduced <= v < fixed (bila introduced kosong: v < fixed)."""
    if introduced is not None and v < introduced:
        return False
    return v < fixed


def extract_facts(rows: list[dict]) -> list[dict]:
    """Baris findings (tool allowlist) -> fakta produk/versi kandidat.

    Return daftar {text, target_url, source_tool}; ekstraksi versi
    dilakukan per-token saat match (regex di sekitar token)."""
    facts: list[dict] = []
    for r in rows or []:
        if r.get("tool") not in ALLOWED_SOURCE_TOOLS:
            continue
        extra = r.get("extra") or {}
        tech = extra.get("tech")
        tech_s = " ".join(tech) if isinstance(tech, list) else ""
        text = " ".join(str(x) for x in
                        (r.get("response"), r.get("title"), tech_s) if x)
        if not text.strip():
            continue
        facts.append({
            "text": norm_text(text),
            "target_url": r.get("target_url"),
            "source_tool": r.get("tool"),
        })
    return facts


def version_near_token(token: str, text: str) -> str | None:
    """Versi terurai di sekitar token produk (apache/2.4.49,
    jquery 3.5.1). Lookahead menolak versi setengah-jadi: '2.4.x'
    TIDAK terbaca '2.4'. Tanpa versi terurai = None."""
    pat = re.compile(re.escape(token) + r"[ /]*(\d+(?:\.\d+)+)(?![.\w])")
    m = pat.search(text)
    return m.group(1) if m else None


def _kev_index(kev_entries: list[dict]) -> dict:
    """Indeks KEV: (vendor_norm, product_norm) -> entri + indeks
    product-norm >=5 char utk direct match."""
    return {"entries": [
        {**e,
         "_vendor": norm_text(e.get("vendorProject", "")),
         "_product": norm_text(e.get("product", ""))}
        for e in (kev_entries or []) if e.get("cveID")
    ]}


def match_kev(fact: dict, idx: dict) -> list[dict]:
    """Semua entri KEV yang cocok dgn satu fakta (direct + alias).
    Match = kehadiran produk di teks fakta — BUKAN klaim versi rentan."""
    text = fact["text"]
    hits: dict[str, dict] = {}
    for e in idx["entries"]:
        prod = e["_product"]
        if len(prod) < 5 or prod in GENERIC_PRODUCT_TOKENS:
            continue
        if prod == e["_vendor"]:
            continue  # entri payung (mis. "Microsoft :: Microsoft") —
        # tanpa kualifikasi produk = kebisingan; yang sah lewat alias.
        if prod in text:
            ver = version_near_token(prod, text)
            hits.setdefault(e["cveID"], {**e, "_via": "direct",
                                         "_token": prod, "_version": ver})
    for token, targets in ALIASES.items():
        tok = norm_text(token)
        if tok not in text:
            continue
        ver = version_near_token(tok, text)
        for vend_sub, prod_sub in targets:
            for e in idx["entries"]:
                if vend_sub in e["_vendor"] and prod_sub in e["_product"]:
                    prev = hits.get(e["cveID"])
                    if prev is not None and not prev.get("_version") and ver:
                        prev["_version"] = ver
                        prev["_via"] = f"alias:{token}"
                    hits.setdefault(e["cveID"],
                                    {**e, "_via": f"alias:{token}",
                                     "_token": tok, "_version": ver})
    return sorted(hits.values(), key=lambda h: h["cveID"])


def load_watchlist(path: Path) -> tuple[list[dict], list[dict]]:
    """Watchlist breaking-CVE (seed kurasi) -> (entri_valid, ditolak).
    Entri tanpa cve/product/tokens/source_url ditolak fail-closed —
    matcher tidak menebak token dari nama produk."""
    valid: list[dict] = []
    rejected: list[dict] = []
    if not path.exists():
        return valid, rejected
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return valid, [{"error": "watchlist tidak terurai"}]
    for s in doc.get("seeds", []) or []:
        if not (s.get("cve") and s.get("product") and s.get("tokens")
                and s.get("source_url")):
            rejected.append(s)
            continue
        toks = [norm_text(t) for t in s["tokens"] if norm_text(t)]
        if not toks:
            rejected.append(s)
            continue
        valid.append({**s, "_tokens": toks,
                      "_product": norm_text(str(s["product"]))})
    return valid, rejected


def match_watchlist(fact: dict,
                    wl_entries: list[dict]) -> list[dict]:
    """Seed watchlist utk satu fakta: token eksplisit di teks fakta =
    lead product-level (TANPA klaim versi — watchlist tidak membawa
    rentang; versi bersebelahan dicatat sbg fakta saja)."""
    text = fact["text"]
    out: list[dict] = []
    for s in wl_entries:
        hit_token = next((t for t in s["_tokens"] if t in text), None)
        if hit_token is None:
            continue
        ver = version_near_token(hit_token, text)
        out.append({**s, "_hit": hit_token, "_version": ver})
    return sorted(out, key=lambda h: h["cve"])


def load_kb(path: Path) -> tuple[list[dict], list[dict]]:
    """KB operator -> (entri_valid, entri_ditolak). Entri tanpa
    source_url/fixed ditolak fail-closed (tercatat, bukan dipakai)."""
    valid: list[dict] = []
    rejected: list[dict] = []
    if not path.exists():
        return valid, rejected
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return valid, [{"error": "kb tidak terurai"}]
    for e in doc.get("entries", []) or []:
        if not (e.get("cve") and e.get("product") and e.get("fixed")
                and e.get("source_url")):
            rejected.append(e)
            continue
        fixed = parse_version(str(e["fixed"]))
        intro = (parse_version(str(e["introduced"]))
                 if e.get("introduced") else None)
        if fixed is None:
            rejected.append(e)
            continue
        valid.append({**e, "_product": norm_text(str(e["product"])),
                      "_fixed": fixed, "_introduced": intro})
    return valid, rejected


def match_kb(fact: dict, kb_entries: list[dict]) -> tuple[list[dict], int, int]:
    """Entri KB operator utk satu fakta: versi fakta terurai DAN di
    dalam rentang operator (introduced <= v < fixed). Return
    (claims, evaluated, skipped) — evaluated = entri KB dgn produk
    cocok; skipped = produk cocok tapi versi tak terurai."""
    text = fact["text"]
    out: list[dict] = []
    evaluated = skipped = 0
    for e in kb_entries:
        prod = e["_product"]
        if prod not in text:
            continue
        evaluated += 1
        ver_s = version_near_token(prod, text)
        if ver_s is None:
            skipped += 1
            continue
        v = parse_version(ver_s)
        if v is None:
            skipped += 1
            continue
        if version_in_range(v, e["_introduced"], e["_fixed"]):
            out.append({**e, "_version": ver_s})
    return out, evaluated, skipped


def build_template_index(corpus_dir: Path, corpus_version: str,
                         cache_path: Path) -> dict | None:
    """Indeks cve-id -> path template (regex YAML, tanpa dependensi).
    Cache dikunci versi korpus (manifest) — versi beda = rebuild; korpus
    tidak ada = None (pengayaan dilewati, fail-closed)."""
    if not corpus_dir.is_dir():
        return None
    if cache_path.exists():
        try:
            c = json.loads(cache_path.read_text(encoding="utf-8"))
            if c.get("corpus_version") == corpus_version:
                return c
        except Exception:  # noqa: BLE001
            pass
    pat = re.compile(r"cve-id:\s*[\"']?(CVE-\d{4}-\d{4,})", re.I)
    index: dict[str, list[str]] = {}
    for p in sorted(corpus_dir.rglob("*.y*ml")):
        try:
            head = p.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            continue
        for m in pat.finditer(head):
            index.setdefault(m.group(1), []).append(
                p.relative_to(corpus_dir).as_posix())
    doc = {"corpus_version": corpus_version, "cves": index}
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        tmp.replace(cache_path)
    except OSError:
        pass  # cache bersifat optimasi — tanpa cache tetap benar
    return doc


def load_kev_entries() -> list[dict] | None:
    """KEV lokal -> daftar entri; file tidak ada = None (fail-closed —
    pemanggil melaporkan 'skipped', bukan mengklaim bersih)."""
    if not KEV_PATH.exists():
        return None
    doc = json.loads(KEV_PATH.read_text(encoding="utf-8"))
    return doc.get("vulnerabilities", [])


def enrich_findings_doc(doc: dict,
                        kev_entries: list[dict]) -> tuple[dict, dict]:
    """Salinan doc findings + HANYA baris pengetahuan (category
    CVE-MATCH — tanpa baris ringkasan AMAN/audit yang membanjiri
    laporan per program); doc ASLI tidak diubah (state scan & drift
    tetap stabil). Watchlist di-load otomatis (fail-closed: file tidak
    ada = tanpa watchlist, bukan klaim bersih)."""
    wl_entries, _ = load_watchlist(WATCHLIST_PATH)
    rows, meta = match_cves(doc.get("findings", []), kev_entries,
                            wl_entries=wl_entries)
    knowledge = [r for r in rows if r.get("category") == "CVE-MATCH"]
    return {**doc, "findings": list(doc.get("findings", [])) + knowledge}, meta


def match_cves(rows: list[dict], kev_entries: list[dict] | None,
               kb_entries: list[dict] | None = None,
               rejected_kb: list[dict] | None = None,
               tpl_index: dict | None = None,
               wl_entries: list[dict] | None = None) -> tuple[list[dict], dict]:
    """Murni: fakta x (KEV + KB operator + watchlist) -> (rows, meta)
    kontrak. Verdict maksimum L1 di semua jalur (docs/CVE-MATCHER.md)."""
    kb_entries = kb_entries or []
    rejected_kb = rejected_kb or []
    wl_entries = wl_entries or []
    out: list[dict] = []
    if kev_entries is None:
        out.append(make_finding(
            tool="cve-matcher",
            title="KEV tidak tersedia — pemetaan CVE dilewati",
            severity="medium",
            description="assets/intel/kev.json tidak ada; cve-matcher "
                        "berjalan fail-closed tanpa memaksakan klaim.",
            recommendation="python tools/intel_sync.py --components kev",
            target_url="intel:kev",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "CVE-MATCH", "kev_missing": True}))
        meta = {"kev_entries": 0, "facts": 0, "matches": 0,
                "kev_missing": True, "ranges_checked": 0,
                "ranges_skipped": 0, "kb_entries": len(kb_entries),
                "kb_rejected": len(rejected_kb),
                "watchlist_entries": len(wl_entries),
                "watchlist_matches": 0}
        return out, meta

    idx = _kev_index(kev_entries)
    facts = extract_facts(rows)
    seen: set[tuple] = set()
    kb_claimed: set[tuple] = set()  # (cve, target_url) — KEV tak mendobel
    n_range = n_skip = 0
    for fact in facts:
        # KB operator dulu (bukti terikat versi = lebih kuat); entri KEV
        # untuk CVE yang sama lalu ter-dedup — tidak ada baris ganda.
        kb_claims, evaluated, skipped = match_kb(fact, kb_entries)
        n_skip += skipped
        n_range += evaluated
        for kb in kb_claims:
            key = (kb["cve"], fact["target_url"], kb.get("_version"),
                   kb["_product"])
            if key in seen:
                continue
            seen.add(key)
            kb_claimed.add((kb["cve"], fact["target_url"]))
            out.append(make_finding(
                tool="cve-matcher",
                title=f"KB operator: {kb['cve']} rentang versi cocok "
                      f"({kb.get('_version')})",
                severity="high",
                description=f"Versi {kb.get('_version')} berada dalam "
                            f"rentang entri KB operator "
                            f"({kb.get('introduced') or '0'} <= v < "
                            f"{kb.get('fixed')}) — sumber: "
                            f"{kb.get('source_url', '')[:160]}. Masih "
                            "lead L1: banner dapat dipalsukan/diprosxy; "
                            "verifikasi manual tetap wajib.",
                recommendation=f"Verifikasi manual + cek advisory: "
                               f"{kb.get('source_url', '')[:160]}",
                cwe=None, target_url=fact["target_url"],
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "CVE-MATCH", "cve": kb["cve"],
                       "via": "operator-kb",
                       "version_detected": kb.get("_version"),
                       "version_claim": True, "report_requires_poc": True}))
        for hit in match_kev(fact, idx):
            if (hit["cveID"], fact["target_url"]) in kb_claimed:
                continue
            key = (hit["cveID"], fact["target_url"],
                   hit.get("_version"), hit.get("_token"))
            if key in seen:
                continue
            seen.add(key)
            # CVE dari KEV juga menandai emitted — watchlist tidak
            # mendobelkan entri yang sudah match lewat KEV.
            kb_claimed.add((hit["cveID"], fact["target_url"]))
            ransomware = (hit.get("knownRansomwareCampaignUse") == "Known")
            tpl = None
            if tpl_index:
                tpls = tpl_index.get("cves", {}).get(hit["cveID"])
                if tpls:
                    tpl = tpls[0]
            ver = hit.get("_version")
            ver_s = f", banner/versi terdeteksi: {ver}" if ver else ""
            out.append(make_finding(
                tool="cve-matcher",
                title=f"KEV: {hit.get('vendorProject', '?')} "
                      f"{hit.get('product', '?')} — {hit['cveID']} "
                      f"dieksploitasi-in-the-wild{ver_s}",
                severity="high" if ransomware else "medium",
                description=f"Produk keluarga ini ada di CISA KEV "
                            f"({hit.get('vulnerabilityName', '')[:160]}). "
                            "KEV tidak membawa version-range — ini lead "
                            "product-level, BUKAN klaim versi rentan. "
                            "VERIFIKASI MANUAL paparan versi wajib.",
                recommendation=("Verifikasi versi produk secara manual; "
                                + (f"template nuclei tersedia: {tpl} "
                                   "(nuclei-templates-scan)"
                                   if tpl else
                                   "pertimbangkan nuclei-templates-scan")),
                cwe=(hit.get("cwes") or [None])[0],
                target_url=fact["target_url"],
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "CVE-MATCH", "cve": hit["cveID"],
                       "via": hit.get("_via"),
                       "version_detected": ver,
                       "version_claim": False,
                       "nuclei_template": tpl,
                       "ransomware_use": ransomware}))
        # [F61b] Watchlist breaking-CVE (di luar KEV) — paling akhir,
        # tidak mendobel KB/KEV untuk CVE yang sama.
        for w in match_watchlist(fact, wl_entries):
            if (w["cve"], fact["target_url"]) in kb_claimed:
                continue
            key = (f"wl:{w['cve']}", fact["target_url"],
                   w.get("_version"), w["_hit"])
            if key in seen:
                continue
            seen.add(key)
            ver_s = (f", versi terdeteksi: {w['_version']}"
                     if w.get("_version") else "")
            out.append(make_finding(
                tool="cve-matcher",
                title=f"WATCHLIST: {w.get('vendor', '?')} "
                      f"{w['product']} — {w['cve']} (di luar KEV)"
                      f"{ver_s}",
                severity="high",
                description=f"Token eksplisit '{w['_hit']}' pada fakta "
                            f"versi; entri watchlist kurasi operator "
                            "(CVE kritis BELUM terkonfirmasi KEV — "
                            "celah konfirmasi = masa paling berbahaya). "
                            f"{str(w.get('note', ''))[:200]} Sumber: "
                            f"{str(w.get('source_url', ''))[:160]}. "
                            "Lead product-level maks L1 — VERIFIKASI "
                            "MANUAL paparan versi wajib.",
                recommendation=f"Pantau advisory + verifikasi versi: "
                               f"{str(w.get('source_url', ''))[:160]}",
                cwe=None, target_url=fact["target_url"],
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "CVE-MATCH", "cve": w["cve"],
                       "via": "watchlist",
                       "version_detected": w.get("_version"),
                       "version_claim": False,
                       "report_requires_poc": True}))
    if not any(r.get("category") == "CVE-MATCH" for r in out):
        out.append(make_finding(
            tool="cve-matcher",
            title="Tidak ada match KEV/KB dari fakta versi yang ada",
            severity="info",
            description=f"{len(facts)} fakta product/version dari tool "
                        "allowlist tidak memunculkan entri KEV/KB yang "
                        "cocok (AMAN/inventaris).",
            target_url=None,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    if rejected_kb:
        out.append(make_finding(
            tool="cve-matcher",
            title=f"KB operator: {len(rejected_kb)} entri ditolak "
                  "fail-closed",
            severity="medium",
            description="Entri KB tanpa cve/product/fixed/source_url "
                        "atau dengan versi tak terurai TIDAK dipakai "
                        "(anti-fabrikasi range).",
            recommendation="Lengkapi field wajib entri KB.",
            target_url="intel:cve-kb",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "CVE-MATCH", "kb_rejected": True}))
    meta = {"kev_entries": len(kev_entries), "facts": len(facts),
            "matches": sum(1 for r in out
                           if r.get("category") == "CVE-MATCH"),
            "ranges_checked": n_range, "ranges_skipped": n_skip,
            "kb_entries": len(kb_entries),
            "kb_rejected": len(rejected_kb),
            "watchlist_entries": len(wl_entries),
            "watchlist_matches": sum(1 for r in out
                                     if r.get("via") == "watchlist"),
            "templates": "ok" if tpl_index else "unavailable"}
    return out, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", nargs="+", required=True,
                    help="file findings.json hasil scan (bisa >1)")
    ap.add_argument("--out", default="findings/cve-matcher.json")
    ap.add_argument("--kb", default=str(KB_PATH),
                    help="KB operator (default assets/intel/cve-kb.json)")
    ap.add_argument("--with-templates", action="store_true",
                    help="indeks template nuclei utk pengayaan saran")
    args = ap.parse_args()

    in_rows: list[dict] = []
    for fp in args.findings:
        p = Path(fp)
        if not p.exists():
            print(f"cve-matcher: input findings tidak ada: {fp}",
                  file=sys.stderr)
            return 2
        in_rows.extend(json.loads(p.read_text(encoding="utf-8"))
                       .get("findings", []))

    if not KEV_PATH.exists():
        kev_entries = None
    else:
        kev_entries = json.loads(
            KEV_PATH.read_text(encoding="utf-8")).get("vulnerabilities", [])
    kb_entries, rejected_kb = load_kb(Path(args.kb))
    wl_entries, wl_rejected = load_watchlist(WATCHLIST_PATH)

    tpl_index = None
    if args.with_templates:
        corpus_version = ""
        man = ROOT / "assets" / "intel" / "manifest.json"
        if man.exists():
            try:
                corpus_version = (json.loads(
                    man.read_text(encoding="utf-8")).get(
                    "components", {}).get("nuclei-templates", {})
                    .get("version", ""))
            except Exception:  # noqa: BLE001
                corpus_version = ""
        tpl_index = build_template_index(TPL_CORPUS_DIR, corpus_version,
                                         TPL_INDEX_PATH)

    out_rows, meta = match_cves(in_rows, kev_entries, kb_entries,
                                rejected_kb, tpl_index, wl_entries)
    write_findings(args.out, out_rows,
                   {**meta, "run": "cve-matcher",
                    "safety_class": "read-only", "requests": 0,
                    "watchlist_rejected": len(wl_rejected),
                    "inputs": [str(p) for p in args.findings]})
    print(f"cve-matcher: fakta={meta['facts']} match={meta['matches']} "
          f"(kev={meta['kev_entries']}, kb={meta['kb_entries']}, "
          f"watchlist={meta['watchlist_entries']}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
