"""[SAFETY: read-only] verdict-audit — audit distribusi verdict produk.

NOL request, NOL eksekusi kode target. Tiga sumber data lokal:
  1. STATIK: skills/*.py — literal verdict=<int> per file (level maksimum
     yang pernah di-capai jalur manapun di dalam skill itu).
  2. REGISTRY: skills/registry.json — safety_class + requires_evidence.
  3. OBSERVASI: semua JSON hasil run di findings/ (reports/scan, night-run
     state, scan per-aset) yang berbentuk output skill
     ({tool, verdict, status} rows) — termasuk scan target nyata.

Output: tabel peringkat "skill dengan lead L1 terbanyak yang berpotensi
naik", tiap skill ditandai SATU kategori strategi bukti (menu operator)
atau "-" (tidak bisa naik — postur/inventaris murni). Rasio global
terbukti/lead/inventaris ikut dicetak (bahasa ringkas untuk laporan).

DISIPLIN: tool ini TIDAK menaikkan verdict apa pun — hanya mengukur dan
menunjukkan di mana upgrade bukti deterministik layak dikerjakan.
Klasifikasi strategi = kurasi eksplisit; skill di luar kurasi ditandai
"-" dengan alasan "belum dikurasi" (bukan ditebak).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"
REGISTRY = SKILLS_DIR / "registry.json"

# Folder findings yang BUKAN data observasi temuan (intel cache, state
# scheduler, dsb). Di-skip agar hitungan hanya dari output skill nyata.
SKIP_DIRS = {"intel", "learning", "programs", "benchmark",
             "manual-verification", "mcp", "discovery", "vdp"}
SKIP_FILES = {"freshness.json", "cwe-check.json", "kev-gap.json",
              "dependency-cve.json", "verdict-audit.json"}
MAX_FILES = 4000
MAX_ROWS = 200_000

# ---------------------------------------------------------------------------
# Kurasi strategi bukti (menu operator — SATU kategori per skill):
#   A = Differential kontrol safe (raw vs safe endpoint)
#   B = N-trial deterministik (threshold terukur)
#   C = OOB interactsh (callback eksternal)
#   D = Response-signature ketat + reproducible GET ulang
#   E = Chain fakta versi -> KB/KEV/NVD -> probe verifikasi
#   F = Playbook lab proof (kelas mutasi — tetap tier-2 lab)
#   "-" = tidak bisa naik (postur/inventaris murni — fakta, bukan kerentanan)
# Format: nama-skill -> (strategi, alasan singkat)
# ---------------------------------------------------------------------------
STRATEGI = {
    # --- A: differensial -----------------------------------------------
    "cors-checker": ("A", "refleksi Origin+credentials sudah differensial; raw-vs-safe tinggal diperluas"),
    "error-oracle": ("A", "sudah differensial (canary vs signature); jaga, tidak perlu ubah"),
    "param-probe-checker": ("A", "sudah differensial (kontrol ikut diuji)"),
    "header-reflection-matrix": ("A", "refleksi header bisa diverifikasi differensial"),
    "form-csrf-checker": ("A", "token ada/absen per form — bisa dikonfirmasi dgn submit canary vs kontrol"),
    "http-method-allow-checker": ("A", "OPTIONS Allow bisa dibandingkan antar method aman/berisiko"),
    "open-redirect-surface": ("A", "redirect bisa dikonfirmasi differensial (host benign vs arbitrer, tanpa mengunjungi host asing)"),
    "internal-info-leak-checker": ("A", "sudah anti-FP (IP RFC1918 non-HTML)"),
    "xss-reflect-check": ("A", "sudah differensial (marker refleksi mentah) — lab_only"),
    "egress-fingerprint-check": ("A", "sudah differensial echo (UA dikirim vs dilihat server)"),
    "graphql-surface-detector": ("A", "introspection on/off = differensial query vs kontrol"),
    "graphql-schema-map": ("A", "introspection on/off = differensial query vs kontrol"),
    "smuggling-clue-checker": ("A", "sinyal clue bisa dikuatkan dgn differensial header"),
    # --- B: N-trial ------------------------------------------------------
    "antibot-posture": ("B", "N-trial: tidak-ada-throttling bisa dibuktikan dgn N request + kode respons terukur (pola F59)"),
    # --- C: OOB ----------------------------------------------------------
    # (tidak ada skill registry saat ini yang jalur naiknya butuh OOB eksternal;
    #  keluarga SSRF/OOB sudah tercakup playbook lab — lihat F)
    # --- D: signature ketat + reproducible -------------------------------
    "directory-listing-detector": ("D", "listing = signature ketat (Index of + parent link); GET ulang identik -> L3"),
    "api-docs-surface": ("D", "openapi/swagger = signature ketat (openapi:/swagger: JSON); GET ulang identik -> L3"),
    "swagger-ui-surface": ("D", "swagger UI = signature ketat; GET ulang identik -> L3"),
    "console-exposure-checker": ("D", "sudah L2 dgn path konsol; GET ulang identik -> L3"),
    "file-exposure-checker": ("D", "file expose = signature konten ketat; GET ulang identik -> L3"),
    "cached-sensitive-files": ("D", "marker signup-welcome = signature ketat halaman sukses aktivasi; GET ulang identik -> L3 (pola CVE-2026-111464)"),
    "debug-page-detector": ("D", "sudah L3 (marker ketat dari bukti)"),
    "cloud-bucket-exposure": ("D", "ListBucketResult = signature XML unik; GET ulang identik -> L2/L3 (atribusi tetap caveat)"),
    "github-leak-check": ("D", "opt-in: konten raw bisa dikonfirmasi (signature secret format) — tetap L1/L2, tanpa ekstraksi"),
    "sourcemap-exposure-checker": ("D", ".map + sourcesContent = signature ketat; GET ulang identik -> L2/L3"),
    "agent-instruction-exposure": ("D", "sudah L2 (anti-fallback HTML); GET ulang identik -> L3"),
    "takeover-fingerprint-checker": ("D", "fingerprint CNA = signature ketat; re-query -> konfirmasi"),
    "takeover-cname-hygiene": ("D", "dangling CNAME bisa dikonfirmasi signature NXDOMAIN/no-CNA + re-query"),
    "wordpress-rest-surface": ("D", "wp-json index = signature JSON eksklusif; GET ulang identik -> L2/L3"),
    "js-secret-scanner-v2": ("D", "secret format-kuat di JS bisa direfetch utk reproduksi (tetap hemat: 1 refetch/file kandidat)"),
    "dns-axfr-check": ("D", "SOA..SOA penuh = signature ketat; re-query TCP/53 -> konfirmasi (sudah L2)"),
    "tls-heartbeat-overread": ("D", "overread terukur byte-akurat (sudah L3-capable)"),
    # --- E: chain fakta versi --------------------------------------------
    "banner-posture": ("-", "absensi header = fakta postur; rantai versi E SUDAH jalan via cve-matcher (F41/F58)"),
    "banner-oracle-ebs": ("E", "marker versi EBS -> KB/watchlist Oracle EBS via cve-matcher (F66 seed); tanpa versi = postur '-'"),
    "banner-plex": ("E", "X-Plex-Version -> KB/watchlist Plex2Shell via cve-matcher (F66 seed); tanpa versi = postur '-'"),
    "server-version-disclosure": ("E", "versi -> KB/KEV (sudah masuk cve-matcher); tidak ada probe tambahan tanpa KB"),
    "js-library-version-checker": ("E", "versi lib -> KB; naik hanya lewat rantai cve-matcher"),
    "api-version-surface": ("E", "inventaris versi API; naik via KB bila rentang cocok"),
    "tech-fingerprint": ("E", "fingerprint -> KB; naik via rantai cve-matcher"),
    "wp-plugin-surface": ("E", "versi plugin readme.txt -> KB/watchlist; probe verifikasi per-CVE bila rentang cocok"),
    "wp-posture": ("E", "versi WP -> KB (enumerasi user sudah L3; xmlrpc/login tetap postur '-')"),
    "php-posture": ("E", "versi PHP -> KB php2shell (sudah jalan); easter-egg phpinfo = D kecil"),
    "magento-surface": ("E", "/magento_version -> KB (sudah jalan)"),
    "gitlab-posture": ("E", "versi -> KB GitLab (sudah jalan)"),
    "beyondtrust-posture": ("E", "marker -> alias KEV + seed watchlist (sudah jalan)"),
    "litellm-posture": ("E", "versi -> KB/KEV (sudah jalan)"),
    "ollama-posture": ("E", "versi -> KB Probllama (sudah jalan)"),
    "vllm-posture": ("E", "marker metrik vllm:* = signature kuat; versi -> KB bila ada entri"),
    "openwebui-posture": ("E", "marker token; naik via KB bila ada entri"),
    "brotli-stack-surface": ("E", "marker stack Node -> watchlist (sudah jalan)"),
    "port-banner-consistency-checker": ("E", "inkonsistensi banner = fakta; naik via KB bila produk dikenali"),
    "mcp-exposure": ("D", "shape transport SSE/JSON-RPC = signature ketat; GET ulang identik -> L2"),
    "cve-matcher": ("-", "lapisan pengetahuan itu sendiri (post-processor NOL request)"),
    "crawler-attribution": ("-", "atribusi crawler dari log milik sendiri = fakta"),
    "manual-verification": ("-", "checklist verifikasi manual, bukan detektor"),
    # --- F: playbook lab ---------------------------------------------------
    "exploit-engine": ("F", "lab-only tier-2/3 — bukti mutasi dari lab sebagai contoh"),
    # --- "-" postur/inventaris murni (fakta, bukan kerentanan) ------------
    "http-security-headers": ("-", "absensi header = fakta postur"),
    "csp-analyzer": ("-", "analisis kebijakan = fakta postur"),
    "hsts-preload-checker": ("-", "status preload = fakta"),
    "cache-control-posture": ("-", "header cache = fakta postur"),
    "cookie-flags-aggregate": ("-", "absensi flag = fakta postur"),
    "cookie-scope": ("-", "scope cookie = fakta postur"),
    "clickjacking-protection-checker": ("-", "absensi XFO/frame-ancestors = fakta postur"),
    "xss-protection-header-checker": ("-", "absensi header = fakta postur"),
    "password-autocomplete-checker": ("-", "atribut autocomplete = fakta postur"),
    "sri-checker": ("-", "absensi integrity = fakta postur"),
    "mixed-content-detector": ("-", "konten campuran = fakta konten"),
    "http2-support-checker": ("-", "dukungan protokol = fakta"),
    "ssl-tls-analyzer": ("-", "postur TLS = fakta konfigurasi"),
    "tls-cipher-suites-checker": ("-", "daftar cipher = fakta konfigurasi"),
    "email-sender-surface": ("-", "SPF/DMARC/MTA-STS/CAA absen = fakta DNS postur"),
    "spf-dmarc-posture": ("-", "SPF/DMARC = fakta DNS postur"),
    "security-txt": ("-", "security.txt absen = fakta postur"),
    "xmlrpc-surface": ("-", "endpoint hidup = fakta postur (diferensial tidak berlaku)"),
    "robots-txt-surface": ("A", "sudah terpasang F75: canary differensial (wildcard-200 terbukti / FP-eliminated / spesifik)"),
    "sitemap-disclosure-checker": ("A", "sudah terpasang F75: canary differensial (wildcard-200 terbukti / FP-eliminated / spesifik)"),
    "well-known-exposure-checker": ("A", "sudah terpasang F75: canary differensial (wildcard-200 terbukti / FP-eliminated / spesifik)"),
    "subdomain-enum-surface": ("-", "inventaris subdomain"),
    "ct-inventory": ("-", "inventaris sertifikat"),
    "wayback-history": ("-", "inventaris arsip"),
    "archive-url-checker": ("-", "inventaris arsip"),
    "typosquat-watch": ("-", "drift CT = fakta (lead sudah L1 sah)"),
    "rdap-whois": ("-", "postur registrar = fakta (transfer-lock sudah L2)"),
    "rdap-enrichment": ("-", "drift registrasi = fakta"),
    "redirect-chain": ("-", "fakta rantai redirect"),
    "cdn-detector": ("-", "inventaris CDN"),
    "waf-fingerprint": ("-", "inventaris WAF"),
    "analytics-tracker-surface": ("-", "inventaris tracker"),
    "open-graph-leak-checker": ("-", "inventaris meta"),
    "third-party-script-risk": ("-", "inventaris skrip pihak ketiga"),
    "favicon-fingerprint": ("-", "hash favicon = inventaris"),
    "llm-endpoint-surface": ("-", "inventaris dari bukti (read-only)"),
    "nuclei-templates-scan": ("-", "pembungkus nuclei eksternal"),
    "program-discovery": ("-", "kandidat program = inventaris"),
    "repo-secret-scan": ("D", "kandidat secret di sumber lokal: format kuat + lokasi stabil = bukti bisa direproduksi ulang (tetap lead, verifikasi manual)"),
    "infra-config-audit": ("-", "audit konfigurasi lokal = fakta"),
    "js-endpoints": ("-", "inventaris endpoint"),
    "banner-posture-evidence": ("E", "varian evidence dari banner-posture"),
    "rate-limit-validator": ("B", "sudah N-trial bounded — lab_only tier-2"),
}

BUCKETS = ("L-x", "L0", "L1", "L2", "L3+")


def bucket_of(verdict: int) -> str:
    if verdict == -1:
        return "L-x"
    if verdict == 0:
        return "L0"
    if verdict == 1:
        return "L1"
    if verdict == 2:
        return "L2"
    return "L3+"


def load_registry(root: Path | None = None) -> dict[str, dict]:
    base = root or ROOT
    reg = json.loads((base / "skills" / "registry.json")
                     .read_text(encoding="utf-8"))
    return {s["name"]: s for s in reg.get("skills", [])}


def static_max_verdicts(root: Path | None = None) -> dict[str, int]:
    """Literal verdict=<int> per file skill (level maksimum di kode)."""
    base = root or ROOT
    out: dict[str, int] = {}
    for f in sorted((base / "skills").glob("*.py")):
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        vals = [int(m) for m in re.findall(r"verdict\s*=\s*(-?\d+)", text)]
        if vals:
            name = f.stem.replace("_", "-")
            out[name] = max(vals)
    return out


def iter_observed_rows(extra_globs: list[str],
                       root: Path | None = None):
    """Yield (sumber, row) dari semua JSON berbentuk output skill."""
    base = root or ROOT
    findings_dir = base / "findings"
    seen = 0
    candidates: list[Path] = []
    if findings_dir.is_dir():
        for p in sorted(findings_dir.rglob("*.json")):
            if len(candidates) >= MAX_FILES:
                break
            rel = p.relative_to(findings_dir)
            if rel.parts and rel.parts[0] in SKIP_DIRS:
                continue
            if p.name in SKIP_FILES or p.name in ("drift.json",
                                                  "run-manifest.json",
                                                  "egress-state.json",
                                                  "nightrun-summary.json",
                                                  "prev-findings.json",
                                                  "weekly-summary.json",
                                                  "findings-knowledge.json",
                                                  "cve-kb.json"):
                continue
            candidates.append(p)
    for g in extra_globs:
        base = Path.cwd()
        for p in sorted(base.glob(g)):
            if p.is_file() and p not in candidates:
                candidates.append(p)
    for p in candidates:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows = None
        if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
            rows = doc["findings"]
        elif isinstance(doc, list):
            rows = doc
        if not rows:
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not isinstance(row.get("tool"), str) or \
                    "verdict" not in row:
                continue
            seen += 1
            if seen > MAX_ROWS:
                return
            src = (str(p.relative_to(base))
                   if p.is_relative_to(base) else str(p))
            yield src, row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--extra", action="append", default=[],
                    help="glob JSON tambahan (relatif CWD); boleh berulang")
    ap.add_argument("--out", default="findings/verdict-audit.json",
                    help="tulisan hasil JSON (LOCAL-ONLY)")
    ap.add_argument("--top", type=int, default=0,
                    help="batasi tabel utama ke N baris teratas")
    args = ap.parse_args()

    registry = load_registry()
    static_max = static_max_verdicts()

    # --- observasi per tool -------------------------------------------
    per_tool: dict[str, Counter] = {}
    per_tool_unconf: dict[str, Counter] = {}
    n_rows = 0
    for _src, row in iter_observed_rows(args.extra):
        n_rows += 1
        tool = row["tool"]
        v = row["verdict"]
        if not isinstance(v, int):
            continue
        b = bucket_of(v)
        if row.get("status") == "confirmed":
            per_tool.setdefault(tool, Counter())[b] += 1
        else:
            per_tool_unconf.setdefault(tool, Counter())[b] += 1

    # --- susun tabel ----------------------------------------------------
    names = sorted(set(static_max) | set(per_tool) | set(per_tool_unconf))
    entries = []
    for name in names:
        conf = per_tool.get(name, Counter())
        unconf = per_tool_unconf.get(name, Counter())
        strat, alasan = STRATEGI.get(name, ("-", "belum dikurasi"))
        reg = registry.get(name, {})
        entries.append({
            "skill": name,
            "obs_l1_confirmed": conf.get("L1", 0),
            "obs_l1_unconfirmed": unconf.get("L1", 0),
            "obs_L0": conf.get("L0", 0) + unconf.get("L0", 0),
            "obs_L2plus": conf.get("L2", 0) + conf.get("L3+", 0),
            "obs_Lx": conf.get("L-x", 0) + unconf.get("L-x", 0),
            "static_max_verdict": static_max.get(name),
            "safety_class": reg.get("safety_class", "?"),
            "strategi": strat,
            "alasan": alasan,
        })

    # urut: berpotensi naik (strategi != "-") dulu, lalu L1 confirmed
    # terbanyak, lalu L1 unconfirmed, lalu nama
    entries.sort(key=lambda e: (0 if e["strategi"] != "-" else 1,
                                -e["obs_l1_confirmed"],
                                -e["obs_l1_unconfirmed"], e["skill"]))

    naik = [e for e in entries if e["strategi"] != "-"]
    total_conf = Counter()
    total_unconf = Counter()
    for c in per_tool.values():
        total_conf.update(c)
    for c in per_tool_unconf.values():
        total_unconf.update(c)
    proven = total_conf["L2"] + total_conf["L3+"]
    lead = total_conf["L1"]
    inv = total_conf["L0"]
    unassessed = sum(total_unconf.values())
    filtered = total_conf["L-x"] + total_unconf["L-x"]

    print(f"verdict-audit - NOL request, sumber: skills/*.py + registry + "
          f"findings/ ({n_rows} baris observasi)")
    print(f"Rasio global: {proven} TERBUKTI (L2+) | {lead} lead L1 "
          f"(PERLU DICEK) | {inv} inventaris L0 | {unassessed} tidak bisa "
          f"dinilai (unconfirmed) | {filtered} tersaring (L-x)")
    print()
    hdr = (f"{'skill':34s} {'L1c':>4s} {'L1u':>4s} {'L0':>4s} {'L2+':>4s} "
           f"{'smax':>4s}  {'strategi':2s}  catatan")
    print(hdr)
    print("-" * len(hdr))
    main_rows = entries[: args.top] if args.top else entries
    for e in main_rows:
        smax = e["static_max_verdict"]
        smax_s = "?" if smax is None else str(smax)
        print(f"{e['skill'][:34]:34s} {e['obs_l1_confirmed']:4d} "
              f"{e['obs_l1_unconfirmed']:4d} {e['obs_L0']:4d} "
              f"{e['obs_L2plus']:4d} {smax_s:>4s}  {e['strategi']:2s}  "
              f"{e['alasan'][:60]}")
    print()
    print(f"Skill ter-kurasi berpotensi naik: {len(naik)}/{len(entries)} "
          f"(strategi A/B/C/D/E/F); sisanya '-' = postur/inventaris murni "
          f"(LANGKAH N: naikkan kualitas laporan, bukan label).")

    doc = {
        "ok": True,
        "tool": "verdict-audit",
        "requests": 0,
        "rows_observed": n_rows,
        "ratio": {"proven_L2plus": proven, "lead_L1": lead,
                  "inventory_L0": inv, "unassessed": unassessed,
                  "filtered": filtered},
        "skills": entries,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"Hasil JSON: {out} (LOCAL-ONLY)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
