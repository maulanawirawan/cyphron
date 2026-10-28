"""[SAFETY: read-only] crawler-attribution — siapa yang mengunjungi situsmu?

Skill F21: analisis atribusi untuk crawler/bot yang tercatat di logmu.
Input: export log Cloudflare (JSON array) atau --ua/--ip eksplisit.
Semua data dari sumber publik: DoH PTR, RDAP IP (rdap.org), dan database
crawler terdokumentasi lokal. NOL trafik ke target.

Yang dihasilkan:
  - Crawler TERDOKUMENTASI (mis. ClaudeBot -> Anthropic via AWS)
    -> L0 SURFACE (inventaris, bukan klaim)
  - Crawler TIDAK terdokumentasi
    -> L1 lead + profil infrastruktur per IP (PTR, organisasi RDAP)
       sebagai bukti atribusi — bukan tuduhan
  - Ringkasan: berapa UA dianalisis, berapa terdokumentasi

Disiplin: "tidak terdokumentasi" adalah FAKTA yang dilaporkan apa adanya;
atribusi ke perusahaan tertentu TIDAK diklaim tanpa bukti (fail-closed).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

TOOL = "crawler-attribution"
UA_HDR = "cyphron-audit/0.1"
MAX_RESPONSE_BYTES = 262_144  # 256 KB — cap bukti; lebih besar = fail-closed

# Crawler terdokumentasi: (substring UA, nama, operator, asal-usual, doc)
DOCUMENTED_CRAWLERS = [
    ("ClaudeBot", "ClaudeBot", "Anthropic", "AWS (AS16509)",
     "https://support.claude.com/en/articles/8898731-anthropic-crawlers-overview"),
    ("Claude-SearchBot", "Claude-SearchBot", "Anthropic", "AWS (AS16509)",
     "https://support.claude.com/en/articles/8898731-anthropic-crawlers-overview"),
    ("Claude-User", "Claude-User", "Anthropic", "AWS (AS16509)",
     "https://support.claude.com/en/articles/8898731-anthropic-crawlers-overview"),
    ("GPTBot", "GPTBot", "OpenAI", "datacenter US", ""),
    ("OAI-SearchBot", "OAI-SearchBot", "OpenAI", "datacenter US", ""),
    ("ChatGPT-User", "ChatGPT-User", "OpenAI", "datacenter US", ""),
    ("Googlebot", "Googlebot", "Google", "Google AS15169", ""),
    ("bingbot", "bingbot", "Microsoft", "Microsoft AS8075", ""),
    ("Applebot", "Applebot", "Apple", "Apple AS714", ""),
    ("DuckDuckBot", "DuckDuckBot", "DuckDuckGo", "-", ""),
    ("UptimeRobot", "UptimeRobot", "UptimeRobot", "monitoring", ""),
    ("Slackbot", "Slackbot", "Slack", "AWS", ""),
    ("GoogleOther", "GoogleOther", "Google", "Google AS15169", ""),
    ("Palo Alto Networks", "Cortex Xpanse", "Palo Alto Networks",
     "attack-surface scanner (self-identifying)",
     "https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity"),
    ("Let's Encrypt validation server", "Let's Encrypt ACME validation",
     "Let's Encrypt / ISRG", "validasi sertifikat", ""),
    ("WhatsApp", "WhatsApp link preview", "Meta", "preview bot", ""),
]


def _get(url: str, timeout: float = 20.0):
    """GET publik dengan cap 256 KB; return bytes atau None (fail-closed)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA_HDR})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return None
            return raw
    except Exception:
        return None


def doh_ptr(ip: str) -> list[str]:
    """PTR record IP via DoH; [] bila tidak ada/gagal."""
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    raw = _get(f"https://dns.google/resolve?name={name}&type=PTR")
    if not raw:
        return []
    try:
        doc = json.loads(raw.decode())
    except Exception:
        return []
    return [a.get("data", "") for a in doc.get("Answer", [])
            if a.get("type") == 12]


def rdap_ip(ip: str) -> dict:
    """RDAP IP: {org, name, country, range} atau {} bila gagal."""
    raw = _get(f"https://rdap.org/ip/{ip}")
    if not raw:
        return {}
    try:
        doc = json.loads(raw.decode())
    except Exception:
        return {}
    org = ""
    for e in doc.get("entities", []):
        for role in e.get("roles", []):
            if role == "registrant" or role == "administrative":
                for item in (e.get("vcardArray") or [None, []])[1]:
                    if item[0] == "fn" and item[3]:
                        org = str(item[3])[:80]
                        break
    remarks = " ".join(
        r.get("description", [""])[0] if isinstance(r.get("description"), list)
        and r.get("description") else str(r.get("description", ""))
        for r in doc.get("remarks", []))
    return {
        "org": org or str(doc.get("name", ""))[:80],
        "name": str(doc.get("name", ""))[:80],
        "country": str(doc.get("country", "")),
        "range": (f"{doc.get('startAddress', '')}-{doc.get('endAddress', '')}"
                  if doc.get("startAddress") else ""),
        "remarks": remarks[:160],
    }


def match_ua(ua: str) -> dict | None:
    """Kembalikan entri crawler terdokumentasi yang cocok, atau None."""
    low = ua.lower()
    for needle, name, operator, origin, doc in DOCUMENTED_CRAWLERS:
        if needle.lower() in low:
            return {"ua": ua, "name": name, "operator": operator,
                    "expected_origin": origin, "doc": doc}
    return None


def parse_log(path: str) -> list[dict]:
    """Parse export log Cloudflare (JSON array) -> [{ip, ua, host, path, ts}].
    Fail-closed: file tidak ada / bukan JSON array = error keras."""
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"{path}: tidak ada — fail-closed")
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise SystemExit(f"{path}: bukan JSON valid ({exc}) — fail-closed")
    if not isinstance(doc, list):
        raise SystemExit(f"{path}: bukan array log — fail-closed")
    out = []
    for row in doc:
        if not isinstance(row, dict):
            continue
        out.append({
            "ip": str(row.get("clientIP", "")),
            "ua": str(row.get("userAgent", "")),
            "host": str(row.get("clientRequestHTTPHost", "")),
            "path": str(row.get("clientRequestPath", "/")),
            "ts": str(row.get("datetime", "")),
        })
    return out


def audit(entries: list[dict], extra_ips: list[str],
          extra_uas: list[str]) -> tuple[list[dict], dict]:
    """Atribusi semua (UA, IP) unik. Return (rows, meta)."""
    pairs = {(e["ua"], e["ip"]) for e in entries if e["ua"] and e["ip"]}
    for ua in extra_uas:
        pairs.add((ua, ""))
    for ip in extra_ips:
        pairs.add(("", ip))

    by_ua: dict[str, set[str]] = {}
    for ua, ip in pairs:
        if ua:
            by_ua.setdefault(ua, set()).add(ip)
        elif ip:
            by_ua.setdefault("(tanpa UA)", set()).add(ip)

    rows: list[dict] = []
    infra_cache: dict[str, dict] = {}
    documented = 0
    requests_made = 0

    for ua, ips in sorted(by_ua.items()):
        hit = match_ua(ua)
        if hit:
            documented += 1
            rows.append(make_finding(
                tool=TOOL,
                title=f"Documented crawler detected: {hit['name']} "
                      f"({hit['operator']})",
                severity="info",
                description=(
                    f"UA '{ua[:80]}' cocok crawler resmi {hit['operator']} — "
                    f"asal-usual: {hit['expected_origin']}. Kunjungan crawler "
                    "pencarian adalah inventaris normal situs publik "
                    "(SURFACE, bukan klaim)."),
                target_url=", ".join(sorted(
                    {e["host"] for e in entries if e["ua"] == ua}) or ["-"])[:120],
                response=json.dumps(
                    {"ua_sample": ua[:120], "ips": sorted(ips)[:5]},
                    ensure_ascii=False)[:400],
                evidence_kind="log", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "SURFACE", "safety_class": "read-only",
                       "ua": ua[:120], "operator": hit["operator"],
                       "doc": hit["doc"], "ip_count": len(ips)}))
            continue

        # Tidak terdokumentasi — kumpulkan profil infra per IP
        profiles = []
        no_ptr = 0
        for ip in sorted(ips):
            if not ip:
                continue
            if ip not in infra_cache:
                ptr = doh_ptr(ip)
                rd = rdap_ip(ip)
                requests_made += 2
                infra_cache[ip] = {"ptr": ptr, "rdap": rd}
            info = infra_cache[ip]
            if not info["ptr"]:
                no_ptr += 1
            profiles.append({
                "ip": ip,
                "ptr": info["ptr"][:2],
                "org": info["rdap"].get("org", ""),
                "country": info["rdap"].get("country", ""),
            })
        orgs = sorted({p["org"] for p in profiles if p["org"]})
        countries = sorted({p["country"] for p in profiles if p["country"]})
        profile_txt = json.dumps(profiles[:5], ensure_ascii=False)[:500]
        rows.append(make_finding(
            tool=TOOL,
            title=f"Undocumented crawler on your logs: {ua[:60]} "
                  f"({len(ips)} IP)",
            severity="low",
            description=(
                f"UA '{ua[:80]}' tidak ada di database crawler terdokumentasi "
                f"mancanegara maupun publik. Profil infrastruktur: {len(ips)} "
                f"IP, {no_ptr} tanpa PTR, jaringan: "
                f"{', '.join(orgs[:3]) or '-'} ({', '.join(countries[:3]) or '-'}). "
                "FAKTA yang dilaporkan: tidak terdokumentasi — atribusi ke "
                "perusahaan tertentu TIDAK diklaim tanpa bukti tambahan "
                "(fail-closed). Pola IP ISP residensial/ISP bisnis tanpa PTR "
                "adalah ciri jaringan distribusi pihak ketiga."),
            target_url=", ".join(sorted(
                {e["host"] for e in entries if e["ua"] == ua}) or ["-"])[:120],
            response=profile_txt,
            evidence_kind="log", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "read-only",
                   "ua": ua[:120], "ip_count": len(ips), "no_ptr": no_ptr,
                   "networks": orgs[:5], "profiles": profiles[:5]}))

    rows.sort(key=lambda r: (r["verdict"], r["title"]))
    meta = {"uas": len(by_ua), "documented": documented,
            "undocumented": len(by_ua) - documented,
            "requests": requests_made}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", action="append", default=[],
                    help="file export log Cloudflare (JSON); boleh diulang")
    ap.add_argument("--ua", action="append", default=[],
                    help="User-Agent eksplisit; boleh diulang")
    ap.add_argument("--ip", action="append", default=[],
                    help="IP eksplisit; boleh diulang")
    ap.add_argument("--out", default="crawler_attribution_findings.json")
    args = ap.parse_args()

    entries: list[dict] = []
    for lg in args.log:
        entries.extend(parse_log(lg))
    if not entries and not args.ua and not args.ip:
        ap.error("butuh --log dan/atau --ua/--ip — fail-closed")

    rows, meta = audit(entries, args.ip, args.ua)
    write_findings(args.out, rows, {
        "logs": args.log, "safety_class": "read-only", **meta})
    undoc = meta.get("undocumented", 0)
    print(f"{TOOL}: {len(rows)} temuan "
          f"({meta.get('documented', 0)} terdokumentasi, {undoc} tidak "
          f"terdokumentasi) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
