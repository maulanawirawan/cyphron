"""[SAFETY: bounded-requests] wp-posture — postur instalasi WordPress
dari target URL (F60; dilatarbelakangi verifikasi nyata dayanastudios:
enumerasi user + versi + xmlrpc + login = permukaan brute-force).

Bounded MAKS 6 GET: / (generator versi), /wp-json/wp/v2/users
(enumerasi), /wp-login.php, /xmlrpc.php, /wp-config.php.bak,
/debug.log. Semua read-only GET — TANPA bruteforce password, TANPA
payload. Yang dikunci:
  - enumerasi user terkonfirmasi (200 + daftar slug, guest tanpa
    kredensial) = L3 reportable (deterministik, CWE-200);
  - xmlrpc.php hidup (200/405 pada GET) = L1 (CWE-XXX: CWE-693? -> 
    tanpa CWE spesifik, inventaris);
  - wp-login.php terbuka = L1 inventaris;
  - versi eksplisit di meta generator = L1 + fakta utk cve-matcher;
  - /debug.log / wp-config backup terbaca = L2 (file sensitif
    ter-ekspos, CWE-538/540);
  - bukan WordPress (tanpa marker) = AMAN.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

MAX_GETS = 6
TIMEOUT_S = 10.0
_RE_WP = re.compile(r"wp-content|wp-includes|wp-json", re.I)
_RE_GENERATOR = re.compile(
    r"<meta[^>]+generator[^>]+content=[\"']([^\"']+)[\"']", re.I)
_RE_SLUG = re.compile(r"\"slug\"\s*:\s*\"([A-Za-z0-9_.\\-]+)\"")
_SENSITIVE_PATHS = ("/debug.log", "/wp-config.php.bak", "/wp-config.php~")


def _get(base: str, path: str):
    """Satu GET bounded (helper level modul - pelajaran guard batch 6:
    helper di dalam audit() memicu guard return-shape)."""
    try:
        req = urllib.request.Request(
            base + path, method="GET",
            headers={"User-Agent": "cyphron-wp-posture"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return r.status, r.read(64_000).decode(
                "utf-8", "replace"), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return (e.code,
                (e.read(16_000) or b"").decode("utf-8", "replace"),
                dict(e.headers.items()) if e.headers else {})
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:120], {}

def audit(url: str) -> tuple[list[dict], dict]:
    """Murni(ish): maks 6 GET -> (rows, meta) kontrak."""
    base = url.rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "https://" + base

    rows: list[dict] = []
    n_get = 0
    # 1) homepage: marker WP + versi generator
    st, body, _ = _get(base, "/")
    n_get += 1
    is_wp = bool(_RE_WP.search(body)) if st == 200 else False
    gm = _RE_GENERATOR.search(body) if st == 200 else None
    gen = gm.group(1) if gm else None
    if not is_wp:
        rows.append(make_finding(
            tool="wp-posture",
            title=f"Tidak ada marker WordPress pada {base}",
            severity="info",
            description="Homepage tidak memuat marker WordPress "
                        "(wp-content/wp-includes/wp-json) — skill WP "
                        "berhenti di sini (AMAN/skop).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))
        return rows, {"url": base, "requests": n_get, "is_wp": False,
                      "users": [], "exposures": 0}
    versions = re.findall(r"[Ww]ordPress\s+(\d+\.\d+(?:\.\d+)?)", gen or "")
    if versions:
        rows.append(make_finding(
            tool="wp-posture",
            title=f"Versi WordPress ter-expose di meta generator "
                  f"({versions[0]})",
            severity="low",
            description=f"Meta generator menyebut versi persis "
                        f"({gen[:120]}) — peta untuk mencocokkan CVE "
                        "core/plugin publik. Fakta versi diteruskan ke "
                        "cve-matcher.",
            recommendation="Hapus/sembunyikan meta generator versi "
                           "(theme/plugin keamanan).",
            cwe="CWE-200", target_url=base + "/",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "WP-POSTURE", "safety_class":
                   "bounded-requests", "version": versions[0]}))
    # 2) enumerasi user via REST (guest)
    st_u, body_u, _ = _get(base, "/wp-json/wp/v2/users")
    n_get += 1
    users: list[str] = []
    if st_u == 200:
        try:
            arr = json.loads(body_u)
            if isinstance(arr, list):
                users = [u.get("slug") for u in arr
                         if isinstance(u, dict) and u.get("slug")]
        except Exception:  # noqa: BLE001
            pass
    if users:
        rows.append(make_finding(
            tool="wp-posture",
            title=f"Enumerasi user WordPress via REST API "
                  f"({', '.join(users[:5])})",
            severity="medium",
            description=f"GET /wp-json/wp/v2/users mengembalikan 200 "
                        f"dengan slug user publik ({', '.join(users[:5])}"
                        f"{'; +' + str(len(users) - 5) + ' lagi' if len(users) > 5 else ''}) "
                        "tanpa kredensial — daftar target brute-force/"
                        "password-spray siap pakai (dikombinasikan "
                        "wp-login/xmlrpc bila hidup). Deterministik dan "
                        "reprodusibel.",
            recommendation="Blokir endpoint users untuk guest (filter "
                           "rest_endpoints / plugin keamanan), samakan "
                           "nickname admin, limit login attempt, 2FA.",
            cwe="CWE-200", target_url=base + "/wp-json/wp/v2/users",
            request="GET /wp-json/wp/v2/users -> 200 (guest)",
            response="slug: " + ", ".join(users[:10]),
            evidence_kind="request-response", finding_class="weakness",
            confidence=1.0, status="confirmed", verdict=3,
            extra={"category": "WP-POSTURE", "safety_class":
                   "bounded-requests", "users": users[:10]}))
    # 3) xmlrpc hidup
    st_x, _, _ = _get(base, "/xmlrpc.php")
    n_get += 1
    if st_x in (200, 405):
        rows.append(make_finding(
            tool="wp-posture",
            title=f"XML-RPC WordPress aktif di {base}",
            severity="low",
            description=f"GET /xmlrpc.php -> {st_x} (endpoint hidup) — "
                        "system.listMethods/multicall memampaskan "
                        "brute-force amplifikasi bila tak dipakai.",
            recommendation="Matikan XML-RPC bila tidak dipakai "
                           "(filter xmlrpc_enabled / blokir path).",
            cwe=None, target_url=base + "/xmlrpc.php",
            request=f"GET /xmlrpc.php -> {st_x}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "WP-POSTURE", "safety_class":
                   "bounded-requests", "status": st_x}))
    # 4) wp-login terbuka
    st_l, body_l, _ = _get(base, "/wp-login.php")
    n_get += 1
    if st_l == 200 and ("user_login" in body_l
                        or "wp-login" in body_l.lower()):
        rows.append(make_finding(
            tool="wp-posture",
            title=f"Halaman login WordPress terbuka di {base}",
            severity="info",
            description="wp-login.php merender form login publik — "
                        "inventaris (standar WP); gabungkan dgn "
                        "enumerasi user = daftar target.",
            recommendation="Limit login attempt + 2FA; batasi akses "
                           "wp-login bila memungkinkan.",
            cwe=None, target_url=base + "/wp-login.php",
            request=f"GET /wp-login.php -> {st_l}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "WP-POSTURE", "safety_class":
                   "bounded-requests"}))
    # 5-6) file sensitif
    for pth in _SENSITIVE_PATHS:
        if n_get >= MAX_GETS:
            break
        st_s, body_s, _ = _get(base, pth)
        n_get += 1
        if st_s == 200 and (
                ("wp-config" in pth and body_s.strip())
                or ("debug.log" in pth and len(body_s.strip()) > 20)):
            rows.append(make_finding(
                tool="wp-posture",
                title=f"File sensitif ter-ekspos: {pth}",
                severity="high" if "wp-config" in pth else "medium",
                description=f"GET {pth} -> 200 dgn konten "
                            f"({len(body_s)} byte) — file backup/log "
                            "tidak boleh terjangkau web.",
                recommendation="Hapus file dari webroot + blokir akses "
                               "(deny rule), rotasi kredensial bila "
                               "wp-config berisi kredensial DB.",
                cwe="CWE-538" if "debug" in pth else "CWE-540",
                target_url=base + pth,
                request=f"GET {pth} -> {st_s}",
                response=body_s[:150],
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=2,
                extra={"category": "WP-POSTURE", "safety_class":
                       "bounded-requests"}))
    if not any(r.get("category") == "WP-POSTURE" for r in rows):
        rows.append(make_finding(
            tool="wp-posture",
            title=f"Postur WordPress bersih pada {base}",
            severity="info",
            description=f"WordPress terdeteksi, namun tanpa enumerasi "
                        "user, tanpa versi ter-expose, xmlrpc tertutup, "
                        "dan tanpa file sensitif (AMAN/inventaris, "
                        f"{n_get} GET).",
            target_url=base,
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class":
                   "bounded-requests"}))
    exposures = sum(1 for r in rows if r.get("category") == "WP-POSTURE"
                    and r.get("verdict", 0) >= 1)
    meta = {"url": base, "requests": n_get, "is_wp": True,
            "users": users, "version": versions[0] if versions else None,
            "exposures": exposures}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", default="wp_posture.json")
    args = ap.parse_args()
    rows, meta = audit(args.url)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"wp-posture: wp={meta['is_wp']} users={len(meta['users'])} "
          f"exposures={meta['exposures']} ({meta['requests']} GET) "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
