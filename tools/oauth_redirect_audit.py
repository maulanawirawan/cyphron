"""[AUDIT: read-only] oauth_redirect_audit — audit OFFLINE validasi
redirect_uri & postur flow OAuth 2.0 dari BUKTI tangkapan probe (nol
jaringan — bukti dibuat operator di lab berizin, tool ini hanya
mengklasifikasi).

Mengisi antrean port SKILL-PORT-QUEUE #0983 (mukul975/
Anthropic-Cybersecurity-Skills 'testing-oauth2-implementation-flaws' —
lisensi sumber Apache-2.0, atribusi konsep; kode dibangun FROM SCRATCH
TANPA menyalin kode sumber). Skill sumber = live probing via Burp/
EsPReSSO; inti deterministiknya diekstrak di sini: (1) generator
matriks varian bypass redirect_uri dari URI kanonik (path-traversal,
authority-confusion @, subdomain-suffix, case, trailing-slash, downgrade
http, param/fragment injection, javascript-scheme, dsb.) yang dicetak
sebagai rencana probe, (2) pengklasifikasi keputusan server dari bukti
{redirect_uri, status, location} per varian.

Input -> mekanisme -> output:
  - INPUT  --matrix + --canonical : cetak matriks probe (rencana,
    tanpa jaringan). INPUT --evidence : JSON tangkapan operator:
    {"target": "...", "probes": [{"id", "status", "location",
    "redirect_uri"?, "response_type"?, "send_state"?, "pkce"?}, ...],
    "exchanges": [{"id": "code-replay", "attempts": [200, 200]}]}
  - MEKANISME: gerbang KONTROL dulu — probe `baseline` (redirect_uri
    kanonik) wajib terbukti menerbitkan code ke origin kanonik; tanpa
    kontrol, differential tidak valid (exit 2, fail-closed). Lalu tiap
    probe diarahkan: keputusan = issued (3xx + location membawa code/
    access_token) vs rejected (4xx/error=) vs other; origin FINAL
    location dibandingkan dgn origin kanonik.
  - OUTPUT findings.json kontrak core (make_finding/write_findings) +
    ringkasan. Nilai code/token di bukti SELALU direduksi (marker hash
    deterministik gaya tools/redact.py) — nilai tak pernah menulis
    keluar.

Pemetaan keputusan -> temuan (anti-FP):
  - varian lintas-origin (host/port/scheme berbeda dari kanonik —
    termasuk downgrade http) diterima + code terbit -> high CWE-601
    confirmed L3 (bukti request/response ter-redaksi);
  - implicit flow (response_type=token) diterima, access_token di
    fragment -> medium CWE-319 confirmed L3 (bocor via history/
    Referer/log);
  - code yang sama ditukar >= 2x sukses -> high CWE-294 confirmed L3
    (single-use tidak ditegakkan);
  - varian SAME-origin (trailing-slash/case/path-append) diterima ->
    low L1 unconfirmed (indikasi prefix-matching — normalisasi bisa
    sah, tidak diklaim);
  - code terbit tanpa state -> info L1 unconfirmed (state = kewajiban
    sisi CLIENT — server menerbitkan tanpa state bukan otomatis vuln);
  - code terbit tanpa code_challenge / challenge plain -> low L1
    unconfirmed (PKCE wajib utk public client di OAuth 2.1);
  - rejected = catatan server strict (bukan temuan).

Ranah eksplisit: probing LIVE ke authorization server = operator
(pakai --matrix sebagai rencana); audit granular scope/konsen = oauth_grant_audit;
playbook state live = exploit_playbooks oauth-state; JWT access token =
jwt_token_audit. Target hanya lab/berizin.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default medium);
2 error input / kontrol baseline tidak terbentuk.

Pemakaian:
  python tools/oauth_redirect_audit.py --canonical https://app.lab.local/callback --matrix
  python tools/oauth_redirect_audit.py --evidence capture.json --out findings.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

from findings import make_finding, validate_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.oauth-redirect-audit/1"
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_FILE_BYTES = 64 * 1024 * 1024

# param OAuth yang nilainya kredensial — SELALU direduksi di bukti
_OAUTH_SECRET_PARAMS = frozenset({
    "code", "access_token", "refresh_token", "id_token", "client_secret",
})

_DEFAULT_PORTS = {"http": 80, "https": 443}


def mask_oauth_value(value: str) -> str:
    """Penanda deterministik gaya tools/redact.py: hash pendek agar
    diff antar-run tetap bisa dibandingkan tanpa membocorkan nilai."""
    h = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"[REDACTED sha256:{h}]"


def _redact_oauth_url(url: str) -> str:
    """Redaksi nilai param OAuth (code/token) di query DAN fragment;
    host/path tidak disentuh. URL tak-valid dibiarkan (bukan crash)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    changed = False

    def _mask_q(q: str) -> str:
        nonlocal changed
        if not q:
            return q
        pairs = parse_qsl(q, keep_blank_values=True)
        if not pairs:
            return q
        out = []
        for k, v in pairs:
            if k.lower() in _OAUTH_SECRET_PARAMS and v:
                changed = True
                out.append((k, mask_oauth_value(v)))
            else:
                out.append((k, v))
        return urlencode(out)

    new_q = _mask_q(parts.query)
    new_f = _mask_q(parts.fragment)
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       new_q, new_f))


def _origin(url: str) -> "tuple[str, str, int] | None":
    """(scheme, host, port-efektif) dari sebuah URL; None bila tak
    bisa diparse (host kosong/scheme tanpa netloc)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if not scheme or not host:
        return None
    port = parts.port
    if port is None:
        port = _DEFAULT_PORTS.get(scheme, 0)
    return scheme, host.lower(), port


def _location_params(location: str) -> "tuple[set[str], set[str]]":
    """(kunci query, kunci fragment) dari sebuah Location — keputusan
    hanya pakai KUNCI, nilai tidak dibaca."""
    try:
        parts = urlsplit(location)
    except ValueError:
        return set(), set()
    qk = {k.lower() for k, _ in parse_qsl(parts.query,
                                          keep_blank_values=True)}
    fk = {k.lower() for k, _ in parse_qsl(parts.fragment,
                                          keep_blank_values=True)}
    return qk, fk


def _decision(probe: dict) -> str:
    """issued | rejected | other — dari status + location."""
    status = probe.get("status")
    location = str(probe.get("location") or "")
    if not isinstance(status, int):
        return "other"
    if 300 <= status < 400 and location:
        qk, fk = _location_params(location)
        if {"code", "access_token", "id_token"} & (qk | fk):
            return "issued"
        if "error" in qk:
            return "rejected"
        return "other"
    if isinstance(status, int) and 400 <= status < 500:
        return "rejected"
    return "other"


def build_redirect_matrix(canonical: str) -> "list[dict]":
    """Matriks varian bypass redirect_uri dari URI kanonik (determinis,
    nol jaringan). Varian mengikuti kelas manipulasi RFC 3986 yang
    dipakai skill sumber (path/authority/case/scheme/param/fragment)."""
    o = _origin(canonical)
    if o is None or not canonical or o[0] not in _DEFAULT_PORTS:
        raise ValueError(
            f"canonical bukan URL http(s) absolut (scheme+host): "
            f"{canonical!r}")
    scheme, host, port = o
    parts = urlsplit(canonical)
    path = parts.path or "/"

    def _rebuild(*, new_scheme: str | None = None,
                 netloc: str | None = None,
                 new_path: str | None = None,
                 new_q: str | None = None,
                 new_frag: str | None = None) -> str:
        return urlunsplit((
            new_scheme or scheme,
            netloc if netloc is not None else parts.netloc,
            new_path if new_path is not None else path,
            new_q if new_q is not None else parts.query,
            new_frag if new_frag is not None else parts.fragment,
        ))

    rows: "list[dict]" = [
        {"id": "baseline", "class": "control", "redirect_uri": canonical,
         "note": "KONTROL: kanonik harus diterima & menerbitkan code "
                 "sebelum varian mana pun bisa diklaim (fail-closed)"},
        {"id": "foreign-origin", "class": "redirect",
         "redirect_uri": "https://evil.example/cb",
         "note": "origin asing eksplisit — diterima = code ke peneliti"},
        {"id": "subdomain-suffix", "class": "redirect",
         "redirect_uri": f"https://{host}.evil.example{path}",
         "note": "host kanonik sebagai prefix subdomain penyerang"},
        {"id": "authority-confusion", "class": "redirect",
         "redirect_uri": f"https://{host}@evil.example{path}",
         "note": "host kanonik jadi userinfo; authority asli = evil"},
        {"id": "path-traversal", "class": "redirect",
         "redirect_uri": f"{canonical}/../../../evil.example",
         "note": "traversal — server lenient bisa menormalkan ke luar"},
        {"id": "prefix-concat", "class": "redirect",
         "redirect_uri": f"{canonical}evil.example",
         "note": "prefix-match: /callbackevil.example diterima"},
        {"id": "path-append", "class": "redirect",
         "redirect_uri": f"{canonical}/extra",
         "note": "append path (same-origin) — indikator lax matching"},
        {"id": "case-host", "class": "redirect",
         "redirect_uri": _rebuild(netloc=host.upper()
                                  + (f":{port}" if parts.port else "")),
         "note": "case host"},
        {"id": "case-path", "class": "redirect",
         "redirect_uri": _rebuild(new_path=path.upper()),
         "note": "case path"},
        {"id": "trailing-slash", "class": "redirect",
         "redirect_uri": f"{canonical}/",
         "note": "trailing slash — normalisasi bisa sah"},
        {"id": "trailing-qmark", "class": "redirect",
         "redirect_uri": f"{canonical}?",
         "note": "tanda tanya kosong"},
        {"id": "param-injection", "class": "redirect",
         "redirect_uri": f"{canonical}?next=https://evil.example",
         "note": "param tambahan — cek passthrough ke callback"},
        {"id": "fragment-injection", "class": "redirect",
         "redirect_uri": f"{canonical}#https://evil.example",
         "note": "fragment injection"},
        {"id": "encoded-fragment", "class": "redirect",
         "redirect_uri": f"{canonical}%23evil.example",
         "note": "fragment ter-encode — decode di server = bypass"},
        {"id": "http-downgrade", "class": "redirect",
         "redirect_uri": _rebuild(new_scheme="http"),
         "note": "downgrade http — code terkirim tanpa TLS"},
        {"id": "explicit-default-port", "class": "redirect",
         "redirect_uri": _rebuild(netloc=f"{host}:{_DEFAULT_PORTS[scheme]}"),
         "note": "port default eksplisit (indikator pencocokan string)"},
        {"id": "other-port", "class": "redirect",
         "redirect_uri": _rebuild(netloc=f"{host}:8443"),
         "note": "port lain (same-host)"},
        {"id": "javascript-scheme", "class": "redirect",
         "redirect_uri": f"javascript://{host}{path}",
         "note": "scheme javascript — diterima = kelas XSS + pencurian "
                 "code (payload canary benign, tanpa skrip nyata)"},
        {"id": "no-redirect-uri", "class": "behavior",
         "omit_params": ["redirect_uri"],
         "note": "redirect_uri dihilangkan — server pakai default? "
                 "(catat location yang dihasilkan)"},
        {"id": "no-state", "class": "behavior",
         "omit_params": ["state"],
         "note": "state dihilangkan — server tetap menerbitkan code? "
                 "validasi state = kewajiban client (verifikasi callback)"},
        {"id": "no-pkce", "class": "behavior",
         "omit_params": ["code_challenge", "code_challenge_method"],
         "note": "PKCE dihilangkan — code terbit tanpa challenge?"},
        {"id": "plain-pkce", "class": "behavior",
         "set_params": {"code_challenge": "canaryverifiercanaryverifier",
                        "code_challenge_method": "plain"},
         "note": "challenge method plain diterima (downgrade dari S256)"},
        {"id": "implicit", "class": "flow",
         "set_params": {"response_type": "token"},
         "note": "implicit flow — access_token di fragment (deprecated "
                 "OAuth 2.1)"},
        {"id": "code-replay", "class": "replay",
         "note": "tukar code yang SAMA >= 2x di token endpoint — "
                 "success kedua = single-use tidak ditegakkan"},
    ]
    return rows


def _probe_matches_matrix(probe: dict, matrix: "list[dict]") -> "dict | None":
    """Cocokkan probe bukti ke baris matriks (by id dulu, lalu by
    redirect_uri persis). None bila tak dikenal."""
    pid = str(probe.get("id") or "")
    for row in matrix:
        if row["id"] == pid:
            return row
    purl = str(probe.get("redirect_uri") or "")
    if purl:
        for row in matrix:
            if row.get("redirect_uri") and row["redirect_uri"] == purl:
                return row
    return None


def _f(tool_title: str, sev: str, cwe: str | None, desc: str, rec: str,
       probe: dict, verdict: int, status: str, confidence: float,
       canonical_origin: str) -> dict:
    loc = _redact_oauth_url(str(probe.get("location") or ""))
    ruri = _redact_oauth_url(str(probe.get("redirect_uri") or ""))
    req = (f"GET authorize?redirect_uri={ruri}"
           + (f"&response_type={probe.get('response_type')}"
              if probe.get("response_type") else ""))
    return make_finding(
        tool="oauth_redirect_audit",
        title=tool_title,
        severity=sev,
        description=desc,
        recommendation=rec,
        cwe=cwe,
        target_url=canonical_origin,
        param=str(probe.get("id") or ""),
        request=req,
        response=f"status={probe.get('status')} location={loc}",
        poc=f"redirect_uri={ruri} -> status {probe.get('status')}; "
            f"location membawa code/token ke origin yang diarahkan",
        evidence_kind="request-response",
        confidence=confidence,
        status=status,
        verdict=verdict,
        extra={"canonical": canonical_origin},
    )


def audit_evidence(evidence: dict,
                   canonical: str | None) -> "tuple[list[dict], dict, list[str]]":
    """Klasifikasi bukti -> (findings, stats, notes). Fail-closed:
    kontrol baseline tidak terbukti -> ValueError (pemanggil keluarkan
    exit 2)."""
    notes: "list[str]" = []
    stats: dict = {"probes": 0, "issued": 0, "rejected": 0, "other": 0}

    probes = evidence.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ValueError("evidence.probes kosong / bukan array — tidak "
                         "ada yang bisa diaudit (fail-closed)")
    matrix = build_redirect_matrix(canonical) if canonical else []
    matrix_ids = {r["id"] for r in matrix}

    base = None
    for p in probes:
        if isinstance(p, dict) and str(p.get("id") or "") == "baseline":
            base = p
            break
    if base is None:
        raise ValueError(
            "probe kontrol id='baseline' wajib ada di evidence.probes — "
            "differential tanpa kontrol tidak valid (fail-closed)")
    if _decision(base) != "issued":
        raise ValueError(
            "kontrol baseline tidak menerbitkan code (status "
            f"{base.get('status')}) — lingkungan probe tidak sesuai "
            "asumsi, tidak ada yang bisa diklaim (fail-closed)")

    can_uri = str(canonical or base.get("redirect_uri") or "")
    can_o = _origin(can_uri)
    if can_o is None:
        raise ValueError(
            "origin kanonik tidak bisa ditentukan dari baseline/"
            "--canonical (fail-closed)")
    can_origin_str = f"{can_o[0]}://{can_o[1]}"
    if can_o[2] != _DEFAULT_PORTS.get(can_o[0]):
        can_origin_str += f":{can_o[2]}"

    findings: "list[dict]" = []
    for probe in probes:
        if not isinstance(probe, dict):
            notes.append("elemen probes bukan objek — dilewati")
            continue
        stats["probes"] += 1
        pid = str(probe.get("id") or "")
        status = probe.get("status")
        if not isinstance(status, int):
            notes.append(f"probe {pid!r}: status bukan integer — "
                         "dilewati (fail-closed)")
            stats["other"] += 1
            continue
        decision = _decision(probe)
        stats[decision] += 1
        row = _probe_matches_matrix(probe, matrix) if matrix else None
        if matrix and row is None:
            notes.append(f"probe id={pid!r} tidak ada di matriks "
                         "kanonik — diklasifikasi generik origin-based")

        loc_origin = _origin(str(probe.get("location") or "")) \
            if decision == "issued" else None
        # Hanya probe redirect-varian yang boleh memicu temuan
        # arah-redirect: baris matriks kelas redirect, ATAU bukti yang
        # mengirim redirect_uri BERBEDA dari kanonik. Probe
        # behavior/flow yang mengirim kanonik persis (state/PKCE/
        # implicit) bukan temuan lax (anti-FP).
        p_uri = str(probe.get("redirect_uri") or "")
        is_redirect_probe = (
            (row is not None and row["class"] == "redirect")
            or (bool(p_uri) and p_uri != can_uri))

        if pid == "baseline" or (row and row["class"] == "control"):
            continue  # kontrol — bukan temuan

        if (decision == "issued" and loc_origin is not None
                and is_redirect_probe):
            # "diterima" berarti code MENGIKUTI redirect_uri yang
            # dikirim probe: origin DAN path location == redirect_uri
            # probe. Server yang menormalkan balik ke kanonik = bukan
            # penerimaan varian (bukan temuan).
            try:
                probe_parts = urlsplit(str(probe.get("redirect_uri") or ""))
                loc_parts = urlsplit(str(probe.get("location") or ""))
            except ValueError:
                probe_parts = loc_parts = None
            probe_uri_o = _origin(str(probe.get("redirect_uri") or ""))
            honored = (
                probe_parts is not None and loc_parts is not None
                and probe_uri_o is not None and loc_origin == probe_uri_o
                and (loc_parts.path or "/") == (probe_parts.path or "/"))
            if not honored:
                notes.append(
                    f"probe {pid!r}: location tidak mengikuti redirect_uri "
                    "varian (server menormalkan/menolak) — bukan temuan")
            else:
                foreign = loc_origin != can_o
                scheme = loc_origin[0]
                if scheme == "javascript":
                    findings.append(_f(
                        "redirect_uri javascript-scheme diterima — code "
                        "terbit ke URI non-http (kelas XSS + pencurian "
                        "code)",
                        "high", "CWE-601",
                        "Authorization server menerima redirect_uri dengan "
                        "scheme javascript dan menaruh code di dalamnya.",
                        "Tolak redirect_uri yang scheme-nya bukan https "
                        "(exact-match pada URI terdaftar); cantumkan "
                        "daftar URI eksak per client.",
                        probe, 3, "confirmed", 0.95, can_origin_str))
                elif foreign:
                    desc = ("Server menerima varian redirect_uri yang "
                            "berakhir di origin lain dari kanonik dan "
                            "meletakkan code di sana — authorization code "
                            "bisa dicegat pihak ketiga.")
                    if scheme == "http":
                        desc += (" Varian ini juga cleartext (http) — "
                                 "code terkirim tanpa TLS.")
                    findings.append(_f(
                        f"redirect_uri lintas-origin diterima ({pid or '?'}"
                        "): code diterbitkan ke origin selain kanonik",
                        "high", "CWE-601",
                        desc,
                        "Validasi redirect_uri exact-match string terhadap "
                        "URI terdaftar (tanpa prefix/normalisasi); tolak "
                        "varian dan log upaya.",
                        probe, 3, "confirmed", 0.95, can_origin_str))
                else:
                    findings.append(_f(
                        f"redirect_uri varian same-origin diterima "
                        f"({pid or '?'}"
                        ") — indikasi pencocokan longgar",
                        "low", "CWE-601",
                        "Varian same-origin diterima apa adanya (bukan "
                        "dinormalkan ke kanonik) — indikator prefix/"
                        "fuzzy-matching; dampak terbatas karena origin "
                        "tetap.",
                        "Kenalkan exact-match; verifikasi bahwa varian "
                        "ini memang tidak diminta oleh client sah.",
                        probe, 1, "unconfirmed", 0.6, can_origin_str))
        if decision == "issued" and (
                pid == "implicit"
                or str(probe.get("response_type") or "") == "token"):
            qk, fk = _location_params(str(probe.get("location") or ""))
            if "access_token" in (qk | fk):
                findings.append(_f(
                    "implicit flow aktif — access_token di Location "
                    "(fragment/query)",
                    "medium", "CWE-319",
                    "response_type=token diterima: token akses keluar di "
                    "URL (fragment) — bocor via history, Referer, dan log.",
                    "Matikan implicit flow di authorization server "
                    "(OAuth 2.1 deprecated); pakai authorization-code + "
                    "PKCE.",
                    probe, 3, "confirmed", 0.9, can_origin_str))
        if decision == "issued" and pid == "no-state":
            findings.append(_f(
                "code diterbitkan tanpa parameter state",
                "info", None,
                "Authorization server menerbitkan code tanpa state. "
                "Validasi state adalah kewajiban client — temuan ini "
                "menandai kebutuhan verifikasi callback, bukan vuln "
                "server.",
                "Pastikan callback client menolak code dengan state yang "
                "tidak terikat sesi (playbook oauth-state menguji ini "
                "live).",
                probe, 1, "unconfirmed", 0.6, can_origin_str))
        if decision == "issued" and pid in ("no-pkce", "plain-pkce"):
            which = ("tanpa code_challenge" if pid == "no-pkce"
                     else "dengan challenge method plain")
            findings.append(_f(
                f"code diterbitkan {which} (PKCE tidak ditegakkan)",
                "low", None,
                "Authorization server menerima permintaan code " + which +
                ". Untuk public client, PKCE (S256) wajib di OAuth 2.1 — "
                "tanpa itu, code interception mungkin.",
                "Tegakkan PKCE S256 untuk semua client publik; tolak "
                "plain.",
                probe, 1, "unconfirmed", 0.6, can_origin_str))

    for ex in evidence.get("exchanges") or []:
        if not isinstance(ex, dict):
            continue
        attempts = ex.get("attempts")
        if (isinstance(attempts, list) and len(attempts) >= 2
                and all(isinstance(a, int) for a in attempts[:2])
                and attempts[0] == 200 and attempts[1] == 200):
            findings.append(make_finding(
                tool="oauth_redirect_audit",
                title="authorization code dapat ditukar ulang "
                      "(single-use tidak ditegakkan)",
                severity="high",
                description="Code yang sama diterima token endpoint "
                            "beberapa kali (semua 200) — code curian "
                            "tetap bisa ditukar setelah pemakaian sah.",
                recommendation="Tegakkan single-use: code kedua harus "
                               "ditolak (invalid_grant) dan token yang "
                               "sudah diterbitkan lewat pemakaian pertama "
                               "dicabut.",
                cwe="CWE-294",
                target_url=can_origin_str,
                param=str(ex.get("id") or "code-replay"),
                request="POST token? grant_type=authorization_code "
                        "(code sama, ditukar 2x)",
                response=f"attempts={attempts[:2]}",
                poc="pertukaran pertama 200, pertukaran kedua 200 — "
                    "replay sukses",
                evidence_kind="request-response",
                confidence=0.95,
                status="confirmed",
                verdict=3,
                extra={"canonical": can_origin_str},
            ))
        else:
            notes.append("exchange code-replay tidak memenuhi pola replay "
                         "sukses (2x 200) — bukan temuan")

    # deterministik: urutkan severity desc lalu title
    findings.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                                 f["title"], f["param"]))
    for f in findings:
        errs = validate_finding(f)
        if errs:
            raise ValueError(f"finding tidak valid (internal): {errs}")
    return findings, stats, notes


def _load_json(path: str, label: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"{label} tak ada: {path}")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{label} melebihi batas ukuran: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} JSON rusak: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label} harus objek JSON: {path}")
    return data


def _parse_args(argv: "list[str] | None") -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Audit OFFLINE validasi redirect_uri OAuth2 dari "
                    "bukti probe — nol jaringan (#0983)")
    ap.add_argument("--evidence", help="JSON tangkapan probe operator")
    ap.add_argument("--canonical",
                    help="redirect_uri kanonik terdaftar (wajib untuk "
                         "--matrix; opsional untuk --evidence — "
                         "fallback ke baseline)")
    ap.add_argument("--matrix", action="store_true",
                    help="cetak matriks probe dari --canonical (rencana, "
                         "tanpa jaringan)")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="medium")
    ap.add_argument("--out", default="findings.json")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)

    if args.matrix:
        if not args.canonical:
            print(json.dumps({"schema": SCHEMA,
                              "error": "--matrix butuh --canonical"}),
                  file=sys.stderr)
            return 2
        try:
            rows = build_redirect_matrix(args.canonical)
        except ValueError as exc:
            print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
                  file=sys.stderr)
            return 2
        doc = {"schema": SCHEMA, "mode": "matrix",
               "canonical": args.canonical, "matrix": rows,
               "note": "rencana probe — kirim sendiri di lab berizin, "
                       "simpan hasilnya sbg --evidence"}
        Path(args.out).write_text(
            json.dumps(doc, indent=2, ensure_ascii=False),
            encoding="utf-8")
        print(f"[oauth_redirect_audit] matriks {len(rows)} probe -> "
              f"{args.out}")
        return 0

    if not args.evidence:
        print(json.dumps({"schema": SCHEMA,
                          "error": "butuh --evidence atau --matrix"}),
              file=sys.stderr)
        return 2
    try:
        evidence = _load_json(args.evidence, "evidence")
        findings, stats, notes = audit_evidence(evidence, args.canonical)
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]
    meta = {"schema": SCHEMA, "mode": "evidence",
            "target": evidence.get("target", ""), "stats": stats,
            "notes": notes, "requests": 0}
    write_findings(args.out, findings, meta)
    print(f"[oauth_redirect_audit] probes={stats['probes']} "
          f"(issued={stats['issued']} rejected={stats['rejected']} "
          f"other={stats['other']}) findings={len(findings)} -> "
          f"{args.out}")
    for n in notes:
        print(f"  note: {n}")
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
