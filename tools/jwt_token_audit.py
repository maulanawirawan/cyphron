r"""[SAFETY: read-only] jwt_token_audit — audit OFFLINE konten token
JWT (header + claims) yang diambil dari bukti triase: vektor header
(alg=none beserta variannya, jku/x5u eksternal, jwk inline, kid
injection) dan higiene klaim (exp hilang, exp mati, umur panjang).
TANPA jaringan, TANPA verifikasi signature (butuh kunci/JWKS — live
ops).

Port konsep dari antrean SKILL-PORT-QUEUE #0498 (mukul975/Anthropic-
Cybersecurity-Skills 'exploiting-jwt-algorithm-confusion-attack' —
alg confusion RS256->HS256, varian alg:none, injeksi kid/jku/x5u;
atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM SCRATCH:
dekoder base64url + aturan cek ditulis sendiri; skill sumber
MENGEKSPLOITASI token live (PyJWT/cryptography/jwt_tool, forge token),
secai hanya MENILAI konten token yang sudah ada di bukti (read-only,
tanpa forge). Sisi eksekusi live dilayani JwtAlgConfusionPlaybook +
JwtWeakSecretPlaybook di tools/exploit_playbooks.py.

Input -> mekanisme -> output:
  - Input : --tokens FILE (satu token per baris, token = segmen
            base64url dipisah '.'; baris kosong/# dilewati) ATAU
            --token "..." (boleh diulang).
  - Mekanisme: split segmen -> decode header/claims (base64url) ->
            cek deterministik per token.
  - Output: temuan {check, severity, token_index, ...} + stats +
            notes; isi klaim sensitif TIDAK diecho penuh (hanya
            iss/aud/sub terpotong, exp/iat numerik).

Cek:
  alg-none        (high)  : header alg hilang / bernilai none (varian
                            None/NONE/nOnE) — verifikasi signature
                            dilewati bila diterima server.
  jwk-header      (high)  : header jwk/jwks berisi kunci inline dari
                            token itu sendiri — vektor substitusi
                            kunci (attacker-supplied key, pola CVE
                            lama; kunci sah tidak pernah inline).
  kid-injection   (high)  : kid berisi path traversal (../, %2e%2e),
                            metakarakter SQL ('/UNION SELECT/--), atau
                            URL (://) — kid dipakai lookup kunci di
                            server.
  jku-header      (medium): header jku (URL JWKS) — kunci bisa diarahkan
                            ke host pihak ketiga; verifikasi host
                            manual (offline tidak tahu daftar sah).
  x5u-header      (medium): header x5u (URL sertifikat) — vektor sama.
  alg-asym-surface (medium): alg asimetris (RS*/PS*/ES*/EdDSA) —
                            permukaan alg-confusion HS256; kepastian
                            server menerima HS256 = uji live playbook.
  exp-missing     (medium): klaim exp tidak ada — token abadi.
  signature-empty (low)   : token tanpa segmen signature (2 segmen
                            atau segmen ketiga kosong).
  exp-stale       (low)   : exp sudah lewat saat audit — token mati di
                            bukti (higiene: token jangan menetap di
                            log/evidence).
  exp-long-lived  (low)   : umur token (exp - iat) > 365 hari.

Fail-closed:
  - file tidak ada / NOL token ter-parse / input kosong -> exit 2.
  - token rusak dicatat di meta (maks 10 sampel), bukan dibuang diam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error.

Pemakaian:
  python tools/jwt_token_audit.py --tokens evidence/jwt.txt
  python tools/jwt_token_audit.py --token "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
  python tools/jwt_token_audit.py --tokens jwt.txt --fail-on medium --out hasil.json
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import time
from pathlib import Path

SCHEMA = "secai.jwt-token-audit/1"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_CHARS = 120
MAX_BROKEN_SAMPLES = 10

_ASYM_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
              "ES256", "ES384", "ES512", "ES256K", "EdDSA"}
_NONE_RE = re.compile(r"^none$", re.I)
_KID_TRAV_RE = re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)
_KID_SQL_RE = re.compile(
    r"('|%27)|(--)|(\bunion\s+select\b)|(\bor\s+1=1\b)|(\bsleep\s*\()",
    re.I)
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://", re.I)


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def parse_token(raw: str) -> dict:
    """Split + decode token -> {header, claims, sig_len}; raise bila
    struktur rusak."""
    parts = raw.strip().split(".")
    if len(parts) < 2:
        raise ValueError("kurang dari 2 segmen")
    header = json.loads(_b64url_decode(parts[0]))
    claims = json.loads(_b64url_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("header/claims bukan objek JSON")
    return {"header": header, "claims": claims,
            "sig_len": len(parts[2]) if len(parts) > 2 else 0}


def audit_token(idx: int, tok: dict, now: float) -> list[dict]:
    """Cek deterministik konten satu token -> daftar temuan."""
    findings: list[dict] = []
    h, c = tok["header"], tok["claims"]
    alg = str(h.get("alg", "") or "")
    base = {"token_index": idx}
    if not alg or _NONE_RE.match(alg):
        findings.append({
            "check": "alg-none", "severity": "high", **base,
            "alg": alg or "(hilang)",
            "message": "alg none/varian atau hilang — signature "
                       "verifikasi bisa dilewati bila server menerima",
        })
    if any(k in h for k in ("jwk", "jwks")):
        findings.append({
            "check": "jwk-header", "severity": "high", **base,
            "message": "kunci inline di header (jwk/jwks) — vektor "
                       "substitusi kunci attacker-supplied",
        })
    kid = str(h.get("kid", "") or "")
    if kid and (_KID_TRAV_RE.search(kid) or _KID_SQL_RE.search(kid)
                or _URL_RE.search(kid)):
        findings.append({
            "check": "kid-injection", "severity": "high", **base,
            "kid": kid[:MAX_EVIDENCE_CHARS],
            "message": "kid berpola traversal/SQL/URL — kid dipakai "
                       "lookup kunci server, verifikasi manual",
        })
    for key, chk in (("jku", "jku-header"), ("x5u", "x5u-header")):
        if key in h:
            findings.append({
                "check": chk, "severity": "medium", **base,
                "url": str(h[key])[:MAX_EVIDENCE_CHARS],
                "message": f"header {key} menunjuk URL eksternal — "
                           "kunci bisa diganti host pihak ketiga, "
                           "cocokkan dgn host JWKS sah",
            })
    if alg in _ASYM_ALGS:
        findings.append({
            "check": "alg-asym-surface", "severity": "medium", **base,
            "alg": alg,
            "message": "alg asimetris — permukaan alg-confusion HS256 "
                       "(kepastian = uji live playbook)",
        })
    exp = c.get("exp")
    iat = c.get("iat")
    if not isinstance(exp, (int, float)):
        findings.append({
            "check": "exp-missing", "severity": "medium", **base,
            "message": "klaim exp tidak ada — token tidak pernah "
                       "kedaluwarsa",
        })
    else:
        if exp < now:
            findings.append({
                "check": "exp-stale", "severity": "low", **base,
                "exp": int(exp),
                "expired_days_ago": int((now - exp) / 86400),
                "message": "token sudah kedaluwarsa saat audit — "
                           "higiene: token mati jangan menetap di "
                           "bukti/log",
            })
        if isinstance(iat, (int, float)) \
                and exp - iat > 365 * 86400:
            findings.append({
                "check": "exp-long-lived", "severity": "low", **base,
                "age_days": int((exp - iat) / 86400),
                "message": "umur token > 1 tahun — rotasi tidak "
                           "teregaksi",
            })
    if tok["sig_len"] == 0:
        findings.append({
            "check": "signature-empty", "severity": "low", **base,
            "message": "token tanpa segmen signature (2 segmen / "
                       "segmen kosong)",
        })
    return findings


def _claim_evidence(c: dict) -> dict:
    out: dict = {}
    for k in ("iss", "aud", "sub"):
        v = c.get(k)
        if isinstance(v, (str, int)):
            out[k] = str(v)[:60]
    return out


def load_tokens(args: argparse.Namespace) -> tuple[list[str], str]:
    raws: list[str] = []
    src = ""
    if args.token:
        raws.extend(args.token)
        src = "cli"
    if args.tokens:
        p = Path(args.tokens)
        if not p.exists():
            raise FileNotFoundError(f"{args.tokens}: file tidak ada")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"{args.tokens} > {MAX_FILE_BYTES} byte")
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raws.extend(line.split())
        src = str(args.tokens)
    return raws, src


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit OFFLINE konten token JWT (header/claims) "
                    "utk vektor alg-none/jwk/jku/x5u/kid + higiene "
                    "exp — nol jaringan, tanpa forge, read-only")
    ap.add_argument("--tokens", help="file berisi token (1 token/"
                                     "segmen per baris)")
    ap.add_argument("--token", action="append",
                    help="token langsung di argumen (boleh diulang)")
    ap.add_argument("--now", type=int, default=None,
                    help="unix epoch referensi exp (default: sekarang)")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="high")
    args = ap.parse_args(argv)

    if not args.tokens and not args.token:
        print("ERROR: butuh --tokens atau --token", file=sys.stderr)
        return 2
    now = float(args.now) if args.now is not None else time.time()

    try:
        raws, src = load_tokens(args)
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    parsed: list[tuple[int, dict]] = []
    broken: list[str] = []
    for i, raw in enumerate(raws):
        try:
            parsed.append((i, parse_token(raw)))
        except (ValueError, binascii.Error) as exc:
            if len(broken) < MAX_BROKEN_SAMPLES:
                broken.append(f"#{i}: {str(exc)[:60]} "
                              f"({raw[:20]}...)")
    if not parsed:
        print("ERROR: nol token JWT ter-parse dari input",
              file=sys.stderr)
        return 2

    findings: list[dict] = []
    alg_seen: dict[str, int] = {}
    for i, tok in parsed:
        findings.extend(audit_token(i, tok, now))
        alg = str(tok["header"].get("alg", "(hilang)"))
        alg_seen[alg] = alg_seen.get(alg, 0) + 1

    stats = {
        "tokens_total": len(raws),
        "tokens_parsed": len(parsed),
        "alg_counts": dict(sorted(alg_seen.items())),
        "source": src,
    }
    notes: list[str] = [
        "audit konten token BUKAN verifikasi signature — kepastian "
        "eksploitasi (alg confusion diterima server, jku di-fetch "
        "penyerang) = uji live JwtAlgConfusionPlaybook",
        "isi klaim sensitif tidak diecho penuh (bukti terpotong)",
    ]
    if broken:
        notes.append(f"{len(broken)} token rusak dicatat di meta "
                     "(bukan dibuang diam)")
    findings.sort(key=lambda f: (f["check"], f["token_index"]))
    order = {"high": 0, "medium": 1, "info": 2, "low": 3}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {"broken_samples": broken,
                 "fail_on": args.fail_on,
                 "now": int(now)},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
