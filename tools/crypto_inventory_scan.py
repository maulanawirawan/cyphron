r"""[AUDIT: read-only] crypto_inventory_scan — inventaris kripto OFFLINE
(CBOM-lite) dari pohon berkas teks: token algoritma di kode/konfigurasi/
IaC dikelasifikasi quantum-vulnerable (Shor), weak-legacy, dan
post-quantum; prioritas migrasi dihitung dgn ketaksamaan Mosca
(data lifetime + waktu migrasi vs estimasi CRQC).

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/migrating-to-post-quantum-cryptography' (#0746 — atribusi ide,
lisensi sumber Apache-2.0). Dibangun FROM SCRATCH TANPA kode sumber itu.
Skill sumber = runbook migrasi LIVE (OpenSSL 3.5, oqs-provider, s_server
dgn group X25519MLKEM768, penerbitan sertifikat ML-DSA); tool ini
memilih sisi STATIS yang bisa dieksekusi nol-jaringan: LANGKAH 1-3 dari
playbook sumber — inventaris (CBOM), klasifikasi, dan prioritas HNDL.
Langkah live (generate kunci, hybrid TLS, verifikasi tanda tangan) = di
luar tool, tetap milik runbook sumber.

Dasar klasifikasi (FIPS 203/204/205 + NIST SP 1800-38):
  - asym-shor    : RSA/DSA/DH/ECDH/ECDSA/EdDSA & kurva klasik — habis
                   oleh Shor begitu CRQC ada; pengganti ML-KEM/ML-DSA;
                   ini SATU-SATUNYA kelas yang wajib dimigrasi
  - weak-legacy  : DES/3DES/RC4/MD5/SHA-1 — lemah BAHKAN tanpa CRQC
                   (lead; hash non-kripto spt checksum boleh sah)
  - grover-note  : AES/SHA keluarga kuat — sekadar diperlemah Grover
                   (kuadratik); dicatat di inventaris, BUKAN temuan
  - pqc          : ML-KEM(Kyber)/ML-DSA(Dilithium)/SLH-DSA(SPHINCS+)/
                   FN-DSA(Falcon)/LMS/XMSS/hybrid X25519MLKEM768 — aman
JWS/JWT alg names (RS256/PS256/ES*/EdDSA) dipetakan juga (ranah rekan:
jwt_token_audit memeriksa KONTEN token; tool ini menyapu kode/konfig).

Ranah tetangga eksplisit: isi sertifikat X.509 = cert_chain_audit,
blok PEM private key = repo_secret_scan (header PEM disarikan di
summary, bukan temuan), CVE dependensi = dependency_cve. Tool ini hanya
TOKEN algoritma di berkas teks yang dipindai — bukan analisis biner,
bukan negosiasi live (ssl_tls_analyzer/tls_cipher_suites_checker).

Input -> mekanisme -> output:
  - Input   : --scan PATH... (berkas atau direktori, berulang) — teks
              <= --max-bytes per berkas (default 2MB); biner (NUL byte)
              / bukan-UTF8 dilewati dan DIHITUNG eksplisit.
  - Mekanisme: regex kata-utuh per token -> klasifikasi -> temuan
              di-dedup per (berkas, algoritma) + inventaris per
              algoritma (kelas, jumlah berkas, contoh) + Mosca:
              priority bila data_lifetime + migration > crqc_years.
  - Output  : temuan {check, severity, object, field, line, message} +
              inventory + mosca + notes + errors; exit 1 bila temuan
              >= --fail-on (default medium), exit 2 bila path absen.

Cek:
  asym-shor-token   (medium): token asimetri klasik ditemukan — LEAD
                              migrasi; verifikasi pemakaian nyata
  weak-legacy-token (medium): DES/3DES/RC4/MD5/SHA-1 — periksa konteks
                              (hash non-kripto boleh sah)
Fail-closed: pohon tanpa satu pun berkas teks terpindai = catatan
            tegas di notes (hasil kosong BUKAN kebersihan); path
            tidak ada = exit 2.

Pemakaian:
  python tools/crypto_inventory_scan.py --scan src/ --scan deploy.yaml
  python tools/crypto_inventory_scan.py --scan . --data-lifetime-years 15
Exit: 0 selesai; 1 temuan gagal ambang; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.crypto-inventory-scan/1"
MAX_FILES_LISTED = 5

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}

# --- tabel token -> (kelas, nama kanonik, catatan pengganti) ------------
# Kata-utuh, case-insensitive; token eksplisit saja (anti-FP: tidak ada
# kata generik seperti "encryption"/"key" tanpa nama algoritma).

SHOR_TOKENS = {
    "rsa": ("asym-shor", "RSA", "ML-DSA (tanda) / ML-KEM (tukar kunci)"),
    "rs256": ("asym-shor", "JWS RS256 (RSA)", "ML-DSA / PS-style PQC"),
    "rs384": ("asym-shor", "JWS RS384 (RSA)", "ML-DSA"),
    "rs512": ("asym-shor", "JWS RS512 (RSA)", "ML-DSA"),
    "ps256": ("asym-shor", "JWS PS256 (RSA-PSS)", "ML-DSA"),
    "ps384": ("asym-shor", "JWS PS384 (RSA-PSS)", "ML-DSA"),
    "ps512": ("asym-shor", "JWS PS512 (RSA-PSS)", "ML-DSA"),
    "dsa": ("asym-shor", "DSA", "ML-DSA"),
    "ecdsa": ("asym-shor", "ECDSA", "ML-DSA"),
    "es256": ("asym-shor", "JWS ES256 (EC)", "ML-DSA"),
    "es384": ("asym-shor", "JWS ES384 (EC)", "ML-DSA"),
    "es512": ("asym-shor", "JWS ES512 (EC)", "ML-DSA"),
    "eddsa": ("asym-shor", "JWS EdDSA (Ed25519/Ed448)", "ML-DSA"),
    "ed25519": ("asym-shor", "Ed25519", "ML-DSA"),
    "ed448": ("asym-shor", "Ed448", "ML-DSA"),
    "ecdh": ("asym-shor", "ECDH", "ML-KEM / hybrid X25519MLKEM768"),
    "ecdhe": ("asym-shor", "ECDHE", "ML-KEM / hybrid"),
    "x25519": ("asym-shor", "X25519 (klasik, non-hybrid)", "X25519MLKEM768"),
    "x448": ("asym-shor", "X448", "ML-KEM / hybrid"),
    "curve25519": ("asym-shor", "Curve25519", "ML-KEM / hybrid"),
    "secp256r1": ("asym-shor", "secp256r1/P-256", "ML-KEM / ML-DSA"),
    "prime256v1": ("asym-shor", "prime256v1/P-256", "ML-KEM / ML-DSA"),
    "secp384r1": ("asym-shor", "secp384r1/P-384", "ML-KEM / ML-DSA"),
    "secp521r1": ("asym-shor", "secp521r1/P-521", "ML-KEM / ML-DSA"),
    "elgamal": ("asym-shor", "ElGamal", "ML-KEM"),
    "diffie-hellman": ("asym-shor", "finite-field DH", "ML-KEM"),
    "dh": ("asym-shor", "DH (kata utuh — verifikasi konteks)",
           "ML-KEM"),
}

WEAK_TOKENS = {
    "md5": ("weak-legacy", "MD5", "SHA-256/SHA-3"),
    "sha1": ("weak-legacy", "SHA-1", "SHA-256/SHA-3"),
    "sha-1": ("weak-legacy", "SHA-1", "SHA-256/SHA-3"),
    "des": ("weak-legacy", "DES tunggal", "AES-256"),
    "3des": ("weak-legacy", "3DES/TDES", "AES-256"),
    "tdes": ("weak-legacy", "3DES/TDES", "AES-256"),
    "des-ede": ("weak-legacy", "DES-EDE", "AES-256"),
    "rc4": ("weak-legacy", "RC4", "AES-256-GCM / ChaCha20"),
    "rc2": ("weak-legacy", "RC2", "AES-256-GCM"),
    "blowfish": ("weak-legacy", "Blowfish", "AES-256-GCM"),
}

GROVER_TOKENS = {
    "aes-128": ("grover-note", "AES-128", "AES-256"),
    "aes128": ("grover-note", "AES-128", "AES-256"),
    "aes-256": ("grover-note", "AES-256", "-"),
    "aes256": ("grover-note", "AES-256", "-"),
    "aes": ("grover-note", "AES (ukuran kunci tak disebut)",
            "AES-256 utk jangka panjang"),
    "chacha20": ("grover-note", "ChaCha20 (kunci 256-bit)", "-"),
    "sha-224": ("grover-note", "SHA-224", "SHA-256+"),
    "sha224": ("grover-note", "SHA-224", "SHA-256+"),
    "sha-256": ("grover-note", "SHA-256", "SHA-384/512 utk jangka panjang"),
    "sha256": ("grover-note", "SHA-256", "SHA-384/512 utk jangka panjang"),
    "sha-384": ("grover-note", "SHA-384", "-"),
    "sha384": ("grover-note", "SHA-384", "-"),
    "sha-512": ("grover-note", "SHA-512", "-"),
    "sha512": ("grover-note", "SHA-512", "-"),
    "sha3": ("grover-note", "SHA-3", "-"),
    "sha3-256": ("grover-note", "SHA-3-256", "-"),
    "sha3-384": ("grover-note", "SHA-3-384", "-"),
    "sha3-512": ("grover-note", "SHA-3-512", "-"),
    "hmac": ("grover-note", "HMAC", "-"),
    "hs256": ("grover-note", "JWS HS256 (HMAC-SHA256)", "-"),
    "hs384": ("grover-note", "JWS HS384", "-"),
    "hs512": ("grover-note", "JWS HS512", "-"),
}

PQC_TOKENS = {
    "ml-kem": ("pqc", "ML-KEM (FIPS 203)", None),
    "mlkem": ("pqc", "ML-KEM (FIPS 203)", None),
    "kyber": ("pqc", "ML-KEM/CRYSTALS-Kyber", None),
    "ml-dsa": ("pqc", "ML-DSA (FIPS 204)", None),
    "mldsa": ("pqc", "ML-DSA (FIPS 204)", None),
    "dilithium": ("pqc", "ML-DSA/CRYSTALS-Dilithium", None),
    "slh-dsa": ("pqc", "SLH-DSA (FIPS 205)", None),
    "slhdsa": ("pqc", "SLH-DSA (FIPS 205)", None),
    "sphincs": ("pqc", "SLH-DSA/SPHINCS+", None),
    "fn-dsa": ("pqc", "FN-DSA (Falcon)", None),
    "xmss": ("pqc", "XMSS", None),
    "x25519mlkem768": ("pqc", "hybrid X25519MLKEM768", None),
    "x25519mlkem512": ("pqc", "hybrid X25519MLKEM512", None),
    "x25519kyber768": ("pqc", "hybrid draft X25519Kyber768", None),
    "secp256r1mlkem768": ("pqc", "hybrid SecP256r1MLKEM768", None),
}

ALL_TABLES = (SHOR_TOKENS, WEAK_TOKENS, GROVER_TOKENS, PQC_TOKENS)

# gabungan: token -> (kelas, nama kanonik, pengganti)
TOKEN_INFO: "dict[str, tuple[str, str, str | None]]" = {}
for _tbl in ALL_TABLES:
    TOKEN_INFO.update(_tbl)

CANON_TO_TOKEN: "dict[str, str]" = {
    info[1]: tok for tok, info in TOKEN_INFO.items()}

RE_PEM_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


def _compile_patterns() -> "dict[str, re.Pattern]":
    """Kata-utuh dengan satu kelonggaran: sufiks '-angka'/'-mode' sah
    (ML-KEM-768, aes-128-gcm, rsa-2048); diikuti HURUF atau UNDERSCORE =
    bukan token (md5sum, des_list, rsaparam — anti-FP). Token yang
    BERAKHIRAN digit tidak boleh diikuti digit lagi (sha3 ≠ sha384)."""
    pats = {}
    for token in TOKEN_INFO:
        neg = r"(?![A-Za-z_0-9])" if token[-1].isdigit() \
            else r"(?![A-Za-z_])"
        pats[token] = re.compile(r"(?<![A-Za-z0-9_])"
                                 + re.escape(token)
                                 + neg,
                                 re.IGNORECASE)
    return pats


def iter_text_files(paths: "list[Path]", max_bytes: int,
                    errors: "list[str]") -> "tuple[list[tuple[Path, str]], int, int]":
    """Jalankan pohon -> [(path, teks)], jumlah biner dilewati, jumlah
    kebesaran dilewati. Bukan-UTF8/biner dihitung eksplisit."""
    out: "list[tuple[Path, str]]" = []
    skipped_binary = 0
    skipped_size = 0

    def handle(p: Path) -> None:
        nonlocal skipped_binary, skipped_size
        try:
            size = p.stat().st_size
            if size > max_bytes:
                skipped_size += 1
                return
            data = p.read_bytes()
        except OSError as exc:
            errors.append(f"{p}: tidak terbaca ({exc})")
            return
        if b"\x00" in data[:8192]:
            skipped_binary += 1
            return
        try:
            out.append((p, data.decode("utf-8")))
        except UnicodeDecodeError:
            skipped_binary += 1

    for base in paths:
        if base.is_dir():
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    handle(p)
        elif base.is_file():
            handle(base)
        else:
            errors.append(f"{base}: tidak ada — dilewati (fail-closed "
                          "bila SEMUA path begitu, lihat scanned)")
    return out, skipped_binary, skipped_size


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan", action="append", type=Path, default=[],
                    metavar="PATH",
                    help="berkas/direktori yang dipindai (boleh berulang)")
    ap.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024,
                    metavar="N")
    ap.add_argument("--data-lifetime-years", type=float, default=None,
                    metavar="YRS",
                    help="umur data rahasia terpanjang di aset ini "
                         "(Mosca; tanpa ini prioritas tak dihitung)")
    ap.add_argument("--crqc-years", type=float, default=10.0,
                    metavar="YRS",
                    help="estimasi tahun sampai CRQC (default 10)")
    ap.add_argument("--migration-years", type=float, default=2.0,
                    metavar="YRS",
                    help="estimasi waktu migrasi (default 2)")
    ap.add_argument("--allow-alg", action="append", default=[],
                    metavar="TOKEN",
                    help="algoritma dikecualikan (sadar, dicatat)")
    ap.add_argument("--allow-check", action="append", default=[],
                    metavar="NAME", help="cek dilewati (dicatat)")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    errors: "list[str]" = []
    findings: "list[dict]" = []
    notes_out: "list[str]" = []

    def add(check, severity, obj, field, line, message):
        if check in args.allow_check:
            return
        findings.append({"check": check, "severity": severity,
                         "object": obj, "field": field,
                         "line": line, "message": message})

    if not args.scan:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "berikan minimal satu --scan PATH — fail-closed",
        }), file=sys.stderr)
        return 2

    patterns = _compile_patterns()
    allow_alg = {t.lower() for t in args.allow_alg}

    if all(not p.exists() for p in args.scan):
        print(json.dumps({
            "schema": SCHEMA,
            "error": "semua --scan PATH tidak ada — fail-closed",
        }), file=sys.stderr)
        return 2

    files, skipped_binary, skipped_size = iter_text_files(
        args.scan, args.max_bytes, errors)

    # per (file, token-kanonik) -> first line; per token -> file set
    hit_line: "dict[tuple[str, str], int]" = {}
    hit_files: "dict[str, set[str]]" = {}
    pem_files: "set[str]" = set()

    for p, text in files:
        rel = str(p)
        for ln, line in enumerate(text.splitlines(), 1):
            if RE_PEM_KEY.search(line):
                pem_files.add(rel)
            if not line:
                continue
            # kumpulkan semua kandidat dgn span, lalu terima longest-
            # match-wins: "ML-DSA-65" = ml-dsa (pqc), BUKAN dsa (shor)
            cands: "list[tuple[int, int, str]]" = []
            for token, pat in patterns.items():
                if token in allow_alg:
                    continue
                if token.lower() not in line.lower():
                    continue
                for m in pat.finditer(line):
                    cands.append((m.start(), m.end(), token))
            accepted: "list[tuple[int, int, str]]" = []
            for s, e, tok in sorted(
                    cands, key=lambda c: (-(c[1] - c[0]), c[0])):
                if any(s < oe and os_ < e for os_, oe, _ in accepted):
                    continue
                accepted.append((s, e, tok))
            for _s, _e, tok in accepted:
                cls, canon, _repl = TOKEN_INFO[tok]
                key = (rel, canon)
                if key not in hit_line:
                    hit_line[key] = ln
                hit_files.setdefault(canon, set()).add(rel)

    for (rel, canon), ln in sorted(hit_line.items(),
                                   key=lambda kv: (kv[0][0], kv[0][1])):
        token = CANON_TO_TOKEN[canon]
        cls, _canon2, repl = TOKEN_INFO[token]
        if cls == "asym-shor" and repl:
            add("asym-shor-token", "medium", rel, canon, ln,
                f"'{canon}' pecah oleh Shor begitu CRQC ada — kandidat "
                f"migrasi ke {repl}; token saja = LEAD, verifikasi "
                "pemakaian nyata (ranah sertifikat = cert_chain_audit)")
        elif cls == "weak-legacy":
            add("weak-legacy-token", "medium", rel, canon, ln,
                f"'{canon}' lemah BAHKAN tanpa CRQC — periksa konteks; "
                "hash non-kripto (checksum) boleh sah; pengganti: "
                f"{repl}")

    # inventory (semua kelas, termasuk grover/pqc)
    inventory = {}
    for canon, files_set in sorted(hit_files.items()):
        cls = TOKEN_INFO[CANON_TO_TOKEN[canon]][0]
        sample = sorted(files_set)[:MAX_FILES_LISTED]
        inventory[canon] = {
            "class": cls,
            "files": len(files_set),
            "examples": sample,
        }

    mosca = None
    if args.data_lifetime_years is not None:
        total = args.data_lifetime_years + args.migration_years
        mosca = {
            "data_lifetime_years": args.data_lifetime_years,
            "migration_years": args.migration_years,
            "crqc_years": args.crqc_years,
            "hndl_priority": total > args.crqc_years,
            "rule": "data_lifetime + migration > crqc_years = prioritas",
        }
        if mosca["hndl_priority"]:
            notes_out.insert(0, "HNDL: data ini masih terbaca saat CRQC "
                             f"datang ({total:.0f} > {args.crqc_years:.0f} "
                             "tahun) — migrasi asym-shor didahulukan")
        else:
            notes_out.insert(0, "HNDL: di bawah garis Mosca "
                             f"({total:.0f} <= {args.crqc_years:.0f} "
                             "tahun) — tetap catat, jangan diabaikan")
    else:
        notes_out.append("Mosca tidak dihitung — berikan "
                         "--data-lifetime-years utk prioritas HNDL")

    if pem_files:
        notes_out.append(
            f"{len(pem_files)} berkas memuat blok PEM private key "
            f"({', '.join(sorted(pem_files)[:3])}"
            f"{'…' if len(pem_files) > 3 else ''}) — ranah "
            "repo_secret_scan, bukan temuan tool ini")
    if not files:
        notes_out.append("TIDAK ada berkas teks terpindai — hasil kosong "
                         "BUKAN kebersihan (fail-closed, periksa path)")
    if skipped_binary:
        notes_out.append(f"{skipped_binary} berkas biner/bukan-UTF8 "
                         "dilewati (dihitung, bukan diam)")
    if skipped_size:
        notes_out.append(f"{skipped_size} berkas > --max-bytes dilewati")
    if args.allow_alg:
        notes_out.append("algoritma di-whitelist: "
                         + ", ".join(sorted(allow_alg)))
    if args.allow_check:
        notes_out.append("check disaring: "
                         + ", ".join(sorted(args.allow_check)))
    notes_out.extend([
        "pindai TOKEN teks — bukan bukti pemakaian kripto nyata; "
        "verifikasi manual sebelum melapor",
        "AES/SHA kuat hanya diperlemah Grover (kuadratik) — dicatat di "
        "inventory, bukan temuan migrasi",
        "langkah live (OpenSSL ML-KEM/ML-DSA, hybrid TLS) = runbook "
        "skill sumber, di luar tool",
    ])

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold
              for f in findings)
    report = {
        "schema": SCHEMA,
        "summary": {
            "files_scanned": len(files),
            "skipped_binary": skipped_binary,
            "skipped_size": skipped_size,
            "algorithms": len(inventory),
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("high", "medium", "low")
            },
        },
        "mosca": mosca,
        "inventory": inventory,
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["object"], f["line"])),
        "notes": notes_out,
        "errors": errors,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())
