"""[AUDIT: read-only] insecure_defaults — deteksi konfigurasi default rentan.

Konsep kategori audit (default credentials, fail-open security settings,
debug features aktif, weak crypto) mengacu pada plugin insecure-defaults
repo trailofbits/skills (8k+ stars, CC-BY-SA-4.0) — dibangun from scratch
TANPA kode/data dari repo itu: semua pola di bawah ditulis sendiri dari
pengetahuan konfigurasi publik yang umum. Lisensi cyphron: PolyForm NC.

Read-only, NOL request jaringan: pindai file/direktori konfigurasi lokal
(--source). Presisi di atas recall (zero-FP, kontrak repo):
  - komentar di-skip (#, //, ;, --, %, <!--) — config yang DIKOMMENT
    bukan konfigurasi aktif;
  - direktori yang di-skip: .git, node_modules, venv, vendor, dist,
    __pycache__, build artifacts;
  - file binary / > batas ukuran di-skip;
  - placeholder ("YOUR_SECRET_HERE", "<...>", "REPLACE_ME", dsb.) tidak
    dihitung — belum diisi bukan berarti insecure dipakai;
  - nilai sensitif TIDAK pernah ditampilkan penuh (prefix 6 + panjang).

Empat kategori:
  1. default-credentials : pasangan user/pass bawaan yang terkenal
     (admin/admin, root/root, postgres/postgres, sa/sa, ...) di config
     aktif — kredensial siap pakai untuk siapa pun yang bisa baca repo.
  2. fail-open           : pengaturan keamanan yang dimatikan
     (ssl_verify=false, rejectUnauthorized=false, force_ssl=false, ...).
  3. debug-features      : mode debug/development aktif di config
     (DEBUG=true, FLASK_ENV=development, NODE_ENV=development, ...).
  4. weak-crypto         : algoritma lemah terpilih (md5/sha1/des/rc4
     sebagai hash/cipher config) dan secret bawaan terkenal
     (jwt_secret=secret, secret_key=changeme, your-256-bit-secret, ...).

Semua temuan = make_finding kontrak cyphron (status confirmed, verdict L2
REPRODUCED — bukti file+baris; POC = perintah baca baris), lulus
validate_finding. Ini scanner STATIC: temuan boleh L2, bukan L3 —
klaim dampak butuh verifikasi live (no proof, no report).

Pemakaian:
  python tools/insecure_defaults.py --source path/ke/config --out f.json
  python tools/insecure_defaults.py --source path/ke/proyek --out f.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in ("core", "tools"):
    sys.path.insert(0, str(ROOT / _p))

from findings import make_finding, validate_finding  # noqa: E402

SCHEMA = "cyphron.insecure-defaults/1"
MAX_FILE_BYTES = 512 * 1024
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "vendor",
             "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
             "target", "site-packages"}
CONFIG_SUFFIXES = {".env", ".yaml", ".yml", ".json", ".toml", ".ini",
                   ".cfg", ".conf", ".properties", ".xml", ".py", ".js",
                   ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".sh",
                   ".txt", ".md", ""}
CONFIG_NAMES = {"dockerfile", ".dockerenv", "docker-compose",
                "makefile", ".env.production", ".env.local", "application",
                "settings", "config"}
BINARY_SNIFF = b"\x00"

COMMENT_PREFIXES = ("#", "//", ";", "--", "%", "<!--", "/*", "*")

# ---- data pola (ditulis sendiri dari pengetahuan konfigurasi umum) ----
DEFAULT_USERS = {
    "admin", "administrator", "root", "user", "guest", "test", "demo",
    "postgres", "mysql", "sa", "oracle", "operator", "service",
}
DEFAULT_PASSWORDS = {
    "admin", "password", "123456", "1234", "12345", "admin123", "admin@123",
    "root", "toor", "password123", "letmein", "welcome", "guest", "user",
    "postgres", "mysql", "sa", "oracle", "test", "demo", "qwerty",
    "changeme", "changeit", "default", "secret", "pass123", "p@ssw0rd",
    "iloveyou", "monkey", "dragon", "master", "login", "abc123",
}
USER_KEYS = {"username", "user", "login", "email", "admin_user", "adminuser",
             "db_user", "db_username", "dbuser", "db_username", "db_user",
             "datasource_username", "spring_datasource_username",
             "db_user", "admin_username", "app_user", "sm_user"}
PASS_KEYS = {"password", "pass", "pwd", "passwd", "db_pass", "db_password",
             "dbpwd", "datasource_password", "spring_datasource_password",
             "admin_password", "admin_pass", "app_password", "secret_pass",
             "pass", "db_password", "password_admin"}
# key -> nilai fail-open (config aktif yang mematikan proteksi)
FAIL_OPEN_KEYS: dict[str, re.Pattern] = {
    r"(ssl_verify|verify_ssl|tls_verify|ssl_check|verify_tls|check_ssl)":
        re.compile(r"^(false|0|no|off)$", re.I),
    r"(insecure_skip_verify|skip_tls_verify|skip_ssl_verify|skip_verify)":
        re.compile(r"^(true|1|yes|on)$", re.I),
    r"(rejectUnauthorized)":
        re.compile(r"^false$", re.I),
    r"(allow_insecure|allowinsecure|allow_insecure_certs)":
        re.compile(r"^(true|1|yes|on)$", re.I),
    r"(enforce_https|force_ssl|force_https|strict_tls)":
        re.compile(r"^(false|0|no|off)$", re.I),
    r"(verify_peer|verify_peer_name|verify_host)":
        re.compile(r"^(false|0|no|off)$", re.I),
}
DEBUG_KEYS: dict[str, re.Pattern] = {
    r"(debug|app_debug|debug_mode|django_debug|flask_debug|debug_enabled)":
        re.compile(r"^(true|1|yes|on)$", re.I),
    r"(flask_env|app_env|django_settings_module_mode|environment|rails_env)":
        re.compile(r"^(development|dev|debug|staging_debug)$", re.I),
    r"(node_env)":
        re.compile(r"^(development|debug)$", re.I),
}
WEAK_HASH_RE = re.compile(
    r"(hash_algorithm|hashing_algorithm|password_hash_algo|digest|cipher|"
    r"encryption)\s*[:=]\s*[\"']?(md5|sha1|des|rc4|md4)[\"']?\s*$", re.I)
# secret bawaan terkenal (jwt.io sample, framework default, dsb.)
WEAK_SECRET_VALUES = {
    "secret", "changeme", "change_me", "change-me", "mysecret", "secret123",
    "your-256-bit-secret", "your_jwt_secret", "jwt_secret", "jwt-secret",
    "supersecret", "super_secret", "s3cr3t", "keyboardcat", "keyboard cat",
    "iloveyou", "defaultsecret", "default_secret", "topsecret",
    "please-change-me", "please_change_me", "replace_me", "replaceme",
}
WEAK_SECRET_KEYS = re.compile(
    r"(secret|secret_key|jwt_secret|token_secret|api_secret|signing_key|"
    r"hmac_key|session_secret|cookie_secret|private_key_password|"
    r"encryption_key)\s*[:=]", re.I)
PLACEHOLDER_RE = re.compile(
    r"your[_\-a-z0-9]*|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|xxx+|example|"
    r"sample[_\-a-z0-9]*|insert[_\-a-z0-9]*|fill[_\-a-z0-9]*|todo|replace[_\-"
    r"a-z0-9]*|REPLACE_ME", re.I)
ASSIGN_RE = re.compile(
    r"^\s*[\"']?([A-Za-z0-9_.\-]+)[\"']?\s*[:=]\s*[\"']?(.*?)[\"']?\s*,?\s*$")


def _mask(value: str) -> str:
    """Nilai TIDAK pernah tampil penuh — prefix 6 + panjang (kontrak repo)."""
    v = value.strip()
    if len(v) <= 6:
        return f"{v[:2]}*** (len {len(v)})"
    return f"{v[:6]}*** (len {len(v)})"


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return (not s) or s.startswith(COMMENT_PREFIXES)


def _looks_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if not v:
        return True
    return bool(PLACEHOLDER_RE.fullmatch(v) or PLACEHOLDER_RE.fullmatch(
        v.replace("-", "_")))


def scan_line(path_str: str, lineno: int, line: str) -> list[dict]:
    """Pindai SATU baris config aktif -> list finding kontrak."""
    findings: list[dict] = []
    if _is_comment(line):
        return findings
    # JSON line ("key": "value", ...) — buang kurung pembuka/penutup
    cleaned = line.strip().strip("{}").strip()
    m = ASSIGN_RE.match(cleaned)
    if not m:
        return findings
    key, value = m.group(1), m.group(2).strip().strip("\"'")
    low_key = key.lower()
    low_val = value.lower()

    def _mk(category: str, severity: str, cwe: str, title: str, desc: str) -> dict:
        return make_finding(
            tool="insecure-defaults",
            title=f"[{category}] {title}",
            severity=severity,
            description=f"{desc} (file: {path_str}, baris {lineno})",
            recommendation="Ganti nilai default/secrets dengan nilai acak "
                           "unik, aktifkan verifikasi TLS, dan matikan mode "
                           "debug di produksi.",
            cwe=cwe,
            file_path=path_str, line_start=lineno,
            evidence_kind="static-analysis",
            finding_class="misconfig", confidence=0.85,
            status="confirmed", verdict=2,
            poc=f"sed -n '{lineno}p' {path_str}  # bukti baris (nilai "
                f"dimask: {_mask(value)})",
            extra={"category": category, "key": key, "value_masked": _mask(value),
                   "safety_class": "read-only-scan"})

    # 1) default credentials
    if low_val and low_val in DEFAULT_PASSWORDS and low_key in PASS_KEYS:
        findings.append(_mk(
            "default-credentials", "high", "CWE-798",
            f"kredensial default di config ({low_key}={_mask(value)})",
            "Password bawaan umum dipakai di file konfigurasi aktif — "
            "sistem bisa dimasuki siapa pun yang tahu list default."))
    if (low_val in DEFAULT_USERS and low_key in USER_KEYS
            and not findings):
        findings.append(_mk(
            "default-credentials", "medium", "CWE-798",
            f"username default di config ({low_key}={value})",
            "Username bawaan aplikasi/database dipakai tanpa perubahan — "
            "menggandakan akun yang dicoba penyerang pertama kali."))

    # 2) fail-open security settings
    for key_re, bad_val_re in FAIL_OPEN_KEYS.items():
        if re.fullmatch(key_re, low_key, re.I) and bad_val_re.match(value):
            findings.append(_mk(
                "fail-open", "high", "CWE-1188",
                f"pengaturan keamanan dimatikan ({key})",
                "Flag verifikasi/proteksi dinonaktifkan di konfigurasi — "
                "koneksi rentan MitM dan kontrol melemah."))
    # 3) debug features
    for key_re, bad_val_re in DEBUG_KEYS.items():
        if re.fullmatch(key_re, low_key, re.I) and bad_val_re.match(value):
            findings.append(_mk(
                "debug-features", "medium", "CWE-489",
                f"mode debug/development aktif ({key}={value})",
                "Mode debug di konfigurasi membocorkan stack trace, "
                "variabel internal, dan kadang shell interaktif."))
    # 4) weak crypto + secret bawaan
    if WEAK_HASH_RE.search(line):
        findings.append(_mk(
            "weak-crypto", "medium", "CWE-327",
            "algoritma kripto lemah dipilih di config",
            "md5/sha1/des/rc4 untuk hash/cipher tidak lagi memadai."))
    if low_val and low_val in WEAK_SECRET_VALUES and WEAK_SECRET_KEYS.search(
            key + " :"):
        if not _looks_placeholder(value):
            findings.append(_mk(
                "weak-crypto", "high", "CWE-798",
                f"secret bawaan terkenal dipakai ({_mask(value)})",
                "Nilai secret sama dengan sample/default yang diketahui "
                "publik — token bisa ditembusangani ulang siapa pun."))
    return findings


def _is_config_file(p: Path) -> bool:
    name = p.name.lower()
    if p.suffix.lower() in CONFIG_SUFFIXES or any(
            name.startswith(n) for n in CONFIG_NAMES):
        return True
    return False


def iter_config_files(source: Path):
    """Iterasi file config di bawah source; skip dir/biner/ukuran."""
    if source.is_file():
        yield source
        return
    for p in sorted(source.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if _is_config_file(p):
            yield p


def scan_source(source: str) -> dict:
    """Pindai sumber; return hasil machine-readable (fail-closed)."""
    src = Path(source)
    if not src.exists():
        raise FileNotFoundError(f"source tidak ada: {source}")
    findings: list[dict] = []
    files_scanned = 0
    errors: list[str] = []
    for p in iter_config_files(src):
        try:
            raw = p.read_bytes()
        except OSError as exc:
            errors.append(f"{p}: {exc}")
            continue
        if BINARY_SNIFF in raw[:8192]:
            continue
        files_scanned += 1
        text = raw.decode("utf-8", "replace")
        for i, line in enumerate(text.splitlines(), start=1):
            findings.extend(scan_line(str(p), i, line))
    # validate_finding return list error — non-kosong = invalid
    invalid = [f for f in findings if validate_finding(f)]
    by_cat: dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "?")  # make_finding meratakan extra
        by_cat[cat] = by_cat.get(cat, 0) + 1
    return {
        "schema": SCHEMA, "source": str(src),
        "files_scanned": files_scanned, "errors": errors,
        "findings_total": len(findings), "by_category": by_cat,
        "findings": findings, "invalid_contract": invalid,
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="insecure_defaults — scanner konfigurasi default "
                    "rentan (read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file atau direktori yang dipindai")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    try:
        result = scan_source(args.source)
    except FileNotFoundError as exc:
        print(f"[insecure-defaults] input tidak valid: {exc}",
              file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    print(f"[insecure-defaults] {result['files_scanned']} file config "
          f"dipindai dari {args.source}")
    for cat, n in sorted(result["by_category"].items()):
        print(f"  - {cat}: {n} temuan")
    print(f"[insecure-defaults] total {result['findings_total']} temuan "
          f"(static, L2); error baca: {len(result['errors'])}")
    if result["invalid_contract"]:
        print(f"[insecure-defaults] PERINGATAN: "
              f"{len(result['invalid_contract'])} baris gagal kontrak",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
