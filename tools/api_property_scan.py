"""[AUDIT: read-only] api_property_scan — audit statis eksposur properti
respons API dan kandidat mass-assignment dari body request yang
ditangkap, SEPENUHNYA offline (JSON tangkapan, nol jaringan).

Mengisi antrean port SKILL-PORT-QUEUE #0392 (mukul975/Anthropic-
Cybersecurity-Skills 'detecting-broken-object-property-level-
authorization' — OWASP API3:2023 BOLA/BOPLA; lisensi sumber Apache-2.0,
atribusi ide — kode dibangun from scratch TANPA menyalin kode sumber).
Pengujian AKTIF (kirim request mass-assignment ke target, verifikasi
readback) TIDAK di-port — di secai itu tugas MassAssignmentPlaybook/
IdorOrdersPlaybook yang berjalan di lab berizin. Yang diekstrak di sini
adalah sisi deterministik statisnya:

  property-exposure  klasifikasi nama properti dalam objek respons
                     terhadap taksonomi sensitivitas (critical/high/
                     medium/low) — properti yang di-layak-ini keluar ke
                     klien padahal tak diperlukan = excessive data
                     exposure (BOPLA). Kalau allowlist field yang
                     diharapkan diberikan (--expected), hanya properti
                     DI LUAR allowlist yang dilaporkan.
  mass-assignment    kandidat field istimewa di body request tangkapan
                     (role/is_admin/account_balance/...) = LEAD; bukti
                     diterimanya server hanya bisa via playbook live.

Pencocokan nama = tokenisasi camelCase + pemisah non-alfanumerik:
"role" cocok pada "userRole"/"user_role" tapi BUKAN pada "console"/
"enrolled" (anti-FP). Nama majemuk ("credit_card", "api_key",
"password_hash") dicek sebagai frasa ter-normalisasi.

Input:
  --file resp.json        satu objek/array JSON respons
  --file capture.jsonl    JSONL: {"path": "/api/x", "response": {...}}
  --expected-file f.json  {"path": ["id","name"]} = field sah per path
  --expected "/api/x=id,name"   bentuk CLI
  --request-file body.json     body request tangkapan (kandidat
                               mass-assignment)
Fail-closed: file kosong / nol objek ter-parse / JSON tidak valid ->
exit 2. Output JSON deterministik terurut. Temuan = LEAD utk triase,
bukan verdict kerentanan terkonfirmasi.

Pemakaian:
  python tools/api_property_scan.py --file resp.json --out temuan.json
  python tools/api_property_scan.py --file capture.jsonl --expected-file allow.json
  python tools/api_property_scan.py --file resp.json --request-file body.json
Exit: 0 selesai (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.api-property-scan/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

# Taksonomi sensitivitas nama properti (konsep publik dari skill sumber,
# dipetakan ulang). Frasa = nama ter-normalisasi (huruf kecil, tanpa
# pemisah); token = kata tunggal hasil tokenisasi.
SENSITIVE_FRASES: dict[str, tuple[str, ...]] = {
    "critical": ("passwordhash", "secretkey", "privatekey", "accesstoken",
                 "refreshtoken", "apikey", "clientsecret", "authheader"),
    "high": ("socialsecurity", "creditcard", "cardnumber", "bankaccount",
             "routingnumber", "cardcvv", "accountbalance",
             "balanceamount"),
    "medium": ("internalnotes", "adminnotes", "createdby", "modifiedby",
               "sessionid", "ipaddress", "permissionlist", "userrole",
               "rolename", "isadmin", "issuperuser", "privilegelevel",
               "accesslevel"),
    "low": ("dateofbirth", "phonenumber", "postaladdress", "streetaddress",
            "emailaddress"),
}
SENSITIVE_TOKENS: dict[str, tuple[str, ...]] = {
    "critical": ("password", "secret", "token", "credential", "apikey"),
    "high": ("ssn", "cvv", "cvc", "iban", "salary", "income"),
    "medium": ("role", "permission", "privilege", "admin", "session"),
    "low": ("phone", "address", "gender", "ethnicity", "age", "dob"),
}
# Catatan: "password" berformat bcrypt/hash direspons = critical
# (passwordhash); nama field "hash" saja TIDAK dianggap sensitif.

# Field istimewa yang TIDAK boleh diterima dari klien (kandidat
# mass-assignment; konsep daftar sumber, verifikasi via playbook live).
MASS_ASSIGN_TOKENS: frozenset[str] = frozenset({
    "role", "admin", "isadmin", "issuperuser", "isstaff", "isverified",
    "isactive", "emailverified", "verified", "accounttype", "tier",
    "subscription", "permissions", "privilege", "creditlimit",
    "discountrate", "accountbalance", "balance", "ratelimit", "quota",
})
MASS_ASSIGN_FRASES: frozenset[str] = frozenset({
    "isadmin", "issuperuser", "isverified", "isactive", "emailverified",
    "accounttype", "subscriptiontier", "discountrate", "creditlimit",
    "accountbalance", "ratelimit", "userrole", "rolename",
    "permissionlist", "privilegelevel",
})

_TOKEN_RE = re.compile(r"[a-z]+|\d+")
_SEV_RANK = ("critical", "high", "medium", "low")

# Frasa yang mengandung kata sensitif tapi lazim TIDAK sensitif
# (anti-FP): token paginasi/kursor, dsb.
_BENIGN_FRASES: frozenset[str] = frozenset({
    "nexttoken", "pagetoken", "paginationtoken", "cursortoken",
    "nextpagetoken", "tokencount", "tokenbucket", "ratelimit",
})


def _norm_name(name: str) -> str:
    """camelCase + pemisah -> frasa huruf kecil tanpa pemisah."""
    # sisipkan spasi sebelum huruf besar lalu lower
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return re.sub(r"[^a-z0-9]+", "", spaced.lower())


def _tokens(name: str) -> list[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return _TOKEN_RE.findall(spaced.lower())


def classify_property(name: str) -> str | None:
    """Kembalikan severity utk nama properti, atau None bila biasa."""
    norm = _norm_name(name)
    if norm in _BENIGN_FRASES:
        return None
    toks = set(_tokens(name))
    for sev in _SEV_RANK:
        if any(p in norm for p in SENSITIVE_FRASES.get(sev, ())):
            return sev
        if any(tok in SENSITIVE_TOKENS.get(sev, ()) for tok in toks):
            return sev
    return None


def is_privileged(name: str) -> bool:
    """True bila nama properti termasuk kandidat mass-assignment."""
    norm = _norm_name(name)
    if norm in MASS_ASSIGN_FRASES:
        return True
    return any(tok in MASS_ASSIGN_TOKENS for tok in _tokens(name))


# ------------------------------------------------------------- walk
def walk_objects(node: object, prefix: str = "",
                 out: list[tuple[str, str, str]] | None = None,
                 depth: int = 0) -> list[tuple[str, str, str]]:
    """Kumpulkan (key_path, nama_properti_leaf, nilai_repr) dari objek.

    Daftar dilalui (indeks disederhanakan '[]') untuk menangkap field
    di dalam array respons. Depth dibatasi utk mencegah struktur liar.
    """
    if out is None:
        out = []
    if depth > 12:
        return out
    if isinstance(node, dict):
        for key, val in node.items():
            kpath = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(val, (dict, list)):
                out.append((kpath, key, ""))
                walk_objects(val, kpath, out, depth + 1)
            else:
                out.append((kpath, key, str(val)[:60]))
    elif isinstance(node, list):
        for item in node[:50]:
            walk_objects(item, prefix, out, depth + 1)
    return out


# ------------------------------------------------------------- parse
def _load_objects(text: str, src: str) -> list[tuple[str, dict]]:
    """Parse teks JSON/JSONL -> [(path, response_obj)].

    Envelope dikenali: objek dengan kunci path/endpoint + response.
    """
    stripped = text.strip()
    objs: list[object] = []
    if stripped.startswith("{") and "\n" in stripped:
        # coba JSONL dulu: setiap baris satu objek JSON
        try:
            objs = [json.loads(ln) for ln in stripped.splitlines()
                    if ln.strip()]
        except json.JSONDecodeError:
            objs = []
    if not objs:
        try:
            objs = [json.loads(stripped)]
        except json.JSONDecodeError as exc:
            raise ValueError(f"{src}: JSON tidak valid ({exc})") from None

    out: list[tuple[str, dict]] = []
    for i, ob in enumerate(objs):
        if isinstance(ob, dict) and "response" in ob:
            path = str(ob.get("path") or ob.get("endpoint") or "")
            resp = ob["response"]
        else:
            path, resp = "", ob
        if not isinstance(resp, (dict, list)):
            raise ValueError(
                f"{src}#{i + 1}: response bukan objek/array JSON")
        out.append((path, resp))
    return out


def _load_expected(path_pairs: list[str], exp_file: str | None) \
        -> dict[str, set[str]]:
    exp: dict[str, set[str]] = {}
    if exp_file:
        p = Path(exp_file)
        if not p.is_file():
            raise ValueError(f"expected-file tidak ada: {p}")
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected-file harus objek {path: [field]}")
        for k, v in data.items():
            exp[k] = {str(x) for x in v}
    for pair in path_pairs:
        if "=" not in pair:
            raise ValueError(f"--expected butuh bentuk path=f1,f2: {pair}")
        k, fields = pair.split("=", 1)
        exp[k] = {f.strip() for f in fields.split(",") if f.strip()}
    return exp


# ------------------------------------------------------------- scan
def scan(paths: list[tuple[str, object]],
         expected: dict[str, set[str]],
         request_obj: object | None) -> dict:
    findings: list[dict] = []
    for path, resp in paths:
        allowed = set(expected.get(path, set()))
        for kpath, name, _val in walk_objects(resp):
            leaf = kpath.rsplit(".", 1)[-1]
            sev = classify_property(name)
            if sev is None:
                continue
            if allowed and leaf in allowed:
                continue  # field sah menurut allowlist
            findings.append({
                "type": "property-exposure", "severity": sev,
                "path": path, "property": kpath,
                "in_allowlist": bool(allowed),
            })
        if allowed:
            # properti sensitif di luar allowlist sudah ditangkap;
            # catat nama allowlist yg tak ditemukan (kesalahan config)
            present = {kp.rsplit(".", 1)[-1] for kp, _n, _v
                       in walk_objects(resp)}
            for miss in sorted(allowed - present):
                findings.append({
                    "type": "allowlist-mismatch", "severity": "info",
                    "path": path, "property": miss,
                    "in_allowlist": True,
                })
    if request_obj is not None:
        for kpath, name, _val in walk_objects(request_obj):
            if is_privileged(name):
                findings.append({
                    "type": "mass-assignment-candidate",
                    "severity": "high", "path": "(request)",
                    "property": kpath, "in_allowlist": False,
                })
    findings.sort(key=lambda f: (f["type"], f["path"], f["property"]))
    stats: dict[str, int] = {}
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1
    return {"schema": SCHEMA, "stats": stats, "findings": findings}


# ------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit statis eksposur properti respons API "
                    "(BOPLA) — offline, fail-closed.")
    ap.add_argument("--file", action="append", default=[],
                    help="file tangkapan respons (JSON/JSONL), diulang")
    ap.add_argument("--expected", action="append", default=[],
                    metavar="PATH=f1,f2",
                    help="allowlist field sah per path")
    ap.add_argument("--expected-file", help="file JSON {path: [field]}")
    ap.add_argument("--request-file", help="body request tangkapan")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    try:
        if not args.file:
            raise ValueError("--file wajib (JSON/JSONL tangkapan)")
        paths: list[tuple[str, dict]] = []
        for fp in args.file:
            p = Path(fp)
            if not p.is_file():
                raise ValueError(f"file tidak ada: {p}")
            if p.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"file melebihi "
                                 f"{MAX_FILE_BYTES} byte: {p}")
            text = p.read_text(encoding="utf-8", errors="replace")
            paths.extend(_load_objects(text, p.name))
        if not paths:
            raise ValueError("nol objek respons ter-parse")
        expected = _load_expected(args.expected, args.expected_file)
        request_obj = None
        if args.request_file:
            rp = Path(args.request_file)
            if not rp.is_file():
                raise ValueError(f"request-file tidak ada: {rp}")
            request_obj = json.loads(
                rp.read_text(encoding="utf-8", errors="replace"))
    except ValueError as exc:
        print(f"[api-property-scan] input error: {exc}", file=sys.stderr)
        return 2

    result = scan(paths, expected, request_obj)
    rendered = json.dumps(result, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
