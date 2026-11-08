r"""[SAFETY: read-only] etcd_config_audit — audit konfigurasi keamanan etcd
& enkripsi-at-rest Kubernetes dari file konfigurasi tersedia (static pod
manifest, dump argumen proses, EncryptionConfiguration). NOL jaringan,
read-only, stdlib murni.

Port INTI DETERMINISTIK dari skill antrean SKILL-PORT-QUEUE:
  #0840 mukul975/Anthropic-Cybersecurity-Skills
       'performing-kubernetes-etcd-security-assessment'
(etcd menyimpan Secret/RBAC/ConfigMap — plaintext default = target
nilai-tertinggi. Konsep sumber Apache-2.0, atribusi di sini — konsep,
bukan teks; kube-bench/etcdctl tetap alat pihak ketiga.)

Input (satu atau lebih; sisi lain dicatat absen eksplisit):
  --etcd-manifest      static pod etcd (kubeadm: kind Pod, container
                       command/args), ATAU teks argumen proses mentah
                       (`ps aux` / unit file) — flag `--flag=value` /
                       `--flag value` / boolean telanjang di-scan.
  --apiserver-manifest static pod kube-apiserver ATAU teks argumen.
  --encryption-config  file EncryptionConfiguration YAML (apiserver).

Pemeriksaan (fakta konfigurasi, masing-masing dgn poc baris sumber):
  etcd   : listen-client-urls/listen-peer-urls memakai http:// (HIGH,
           transport plaintext); client-cert-auth / peer-client-cert-auth
           absen atau false (HIGH — etcd tanpa mTLS = siapa pun di
           control plane bisa baca Secret); auto-tls / peer-auto-tls
           true (HIGH — sertifikat otomatis tanpa validasi identitas);
           trusted-ca-file / peer-trusted-ca-file absen saat cert-auth
           nyala (MEDIUM); cert-file absen saat listener https (MEDIUM);
           enable-v2 true (LOW — API v2 deprecated, permukaan lebih
           lebar).
  apisrv : etcd-servers ada entri non-https:// (HIGH); etcd-servers
           absen (MEDIUM — cakupan tak terverifikasi, dicatat);
           etcd-cafile/etcd-certfile/etcd-keyfile absen saat server
           https (MEDIUM, digabung); encryption-provider-config absen
           (HIGH — Secret plaintext at-rest, default naik).
  encfg  : resources wajib mencakup "secrets"; provider PERTAMA identity
           (HIGH — tulisan tetap plaintext walau config dipasang);
           provider enkripsi dikenal (kms/aescbc/aesgcm/secretbox) =
           lewat; identity SETELAH provider enkripsi = info (fallback
           baca-migrasi yang sah); provider asing DIHITUNG (fail-closed);
           panjang kunci diverifikasi (aescbc 16, aesgcm 16/24/32,
           secretbox 32 byte base64-decoded) — NILAI KUNCI TIDAK PERNAH
           di-output (redaksi panjang saja, spirit secret tools).

Verdict: fakta konfigurasi terbukti dari baris sumber -> status
confirmed, evidence_kind "arithmetic", verdict L3, poc = flag/redaksi.

Fail-closed: file tidak ada / TIDAK ADA flag yang dikenali dari semua
input -> exit 2 (bukti kosong bukan "bersih"). Parse dokumen gagal
dihitung unparsed di meta.

Pemakaian:
  python tools/etcd_config_audit.py --etcd-manifest etcd-pod.yaml \\
      --apiserver-manifest ka-pod.yaml --encryption-config enc.yaml \\
      --out f.json
Exit: 0 bersih, 1 ada temuan, 2 error input.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))
from findings import make_finding, write_findings  # noqa: E402
from k8s_rbac_audit import parse_documents  # noqa: E402

SCHEMA = "secai.etcd-config-audit/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

ETCD_FLAGS = {
    "listen-client-urls", "listen-peer-urls", "client-cert-auth",
    "peer-client-cert-auth", "trusted-ca-file", "peer-trusted-ca-file",
    "cert-file", "key-file", "peer-cert-file", "peer-key-file",
    "auto-tls", "peer-auto-tls", "enable-v2", "data-dir",
}
APISERVER_FLAGS = {
    "etcd-servers", "etcd-cafile", "etcd-certfile", "etcd-keyfile",
    "encryption-provider-config",
}
# panjang kunci sah (byte, base64-decoded) per provider enkripsi
KEY_LENGTHS = {"aescbc": {16}, "aesgcm": {16, 24, 32},
               "secretbox": {32}}
KNOWN_PROVIDERS = {"kms", "aescbc", "aesgcm", "secretbox", "identity"}

_TOKEN_FLAG_RE = re.compile(r"^--([a-z][a-z0-9.\-]*)(?:=(.*))?$")

_BOOLEAN_FLAGS = {"client-cert-auth", "peer-client-cert-auth", "auto-tls",
                  "peer-auto-tls", "enable-v2"}


def extract_flags_text(text: str) -> dict[str, str]:
    """Scan flag dari teks mentah (`--flag=value`, `--flag value`,
    boolean telanjang). Token berikut yang mulai `--` TIDAK ditelan
    sbg nilai (boolean telanjang). Token-based — andal utk baris
    command/args kubeadm maupun output `ps`."""
    out: dict[str, str] = {}
    tokens = text.split()
    i = 0
    while i < len(tokens):
        m = _TOKEN_FLAG_RE.match(tokens[i])
        if m:
            name = m.group(1)
            if name in ETCD_FLAGS or name in APISERVER_FLAGS:
                val = m.group(2)
                if val is None:
                    nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                    if nxt is not None and not nxt.startswith("--"):
                        val = nxt
                        i += 1
                if val is None:
                    val = "true" if name in _BOOLEAN_FLAGS else ""
                out[name] = val.strip("\"'")
        i += 1
    return out


def extract_flags_manifest(doc: dict) -> dict[str, str]:
    """Kumpulkan flag dari static pod manifest (containers[].command/args,
    dipisah spasi per item ala kubeadm)."""
    text_parts: list[str] = []
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return {}
    containers = spec.get("containers")
    if not isinstance(containers, list):
        return {}
    for c in containers:
        if not isinstance(c, dict):
            continue
        for key in ("command", "args"):
            items = c.get(key)
            if isinstance(items, list):
                text_parts.extend(str(x) for x in items)
            elif isinstance(items, str):
                text_parts.append(items)
    return extract_flags_text(" ".join(text_parts))


def _bool(v: str | None) -> bool | None:
    if v is None or v == "":
        return None
    low = v.strip().lower()
    if low in ("true", "1", "yes"):
        return True
    if low in ("false", "0", "no"):
        return False
    return None


def _urls(v: str | None) -> list[str]:
    return [u.strip() for u in (v or "").split(",") if u.strip()]


def audit_etcd(flags: dict[str, str], src: str) -> list[tuple[str, str, str]]:
    """Return list (severity, judul, poc) sisi etcd."""
    out: list[tuple[str, str, str]] = []

    def poc_of(name: str) -> str:
        return f"{src}: --{name}={flags.get(name, '<absen>')}"

    for url_flag in ("listen-client-urls", "listen-peer-urls"):
        urls = _urls(flags.get(url_flag))
        for u in urls:
            if u.startswith("http://"):
                out.append((
                    "high",
                    f"etcd {url_flag} plaintext http:// ({u})",
                    poc_of(url_flag)))
    cca = _bool(flags.get("client-cert-auth"))
    if cca is not True:
        out.append((
            "high",
            "etcd client-cert-auth tidak aktif"
            + (" (false)" if cca is False else " (flag absen)"),
            poc_of("client-cert-auth")))
    pcca = _bool(flags.get("peer-client-cert-auth"))
    if pcca is not True:
        out.append((
            "high",
            "etcd peer-client-cert-auth tidak aktif"
            + (" (false)" if pcca is False else " (flag absen)"),
            poc_of("peer-client-cert-auth")))
    for auto in ("auto-tls", "peer-auto-tls"):
        if _bool(flags.get(auto)) is True:
            out.append((
                "high",
                f"etcd {auto}=true — sertifikat otomatis tanpa CA "
                "terverifikasi",
                poc_of(auto)))
    if cca is True and not flags.get("trusted-ca-file"):
        out.append((
            "medium",
            "etcd client-cert-auth aktif tanpa trusted-ca-file — "
            "identitas klien klien tak divalidasi CA",
            poc_of("trusted-ca-file")))
    if pcca is True and not flags.get("peer-trusted-ca-file"):
        out.append((
            "medium",
            "etcd peer-client-cert-auth aktif tanpa peer-trusted-ca-file",
            poc_of("peer-trusted-ca-file")))
    has_https = any(u.startswith("https://")
                    for u in _urls(flags.get("listen-client-urls")))
    if has_https and not flags.get("cert-file"):
        out.append((
            "medium",
            "etcd listener https tanpa cert-file (server TLS tak lengkap)",
            poc_of("cert-file")))
    if _bool(flags.get("enable-v2")) is True:
        out.append((
            "low",
            "etcd enable-v2=true — API v2 deprecated, permukaan lebih "
            "lebar tanpa kebutuhan",
            poc_of("enable-v2")))
    return out


def audit_apiserver(flags: dict[str, str],
                    src: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []

    def poc_of(name: str) -> str:
        return f"{src}: --{name}={flags.get(name, '<absen>')}"

    servers = _urls(flags.get("etcd-servers"))
    if not servers:
        out.append((
            "medium",
            "kube-apiserver etcd-servers absen — transport etcd tak "
            "terverifikasi dari konfigurasi ini",
            poc_of("etcd-servers")))
    else:
        bad = [u for u in servers if not u.startswith("https://")]
        if bad:
            out.append((
                "high",
                f"kube-apiserver etcd-servers non-https: {', '.join(bad)}",
                poc_of("etcd-servers")))
        else:
            missing = [f for f in ("etcd-cafile", "etcd-certfile",
                                   "etcd-keyfile") if not flags.get(f)]
            if missing:
                out.append((
                    "medium",
                    "kube-apiserver ke etcd https tanpa "
                    + "/".join(missing),
                    poc_of("etcd-servers")))
    if not flags.get("encryption-provider-config"):
        out.append((
            "high",
            "kube-apiserver tanpa encryption-provider-config — Secret "
            "tersimpan PLAINTEXT di etcd (default naik)",
            poc_of("encryption-provider-config")))
    return out


def audit_encryption_config(doc: dict, src: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    if str(doc.get("kind", "")) != "EncryptionConfiguration":
        return [( "medium",
                  f"{src}: dokumen bukan EncryptionConfiguration "
                  f"(kind={doc.get('kind', '?')})",
                  f"{src}: kind={doc.get('kind', '?')}")]
    resources = doc.get("resources")
    if not isinstance(resources, list) or not resources:
        return [(("medium"), f"{src}: EncryptionConfiguration tanpa "
                             "resources — tidak mengenkripsi apa pun",
                 f"{src}: resources=<absen>")]
    secret_covered = False
    for ridx, r in enumerate(resources):
        if not isinstance(r, dict):
            continue
        names = r.get("resources")
        names = names if isinstance(names, list) else []
        providers = r.get("providers")
        providers = providers if isinstance(providers, list) else []
        if "secrets" in [str(n).strip() for n in names]:
            secret_covered = True
        for pidx, p in enumerate(providers):
            if not isinstance(p, dict) or not p:
                out.append(("medium",
                            f"{src}: provider index {pidx} tak terurai "
                            "(fail-closed)",
                            f"{src}: resources[{ridx}].providers[{pidx}]"))
                continue
            pname = next(iter(p.keys()))
            cfg = p[pname]
            if pname == "identity":
                if pidx == 0 and len(providers) > 0:
                    out.append((
                        "high",
                        f"{src}: provider PERTAMA identity — Secret tetap "
                        "DITULIS PLAINTEXT walau config dipasang "
                        "(identity hanya sah sbg fallback SETELAH provider "
                        "enkripsi utk migrasi baca)",
                        f"{src}: resources[{ridx}].providers[0]=identity"))
                else:
                    out.append((
                        "info",
                        f"{src}: identity fallback setelah provider "
                        "enkripsi (pola migrasi baca yang sah)",
                        f"{src}: resources[{ridx}].providers[{pidx}]="
                        "identity"))
                continue
            if pname not in KNOWN_PROVIDERS:
                out.append((
                    "medium",
                    f"{src}: provider tidak dikenal '{pname}' — DIHITUNG, "
                    "bukan dilewati diam-diam",
                    f"{src}: resources[{ridx}].providers[{pidx}]={pname}"))
                continue
            if pname == "kms":
                # kms: kunci di KMS eksternal — panjang tak diverifikasi
                continue
            keys = (cfg or {}).get("keys")
            if not isinstance(keys, list) or not keys:
                out.append((
                    "medium",
                    f"{src}: provider {pname} tanpa keys",
                    f"{src}: resources[{ridx}].providers[{pidx}].keys"
                    "=<absen>"))
                continue
            for k in keys:
                if not isinstance(k, dict):
                    continue
                kname = str(k.get("name", "?"))
                secret_b64 = k.get("secret")
                try:
                    raw = base64.b64decode(str(secret_b64), validate=True)
                    length = len(raw)
                except (binascii.Error, TypeError, ValueError):
                    out.append((
                        "medium",
                        f"{src}: kunci {pname}/{kname} bukan base64 valid",
                        f"{src}: key={kname} secret=<redacted,bukan-b64>"))
                    continue
                if length not in KEY_LENGTHS[pname]:
                    out.append((
                        "medium",
                        f"{src}: kunci {pname}/{kname} panjang {length} "
                        f"byte (sah: {sorted(KEY_LENGTHS[pname])})",
                        f"{src}: key={kname} decoded_len={length} "
                        "value=<redacted>"))
    if not secret_covered:
        out.append((
            "high",
            f"{src}: EncryptionConfiguration tidak mencakup resource "
            "'secrets' — Secret tetap plaintext",
            f"{src}: resources={[r.get('resources') for r in resources
                                 if isinstance(r, dict)]}"))
    return out


def load_input(path: Path) -> tuple[list[dict[str, str]], list[str], list[dict]]:
    """Muat file -> (daftar flag-dict per sumber, catatan unparsed,
    dokumen EncryptionConfiguration mentah). Flag di-scan dari TEKS
    MENTAH (parser YAML subset memecah `- --flag=v` di ':' pertama —
    regex flag lebih andal utk bentuk command/args kubeadm);
    EncryptionConfiguration tetap via parse_documents (butuh struktur)."""
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path}: terlalu besar")
    text = path.read_text(encoding="utf-8", errors="replace")
    flags_dicts: list[dict[str, str]] = []
    unparsed: list[str] = []
    enc_docs: list[dict] = []
    try:
        docs = parse_documents(text)
    except (ValueError, json.JSONDecodeError) as exc:
        docs = []
        unparsed.append(f"{path}: YAML subset gagal: {exc}")
    for d in docs:
        if isinstance(d, dict) and \
                str(d.get("kind", "")) == "EncryptionConfiguration":
            enc_docs.append(d)
    f = extract_flags_text(text)
    if f:
        flags_dicts.append(f)
    elif not enc_docs:
        unparsed.append(f"{path}: tidak ada flag etcd/apiserver dikenali")
    return flags_dicts, unparsed, enc_docs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="[SAFETY: read-only] etcd_config_audit — audit "
                    "konfigurasi etcd + enkripsi-at-rest dari file "
                    "konfigurasi (NOL jaringan)")
    ap.add_argument("--etcd-manifest", default=None)
    ap.add_argument("--apiserver-manifest", default=None)
    ap.add_argument("--encryption-config", default=None)
    ap.add_argument("--out", default="etcd_config_audit_findings.json")
    args = ap.parse_args(argv)

    inputs: list[tuple[str, Path]] = []
    if args.etcd_manifest:
        inputs.append(("etcd", Path(args.etcd_manifest)))
    if args.apiserver_manifest:
        inputs.append(("apiserver", Path(args.apiserver_manifest)))
    if args.encryption_config:
        inputs.append(("enc", Path(args.encryption_config)))
    if not inputs:
        print("[etcd_config_audit] tanpa --etcd-manifest/"
              "--apiserver-manifest/--encryption-config: tidak ada "
              "kesimpulan (fail-closed)", file=sys.stderr)
        return 2
    for _, p in inputs:
        if not p.is_file():
            print(f"[etcd_config_audit] file tidak ada: {p} "
                  "(fail-closed)", file=sys.stderr)
            return 2

    findings: list[dict] = []
    unparsed: list[str] = []
    recognized = 0
    etcd_seen = apiserver_seen = enc_seen = False
    for side, p in inputs:
        try:
            flags_list, notes, enc_docs = load_input(p)
        except (OSError, ValueError) as exc:
            print(f"[etcd_config_audit] {exc} (fail-closed)",
                  file=sys.stderr)
            return 2
        unparsed.extend(notes)
        for f in flags_list:
            if side in ("etcd", "apiserver"):
                etcd_flags = {k: v for k, v in f.items() if k in ETCD_FLAGS}
                api_flags = {k: v for k, v in f.items()
                             if k in APISERVER_FLAGS}
                if etcd_flags:
                    etcd_seen = True
                    recognized += 1
                    for sev, title, poc in audit_etcd(etcd_flags, str(p)):
                        findings.append(_mk(sev, title, poc, str(p)))
                if api_flags:
                    apiserver_seen = True
                    recognized += 1
                    for sev, title, poc in audit_apiserver(api_flags,
                                                           str(p)):
                        findings.append(_mk(sev, title, poc, str(p)))
        for d in enc_docs:
            enc_seen = True
            recognized += 1
            for sev, title, poc in audit_encryption_config(d, str(p)):
                findings.append(_mk(sev, title, poc, str(p)))

    if recognized == 0:
        print(f"[etcd_config_audit] 0 konfigurasi dikenali dari "
              f"{len(inputs)} input ({len(unparsed)} unparsed) — tidak "
              "ada kesimpulan (fail-closed)", file=sys.stderr)
        return 2

    meta = {
        "schema": SCHEMA,
        "inputs": [str(p) for _, p in inputs],
        "etcd_side": etcd_seen,
        "apiserver_side": apiserver_seen,
        "encryption_config": enc_seen,
        "unparsed": unparsed,
        "note": "audit konfigurasi statis; verifikasi isi-etcd langsung "
                "(etcdctl hexdump) & snapshot backup = ops live di luar "
                "tool ini",
    }
    write_findings(args.out, findings, meta)
    if findings:
        hi = sum(1 for f in findings if f["severity"] == "high")
        print(f"[etcd_config_audit] {len(findings)} temuan "
              f"({hi} high) -> {args.out}")
        return 1
    print(f"[etcd_config_audit] konfigurasi bersih sesuai cek tersedia "
          f"(etcd={etcd_seen}, apiserver={apiserver_seen}, "
          f"enc={enc_seen}) -> {args.out}")
    return 0


def _mk(severity: str, title: str, poc: str, file_path: str) -> dict:
    return make_finding(
        tool="etcd-config-audit",
        title=title,
        severity=severity,
        description=title,
        recommendation=(
            "Samakan dgn baseline kubeadm/CIS: mTLS dua arah etcd "
            "(client+peer cert-auth dgn CA eksplisit), listener https, "
            "EncryptionConfiguration dgn provider enkripsi non-identity "
            "mencakup secrets; uji baca-langsung etcdctl hanya di lab"),
        poc=poc,
        evidence_kind="arithmetic",
        finding_class="weakness" if severity in ("high", "medium")
                      else "observation",
        confidence=1.0,
        status="confirmed",
        verdict=2,
        extra={"schema": SCHEMA},
        file_path=file_path,
    )


if __name__ == "__main__":
    sys.exit(main())
