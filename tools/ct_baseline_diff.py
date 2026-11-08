"""[AUDIT: read-only] ct_baseline_diff — diff baseline Certificate
Transparency -> alert penerbitan sertifikat mencurigakan.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/auditing-tls-certificate-transparency-logs' (#0271) — atribusi
ide; lisensi sumber Apache-2.0. Dibangun from scratch TANPA menyalin
kode sumber itu. NOL jaringan: record CT (format crt.sh / certspotter:
common_name, name_value/SANs, issuer_name, not_before/not_after,
serial_number) dibaca dari file JSON lokal — pengambilan data live
tetap milik skills/ct_inventory.py atau ekspor crt.sh; tool ini murni
mesin diff baseline + aturan alert deterministik.

Aturan alert (zero-FP — hanya bentuk eksplisit, bukan heuristik tebakan):
  unauthorized-ca   issuer TIDAK memuat salah satu item allowlist CA
                    (critical). Hanya aktif bila --ca-allowlist diberi;
                    tanpa allowlist, issuer tak dikenal TIDAK dianggap
                    bersalah (fail-closed ke arah minimal temuan).
  new-wildcard      nama wildcard (*.sub.domain) milik domain terpantau
                    yang belum ada di baseline (high).
  new-subdomain     nama non-wildcard di bawah domain terpantau yang
                    belum ada di baseline (high).
  typosquat-cert    registrable domain sertifikat cocok permutasi
                    domain terpantau (omission/transposition/keyboard-
                    adjacent/insertion/bitsquatting/homoglyph) —
                    critical. Butuh --typosquat (off default).
  short-lived       masa berlaku < 24 jam (medium; bisa diatur
                    --max-lifetime-hours) — indikasi infrastruktur
                    phishing berumur pendek.
  expiring-soon     sertifikat (baseline atau current, sekali per
                    identitas) kedaluwarsa <= --expiring-days hari dari
                    --now (low).

Domain terpantau = gabungan --domain (repeatable) dan "domains" di file
baseline. Nama milik domain <=> sama persis atau berakhiran "." + domain.

Fail-closed:
  - file tidak ada / JSON tidak valid              -> exit 2
  - file tanpa SATU record valid pun               -> exit 2
  - record rusak (tanpa nama, tanggal rusak)       -> dihitung di
    meta.malformed_*, TIDAK PERNAH dianggap bersih
  - tanpa domain terpantau -> aturan berbasis domain dilewati dan
    dicatat di meta.rules_skipped (tidak ada temuan diam-diam)
  - output deterministik: temuan terurut (severity, code, name, serial)

Pemakaian:
  python tools/ct_baseline_diff.py --baseline base.json --current now.json \
      --domain example.com --ca-allowlist cas.txt --now 2026-11-08T00:00:00Z
  python tools/ct_baseline_diff.py --baseline base.json --current now.json \
      --domain example.go.id --typosquat --fail-on high --out diff.json
Exit: 0 selesai; 1 ada temuan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "secai.ct-baseline-diff/1"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PERMUTATIONS = 600

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

HOMOGLYPH = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4",
             "s": "5", "t": "7", "g": "9", "b": "8"}
KB_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


# ------------------------------------------------------------ waktu
def parse_ts(value: str) -> datetime:
    """Parse ISO-8601 longgar (Z / naive / date-only) -> UTC aware."""
    s = value.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    if "T" not in s and " " not in s and len(s) == 10:
        s += "T00:00:00+00:00"
    elif "+" not in s[10:] and "-" not in s[10:]:
        s += "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ------------------------------------------------------------ record
@dataclass(frozen=True)
class Cert:
    serial: str | None
    cn: str
    names: tuple[str, ...]
    issuer: str | None
    nb: datetime | None
    na: datetime | None
    identity: tuple


def _first(obj: dict, *keys: str):
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def normalize_record(obj: object) -> Cert:
    """crt.sh/certspotter-ish record -> Cert. Raise ValueError bila rusak."""
    if not isinstance(obj, dict):
        raise ValueError("record bukan objek")
    names: list[str] = []
    sans = obj.get("sans") or obj.get("dns_names")
    if isinstance(sans, list):
        names.extend(str(x).strip().lower().rstrip(".")
                     for x in sans if str(x).strip())
    nv = obj.get("name_value")
    if isinstance(nv, str):
        names.extend(p.strip().lower().rstrip(".") for p in nv.splitlines()
                     if p.strip())
    cn = (_first(obj, "common_name", "cn") or "").lower().rstrip(".")
    if cn and cn not in names:
        names.insert(0, cn)
    if not names:
        raise ValueError("record tanpa nama (CN/SAN kosong)")
    nb_s = _first(obj, "not_before")
    na_s = _first(obj, "not_after")
    try:
        nb = parse_ts(nb_s) if nb_s else None
        na = parse_ts(na_s) if na_s else None
    except (ValueError, TypeError) as exc:
        raise ValueError(f"tanggal tidak ter-parse: {exc}") from exc
    serial = _first(obj, "serial_number", "serial")
    issuer = _first(obj, "issuer_name", "issuer", "issuer_o")
    identity = (("serial", serial) if serial
                else ("noserial", cn, issuer, nb_s))
    return Cert(serial=serial, cn=cn or names[0],
                names=tuple(dict.fromkeys(names)), issuer=issuer,
                nb=nb, na=na, identity=identity)


def load_records(path: Path) -> tuple[list[Cert], int]:
    """Baca file JSON record; balikkan (valid, malformed). Fail-closed."""
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"{path} melebihi {MAX_FILE_BYTES} byte")
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, dict):
        data = (data.get("certificates") or data.get("records")
                or data.get("results"))
        if data is None:
            raise ValueError(f"{path}: JSON objek tanpa 'certificates'/'records'")
    if not isinstance(data, list):
        raise ValueError(f"{path}: bukan list record")
    ok: list[Cert] = []
    bad = 0
    for item in data:
        try:
            ok.append(normalize_record(item))
        except ValueError:
            bad += 1
    if not ok:
        raise ValueError(f"{path}: tidak ada record valid "
                         f"({bad} malformed) — fail-closed")
    return ok, bad


# ------------------------------------------------------------ domain
def under_domain(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def registrable_of(name: str) -> str:
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _kb_adjacent(ch: str) -> list[str]:
    for row in KB_ROWS:
        if ch in row:
            i = row.index(ch)
            out = []
            if i > 0:
                out.append(row[i - 1])
            if i < len(row) - 1:
                out.append(row[i + 1])
            return out
    return []


def generate_permutations(domain: str, cap: int = MAX_PERMUTATIONS
                          ) -> list[str]:
    """Permutasi typosquat dari bagian nama domain (sebelum TLD pertama).

    Kategori (mengikuti taksonomi sumber #0271): omission, transposition,
    keyboard-adjacent replacement & insertion, bitsquatting, homoglyph.
    Deterministik: hasil diurut; original tidak disertakan; di-cap.
    """
    name, _, tld = domain.partition(".")
    suffix = "." + tld if tld else ""
    seen: set[str] = {domain}

    def add(newname: str) -> None:
        cand = newname + suffix
        if cand not in seen:
            seen.add(cand)

    for i in range(len(name)):                       # omission
        add(name[:i] + name[i + 1:])
    for i in range(len(name) - 1):                   # transposition
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    for i, ch in enumerate(name):                    # replacement + homoglyph
        for nb in _kb_adjacent(ch):
            add(name[:i] + nb + name[i + 1:])
        hg = HOMOGLYPH.get(ch)
        if hg and hg != ch:
            add(name[:i] + hg + name[i + 1:])
    for i, ch in enumerate(name):                    # insertion
        for nb in _kb_adjacent(ch) + ["-"]:
            add(name[:i] + nb + ch + name[i + 1:])
            add(name[:i] + ch + nb + name[i + 1:])
    for i, ch in enumerate(name):                    # bitsquatting
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isascii() and (flipped.isalnum() or flipped == "-"):
                add(name[:i] + flipped + name[i + 1:])
    seen.discard(domain)
    return sorted(seen)[:cap]


# ------------------------------------------------------------ allowlist
def load_allowlist(path: Path) -> set[str]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"{path}: allowlist JSON harus list")
        items = [str(x) for x in data]
    else:
        items = raw.splitlines()
    return {x.strip().lower() for x in items if x.strip()}


def ca_authorized(issuer: str, allowlist: set[str]) -> bool:
    """Authorized <=> allowlist item mana pun substring dari issuer.

    Arah match sengaja longgar (issuer 'DigiCert TLS RSA' lolos oleh
    item 'digicert') — salah sisi = MENYEMBUNYIKAN alert, bukan
    membuat alert palsu.
    """
    low = issuer.lower()
    return any(item in low for item in allowlist)


# ------------------------------------------------------------ mesin
def _f(code: str, severity: str, cert: Cert, name: str, detail: str
       ) -> dict:
    return {"code": code, "severity": severity, "name": name,
            "serial": cert.serial, "issuer": cert.issuer, "detail": detail}


def diff_ct(baseline: list[Cert], current: list[Cert], *,
            domains: set[str], allowlist: set[str] | None,
            now: datetime, max_lifetime_hours: float = 24.0,
            expiring_days: int = 30, typosquat: bool = False,
            max_permutations: int = MAX_PERMUTATIONS) -> dict:
    baseline_names: set[str] = set()
    seen_identity: set[tuple] = set()
    for c in baseline:
        baseline_names.update(c.names)
        seen_identity.add(c.identity)

    findings: list[dict] = []
    seen_findings: set[tuple] = set()
    rules_skipped: list[str] = []

    permuts: set[str] = set()
    if typosquat and domains:
        for d in sorted(domains):
            permuts.update(generate_permutations(d, max_permutations))
        permuts = {p for p in permuts
                   if not any(under_domain(p, d) for d in domains)}
    elif typosquat and not domains:
        rules_skipped.append("typosquat-cert (tanpa domain terpantau)")

    monitored = bool(domains)
    if not monitored:
        rules_skipped.extend(["new-subdomain (tanpa domain terpantau)",
                              "new-wildcard (tanpa domain terpantau)",
                              "typosquat-cert (tanpa domain terpantau)"])

    def emit(finding: dict) -> None:
        key = (finding["code"], finding["name"], finding["serial"],
               finding["issuer"])
        if key not in seen_findings:
            seen_findings.add(key)
            findings.append(finding)

    for c in current:
        if allowlist is not None and c.issuer and \
                not ca_authorized(c.issuer, allowlist):
            emit(_f("unauthorized-ca", "critical", c, c.cn,
                    f"issuer '{c.issuer}' tidak ada di allowlist CA"))
        for name in c.names:
            reg = registrable_of(name)
            if typosquat and permuts and reg in permuts and \
                    not any(under_domain(reg, d) for d in domains):
                emit(_f("typosquat-cert", "critical", c, name,
                        f"registrable domain '{reg}' cocok permutasi "
                        "domain terpantau"))
                continue
            if not monitored:
                continue
            hosts = [d for d in domains if under_domain(name, d)]
            if not hosts:
                continue
            if name.startswith("*."):
                if name not in baseline_names:
                    emit(_f("new-wildcard", "high", c, name,
                            "wildcard baru — tidak ada di baseline"))
            elif name not in baseline_names:
                emit(_f("new-subdomain", "high", c, name,
                        "nama baru di bawah domain terpantau — tidak "
                        "ada di baseline"))
        if c.nb and c.na:
            lifetime_h = (c.na - c.nb).total_seconds() / 3600.0
            if 0 < lifetime_h < max_lifetime_hours:
                emit(_f("short-lived", "medium", c, c.cn,
                        f"masa berlaku {lifetime_h:.1f} jam "
                        f"(< {max_lifetime_hours:g} jam)"))

    # expiring-soon: baseline + current, sekali per identitas
    cur_ids = {c.identity for c in current}
    for c in current + [x for x in baseline
                        if x.identity not in cur_ids]:
        if c.na and c.na > now and \
                (c.na - now) <= timedelta(days=expiring_days):
            emit(_f("expiring-soon", "low", c, c.cn,
                    f"kedaluwarsa {(c.na - now).days} hari lagi "
                    f"(<= {expiring_days} hari)"))

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["code"],
                                 f["name"], f["serial"] or ""))
    by_sev: dict[str, int] = {}
    by_code: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_code[f["code"]] = by_code.get(f["code"], 0) + 1
    return {
        "schema": SCHEMA,
        "monitored_domains": sorted(domains),
        "meta": {
            "baseline_certs": len(baseline),
            "current_certs": len(current),
            "now": now.isoformat().replace("+00:00", "Z"),
            "ca_allowlist": bool(allowlist),
            "typosquat": bool(permuts) if typosquat else False,
            "rules_skipped": rules_skipped,
        },
        "summary": {"findings_total": len(findings),
                    "by_severity": dict(sorted(by_sev.items(),
                                               key=lambda kv: SEV_ORDER[kv[0]])),
                    "by_code": dict(sorted(by_code.items()))},
        "findings": findings,
    }


# ------------------------------------------------------------ CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ct_baseline_diff — diff baseline CT log -> alert "
                    "penerbitan sertifikat (offline, nol jaringan).")
    ap.add_argument("--baseline", required=True,
                    help="JSON baseline record CT (sebelumnya)")
    ap.add_argument("--current", required=True,
                    help="JSON record CT terkini")
    ap.add_argument("--domain", action="append", default=[],
                    help="domain terpantau (repeatable)")
    ap.add_argument("--ca-allowlist",
                    help="file allowlist CA (.json list atau teks per baris)")
    ap.add_argument("--now",
                    help="waktu acuan ISO-8601 (default: sekarang UTC)")
    ap.add_argument("--max-lifetime-hours", type=float, default=24.0)
    ap.add_argument("--expiring-days", type=int, default=30)
    ap.add_argument("--typosquat", action="store_true",
                    help="aktifkan aturan typosquat-cert")
    ap.add_argument("--max-permutations", type=int, default=MAX_PERMUTATIONS)
    ap.add_argument("--fail-on", choices=("critical", "high", "any"))
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    for label, name in (("baseline", args.baseline), ("current", args.current)):
        if not Path(name).exists():
            print(f"[ct-baseline-diff] file {label} tidak ada: {name}",
                  file=sys.stderr)
            return 2
    try:
        base, bad_b = load_records(Path(args.baseline))
        cur, bad_c = load_records(Path(args.current))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ct-baseline-diff] gagal: {exc}", file=sys.stderr)
        return 2

    allowlist: set[str] | None = None
    if args.ca_allowlist:
        if not Path(args.ca_allowlist).exists():
            print("[ct-baseline-diff] allowlist tidak ada: "
                  f"{args.ca_allowlist}", file=sys.stderr)
            return 2
        try:
            allowlist = load_allowlist(Path(args.ca_allowlist))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"[ct-baseline-diff] allowlist rusak: {exc}",
                  file=sys.stderr)
            return 2
        if not allowlist:
            print("[ct-baseline-diff] allowlist kosong — fail-closed",
                  file=sys.stderr)
            return 2

    if args.now:
        try:
            now = parse_ts(args.now)
        except (ValueError, TypeError) as exc:
            print(f"[ct-baseline-diff] --now tidak valid: {exc}",
                  file=sys.stderr)
            return 2
    else:
        now = datetime.now(timezone.utc)

    domains = {d.strip().lower().rstrip(".") for d in args.domain if d.strip()}
    for d in domains:
        if "." not in d:
            print(f"[ct-baseline-diff] domain tanpa TLD: {d}",
                  file=sys.stderr)
            return 2

    result = diff_ct(
        base, cur, domains=domains, allowlist=allowlist, now=now,
        max_lifetime_hours=args.max_lifetime_hours,
        expiring_days=args.expiring_days, typosquat=args.typosquat,
        max_permutations=max(1, args.max_permutations))
    result["meta"]["malformed_baseline"] = bad_b
    result["meta"]["malformed_current"] = bad_c

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    skipped = result["meta"]["rules_skipped"]
    print(f"[ct-baseline-diff] baseline={result['meta']['baseline_certs']} "
          f"current={result['meta']['current_certs']} "
          f"domain={len(domains)} now={result['meta']['now']}")
    print(f"[ct-baseline-diff] temuan: {s['findings_total']} "
          f"({', '.join(f'{k}={v}' for k, v in s['by_severity'].items()) or '-'})")
    for f in result["findings"][:10]:
        print(f"  [{f['severity']:8}] {f['code']:16} {f['name']}")
    if skipped:
        print(f"[ct-baseline-diff] aturan dilewati: {'; '.join(skipped)}")
    if args.fail_on:
        sev = s["by_severity"]
        hit = (args.fail_on == "any" and s["findings_total"] > 0) or \
              (args.fail_on == "high" and (sev.get("critical", 0)
                                           + sev.get("high", 0)) > 0) or \
              (args.fail_on == "critical" and sev.get("critical", 0) > 0)
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
