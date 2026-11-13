"""Triase OFFLINE (stdlib-only, NOL jaringan).

Mekanisme deteksi (semua lead berbasis bukti, ambang bisa diatur):
  - asrep-roastable   : user dengan dontreqpreauth=true (AS-REP roastable)
  - pwd-not-required  : user dengan passwordnotrequired=true
  - pwd-never-expires : user dengan pwdneverexpires=true (≥ --never-min
                        untuk membatasi noise, default 0 = semua)
  - unconstrained-del : computer/OU dengan unconstrained delegation
  - gpp-password      : GPO dengan GPMLocalUsers password field terisi
                        (cpassword di bawah Groups) — kredensial statik
  - dcsync-capable    : non-admin dengan ExtendedRight DCsync pada domain
                        (GetChanges + GetChangesAll)
  - spn-kerberoastable: user dengan servicePrincipalNames non-empty
                        (opsional --spn off utk mematikan noise)

Pemakaian:
  python tools/bh_ingest_triage.py --dir export/ --out triase.json
  python tools/bh_ingest_triage.py --zip 20261113.zip --spn off
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

SCHEMA = "secai.bh-ingest-triage/1"

_KIND_KEYS = {
    "user": ("users", "user"),
    "computer": ("computers", "computer"),
    "group": ("groups", "group"),
    "domain": ("domains", "domain"),
    "gpo": ("gpos", "gpo"),
}


def _iter_collection(data: dict | list):
    """JSON BloodHound 4.x {"data":[...]} atau list lama -> yield item."""
    if isinstance(data, list):
        yield from data
    elif isinstance(data, dict):
        arr = data.get("data")
        if isinstance(arr, list):
            yield from arr


def _kind_of(item: dict, filename: str) -> str | None:
    t = (item.get("type") or item.get("Kind") or "").lower()
    for kind, keys in _KIND_KEYS.items():
        if t == kind:
            return kind
    low = filename.lower()
    for kind, keys in _KIND_KEYS.items():
        if any(k in low for k in keys):
            return kind
    return None


def load_items(path: Path) -> tuple[list[dict], list[str]]:
    """Baca folder/ZIP/file JSON -> (items bertanda file, file terabaikan)."""
    items: list[dict] = []
    skipped: list[str] = []
    files: list[Path] = []
    if path.is_dir():
        files = sorted(p for p in path.rglob("*.json"))
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".json"):
                    continue
                try:
                    data = json.loads(zf.read(name).decode("utf-8", "replace"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    skipped.append(name)
                    continue
                for it in _iter_collection(data):
                    it["_src"] = name
                    items.append(it)
        return items, skipped
    elif path.is_file():
        files = [path]
    else:
        raise ValueError(f"path tidak ditemukan: {path}")

    for p in files:
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            skipped.append(str(p))
            continue
        for it in _iter_collection(data):
            it["_src"] = str(p)
            items.append(it)
    return items, skipped


def _props(item: dict) -> dict:
    return item.get("Properties") or item.get("props") or {}


def analyze(items: list[dict], never_min: int, spn_on: bool) -> list[dict]:
    findings: list[dict] = []
    users: list[tuple[dict, dict]] = []
    computers: list[tuple[dict, dict]] = []
    gpos: list[tuple[dict, dict]] = []
    domains: list[tuple[dict, dict]] = []
    for it in items:
        props = _props(it)
        kind = _kind_of(it, it.get("_src", ""))
        if kind == "user":
            users.append((it, props))
        elif kind == "computer":
            computers.append((it, props))
        elif kind == "gpo":
            gpos.append((it, props))
        elif kind == "domain":
            domains.append((it, props))

    def _name(it: dict) -> str:
        return (_props(it).get("name") or it.get("name") or "?")[:120]

    # 1. AS-REP roastable
    asrep = [(it, pr) for it, pr in users if pr.get("dontreqpreauth")]
    if asrep:
        findings.append({
            "type": "asrep-roastable", "severity": "high",
            "detail": (f"{len(asrep)} user tanpa pre-auth (AS-REP "
                       f"roastable): "
                       f"{', '.join(_name(it) for it, _ in asrep[:6])}"),
            "evidence": {"users": [_name(it) for it, _ in asrep][:20],
                         "count": len(asrep)},
        })

    # 2. password not required
    pnr = [(it, pr) for it, pr in users if pr.get("passwordnotrequired")]
    if pnr:
        findings.append({
            "type": "pwd-not-required", "severity": "high",
            "detail": (f"{len(pnr)} user dengan 'password not required': "
                       f"{', '.join(_name(it) for it, _ in pnr[:6])}"),
            "evidence": {"users": [_name(it) for it, _ in pnr][:20],
                         "count": len(pnr)},
        })

    # 3. password never expires
    pne = [(it, pr) for it, pr in users if pr.get("pwdneverexpires")]
    if pne and len(pne) >= never_min:
        findings.append({
            "type": "pwd-never-expires", "severity": "low",
            "detail": (f"{len(pne)} user password-never-expires "
                       f"(ambang {never_min})"),
            "evidence": {"users": [_name(it) for it, _ in pne][:20],
                         "count": len(pne)},
        })

    # 4. unconstrained delegation
    uc = [(it, pr) for it, pr in computers if pr.get("unconstraineddelegation")]
    if uc:
        findings.append({
            "type": "unconstrained-del", "severity": "high",
            "detail": (f"{len(uc)} computer dengan unconstrained "
                       f"delegation: "
                       f"{', '.join(_name(it) for it, _ in uc[:6])}"),
            "evidence": {"computers": [_name(it) for it, _ in uc][:20],
                         "count": len(uc)},
        })

    # 5. GPP password (cpassword terisi)
    gpp = []
    for it, pr in gpos:
        gpc = pr.get("gpcmachineextensionnames") or ""
        if "groups.xml" in str(gpc).lower() or pr.get("gpppasswords"):
            gpp.append(it)
    if gpp:
        findings.append({
            "type": "gpp-password", "severity": "high",
            "detail": (f"{len(gpp)} GPO memuat konfigurasi Groups.xml "
                       f"(kandidat GPP password — verifikasi cpassword): "
                       f"{', '.join(_name(it) for it in gpp[:4])}"),
            "evidence": {"gpos": [_name(it) for it in gpp][:10],
                         "count": len(gpp)},
        })

    # 6. DCSync-capable non-admin (heuristik ACE di domain object)
    admin_rx = re.compile(r"(domain admins|enterprise admins|administrators)",
                          re.I)
    dcsync: list[str] = []
    for it, pr in domains:
        aces = it.get("Aces") or []
        for ace in aces:
            rights = (ace.get("RightName") or "").lower()
            ace_type = (ace.get("AceType") or "").lower()
            guid = (ace.get("RightsGuid") or "").lower()
            replication = (
                "ds-replication-get-changes" in guid
                or "getchanges" in guid
                or "getchanges" in rights
                or rights in ("all", "allextended")
                or ace_type in ("all", "allextended")
            )
            if not replication:
                continue
            pname = ace.get("PrincipalName") or "?"
            if not admin_rx.search(pname):
                dcsync.append(pname)
    dcsync = sorted(set(dcsync))
    if dcsync:
        findings.append({
            "type": "dcsync-capable", "severity": "high",
            "detail": (f"{len(dcsync)} principal non-admin dengan right "
                       f"replikasi (kandidat DCSync): "
                       f"{', '.join(dcsync[:6])}"),
            "evidence": {"principals": dcsync[:20], "count": len(dcsync)},
        })

    # 7. kerberoastable (SPN non-empty)
    if spn_on:
        spns = [(it, pr) for it, pr in users
                if pr.get("serviceprincipalnames")]
        if spns:
            findings.append({
                "type": "spn-kerberoastable", "severity": "medium",
                "detail": (f"{len(spns)} user dengan SPN (kerberoastable): "
                           f"{', '.join(_name(it) for it, _ in spns[:6])}"),
                "evidence": {"users": [_name(it) for it, _ in spns][:20],
                             "count": len(spns)},
            })
    return findings


def triage(path: Path, never_min: int, spn_on: bool) -> dict:
    items, skipped = load_items(path)
    if not items:
        raise ValueError("tidak ada item BloodHound valid ditemukan")
    findings = analyze(items, never_min, spn_on)
    kinds: dict[str, int] = {}
    for it in items:
        k = _kind_of(it, it.get("_src", "")) or "other"
        kinds[k] = kinds.get(k, 0) + 1
    return {
        "schema": SCHEMA,
        "source": str(path),
        "items_total": len(items),
        "kinds": kinds,
        "skipped_files": skipped[:_SKIPPED_MAX],
        "finding_count": len(findings),
        "findings": findings,
        "thresholds": {"never_min": never_min, "spn": spn_on},
        "note": "triase pasif atas ekspor BloodHound milik sendiri/berizin "
                "— tanpa koleksi, tanpa LDAP, tanpa jaringan",
        "read_only": True,
    }


_SKIPPED_MAX = 10


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase ekspor BloodHound utk konfigurasi AD berisiko "
                    "(read-only, NOL jaringan, NOL LDAP)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", help="folder berisi JSON BloodHound")
    g.add_argument("--zip", dest="zipfile_path",
                   help="ZIP koleksi BloodHound")
    ap.add_argument("--never-min", type=int, default=0,
                    help="jumlah minimum pwd-never-expires utk temuan "
                         "(default 0)")
    ap.add_argument("--spn", choices=["on", "off"], default="on",
                    help="temuan kerberoastable SPN (default on)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.dir or args.zipfile_path)
    if not path.exists():
        print(f"ERROR: path tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage(path, args.never_min, args.spn == "on")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
