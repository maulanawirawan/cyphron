"""[SAFETY: read-only] dep_confusion_check — deteksi risiko dependency
confusion / namespace attack dari manifest & konfigurasi registry.

Mengisi antrean port SKILL-PORT-QUEUE #0144 (sumber SnailSploit/
Claude-Red skill 'offensive-dependency-confusion'; atribusi ide). Skill
sumber merangkum riset publik Alex Birsan (2021): package manager yang
menyelesaikan nama dari MULTI sumber bisa memilih paket publik yang
diperebutkan penyerang daripada paket privat internal. Tool ini menyediakan
sisi defensifnya — memeriksa manifest + konfigurasi registry sebuah
proyek dan menandai konfigurasi yang membuat nama internal bisa jatuh
ke registry publik. Aturan ditulis sendiri dari mekanisme resolusi yang
didokumentasikan publik (npm, pip, NuGet) — TANPA menyalin kode sumber.
Lisensi secai: PolyForm NC.

Pemeriksaan (offline, NOL jaringan secara default):
  npm   — package.json: dependency @scope tanpa pemetaan
          '@scope:registry=' di .npmrc  -> HIGH (fallback ke publik);
          nama internal (--internal) yang unscoped di deps -> HIGH;
          package-lock.json/yarn.lock: host 'resolved' tercampur -> MEDIUM.
  pip   — requirements.txt: '--index-url' + '--extra-index-url' bersamaan
          -> MEDIUM (resolusi bisa memilih index publik); nama internal
          dari --internal yang tidak ter-pin di multi-index -> HIGH.
  NuGet — NuGet.config: >= 2 <packageSources> tanpa <packageSourceMapping>
          -> HIGH (feed dipilih berurutan, tanpa mapping per-paket).

--internal FILE: daftar nama paket internal (satu per baris, '#'
komentar). Tanpa daftar ini, cek nama-spesifik dilewati (offline tidak
ada cara membedakan nama internal vs publik — fail-closed, tidak
mengklaim aman).

--verify-registry (OPT-IN, jaringan): nama internal dicek ke registry
publik (registry.npmjs.org / pypi.org) — 1 GET per nama. Tidak ditemukan
= belum terklaim (lead naik ke HIGH dengan detail). Gagal jaringan =
catat 'unverified' — TIDAK dianggap aman (fail-closed).

Exit: 0 = file terurai (lead tetap dilaporkan); 1 = gate --fail-on
tercapai (default --fail-on HIGH); 2 = input error (file hilang/rusak).

Pemakaian:
  python tools/dep_confusion_check.py --file package.json --file .npmrc
  python tools/dep_confusion_check.py --file requirements.txt \
      --internal internal-names.txt --verify-registry --out dc.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.dep-confusion-check/1"
UA = "secai-dep-confusion-check/1 (read-only; authorized lab use)"
NPM_DEFAULT_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


class InputError(Exception):
    """File input tidak bisa diurai — fail-closed: exit 2."""


class Lead:
    """Satu temuan risiko konfigurasi (bukan bukti eksploitasi)."""

    def __init__(self, severity: str, ecosystem: str, file: str,
                 detail: str, recommendation: str, line: int | None = None,
                 package: str | None = None) -> None:
        self.lead = {
            "severity": severity, "ecosystem": ecosystem, "file": file,
            "line": line, "package": package, "detail": detail,
            "recommendation": recommendation,
        }


def _read_lines(path: Path) -> "tuple[list[str] | None, str | None]":
    try:
        return path.read_text(encoding="utf-8",
                              errors="strict").splitlines(), None
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"tidak bisa dibaca: {exc}"


# --- npm ----------------------------------------------------------------

def load_internal_names(path: Path) -> dict[str, list[str]]:
    """--internal -> {'npm': [...], 'pypi': [...]}. Baris 'npm:x' /
    'pypi:x' eksplisit; nama telanjang masuk keduanya (dicek di
    ekosistem yang relevan di manifest)."""
    lines, err = _read_lines(path)
    if err:
        raise InputError(f"{path}: {err}")
    out = {"npm": [], "pypi": []}
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("npm:"):
            out["npm"].append(s[4:].strip())
        elif s.lower().startswith("pypi:"):
            out["pypi"].append(s[5:].strip())
        else:
            out["npm"].append(s)
            out["pypi"].append(s)
    return out


def check_npm_package_json(path: Path, leads: list[Lead],
                           internal: dict[str, list[str]]) -> dict:
    """Kumpulkan dep names + scopes; flag scope tanpa pemetaan .npmrc
    dan nama internal unscoped."""
    info: dict = {"scopes": set(), "unscoped": set(), "raw": None}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: package.json tidak bisa diurai: {exc}")
    info["raw"] = doc
    for section in ("dependencies", "devDependencies",
                    "optionalDependencies"):
        deps = doc.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name in deps:
            if name.startswith("@") and "/" in name:
                info["scopes"].add(name[1:].split("/", 1)[0])
            else:
                info["unscoped"].add(name)
    # scope tanpa pemetaan ditandai nanti di check_npmrc (butuh .npmrc)
    for name in sorted(internal.get("npm", [])):
        if name in info["unscoped"]:
            leads.append(Lead(
                "HIGH", "npm", str(path), package=name,
                detail=(f"nama internal '{name}' unscoped di "
                        "package.json — jika npm dikonfigurasi ke "
                        "registry default publik, nama ini bisa "
                        "diklaim penyerang (dependency confusion)"),
                recommendation=("scope-kan paket internal "
                                "(@corp/nama) DAN petakan "
                                "'@corp:registry=<privat>' di .npmrc")))
    return info


def check_npmrc(path: Path, leads: list[Lead],
                pkg_info: dict) -> None:
    """@scope yang dipakai package.json harus dipetakan eksklusif."""
    lines, err = _read_lines(path)
    if err:
        raise InputError(f"{path}: .npmrc tidak bisa dibaca: {err}")
    mapped: set[str] = set()
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        m = re.match(r"^@([^:]+):registry\s*=", s)
        if m:
            mapped.add(m.group(1))
    for scope in sorted(pkg_info.get("scopes", set())):
        if scope not in mapped:
            leads.append(Lead(
                "HIGH", "npm", str(path), package=f"@{scope}",
                detail=(f"scope '@{scope}' dipakai di manifest tapi "
                        "tidak ada pemetaan '@scope:registry=' — "
                        "instalasi bisa jatuh ke registry publik"),
                recommendation=("petakan '@scope:registry=' ke "
                                "registry privat + 'always-auth=true'")))
    # registry default privat TANPA always-auth -> LOW (token tak terkirim)
    default_reg = None
    for raw in lines:
        m = re.match(r"^registry\s*=\s*(\S+)", raw.strip())
        if m:
            default_reg = m.group(1)
    if default_reg and "npmjs.org" not in default_reg:
        has_auth = any(re.match(r"^always-auth\s*=\s*true", l.strip())
                       for l in lines)
        if not has_auth:
            leads.append(Lead(
                "LOW", "npm", str(path),
                detail=("registry default bukan npmjs.org tapi "
                        "'always-auth' tidak true"),
                recommendation=("set 'always-auth=true' agar kredensial "
                                "konsisten dikirim ke registry privat")))


def _host_of(url: str) -> str | None:
    m = re.match(r"^https?://([^/]+)/", url or "")
    return m.group(1) if m else None


def check_npm_lock(path: Path, leads: list[Lead]) -> None:
    """package-lock.json: sumber 'resolved' tercampur publik vs lain."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: lockfile tidak bisa diurai: {exc}")
    packages = doc.get("packages") or {}
    hosts: dict[str, list[str]] = {}
    for name, meta in packages.items():
        url = (meta or {}).get("resolved") or ""
        h = _host_of(url)
        if h:
            hosts.setdefault(h, []).append(name)
    non_default = [h for h in hosts if h not in NPM_DEFAULT_HOSTS]
    if non_default and any(h in NPM_DEFAULT_HOSTS for h in hosts):
        leads.append(Lead(
            "MEDIUM", "npm", str(path),
            detail=("lockfile mencampur registry publik dan "
                    f"non-publik: {','.join(sorted(non_default)[:5])}"
                    + ("..." if len(non_default) > 5 else "")),
            recommendation=("pastikan semua paket internal ter-resolve "
                            "EKSklusif dari registry privat; semak "
                            "resolved URL tidak wajar")))


def check_yarn_lock(path: Path, leads: list[Lead]) -> None:
    lines, err = _read_lines(path)
    if err:
        raise InputError(f"{path}: yarn.lock tidak bisa dibaca: {err}")
    hosts: set[str] = set()
    for raw in lines:
        m = re.search(r'resolved\s+"https?://([^/]+)/', raw)
        if m:
            hosts.add(m.group(1))
    non_default = [h for h in hosts if h not in NPM_DEFAULT_HOSTS]
    if non_default and any(h in NPM_DEFAULT_HOSTS for h in hosts):
        leads.append(Lead(
            "MEDIUM", "npm", str(path),
            detail=("yarn.lock mencampur registry publik dan "
                    f"non-publik: {','.join(sorted(non_default)[:5])}"),
            recommendation=("pastikan paket internal ter-resolve "
                            "eksklusif dari registry privat")))


# --- pip ----------------------------------------------------------------

def check_requirements(path: Path, leads: list[Lead],
                       internal: dict[str, list[str]]) -> None:
    lines, err = _read_lines(path)
    if err:
        raise InputError(f"{path}: requirements tidak bisa dibaca: {err}")
    index_urls: list[tuple[int, str]] = []
    extra_urls: list[tuple[int, str]] = []
    unpinned: list[str] = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(?:--index-url|-i)\s+(\S+)", s)
        if m:
            index_urls.append((i, m.group(1)))
            continue
        m = re.match(r"^--extra-index-url\s+(\S+)", s)
        if m:
            extra_urls.append((i, m.group(1)))
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", s)
        if m and not s.startswith("-"):
            name = m.group(1).lower().replace("_", "-")
            if not re.search(r"[=~<>!]\s*\d|@\s*\S", s):
                unpinned.append(name)
    if index_urls and extra_urls:
        leads.append(Lead(
            "MEDIUM", "pypi", str(path), line=extra_urls[0][0],
            detail=("--extra-index-url dipakai bersama --index-url — "
                    "pip menyelesaikan paket dari SEMUA index; versi "
                    "tertinggi di index publik bisa menang"),
            recommendation=("hindari multi-index; kalau wajib, pin "
                            "==versi + --hash untuk paket internal")))
        internal_set = {n.lower().replace("_", "-")
                        for n in internal.get("pypi", [])}
        for name in unpinned:
            if name in internal_set:
                leads.append(Lead(
                    "HIGH", "pypi", str(path), package=name,
                    detail=(f"nama internal '{name}' tidak ter-pin di "
                            "file multi-index — nama ini bisa "
                            "diperebutkan di index publik dengan "
                            "versi lebih tinggi"),
                    recommendation=("pin versi + hash, atau pindahkan "
                                    "ke index tunggal privat")))


# --- NuGet --------------------------------------------------------------

def check_nuget_config(path: Path, leads: list[Lead]) -> None:
    try:
        root = ET.parse(str(path)).getroot()
    except (OSError, ET.ParseError) as exc:
        raise InputError(f"{path}: NuGet.config tidak bisa diurai: {exc}")
    sources = []
    for el in root.iter():
        tag = el.tag.lower()
        if tag.endswith("add") and el.get("value"):
            # <packageSources><add key=... value=... /></packageSources>
            sources.append((el.get("key") or "?", el.get("value") or ""))
    has_mapping = any(el.tag.lower().endswith("packagesourcemapping")
                      for el in root.iter())
    if len(sources) >= 2 and not has_mapping:
        names = ",".join(k for k, _ in sources[:5])
        leads.append(Lead(
            "HIGH", "nuget", str(path),
            detail=(f"{len(sources)} feed tanpa <packageSourceMapping>: "
                    f"{names} — NuGet memilih feed berurutan; paket "
                    "internal di feed pertama bisa 'ditangkap' feed "
                    "publik berikutnya"),
            recommendation=("tambahkan <packageSourceMapping> yang "
                            "memetakan paket internal eksklusif ke "
                            "feed privat")))


# --- verifikasi registry (opt-in) ---------------------------------------

def http_get_status(url: str, timeout: float = 10.0) -> int | None:
    """1 GET — kembalikan HTTP status; None = gagal jaringan
    (fail-closed: None TIDAK diartikan 'aman')."""
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError, ValueError):
        return None


def verify_registry_claim(name: str, ecosystem: str) -> str:
    """'claimed' | 'unclaimed' | 'unverified' (fail-closed)."""
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{urllib.request.quote(name)}"
    elif ecosystem == "pypi":
        url = (f"https://pypi.org/pypi/"
               f"{urllib.request.quote(name)}/json")
    else:
        return "unverified"
    status = http_get_status(url)
    if status == 200:
        return "claimed"
    if status == 404:
        return "unclaimed"
    return "unverified"


# --- driver ---------------------------------------------------------------

def _ecosystem_of(path: Path) -> str | None:
    n = path.name.lower()
    if n in ("package.json",):
        return "npm-json"
    if n in ("package-lock.json",):
        return "npm-lock"
    if n in ("yarn.lock",):
        return "yarn-lock"
    if n in (".npmrc",):
        return "npmrc"
    if n.startswith("requirements") and n.endswith(".txt"):
        return "pypi"
    if n in ("nuget.config", "nuget.config.xml"):
        return "nuget"
    return None


def run_checks(files: list[Path],
               internal_path: Path | None,
               verify: bool) -> "tuple[list[Lead], list[dict]]":
    leads: list[Lead] = []
    notes: list[dict] = []
    internal: dict[str, list[str]] = {"npm": [], "pypi": []}
    if internal_path is not None:
        internal = load_internal_names(internal_path)
    pkg_info: dict = {}
    npmrc_seen = False
    for path in files:
        eco = _ecosystem_of(path)
        if eco is None:
            notes.append({"file": str(path),
                          "note": "format tidak dikenal — dilewati"})
            continue
        if eco == "npm-json":
            pkg_info = check_npm_package_json(path, leads, internal)
        elif eco == "npmrc":
            npmrc_seen = True
            check_npmrc(path, leads, pkg_info or {"scopes": set()})
        elif eco == "npm-lock":
            check_npm_lock(path, leads)
        elif eco == "yarn-lock":
            check_yarn_lock(path, leads)
        elif eco == "pypi":
            check_requirements(path, leads, internal)
        elif eco == "nuget":
            check_nuget_config(path, leads)

    # manifest pakai @scope tapi .npmrc tidak diberikan sama sekali:
    # pemetaan tidak bisa dipastikan (bisa di config global) — MEDIUM,
    # bukan HIGH (zero-FP: tidak mengklaim pasti rentan)
    if pkg_info.get("scopes") and not npmrc_seen:
        for scope in sorted(pkg_info["scopes"]):
            leads.append(Lead(
                "MEDIUM", "npm", "input", package=f"@{scope}",
                detail=(f"scope '@{scope}' dipakai di manifest tapi "
                        ".npmrc tidak ada di input — pemetaan registry "
                        "tidak bisa diverifikasi offline"),
                recommendation=("sertakan .npmrc proyek pada --file "
                                "agar pemetaan '@scope:registry=' "
                                "diperiksa")))

    if verify:
        seen: set[tuple[str, str]] = set()
        for lead in [l.lead for l in leads]:
            name, eco = lead.get("package"), lead["ecosystem"]
            if not name or eco not in ("npm", "pypi"):
                continue
            if eco == "npm" and name.startswith("@"):
                # nama scoped: klaim publik tidak dicek cara sama
                notes.append({"file": lead["file"], "package": name,
                              "note": "nama scoped — verifikasi klaim "
                                      "publik dilewati"})
                continue
            key = (name, eco)
            if key in seen:
                continue
            seen.add(key)
            status = verify_registry_claim(name, eco)
            if status == "unclaimed":
                lead["severity"] = "HIGH"
                lead["detail"] += (
                    " — VERIFIKASI: nama TIDAK terklaim di registry "
                    "publik, langsung dapat diperebutkan")
            elif status == "unverified":
                notes.append({
                    "file": lead["file"], "package": name,
                    "note": ("verifikasi registry gagal — klaim "
                             "TIDAK dianggap aman (fail-closed)")})
            else:
                notes.append({"file": lead["file"], "package": name,
                              "note": "terklaim di registry publik"})
    return leads, notes


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deteksi risiko dependency confusion dari "
                    "manifest/konfigurasi registry — read-only, "
                    "nol jaringan (kecuali --verify-registry).")
    ap.add_argument("--file", action="append", default=[],
                    help="manifest/konfigurasi (boleh berulang): "
                         "package.json, .npmrc, package-lock.json, "
                         "yarn.lock, requirements*.txt, NuGet.config")
    ap.add_argument("--internal",
                    help="file nama paket internal (satu per baris; "
                         "opsi 'npm:'/'pypi:' eksplisit)")
    ap.add_argument("--verify-registry", action="store_true",
                    help="OPT-IN jaringan: cek klaim nama internal di "
                         "registry publik (1 GET per nama)")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "NONE"],
                    help="gate exit 1 bila severity tercapai "
                         "(default HIGH; NONE = tidak pernah)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    if not args.file:
        print("ERROR: --file wajib (minimal satu manifest/konfigurasi)",
              file=sys.stderr)
        return 2
    files = [Path(f) for f in args.file]
    missing = [f for f in files if not f.is_file()]
    if missing:
        for f in missing:
            print(f"ERROR: file tidak ada: {f}", file=sys.stderr)
        return 2

    internal_path = Path(args.internal) if args.internal else None
    if internal_path is not None and not internal_path.is_file():
        print(f"ERROR: --internal tidak ada: {internal_path}",
              file=sys.stderr)
        return 2
    try:
        leads, notes = run_checks(files, internal_path,
                                  args.verify_registry)
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    lead_dicts = [l.lead for l in leads]
    summary = {sev: sum(1 for d in lead_dicts
                        if d["severity"] == sev)
               for sev in ("HIGH", "MEDIUM", "LOW", "INFO")}
    out = {"schema": SCHEMA, "files": [str(f) for f in files],
           "internal": str(internal_path) if internal_path else None,
           "verify_registry": args.verify_registry, "leads": lead_dicts,
           "notes": notes, "summary": summary}
    text = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)

    if args.fail_on == "NONE":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[d["severity"]] >= threshold
           for d in lead_dicts):
        print(f"GATE GAGAL: ada lead >= {args.fail_on}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
