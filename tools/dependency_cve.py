"""[F67][SAFETY: read-only] dependency-cve — audit dependensi lokal
terhadap rentang versi CVE yang otoritatif.

Dua sumber, keduanya fail-closed. Ladder verifikasi (eliminasi FP
sampai titik akhir):
  - NVD + OSV sepakat         -> L2 cross-confirmed (dua sumber);
  - NVD hit tapi OSV yang memetakan paket menyatakan versi TIDAK
    terdampak                 -> L-x REJECTED (FP tereliminasi,
    tercatat — bukan dilaporkan);
  - single-source / OSV gagal -> L1 lead (verifikasi manual);
  - reportable tetap L3+      -> jalur lab/playbook, bukan di sini.
  1. OFFLINE (default): assets/intel/nvd-ranges.json — rentang versi
     dari CPE cpeMatch NVD (vendor, product, exact/start/end). Match =
     nama paket ternormalisasi SAMA PERSIS dengan product CPE (bukan
     substring) DAN versi di dalam rentang. Versi tak terurai = dilewati.
  2. ONLINE opt-in (--osv): OSV.dev API per paket — rentang eksplisit
     per ekosistem (PyPI/npm) + cache TTL 24 jam. Gagal jaringan =
     dilewati dengan catatan (BUKAN klaim bersih).

Masukan: requirements.txt, package-lock.json, CycloneDX JSON, SPDX
JSON. NOL request kecuali --osv. Tanpa klaim di luar rentang eksplisit.

Pemakaian:
  python tools/dependency_cve.py --file requirements.txt
  python tools/dependency_cve.py --file package-lock.json --osv
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

NVD_RANGES_PATH = ROOT / "assets" / "intel" / "nvd-ranges.json"
CONFIG_PATH = ROOT / "assets" / "intel" / "dependency-config.json"
ALIASES_PATH = ROOT / "assets" / "intel" / "dep-aliases.json"
OSV_URL = "https://api.osv.dev/v1/query"
OSV_ECO = {"pypi": "PyPI", "npm": "npm"}
_OSV_SEV = {"CRITICAL": "critical", "HIGH": "high",
            "MODERATE": "medium", "LOW": "low"}
_REQ_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)$")
_RE_NONALNUM = re.compile(r"[^a-z0-9.]+")


# --------------------------------------------------------------- parsing

def parse_requirements(text: str) -> list[dict]:
    """requirements.txt -> [{ecosystem, name, version, line}]. Hanya
    pin `==` yang dipakai (rentang bebas tidak bisa diaudit zero-FP)."""
    out: list[dict] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://",
                                       "https://", ".", "file:")):
            continue
        line = line.split("--hash=")[0].strip()
        line = line.split(";", 1)[0].strip()
        m = _REQ_RE.match(line)
        if m:
            out.append({"ecosystem": "pypi", "name": m.group(1),
                        "version": m.group(2), "line": i})
    return out


def parse_package_lock(doc: dict) -> list[dict]:
    """package-lock.json v1/v2/v3 -> [{ecosystem, name, version, line}].
    Hanya entri ber-versi eksplisit; nama scoped dipertahankan utuh."""
    out: list[dict] = []

    def add(name: str, ver: str | None, line: int = 0) -> None:
        if name and ver:
            out.append({"ecosystem": "npm", "name": name,
                        "version": str(ver), "line": line})

    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, val in packages.items():
            if not key or not isinstance(val, dict):
                continue
            name = val.get("name") or key.rsplit("node_modules/", 1)[-1]
            add(name, val.get("version"))
        return out
    deps = doc.get("dependencies")

    def walk(tree: dict) -> None:
        if not isinstance(tree, dict):
            return
        for name, val in tree.items():
            if not isinstance(val, dict):
                continue
            add(name, val.get("version"))
            if isinstance(val.get("dependencies"), dict):
                walk(val["dependencies"])

    if isinstance(deps, dict):
        walk(deps)
    return out


def parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """pkg:type/namespace/name@version?qualifiers -> (eco, name, version).
    Nama npm scoped dipertahankan '@scope/name' (namespace + nama)."""
    m = re.match(r"^pkg:([A-Za-z0-9.+-]+)/(.+?)(?:@([^?#]+))?"
                 r"(?:[?#].*)?$", str(purl or ""))
    if not m:
        return None
    eco = m.group(1).lower()
    path = unquote(m.group(2))
    name = path if (eco == "npm" and path.startswith("@")) \
        else path.split("/")[-1]
    return eco, name, m.group(3)


def parse_cyclonedx(doc: dict) -> list[dict]:
    """CycloneDX JSON -> deps (ekosistem dari purl bila ada)."""
    out: list[dict] = []
    for comp in doc.get("components", []) or []:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        ver = comp.get("version")
        eco = "unknown"
        purl = comp.get("purl")
        if purl:
            p = parse_purl(purl)
            if p:
                eco, pname, pver = p
                name = pname or name
                ver = pver or ver
        if name and ver:
            out.append({"ecosystem": eco, "name": str(name),
                        "version": str(ver), "line": 0})
    return out


def parse_spdx(doc: dict) -> list[dict]:
    """SPDX JSON -> deps (ekosistem dari externalRefs purl)."""
    out: list[dict] = []
    for pkg in doc.get("packages", []) or []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        ver = pkg.get("versionInfo")
        eco = "unknown"
        for ref in pkg.get("externalRefs", []) or []:
            loc = str(ref.get("referenceLocator") or "")
            if not loc.startswith("pkg:"):
                continue
            p = parse_purl(loc)
            if p:
                eco, pname, pver = p
                name = pname or name
                ver = pver or ver
            break
        if name and ver:
            out.append({"ecosystem": eco, "name": str(name),
                        "version": str(ver), "line": 0})
    return out


def detect_format(path: Path, text: str) -> str:
    """Tebak format dari nama file lalu isi (JSON sniffing)."""
    name = path.name.lower()
    if name.endswith((".cdx.json", ".cdx")):
        return "cyclonedx"
    if name.endswith((".spdx.json", ".spdx")):
        return "spdx"
    if name == "package-lock.json":
        return "package-lock"
    if name.startswith("requirements") or name.endswith(".txt"):
        return "requirements"
    try:
        doc = json.loads(text)
    except Exception:  # noqa: BLE001
        return "requirements"
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if doc.get("spdxVersion"):
            return "spdx"
        if "lockfileVersion" in doc or (
                "packages" in doc and "dependencies" in doc):
            return "package-lock"
    return "requirements"


# ------------------------------------------------------------- versioning

def _norm(s: str) -> str:
    return " ".join(_RE_NONALNUM.sub(" ", str(s).lower()).split())


def _ver(s: str) -> tuple[int, ...] | None:
    parts = str(s).strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _trim(v: tuple[int, ...]) -> tuple[int, ...]:
    out = list(v)
    while out and out[-1] == 0:
        out.pop()
    return tuple(out)


def _in_range(version: str, e: dict) -> bool:
    """Versi di dalam rentang entri NVD. Semua constraint yang bisa
    diurai WAJIB terpenuhi; constraint tak terurai = False (fail-closed)."""
    v = _ver(version)
    if v is None:
        return False
    if e.get("exact"):
        ex = _ver(e["exact"])
        return ex is not None and _trim(v) == _trim(ex)
    hit = False
    if e.get("start_incl"):
        s = _ver(e["start_incl"])
        if s is None:
            return False
        hit = True
        if v < s:
            return False
    if e.get("start_excl"):
        s = _ver(e["start_excl"])
        if s is None:
            return False
        hit = True
        if v <= s:
            return False
    if e.get("end_incl"):
        s = _ver(e["end_incl"])
        if s is None:
            return False
        hit = True
        if v > s:
            return False
    if e.get("end_excl"):
        s = _ver(e["end_excl"])
        if s is None:
            return False
        hit = True
        if v >= s:
            return False
    return hit


# ------------------------------------------------------------- nvd index

def load_nvd_index(path: Path) -> tuple[dict[str, list[dict]], dict]:
    """nvd-ranges.json -> (index product_norm -> entries, meta)."""
    if not path.is_file():
        return {}, {"entries": 0, "products": 0,
                    "error": f"nvd-ranges tidak ada: {path}"}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {}, {"entries": 0, "products": 0,
                    "error": f"nvd-ranges tidak terurai: {exc}"}
    idx: dict[str, list[dict]] = {}
    for e in doc.get("entries", []) or []:
        if not (e.get("cve") and e.get("product")):
            continue
        key = e.get("product_norm") or _norm(e["product"])
        idx.setdefault(key, []).append(e)
    meta = {"entries": sum(len(v) for v in idx.values()),
            "products": len(idx),
            "synced_at": doc.get("synced_at")}
    return idx, meta


def load_config(path: Path | None = None) -> dict:
    """dependency-config.json -> {osv_default, osv_cache_ttl_hours}.
    File hilang/rusak = default lokal-first (OSV OFF)."""
    path = path or CONFIG_PATH
    defaults = {"osv_default": False, "osv_cache_ttl_hours": 24.0}
    if not path.is_file():
        return defaults
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return defaults
    out = dict(defaults)
    if isinstance(doc.get("osv_default"), bool):
        out["osv_default"] = doc["osv_default"]
    try:
        out["osv_cache_ttl_hours"] = float(
            doc.get("osv_cache_ttl_hours", 24.0))
    except (TypeError, ValueError):
        pass
    return out


def load_aliases(path: Path | None = None) -> dict[tuple, set]:
    """dep-aliases.json -> {(ecosystem, package_norm): {product_norm}}.
    Hanya mapping terverifikasi; entri cacat ditolak senyap."""
    path = path or ALIASES_PATH
    out: dict[tuple, set] = {}
    if not path.is_file():
        return out
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return out
    for e in doc.get("entries", []) or []:
        if not (e.get("ecosystem") and e.get("package")
                and e.get("product")):
            continue
        key = (str(e["ecosystem"]).lower(), _norm(e["package"]))
        out.setdefault(key, set()).add(_norm(e["product"]))
    return out


# ---------------------------------------------------------------- OSV

def _osv_interval_hit(version: str, affected: list) -> dict | None:
    v = _ver(version)
    if v is None:
        return None
    for aff in affected or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            start: tuple | None = ()
            intervals: list[tuple] = []
            ok = True
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    iv = ev["introduced"]
                    if iv == "0":
                        start = ()
                    else:
                        s = _ver(iv)
                        if s is None:
                            ok = False
                            break
                        start = s
                elif "fixed" in ev:
                    f = _ver(ev["fixed"])
                    if f is None:
                        ok = False
                        break
                    intervals.append((start, f, "fixed", ev["fixed"]))
                    start = None
                elif "last_affected" in ev:
                    l = _ver(ev["last_affected"])
                    if l is None:
                        ok = False
                        break
                    intervals.append((start, l, "last",
                                      ev["last_affected"]))
                    start = None
            if not ok:
                continue
            if start is not None:
                intervals.append((start, None, "open", None))
            for lo, hi, kind, raw in intervals:
                if lo is not None and v < lo:
                    continue
                if kind == "fixed":
                    if v < hi:
                        return {"fixed": raw}
                elif kind == "last":
                    if v <= hi:
                        return {"fixed": None, "last_affected": raw}
                else:
                    return {"fixed": None}
    return None


def _osv_vulns(version: str, doc: dict) -> list[dict]:
    """Response OSV -> daftar {id, cve, fixed, severity, summary, url,
    withdrawn} untuk rentang yang HIT pada versi ini. Record withdrawn
    ikut dikembalikan TANDA-tanda (bukan dasar temuan/eliminasi)."""
    out: list[dict] = []
    for v in doc.get("vulns", []) or []:
        hit = _osv_interval_hit(version, v.get("affected") or [])
        if hit is None:
            continue
        aliases = v.get("aliases") or []
        cve = next((a for a in aliases if str(a).startswith("CVE-")),
                   v.get("id", ""))
        refs = v.get("references") or []
        url = (refs[0].get("url") if refs else None) or \
            f"https://osv.dev/vulnerability/{v.get('id', '')}"
        sev_raw = str((v.get("database_specific") or {})
                      .get("severity") or "").upper()
        out.append({
            "id": v.get("id", ""),
            "cve": cve,
            "fixed": hit.get("fixed"),
            "last_affected": hit.get("last_affected"),
            "severity": _OSV_SEV.get(sev_raw, "medium"),
            "summary": (v.get("summary") or "")[:200],
            "url": url,
            "withdrawn": bool(v.get("withdrawn")),
        })
    return out


def _osv_lookup(dep: dict, cache_dir: Path,
                ttl_hours: float) -> tuple[dict | None, bool, str | None]:
    """Query OSV per PAKET (tanpa versi) -> semua vuln paket itu; versi
    dievaluasi sendiri lewat rentang. Cache TTL per (ecosystem, name).
    Return (doc, cache_hit, error)."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(
        f"{dep['ecosystem']}|{dep['name']}".encode()
    ).hexdigest()[:20]
    cache_file = cache_dir / f"{key}.json"
    if cache_file.is_file():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if time.time() - float(cached.get("ts", 0)) < ttl_hours * 3600:
                return cached.get("doc"), True, None
        except Exception:  # noqa: BLE001
            pass
    body = json.dumps({
        "package": {"name": dep["name"],
                    "ecosystem": OSV_ECO.get(dep["ecosystem"],
                                             dep["ecosystem"])},
    }).encode()
    req = urllib.request.Request(
        OSV_URL, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "cyphron-dependency-cve"})
    try:
        with urllib.request.urlopen(req, timeout=30.0) as r:
            doc = json.loads(r.read())
    except Exception as exc:  # noqa: BLE001
        return None, False, f"{type(exc).__name__}: {exc}"[:120]
    try:
        cache_file.write_text(
            json.dumps({"ts": time.time(), "doc": doc}),
            encoding="utf-8")
    except OSError:
        pass
    return doc, False, None


# ---------------------------------------------------------------- check

def check_deps(deps: list[dict], index: dict[str, list[dict]],
               osv: bool = False, cache_dir: Path | None = None,
               cache_ttl_hours: float = 24.0,
               osv_lookup=_osv_lookup,
               aliases: dict[tuple, set] | None = None
               ) -> tuple[list[dict], dict]:
    """Murni(ish): dependensi x (NVD ranges + OSV) -> (rows, meta).
    Ladder: L1 single-source (NVD ATAU OSV) -> L2 cross-confirmed
    (dua sumber independen sepakat) -> L-x REJECTED bila OSV yang
    memetakan paket menyatakan versi TIDAK terdampak (eliminasi FP,
    tercatat). Reportable tetap butuh L3+ (verifikasi manual/lab).
    `aliases` memetakan (ekosistem, paket) -> product CPE terverifikasi
    (mengurangi unmapped TANPA menambah klaim)."""
    rows: list[dict] = []
    seen: set[tuple] = set()
    n_pkg = n_match = n_unmapped = n_skipped = 0
    n_osv_q = n_osv_hit = n_osv_cache = n_osv_err = 0
    n_osv_skip = n_alias = 0
    n_cross = n_eliminated = 0
    cache_dir = cache_dir or (ROOT / "cache" / "osv")

    uniq: dict[tuple, dict] = {}
    for d in deps:
        uniq[(d["ecosystem"], _norm(d["name"]), d["version"])] = d

    for d in uniq.values():
        n_pkg += 1
        if _ver(d["version"]) is None:
            n_skipped += 1
            continue
        alias_set = (aliases or {}).get(
            (d["ecosystem"], _norm(d["name"])), set())
        if alias_set:
            n_alias += 1
        keys = {_norm(d["name"])} | set(alias_set)
        entries: list[dict] = []
        seen_obj: set[int] = set()
        for key in keys:
            for e in index.get(key, []):
                if id(e) in seen_obj:
                    continue
                seen_obj.add(id(e))
                entries.append(e)
        if not entries:
            n_unmapped += 1
        nvd_hits = [e for e in entries
                    if _in_range(d["version"], e)]

        osv_vulns: list[dict] = []
        osv_package_known = False
        osv_ok = False
        if osv:
            if d["ecosystem"] not in OSV_ECO:
                n_osv_skip += 1
            else:
                n_osv_q += 1
                doc, cached, err = osv_lookup(d, cache_dir,
                                              cache_ttl_hours)
                if cached:
                    n_osv_cache += 1
                if err:
                    n_osv_err += 1
                else:
                    osv_ok = True
                    osv_package_known = bool(
                        (doc or {}).get("vulns", []))
                    osv_vulns = _osv_vulns(d["version"], doc or {})

        osv_by_id: dict[str, dict] = {}
        for v in osv_vulns:
            for vid in {v["cve"], v["id"]}:
                if vid:
                    osv_by_id[vid] = v

        # Lapis verifikasi lead NVD: sepakat -> L2, tidak sepakat ->
        # L-x REJECTED (tercatat), single-source -> L1.
        for e in nvd_hits:
            k = (e["cve"], d["name"], d["version"])
            if k in seen:
                continue
            seen.add(k)
            n_match += 1
            fixed = e.get("end_excl")
            sev = ("critical" if (e.get("cvss") or 0) >= 9.0
                   else "high")
            osv_v = osv_by_id.get(e["cve"])
            if (osv_ok and osv_v is not None
                    and not osv_v.get("withdrawn")):
                n_cross += 1
                rows.append(make_finding(
                    tool="dependency-cve",
                    title=f"Dependensi rentan (cross-confirmed): "
                          f"{d['name']} {d['version']} ({e['cve']})",
                    severity=sev,
                    description=(f"Dua sumber independen SEPAKAT untuk "
                                 f"{d['name']} {d['version']}: rentang "
                                 f"CPE NVD {e.get('vendor', '?')}:"
                                 f"{e.get('product', '?')} dan OSV "
                                 f"({osv_v['id']}). "
                                 + (f"Versi fix: "
                                    f"{osv_v.get('fixed') or fixed}."
                                    if (osv_v.get('fixed') or fixed)
                                    else
                                    "Fix belum eksplisit — cek "
                                    "advisory.")),
                    recommendation=("Upgrade + verifikasi: "
                                    + str(osv_v.get("url")
                                          or e.get("source_url", ""))
                                    [:160]),
                    target_url=f"file:{d['ecosystem']}:{d['name']}",
                    evidence_kind="file-manifest",
                    finding_class="weakness", confidence=1.0,
                    status="confirmed", verdict=2,
                    extra={"category": "DEPENDENCY-CVE",
                           "safety_class": "read-only",
                           "ecosystem": d["ecosystem"],
                           "package": d["name"],
                           "version": d["version"], "cve": e["cve"],
                           "cvss": e.get("cvss"),
                           "fixed": osv_v.get("fixed") or fixed,
                           "sources": ["nvd-range", "osv"],
                           "cross_confirmed": True,
                           "source_url": e.get("source_url"),
                           "via": "nvd+osv"}))
                continue
            if osv_ok and osv_v is None and osv_package_known:
                # OSV demonstrably mengenal paket ini (ada record),
                # tapi tidak ada rentang valid yang mencakup CVE ini
                # untuk versi -> lead NVD DITOLAK (eliminasi FP).
                n_eliminated += 1
                rows.append(make_finding(
                    tool="dependency-cve",
                    title=f"FP tereliminasi: {d['name']} {d['version']} "
                          f"{e['cve']} (OSV tidak setuju)",
                    severity="info",
                    description=(f"Lead NVD-range "
                                 f"({e.get('vendor', '?')}:"
                                 f"{e.get('product', '?')}) DITOLAK: "
                                 "OSV memetakan paket per-ekosistem dan "
                                 f"mengenal {d['name']}, namun TIDAK ada "
                                 "rentang valid yang mencakup "
                                 f"{e['cve']} untuk versi ini "
                                 "(withdrawn tidak dihitung). "
                                 "Kemungkinan: CPE product ambigu / "
                                 "rentang beda branch. Dua sumber tidak "
                                 "sepakat -> L-x REJECTED (tercatat, "
                                 "bukan dilaporkan)."),
                    recommendation=("Verifikasi manual dua sumber: "
                                    + str(e.get("source_url", ""))[:120]
                                    + " + https://osv.dev"),
                    target_url=f"file:{d['ecosystem']}:{d['name']}",
                    evidence_kind="file-manifest",
                    finding_class="posture", confidence=1.0,
                    status="false-positive", verdict=-1,
                    extra={"category": "FP-ELIMINATED",
                           "safety_class": "read-only",
                           "ecosystem": d["ecosystem"],
                           "package": d["name"],
                           "version": d["version"], "cve": e["cve"],
                           "nvd_source": e.get("source_url"),
                           "reason": "osv-disagree"}))
                continue
            rows.append(make_finding(
                tool="dependency-cve",
                title=f"Dependensi rentan: {d['name']} {d['version']} "
                      f"({e['cve']})",
                severity=sev,
                description=(f"{d['name']} {d['version']} berada di "
                             f"rentang CPE NVD {e.get('vendor', '?')}:"
                             f"{e.get('product', '?')} untuk {e['cve']} "
                             f"(CVSS {e.get('cvss')}). "
                             + (f"Versi fix (endExcluding): {fixed}."
                                if fixed else
                                "Batas atas inklusif/tanpa fix "
                                "eksplisit — cek advisory vendor.")
                             + (" Single-source (OSV tidak di-query "
                                "atau tidak merespons)."
                                if not osv_ok else "")),
                recommendation=(
                    f"Upgrade ke >= {fixed} + cek advisory: "
                    f"{str(e.get('source_url', ''))[:160]}"
                    if fixed else
                    "Upgrade mengikuti advisory vendor; verifikasi "
                    "manual."),
                target_url=f"file:{d['ecosystem']}:{d['name']}",
                evidence_kind="file-manifest", finding_class="weakness",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "DEPENDENCY-CVE", "safety_class":
                       "read-only", "ecosystem": d["ecosystem"],
                       "package": d["name"], "version": d["version"],
                       "cve": e["cve"], "cvss": e.get("cvss"),
                       "fixed": fixed,
                       "source_url": e.get("source_url"),
                       "via": "nvd-range"}))
        # OSV-only (tidak ada di NVD) -> L1 single-source; record
        # withdrawn TIDAK dihitung sebagai temuan.
        for v in osv_vulns:
            if v.get("withdrawn"):
                continue
            k = (v["cve"] or v["id"], d["name"], d["version"])
            if k in seen:
                continue
            seen.add(k)
            n_osv_hit += 1
            fix_s = (f"Versi fix: {v['fixed']}."
                     if v.get("fixed") else
                     "Fix belum eksplisit — cek advisory.")
            rows.append(make_finding(
                tool="dependency-cve",
                title=f"Dependensi rentan (OSV): {d['name']} "
                      f"{d['version']} ({v['cve'] or v['id']})",
                severity=v["severity"],
                description=f"OSV.dev menyatakan {d['name']} "
                            f"{d['version']} berada di rentang "
                            f"terdampak {v['id']}"
                            + (f" (CVE: {v['cve']})" if v["cve"] else "")
                            + f". {v['summary']} " + fix_s,
                recommendation=f"Upgrade + verifikasi: {v['url'][:160]}",
                target_url=f"file:{d['ecosystem']}:{d['name']}",
                evidence_kind="file-manifest",
                finding_class="weakness", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "DEPENDENCY-CVE", "safety_class":
                       "read-only", "ecosystem": d["ecosystem"],
                       "package": d["name"], "version": d["version"],
                       "cve": v["cve"], "osv_id": v["id"],
                       "fixed": v.get("fixed"),
                       "source_url": v["url"], "via": "osv"}))
    meta = {"packages": n_pkg, "matches": n_match,
            "unmapped": n_unmapped, "skipped_unparsed": n_skipped,
            "osv_queries": n_osv_q, "osv_hits": n_osv_hit,
            "osv_cache_hits": n_osv_cache, "osv_errors": n_osv_err,
            "osv_skipped_ecosystem": n_osv_skip,
            "alias_mapped": n_alias,
            "cross_confirmed": n_cross, "eliminated": n_eliminated,
            "intel_entries": sum(len(v) for v in index.values()),
            "safety_class": "read-only"}
    if not rows:
        rows.append(make_finding(
            tool="dependency-cve",
            title=f"Tidak ada dependensi yang cocok dengan rentang CVE "
                  f"({n_pkg} paket)",
            severity="info",
            description="Tidak ada paket ber-versi eksplisit yang masuk "
                        "rentang NVD/OSV yang tersedia — BUKAN jaminan "
                        "bebas CVE (indeks bisa belum memuat paket ini; "
                        "lihat meta unmapped).",
            target_url=None,
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN", "safety_class": "read-only"}))
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="requirements.txt / package-lock.json / "
                         "CycloneDX / SPDX")
    ap.add_argument("--format", choices=["auto", "requirements",
                                         "package-lock", "cyclonedx",
                                         "spdx"], default="auto")
    ap.add_argument("--nvd", default=str(NVD_RANGES_PATH))
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--osv", action="store_true",
                     help="paksa query OSV.dev live (cache TTL)")
    grp.add_argument("--offline", action="store_true",
                     help="paksa offline (abaikan config)")
    ap.add_argument("--cache-dir", default=str(ROOT / "cache" / "osv"))
    ap.add_argument("--cache-ttl-hours", type=float, default=None,
                    help="override TTL cache OSV (jam)")
    ap.add_argument("--out", default="findings/dependency-cve.json")
    args = ap.parse_args()

    p = Path(args.file)
    if not p.exists():
        print(f"dependency-cve: file tidak ada: {p} (exit 2, "
              "fail-closed)", file=sys.stderr)
        return 2
    cfg = load_config()
    osv_enabled = (True if args.osv else
                   False if args.offline else
                   bool(cfg.get("osv_default")))
    ttl = (args.cache_ttl_hours if args.cache_ttl_hours is not None
           else float(cfg.get("osv_cache_ttl_hours", 24.0)))
    text = p.read_text(encoding="utf-8", errors="replace")
    fmt = args.format if args.format != "auto" else detect_format(p, text)
    try:
        if fmt == "requirements":
            deps = parse_requirements(text)
        elif fmt == "package-lock":
            deps = parse_package_lock(json.loads(text))
        elif fmt == "cyclonedx":
            deps = parse_cyclonedx(json.loads(text))
        elif fmt == "spdx":
            deps = parse_spdx(json.loads(text))
        else:
            print(f"dependency-cve: format tidak dikenal: {fmt} "
                  "(exit 2)", file=sys.stderr)
            return 2
    except Exception as exc:  # noqa: BLE001
        print(f"dependency-cve: input tidak terurai ({fmt}): {exc} "
              "(exit 2)", file=sys.stderr)
        return 2

    index, intel_meta = load_nvd_index(Path(args.nvd))
    rows, meta = check_deps(deps, index, osv=osv_enabled,
                            cache_dir=Path(args.cache_dir),
                            cache_ttl_hours=ttl,
                            aliases=load_aliases())
    if intel_meta.get("error"):
        rows.insert(0, make_finding(
            tool="dependency-cve",
            title="Intel NVD ranges tidak tersedia — audit offline "
                  "dilewati",
            severity="medium",
            description=f"{intel_meta['error']}. Tanpa indeks rentang, "
                        "audit offline tidak boleh mengklaim apa pun "
                        "(fail-closed).",
            recommendation="python tools/intel_sync.py --components "
                           "nvd-ranges",
            target_url="intel:nvd-ranges",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "DEPENDENCY-CVE", "safety_class":
                   "read-only", "intel_missing": True}))
    write_findings(args.out, rows, {
        **meta, "run": "dependency-cve", "format": fmt,
        "osv_enabled": osv_enabled, "input": str(p),
        "intel": intel_meta,
        "requests": meta.get("osv_queries", 0),
    })
    print(f"dependency-cve: format={fmt} paket={meta['packages']} "
          f"match={meta['matches']} unmapped={meta['unmapped']} "
          f"osv={meta['osv_hits']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
