"""[F65][SAFETY: read-only] Supply-chain check — higienis dependensi
dari file pin lokal, NOL request (jaringan tidak disentuh).

Latar (Black Oktober 2026): gelombang kompromi supply chain — LiteLLM
v1.107.0 DIKOMPROMIKAN di PyPI/Docker (TeamPCP), PyPI 1.82.7/1.82.8
beracun, Tensorlake npm 0.5.144 ber-worm + "hostage token", GhostAction
via GitHub Actions, Mini Shai-Hulud/ChainDrop sepanjang 2026. Pola:
kompromi identitas rilis — mitigasi dasar: JANGAN memakai versi yang
diketahui beracun + pin dengan hash.

Pemeriksaan per baris file (--file):
  1. (ecosystem, package, version) kena blocklist terkurasi
     (assets/intel/poisoned-packages.json) -> lead HIGH;
  2. baris tidak ter-pin versi -> lead LOW (tidak reproducible);
  3. pin tanpa `--hash=` pada baris yang sama -> lead LOW (pin tanpa
     hash = kepercayaan buta pada registry). Batasan terdokumentasi:
     hash multi-baris gaya pip-compile TIDAK diurai — file gaya itu
     bisa menghasilkan lead "tanpa hash" palsu (false-positive LOW
     yang diketahui, catat di meta).

Fail-closed: file input tidak ada = exit 2 (tanpa temuan); blocklist
tidak ada = baris audit + pemeriksaan poisoned dilewati (bukan klaim
bersih). Format baris: pypi `name==ver` / `name` / `name[extra]==ver`;
npm `name@ver` / `@scope/name@ver`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
from findings import make_finding, write_findings  # noqa: E402

BLOCKLIST_PATH = ROOT / "assets" / "intel" / "poisoned-packages.json"
_RE_WS = re.compile(r"\s+")


def load_blocklist(path: Path | None = None) -> tuple[list[dict], list[dict]]:
    """Blocklist terkurasi -> (entri_valid, ditolak). Fail-closed:
    entri tanpa ecosystem/package/versions/source_url ditolak."""
    path = path or BLOCKLIST_PATH
    valid: list[dict] = []
    rejected: list[dict] = []
    if not path.exists():
        return valid, [{"error": f"blocklist tidak ada: {path}"}]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return valid, [{"error": "blocklist tidak terurai"}]
    for e in doc.get("entries", []) or []:
        if not (e.get("ecosystem") and e.get("package")
                and e.get("versions") and e.get("source_url")):
            rejected.append(e)
            continue
        valid.append({
            "ecosystem": str(e["ecosystem"]).lower(),
            # npm scoped "@scope/name" — @ depan dilepas, paritas dgn
            # parser baris (rpartition("@") + lstrip("@")).
            "package": str(e["package"]).lower().lstrip("@"),
            "versions": [str(v) for v in e["versions"]],
            "campaign": str(e.get("campaign") or ""),
            "note": str(e.get("note") or ""),
            "source_url": str(e["source_url"]),
        })
    return valid, rejected


def parse_line(raw: str, ecosystem: str) -> dict | None:
    """Satu baris dependensi -> {package, version|None, hash: bool}.
    Baris komentar/kosong = None (dilewati)."""
    line = raw.strip()
    if not line or line.startswith(("#", "-", "//")):
        return None
    has_hash = "--hash=" in line
    line = line.split("--hash=")[0].strip()
    line = _RE_WS.sub(" ", line)
    if ecosystem == "npm":
        # @scope/name@1.2.3 | name@1.2.3 | name
        pkg, _, ver = line.rpartition("@")
        if not pkg:
            return {"package": line.lstrip("@"), "version": None,
                    "hash": has_hash}
        return {"package": pkg.lstrip("@"), "version": ver or None,
                "hash": has_hash}
    # pypi: name[extra]==1.2.3 | name | name>=1.0
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?(?:==|>=|<=|~=)\s*"
                 r"([A-Za-z0-9_.\-]+)$", line)
    if m:
        return {"package": m.group(1).lower(), "version": m.group(2),
                "hash": has_hash}
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?$", line)
    if m:
        return {"package": m.group(1).lower(), "version": None,
                "hash": has_hash}
    return None


def check(content: str, ecosystem: str,
          blocklist: list[dict]) -> tuple[list[dict], dict]:
    """Murni: isi file + blocklist -> (rows, meta) kontrak.
    Verdict maksimum L1 (lead) di semua jalur."""
    rows: list[dict] = []
    n_pkg = n_poisoned = n_unpinned = n_nohash = 0
    for i, raw in enumerate(content.splitlines(), start=1):
        parsed = parse_line(raw, ecosystem)
        if parsed is None:
            continue
        n_pkg += 1
        pkg, ver = parsed["package"], parsed["version"]
        if ver is None:
            n_unpinned += 1
            rows.append(make_finding(
                tool="supplychain-check",
                title=f"Dependensi tidak ter-pin: {pkg} (baris {i})",
                severity="low",
                description=f"'{pkg}' tanpa pin versi — build tidak "
                            "reproducible dan otomatis menerima rilis "
                            "BARU apa pun (pola serangan supply chain "
                            "2026: rilis baru beracun muncul PADA jam "
                            "kejadian).",
                recommendation="Pin versi eksplisit + hash "
                               "(pip-compile / npm lockfile).",
                target_url=f"file:{ecosystem}:{pkg}",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "SUPPLY-CHAIN", "safety_class":
                       "read-only", "line": i, "package": pkg}))
            continue
        hit = next((b for b in blocklist
                    if b["ecosystem"] == ecosystem
                    and (b["package"] == pkg
                         or pkg.endswith("/" + b["package"]))
                    and ver in b["versions"]), None)
        if hit:
            n_poisoned += 1
            rows.append(make_finding(
                tool="supplychain-check",
                title=f"PAKET BERACUN: {pkg}=={ver} ({hit['campaign']})",
                severity="high",
                description=f"(ecosystem, package, version) kena "
                            f"blocklist terkurasi: {hit['note'][:220]}. "
                            "JANGAN build/deploy dengan versi ini; "
                            "periksa host + kredensial yang menyentuh "
                            "versi tersebut.",
                recommendation=f"Cek advisory: {hit['source_url'][:160]}"
                               " — naik ke versi bersih, rotasi "
                               "kredensial CI/registry.",
                target_url=f"file:{ecosystem}:{pkg}",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "SUPPLY-CHAIN", "safety_class":
                       "read-only", "line": i, "package": pkg,
                       "version": ver, "campaign": hit["campaign"],
                       "source_url": hit["source_url"]}))
        if not parsed["hash"]:
            n_nohash += 1
            rows.append(make_finding(
                tool="supplychain-check",
                title=f"Pin tanpa hash: {pkg}=={ver} (baris {i})",
                severity="low",
                description=f"'{pkg}=={ver}' tanpa --hash= pada baris "
                            "yang sama — kepercayaan buta pada "
                            "registry. (Batasan: hash multi-baris gaya "
                            "pip-compile tidak diurai — file gaya itu "
                            "bisa menghasilkan lead ini palsu.)",
                recommendation="Pin + hash (pip-compile --generate-hashes"
                               " / npm lockfile integrity).",
                target_url=f"file:{ecosystem}:{pkg}",
                evidence_kind="file-manifest", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=1,
                extra={"category": "SUPPLY-CHAIN", "safety_class":
                       "read-only", "line": i, "package": pkg,
                       "version": ver}))
    meta = {"packages": n_pkg, "poisoned": n_poisoned,
            "unpinned": n_unpinned, "no_hash": n_nohash,
            "blocklist_entries": len(blocklist),
            "known_limitation": "hash multi-baris pip-compile tidak "
                                "diurai"}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="file pin (requirements.txt / package list)")
    ap.add_argument("--ecosystem", choices=["pypi", "npm"],
                    default="pypi")
    ap.add_argument("--out", default="findings/supplychain.json")
    args = ap.parse_args()
    p = Path(args.file)
    if not p.exists():
        print(f"supplychain-check: file tidak ada: {p} (exit 2, "
              "fail-closed)", file=sys.stderr)
        return 2
    blocklist, rejected = load_blocklist()
    rows, meta = check(p.read_text(encoding="utf-8", errors="replace"),
                       args.ecosystem, blocklist)
    if rejected:
        rows.append(make_finding(
            tool="supplychain-check",
            title=f"Blocklist: {len(rejected)} entri ditolak "
                  "fail-closed",
            severity="medium",
            description="Entri blocklist tanpa "
                        "ecosystem/package/versions/source_url TIDAK "
                        "dipakai (anti-fabrikasi).",
            recommendation="Lengkapi field wajib entri blocklist.",
            target_url="intel:poisoned-packages",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SUPPLY-CHAIN", "safety_class":
                   "read-only", "rejected": True}))
    write_findings(args.out, rows,
                   {**meta, "run": "supplychain-check",
                    "safety_class": "read-only", "requests": 0,
                    "ecosystem": args.ecosystem, "input": str(p)})
    print(f"supplychain-check: paket={meta['packages']} "
          f"beracun={meta['poisoned']} tanpa-pin={meta['unpinned']} "
          f"tanpa-hash={meta['no_hash']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
