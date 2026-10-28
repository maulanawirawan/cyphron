"""[F43] CWE check — audit referensi CWE di kode vs katalog MITRE lokal.

Produk reliable = tidak mengutip pengetahuan jaman dulu: setiap
"CWE-xxx" di skills/tools/core + registry.json diverifikasi terhadap
katalog katalog MITRE (assets/intel/cwe-1000.csv, di-sync intel_sync):
  - ID tidak ada di katalog = lead (typo/ID tidak valid);
  - ID berstatus Deprecated = lead (referensi usang — pindah ke
    penerusnya di katalog);
  - semua bersih = satu baris AMAN (inventaris).
NOL request (katalog lokal); katalog tidak ada = baris audit
"jalankan intel_sync", bukan crash. Kontrak: (rows, meta).

Pemakaian:
  python tools/intel_sync.py --components cwe     # sekali (TTL 7 hari)
  python tools/cwe_check.py --out findings/cwe-check.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))

from findings import make_finding, write_findings  # noqa: E402
import intel_sync  # noqa: E402

DEFAULT_PATHS = ["skills", "tools", "core", "skills/registry.json"]
_RE_CWE = re.compile(r"CWE-\d{1,5}")


def collect_cwe_refs(rel_paths: list[str]) -> dict[str, list[str]]:
    """Kumpulkan referensi CWE dari file/dir allowlist -> {cwe: [file]}.
    Ber-dir = *.py rekursif; ber-file = satu file (py/json)."""
    refs: dict[str, list[str]] = {}
    seen_files: set[Path] = set()
    for rel in rel_paths:
        p = ROOT / rel
        if p.is_dir():
            files = sorted(p.rglob("*.py"))
        elif p.is_file():
            files = [p]
        else:
            continue
        for f in files:
            if f in seen_files or f.name == "cwe_check.py":
                continue  # audit bukan sumber referensi
            seen_files.add(f)
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel_s = f.relative_to(ROOT).as_posix()
            for m in _RE_CWE.finditer(text):
                refs.setdefault(m.group(0), []).append(rel_s)
    return refs


def check_cwes(refs: dict[str, list[str]],
               catalog: dict[str, dict] | None) -> tuple[list[dict], dict]:
    """Murni: referensi x katalog -> (rows, meta). catalog None/{} tanpa
    file = baris audit fail-closed (bukan klaim bersih)."""
    rows: list[dict] = []
    if catalog is None:
        rows.append(make_finding(
            tool="cwe-check",
            title="Katalog CWE tidak tersedia — audit dilewati",
            severity="medium",
            description="assets/intel/cwe-1000.csv tidak ada; referensi "
                        "CWE di kode TIDAK bisa diverifikasi (fail-closed, "
                        "tidak ada klaim bersih).",
            recommendation="python tools/intel_sync.py --components cwe",
            target_url="intel:cwe",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "CWE-CHECK", "catalog_missing": True}))
        return rows, {"refs": len(refs), "catalog_missing": True,
                      "unknown": 0, "deprecated": 0, "clean": 0}

    unknown = {c: fs for c, fs in refs.items() if c not in catalog}
    deprecated = {c: fs for c, fs in refs.items()
                  if c in catalog and catalog[c].get("status") == "Deprecated"
                  and c not in unknown}
    for c, fs in sorted(unknown.items()):
        rows.append(make_finding(
            tool="cwe-check",
            title=f"Referensi {c} tidak dikenal katalog MITRE",
            severity="medium",
            description=f"{c} tidak ada di katalog CWE ({len(catalog)} "
                        "entri) — kemungkinan typo atau ID tidak valid. "
                        f"Dipakai di: {', '.join(sorted(set(fs))[:4])}.",
            recommendation="Perbaiki ID sesuai katalog MITRE terkini.",
            cwe=None, target_url="intel:cwe",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "CWE-CHECK", "cwe": c, "kind": "unknown",
                   "files": sorted(set(fs))[:8]}))
    for c, fs in sorted(deprecated.items()):
        rows.append(make_finding(
            tool="cwe-check",
            title=f"Referensi {c} usang (Deprecated di katalog MITRE)",
            severity="low",
            description=f"{c} ({catalog[c].get('name', '')}) berstatus "
                        "Deprecated — pengetahuan jaman lalu; katalog "
                        f"menunjuk penerusnya. Dipakai di: "
                        f"{', '.join(sorted(set(fs))[:4])}.",
            recommendation="Ikuti entri penerus di katalog MITRE.",
            cwe=c, target_url="intel:cwe",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "CWE-CHECK", "cwe": c,
                   "kind": "deprecated", "files": sorted(set(fs))[:8]}))
    if not rows:
        rows.append(make_finding(
            tool="cwe-check",
            title=f"Semua referensi CWE sah ({len(refs)} ID unik, "
                  "katalog MITRE lokal)",
            severity="info",
            description=f"{len(refs)} ID CWE unik di kode semua terdaftar "
                        "di katalog MITRE dan tidak ada yang Deprecated "
                        "(AMAN/inventaris).",
            target_url="intel:cwe",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    meta = {"refs": len(refs), "catalog_missing": False,
            "unknown": len(unknown), "deprecated": len(deprecated),
            "clean": len(refs) - len(unknown) - len(deprecated),
            "catalog_entries": len(catalog)}
    return rows, meta


def knowledge_audit() -> tuple[list[dict], dict]:
    """Audit repo-wide utk orkestrator (nightrun/report_pack): katalog
    lokal bila ada, None bila tidak (baris audit fail-closed)."""
    cat_path = ROOT / "assets" / "intel" / "cwe-1000.csv"
    catalog = intel_sync.load_cwe_catalog() if cat_path.exists() else None
    refs = collect_cwe_refs(DEFAULT_PATHS)
    return check_cwes(refs, catalog)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="findings/cwe-check.json")
    ap.add_argument("--paths", nargs="*", default=DEFAULT_PATHS,
                    help="file/dir yang di-audit (default skills+tools+core)")
    args = ap.parse_args()

    catalog_path = ROOT / "assets" / "intel" / "cwe-1000.csv"
    catalog = intel_sync.load_cwe_catalog() if catalog_path.exists() else None
    refs = collect_cwe_refs(args.paths)
    rows, meta = check_cwes(refs, catalog)
    write_findings(args.out, rows,
                   {**meta, "run": "cwe-check", "safety_class": "read-only",
                    "requests": 0})
    print(f"cwe-check: {meta['refs']} ref | unknown={meta['unknown']} "
          f"deprecated={meta['deprecated']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
