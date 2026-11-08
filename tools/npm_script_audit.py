"""[AUDIT: read-only] npm_script_audit — audit lifecycle-script npm lokal, NOL request.

Mengisi antrean port dari trailofbits/skills plugin 'supply-chain-risk-auditor'
(antrean SKILL-PORT-QUEUE; atribusi konsep). Kriteria yang diport:
install-time script execution — paket npm yang menjalankan skrip saat
preinstall/install/postinstall/prepare adalah permukaan eksekusi kode pihak
ketiga di mesin pengembang (gelombang kompromi 2026 — Tensorlake ber-worm,
Shai-Hulud — menular lewat jalur ini). Kriteria lain skill sumber (advisory
sweep, publisher concentration, repo staleness) butuh jaringan/gh dan SUDAH
diliput alat secai lain (dependency_cve: rentang CVE; supplychain_check:
blocklist + pin/hash) — tidak diduplikasi di sini. Ditulis dari nol, stdlib
saja, tanpa jaringan; bukan salinan kode pihak lain. Lisensi: PolyForm NC.

Mekanisme (deterministik, read-only): baca SATU file package.json (mode
--manifest) atau SATU pohon node_modules/ (mode --root, default), ekstrak
semua lifecycle script npm, tandai yang berbahaya. Setiap script adalah lead
L0 OBSERVED — keberadaan script = fakta statis, bukan bukti eksploitasi.

Skoring (deterministik, regex publik):
  - pattern eksekusi jaringan/obfuskasi (curl|wget ... | sh, node -e,
    base64 -d, eval, powershell -enc) -> severity HIGH
  - lifecycle script lain (termasuk kosong-butuh-cek) -> severity LOW
  - script lifecycle TIDAK ADA -> tidak diemisikan (meta menghitung)

Fail-closed:
  - file/pohon tidak ada ATAU bukan JSON        -> error exit 2
  - package.json tidak terbaca dalam pohon      -> dihitung meta.unreadable,
    bukan klaim bersih diam-diam
  - ancaman dilarang (NEVER-LIST) tidak relevan di sini — alat murni baca
Exit: 0 findings.json tertulis (meta lengkap); 2 input tidak valid.

Pemakaian:
  python tools/npm_script_audit.py --root /path/proyek --out findings/npm/findings.json
  python tools/npm_script_audit.py --manifest /path/package.json --out f.json
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

# lifecycle scripts yang dieksekusi npm saat `npm install` / `npm ci`
LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
# pola eksekusi berisiko tinggi pada isi script (deterministik, publik)
HIGH_RISK_PATTERNS = (
    (r"\bcurl\b[^|;&]*\|\s*(ba)?sh", "curl piped ke shell"),
    (r"\bwget\b[^|;&]*\|\s*(ba)?sh", "wget piped ke shell"),
    (r"\bnode\s+(-e|--eval)\b", "node -e (eval inline)"),
    (r"\beval\s*\(", "eval() eksplisit"),
    (r"base64\s+-d|frombase64|atob\s*\(", "dekoding base64 saat eksekusi"),
    (r"powershell(\.exe)?\s+(-enc|-command)", "powershell enc/command"),
    (r"\birm\b|\biwr\b|\bInvoke-WebRequest\b", "unduhan PowerShell inline"),
    (r"npm\s+config\s+set\s+[^;|&]*(pre|post)_", "overwrite lifecycle npm"),
)

_RE_HIGH = tuple((re.compile(p, re.I), label) for p, label in HIGH_RISK_PATTERNS)


def load_manifest(path: Path) -> tuple[dict, list[str]]:
    """Baca satu package.json -> (dict, daftar error bila gagal)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"{path}: {exc}"]
    if not isinstance(doc, dict):
        return {}, [f"{path}: bukan objek JSON"]
    return doc, []


def classify_script(cmd: str) -> tuple[str, str]:
    """(severity, alasan) untuk satu isi script — deterministik."""
    for rx, label in _RE_HIGH:
        if rx.search(cmd):
            return "high", label
    return "low", "lifecycle script npm"


def manifest_findings(manifest_path: Path, doc: dict,
                      pkg_name: str) -> list[dict]:
    """Lead untuk semua lifecycle script pada satu manifest."""
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return []
    version = str(doc.get("version") or "?")
    out: list[dict] = []
    for phase in LIFECYCLE_SCRIPTS:
        cmd = scripts.get(phase)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        severity, reason = classify_script(cmd)
        out.append(make_finding(
            tool="npm_script_audit",
            title=f"lifecycle {phase} pada {pkg_name}@{version} ({reason})",
            severity=severity,
            description=(f"package.json memuat script `{phase}` yang "
                         f"dijalankan npm otomatis saat instalasi: "
                         f"`{cmd[:300]}`. Ini eksekusi kode pihak ketiga "
                         "di mesin pengembang."),
            recommendation=("Tinjau isi script sebelum install; untuk build "
                            "terkontrol pertimbangkan `npm ci "
                            "--ignore-scripts` bila build tak membutuhkan "
                            "script native."),
            target_url=f"file:npm:{pkg_name}@{version}",
            file_path=str(manifest_path),
            evidence_kind="static-analysis",
            finding_class="weakness",
            confidence=1.0,
            status="unconfirmed",
            verdict=0,
            extra={"npm_lifecycle": phase, "npm_script": cmd[:300]},
        ))
    return out


def audit_root(root: Path) -> tuple[list[dict], dict]:
    """Audit pohon proyek: package.json akar + node_modules/**/package.json.

    Fail-closed: akar tidak ada / root manifest tidak valid -> ValueError.
    Manifest anak yang tidak terbaca dihitung di meta (bukan diam-diam).
    """
    if not root.is_dir():
        raise ValueError(f"root bukan direktori: {root}")
    meta: dict = {
        "requests": 0,
        "root": str(root),
        "manifests_scanned": 0,
        "manifests_unreadable": [],
        "packages_without_lifecycle": 0,
        "high_risk": 0,
    }
    manifest_paths: list[Path] = []
    root_manifest = root / "package.json"
    if not root_manifest.is_file():
        raise ValueError(f"package.json tidak ada di root: {root}")
    manifest_paths.append(root_manifest)
    node_modules = root / "node_modules"
    if node_modules.is_dir():
        manifest_paths.extend(sorted(node_modules.glob("*/package.json")))
        manifest_paths.extend(sorted(node_modules.glob("@*/*/package.json")))
        # nested node_modules (dependency punya dependency sendiri)
        manifest_paths.extend(
            sorted(p for p in node_modules.glob("*/node_modules/*/"
                                                 "package.json")))
        manifest_paths.extend(
            sorted(p for p in node_modules.glob("@*/*/node_modules/*/"
                                                 "package.json")))
    findings: list[dict] = []
    for mpath in manifest_paths:
        doc, errs = load_manifest(mpath)
        if errs:
            meta["manifests_unreadable"].extend(errs)
            continue
        meta["manifests_scanned"] += 1
        name = str(doc.get("name") or mpath.parent.name)
        f = manifest_findings(mpath, doc, name)
        if f:
            findings.extend(f)
        else:
            meta["packages_without_lifecycle"] += 1
    meta["high_risk"] = sum(1 for x in findings if x["severity"] == "high")
    return findings, meta


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="npm_script_audit — audit lifecycle-script npm lokal "
                    "(read-only; NOL request; lead L0 OBSERVED).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--root", help="direktori proyek (package.json + node_modules)")
    src.add_argument("--manifest", help="satu file package.json saja")
    ap.add_argument("--out", required=True, help="path findings.json output")
    args = ap.parse_args(argv)
    try:
        if args.manifest:
            p = Path(args.manifest)
            if not p.is_file():
                raise ValueError(f"manifest tidak ada: {p}")
            doc, errs = load_manifest(p)
            if errs:
                raise ValueError(errs[0])
            meta: dict = {"requests": 0, "root": str(p),
                          "manifests_scanned": 1,
                          "manifests_unreadable": [],
                          "packages_without_lifecycle": 0, "high_risk": 0}
            findings = manifest_findings(p, doc, str(doc.get("name") or p.stem))
            meta["high_risk"] = sum(1 for x in findings
                                    if x["severity"] == "high")
        else:
            findings, meta = audit_root(Path(args.root))
    except ValueError as exc:
        print(f"[npm-script-audit] ditolak: {exc}", file=sys.stderr)
        return 2
    write_findings(args.out, findings, meta=meta)
    print(f"[npm-script-audit] manifests={meta['manifests_scanned']} "
          f"-> findings={len(findings)} "
          f"(high-risk {meta['high_risk']}, tanpa-lifecycle "
          f"{meta['packages_without_lifecycle']}, "
          f"tidak-terbaca {len(meta['manifests_unreadable'])})")
    if meta["manifests_unreadable"]:
        for err in meta["manifests_unreadable"]:
            print(f"[npm-script-audit] unreadable: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
