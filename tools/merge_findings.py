"""Gabung beberapa findings.json menjadi SATU findings.json (satu pintu).

[rapikan] Sejak dedup lintas-mode, SEMANTIK dedup ada DUA implementasi
setara (tools ini + `cyphron merge --dedup-id`). Tool ini kini THIN
WRAPPER: delegasikan merge+dedup ke binary `cyphron merge` (satu
implementasi), lalu normalkan meta balik ke bentuk kontrak tool ini
(run label, sources [{file,findings,meta}], requests jumlahan) agar
konsumen lama (report_pdf dkk.) tidak berubah.

Fallback python murni dipertahankan UTUH untuk kondisi binary tidak
ada (mis. export OSS tanpa build). Bila binary ADA tetapi gagal
(input kontrak-invalid) → error keras exit 1: fail-closed, TIDAK
diam-diam turun ke jalur tanpa validasi.

Pemakaian (flag lama dipertahankan):
  python tools/merge_findings.py --out findings/t/findings.json \
      findings/t/a.json findings/t/b.json [--run label] [--dedup-id]

Env: CYPHRON_EXE = path binary (default core-rs/target/release/cyphron).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from atomic import atomic_write_text  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def resolve_exe() -> Path | None:
    env = os.environ.get("CYPHRON_EXE")
    if env:
        p = Path(env)
        return p if p.exists() else None
    exe = "cyphron.exe" if sys.platform == "win32" else "cyphron"
    p = ROOT / "core-rs" / "target" / "release" / exe
    return p if p.exists() else None


def load_sources(inputs: list[str]) -> tuple[list[dict], list[Path]]:
    """Baca input yang valid (ada + ok=true) — meta sumber dihitung di
    sini supaya meta output identik di jalur binary maupun python."""
    sources: list[dict] = []
    usable: list[Path] = []
    for inp in inputs:
        p = Path(inp)
        if not p.exists():
            print(f"SKIP (tidak ada): {p}")
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        if not doc.get("ok"):
            print(f"SKIP (ok=false): {p}")
            continue
        n = len(doc.get("findings", []))
        sources.append({"file": str(p), "findings": n,
                        "meta": doc.get("data", {})})
        usable.append(p)
        print(f"+ {p} ({n} findings)")
    return sources, usable


def merge_via_binary(exe: Path, usable: list[Path], dedup_id: bool
                     ) -> list[dict] | None:
    """Delegasi ke `cyphron merge` (validasi kontrak + dedup dedup_by_id).
    Return daftar findings gabungan, None bila binary gagal (caller
    memutuskan: fallback hanya bila binary tidak ada)."""
    with tempfile.TemporaryDirectory(prefix="cyphron-merge_") as td:
        tmp_out = Path(td) / "merged.json"
        argv = [str(exe), "merge", "--out", str(tmp_out)]
        if dedup_id:
            argv.append("--dedup-id")
        argv += [str(p) for p in usable]
        r = subprocess.run(argv, capture_output=True, text=True,
                           cwd=str(ROOT), timeout=600)
        if r.returncode != 0 or not tmp_out.exists():
            print(f"ERROR: cyphron merge gagal (rc={r.returncode}): "
                  f"{(r.stderr or r.stdout)[-400:]}", file=sys.stderr)
            return None
        doc = json.loads(tmp_out.read_text(encoding="utf-8"))
        return doc.get("findings", [])


def merge_pure_python(usable: list[Path], dedup_id: bool) -> tuple[list[dict], int]:
    """Jalur fallback tanpa binary: gabung + dedup id (semantik FAO)."""
    merged: list[dict] = []
    seen: dict[str, int] = {}
    dups = 0
    for p in usable:
        doc = json.loads(p.read_text(encoding="utf-8"))
        for f in doc.get("findings", []):
            fid = f.get("id")
            if dedup_id and fid and fid in seen:
                dups += 1
                merged[seen[fid]]["dup_count"] = (
                    merged[seen[fid]].get("dup_count", 1) + 1)
                continue
            if dedup_id and fid:
                seen[fid] = len(merged)
            merged.append(f)
    return merged, dups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("inputs", nargs="+", help="file findings.json input")
    ap.add_argument("--out", required=True)
    ap.add_argument("--run", default="tier0-run",
                    help="label run tersimpan di meta")
    ap.add_argument("--dedup-id", action="store_true",
                    help="buang temuan ber-id identik (id = sha tool|title|"
                         "target|file|param) — semantik dedup FAO; baris "
                         "pertama dipertahankan + dup_count dicatat")
    args = ap.parse_args()

    sources, usable = load_sources(args.inputs)
    if not usable:
        print("tidak ada input valid — tidak ada yang di-merge", file=sys.stderr)
        return 2

    dedup_dropped: int | None = None
    exe = resolve_exe()
    if exe is not None:
        findings = merge_via_binary(exe, usable, args.dedup_id)
        if findings is None:
            return 1  # binary ada tapi gagal — fail-closed, bukan fallback senyap
        if args.dedup_id:
            # meta dedup dihitung ulang dari baris (dup_count) supaya
            # meta identik dengan jalur python tanpa pass tambahan
            dedup_dropped = sum(
                int(f.get("dup_count", 1)) - 1 for f in findings
                if f.get("dup_count"))
    else:
        findings, dedup_dropped = merge_pure_python(usable, args.dedup_id)
        if not args.dedup_id:
            dedup_dropped = None

    out_doc = {
        "ok": True,
        "data": {
            "run": args.run,
            "sources": sources,
            "total_findings": len(findings),
            **({"dedup": {"duplicates_dropped": dedup_dropped}}
               if args.dedup_id else {}),
        },
        "findings": findings,
        "requests": int(sum(s["meta"].get("requests", 0) for s in sources)),
    }
    p = Path(args.out)
    # atomic write: pembaca tidak pernah melihat setengah file saat
    # merge besar atau proses mati di tengah tulis
    atomic_write_text(p, json.dumps(out_doc, indent=2, ensure_ascii=False))
    dup_note = (f" (dedup: {dedup_dropped} duplikat dibuang)"
                if args.dedup_id else "")
    engine = "cyphron merge" if exe is not None else "python murni"
    print(f"merged: {len(findings)} findings{dup_note} -> {p} [{engine}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
