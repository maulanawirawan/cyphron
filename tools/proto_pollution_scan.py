"""[SAFETY: read-only, NOL jaringan] proto_pollution_scan — pencari gadget
prototype-pollution STATIK pada sumber JavaScript (CWE-1321).

Konsep prototype pollution JS (penulisan ke __proto__/constructor.prototype,
recursive-merge tak-berpenjaga) — dibangun FROM SCRATCH, stdlib murni, TANPA
jaringan. Analisis TEKS-sumber (bukan eksekusi).

Ceruk vs modul lain (anti-duplikasi):
  - `js_endpoints` / `diff_risk_scan` = permukaan endpoint / diff risiko; tak
    menilai sink prototype-pollution. Tool ini khusus gadget __proto__.

"Kejar sampai verdict": penulisan eksplisit ke `__proto__[x]` /
`constructor.prototype[x]` / `obj[a][b] = ...` di dalam loop merge rekursif =>
L2 REPRODUCED `source` (fakta struktural di file:line). Penyebutan lebih lemah
(hanya membaca __proto__, atau merge dangkal) => L1 LEAD. Tidak ada => L0.

Input -> mekanisme -> output:
  - Input : --file (diulang) dan/atau --dir (rekursif) sumber .js/.ts/.mjs/.cjs.
  - Output: JSON {schema,tool,stats,notes,findings} satu-pintu; --out kontrak;
            --fail-on. Exit 0/1/2. Biner/oversize dilewati tercatat.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.proto-pollution-scan/1"
TOOL = "proto-pollution-scan"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILES = 2000
EXT = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# sink KUAT (penulisan): __proto__[..]= , constructor.prototype[..]= ,
# obj["__proto__"]= , Object.assign/merge recursive bracket write
_RE_STRONG = [
    ("proto-write-bracket",
     re.compile(r"""\[\s*['"]__proto__['"]\s*\]\s*(\[[^\]]+\])*\s*=""")),
    ("proto-write-dot", re.compile(r"\.__proto__\s*(\[[^\]]+\])*\s*=")),
    ("constructor-prototype-write",
     re.compile(r"\.constructor\s*\.\s*prototype\s*(\[[^\]]+\])*\s*=")),
    ("recursive-merge-bracket",
     re.compile(r"""(?:merge|extend|deepAssign|setValue|set)\s*\([^)]*\)[\s\S]{0,200}?\[[^\]]+\]\s*\[[^\]]+\]\s*=""")),
]
# kandidat LEMAH: menyebut __proto__ tanpa penulisan jelas, atau key dinamis
# obj[a][b] = tanpa penjaga __proto__/constructor
_RE_WEAK = [
    ("proto-mention", re.compile(r"__proto__")),
    ("dynamic-nested-assign", re.compile(r"\w+\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=")),
]
# penjaga yang MENIADAKAN risiko bila ada di dekat sink
_RE_GUARD = re.compile(
    r"(===?\s*['\"]__proto__['\"]|Object\.freeze|hasOwnProperty|"
    r"Object\.create\(null\)|Map\(|__proto__['\"]?\s*:\s*null|"
    r"key\s*===?\s*['\"]constructor['\"])")


def _lineno(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(name: str, text: str) -> list[dict]:
    findings: list[dict] = []
    guarded = bool(_RE_GUARD.search(text))
    seen: set[tuple] = set()
    for cls, rx in _RE_STRONG:
        for m in rx.finditer(text):
            ln = _lineno(text, m.start())
            key = (name, ln, cls)
            if key in seen:
                continue
            seen.add(key)
            snippet = text[m.start():m.start() + 120].splitlines()[0].strip()
            # penjaga di file menurunkan ke LEAD (bisa jadi sudah dimitigasi)
            if guarded:
                findings.append(make_finding(
                    tool=TOOL,
                    title="Prototype-pollution sink (guarded nearby) %s:%d" % (Path(name).name, ln),
                    severity="medium", cwe="CWE-1321",
                    description=("Write to %s at %s:%d, but a guard "
                                 "(__proto__ check / Object.create(null) / Map) "
                                 "exists in this file — verify it covers this sink."
                                 % (cls, Path(name).name, ln)),
                    recommendation="Confirm the guard protects THIS write path.",
                    file_path=name, line_start=ln, param="%s:%d:%s" % (name, ln, cls),
                    status="unconfirmed", verdict=1, evidence_kind="source",
                    confidence=0.6, poc=snippet, extra={"gadget": cls, "kind": "proto"}))
            else:
                findings.append(make_finding(
                    tool=TOOL,
                    title="Prototype-pollution sink %s:%d" % (Path(name).name, ln),
                    severity="high", cwe="CWE-1321",
                    description=("Unguarded write to %s at %s:%d — attacker-"
                                 "controlled keys can pollute Object.prototype."
                                 % (cls, Path(name).name, ln)),
                    recommendation=("Reject __proto__/constructor/prototype keys; "
                                    "use Map or Object.create(null); freeze prototypes."),
                    file_path=name, line_start=ln, param="%s:%d:%s" % (name, ln, cls),
                    status="confirmed", verdict=2, evidence_kind="source",
                    confidence=0.95, poc="%s:%d  %s" % (Path(name).name, ln, snippet),
                    extra={"gadget": cls, "kind": "proto"}))
    if not any(f for f in findings):  # tak ada sink kuat -> cek kandidat lemah
        for cls, rx in _RE_WEAK:
            for m in rx.finditer(text):
                ln = _lineno(text, m.start())
                key = (name, ln, cls)
                if key in seen:
                    continue
                seen.add(key)
                if cls == "proto-mention":
                    continue  # penyebutan saja: catat tapi jangan jadi temuan
                snippet = text[m.start():m.start() + 100].splitlines()[0].strip()
                findings.append(make_finding(
                    tool=TOOL,
                    title="Dynamic nested assignment (weak PP candidate) %s:%d" % (Path(name).name, ln),
                    severity="low", cwe="CWE-1321",
                    description=("Nested bracket assignment obj[a][b]= at %s:%d "
                                 "with no visible __proto__ guard — weak "
                                 "prototype-pollution candidate." % (Path(name).name, ln)),
                    recommendation="Validate keys against __proto__/constructor/prototype.",
                    file_path=name, line_start=ln, param="%s:%d:%s" % (name, ln, cls),
                    status="unconfirmed", verdict=1, evidence_kind="source",
                    confidence=0.4, poc=snippet, extra={"gadget": cls, "kind": "proto"}))
    return findings


def scan(files: list[tuple[str, str]]) -> dict:
    notes: list[str] = []
    findings: list[dict] = []
    scanned = 0
    for name, text in files:
        if "\x00" in text[:8192]:
            notes.append("biner dilewati: %s" % name)
            continue
        scanned += 1
        findings.extend(scan_text(name, text))
    if not findings:
        findings.append(make_finding(
            tool=TOOL, title="No prototype-pollution gadget found",
            severity="info",
            description="Scanned %d JS source file(s); no __proto__/prototype "
                        "write sinks (checked, nothing found)." % scanned,
            recommendation="Widen the source set to strengthen this negative.",
            param="summary", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.6, extra={"kind": "summary"}))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]],
                                 f.get("file_path") or "", f.get("line_start") or 0))
    stats = {"files": scanned, "findings": len(findings), "by_severity": {}}
    for f in findings:
        stats["by_severity"][f["severity"]] = stats["by_severity"].get(f["severity"], 0) + 1
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": notes,
            "findings": findings}


def _collect(paths: list[str], dirs: list[str]) -> list[tuple[str, str]]:
    files: list[Path] = []
    for p in paths:
        fp = Path(p)
        if not fp.is_file():
            raise ValueError("file tidak ada: %s" % fp)
        files.append(fp)
    for d in dirs:
        dp = Path(d)
        if not dp.is_dir():
            raise ValueError("direktori tidak ada: %s" % dp)
        files.extend(sorted(x for x in dp.rglob("*")
                            if x.is_file() and x.suffix.lower() in EXT
                            and x.stat().st_size <= MAX_FILE_BYTES))
    if len(files) > MAX_FILES:
        raise ValueError("terlalu banyak file (%d)" % len(files))
    if not files:
        raise ValueError("nol file sumber JS")
    return [(str(fp), fp.read_text(encoding="utf-8", errors="replace")) for fp in files]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Static prototype-pollution gadget finder for JS — offline.")
    ap.add_argument("--file", action="append", default=[])
    ap.add_argument("--dir", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    if not args.file and not args.dir:
        print("[proto-pollution-scan] input error: --file/--dir wajib", file=sys.stderr)
        return 2
    try:
        files = _collect(args.file, args.dir)
    except (OSError, ValueError) as exc:
        print("[proto-pollution-scan] input error: %s" % exc, file=sys.stderr)
        return 2
    result = scan(files)
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": result["notes"], "requests": 0})
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if any(f["severity"] != "info" for f in result["findings"]) else 0
    need = {"high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
