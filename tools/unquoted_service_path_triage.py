"""[SAFETY: read-only] unquoted_service_path_triage — wave-3 Windows:
deteksi OFFLINE service path TIDAK TERKUTIP yang mengandung spasi
(T1574.009 Unquoted Path — privesc/lateral klasik): Windows mencoba
kandidat exe per-token sebelum path lengkap, jadi binary yang ditanam
di satu token direktori teratas dieksekusi saat service start.

Format input yang didukung (deteksi otomatis):
  - JSON array / object service  : field ImagePath / BinaryPathName +
                                   (opsional) Name/ServiceName
  - NDJSON                       : satu object JSON per baris
  - teks dump                    : baris `KEY : value` / `KEY = value`
                                   (sc qc: BINARY_PATH_NAME; ekspor
                                   .reg/.txt: ImagePath/BinaryPathName)
Sinyal:
  - unquoted-space   : path tanpa kutip pembuka DAN mengandung spasi
                       (kandidat exe per-token dihitung deterministik,
                       maks --max-chain entri)
  - expandable-path  : path memakai variabel %...% ber-spasi (tidak
                       eksploitabel langsung — info, bukan temuan)
Severity: unquoted-space = medium (offline tidak bisa memverifikasi
writability direktori — LIMITASI JUJUR; konfirmasi dengan icacls di
host). Path terkutip / tanpa spasi = zero-FP (bukan temuan).

Fail-closed: tidak ada entri service terparse -> exit 2.

Referensi konsep: entri "Unquoted service paths without PowerUp"
(A-poc/RedTeam-Tools) — kode dibangun from scratch.

Pemakaian:
  python tools/unquoted_service_path_triage.py --file svc.json --out f.json
  python tools/unquoted_service_path_triage.py --file scqc.txt
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.unquoted-service-path-triage/1"

_NAME_KEYS = ("name", "servicename", "service_name", "service",
              "displayname")
_PATH_KEYS = ("imagepath", "binarypathname", "binary_path_name",
              "pathname")
_TEXT_LINE = re.compile(
    r"^\s*\"?([A-Za-z_][A-Za-z0-9_ ]*?)\"?\s*[:=]\s*(.+?)\s*$")
_MAX_CHAIN_DEFAULT = 6


def _find_field(obj: dict, keys: tuple[str, ...]) -> str:
    for k in obj:
        if k.lower().replace("-", "_") in keys:
            v = obj[k]
            if isinstance(v, str):
                return v
    return ""


def _parse_services(text: str) -> list[dict]:
    """Kembalikan [{name, path}] dari JSON/NDJSON/teks."""
    out: list[dict] = []
    stripped = text.strip()
    # 1) JSON utuh (array atau object)
    if stripped.startswith(("[", "{")):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, list):
            for e in doc:
                if isinstance(e, dict):
                    out.append({"name": _find_field(e, _NAME_KEYS),
                                "path": _find_field(e, _PATH_KEYS)})
            return out
        if isinstance(doc, dict):
            if isinstance(doc.get("services"), list):
                for e in doc["services"]:
                    if isinstance(e, dict):
                        out.append({"name": _find_field(e, _NAME_KEYS),
                                    "path": _find_field(e, _PATH_KEYS)})
                return out
            out.append({"name": _find_field(doc, _NAME_KEYS),
                        "path": _find_field(doc, _PATH_KEYS)})
            return out
    # 2) NDJSON
    nd = 0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                out.append({"name": _find_field(e, _NAME_KEYS),
                            "path": _find_field(e, _PATH_KEYS)})
                nd += 1
    if nd:
        return out
    # 3) teks key:value — kumpulkan berpasangan nama/path berurutan
    cur: dict = {}
    for line in text.splitlines():
        m = _TEXT_LINE.match(line)
        if not m:
            continue
        key = m.group(1).lower().replace("-", "_").replace(" ", "_")
        val = m.group(2).strip().strip('"')
        if key in _PATH_KEYS:
            cur["path"] = val
            cur["name"] = cur.get("name", "")
            out.append(cur)
            cur = {}
        elif key in _NAME_KEYS:
            cur["name"] = val
    return out


def _exe_chain(path: str, max_chain: int) -> list[str]:
    """Kandidat exe yang dicoba Windows utk path unquoted (urut) —
    berhenti di token yang berakhiran .exe (exe asli; sisanya argumen).
    Kosong = exe token pertama langsung resolve (tidak eksploitabel)."""
    parts = path.split()
    chain: list[str] = []
    for i in range(1, len(parts) + 1):
        cand = " ".join(parts[:i])
        if cand.lower().endswith(".exe"):
            break
        chain.append(cand + ".exe")
        if len(chain) >= max_chain:
            break
    return chain


def audit_service(entry: dict, max_chain: int) -> dict | None:
    path = entry.get("path") or ""
    if not path or not path.strip():
        return None
    quoted = path.lstrip().startswith('"') and '"' in path[1:]
    if quoted:
        return None
    if "%" in path:
        # variabel lingkungan belum diekspansi — keputusan butuh nilai
        # runtime; bukan temuan unquoted murni.
        if " " in path:
            return {"name": entry.get("name") or "", "path": path[:200],
                    "signal": "expandable-path", "severity": "info",
                    "chain": []}
        return None
    if " " not in path:
        return None
    chain = _exe_chain(path.strip(), max_chain)
    if not chain:
        # token pertama langsung berakhir .exe (mis. svchost.exe -k
        # netsvcs): spasi hanya di argumen — tidak eksploitabel.
        return None
    return {"name": entry.get("name") or "", "path": path[:200],
            "signal": "unquoted-space", "severity": "medium",
            "chain": chain}


def triage_text(text: str, max_chain: int = _MAX_CHAIN_DEFAULT) -> dict:
    services = _parse_services(text)
    services = [s for s in services if s.get("path")]
    if not services:
        raise ValueError("tidak ada entri service terparse dari input")
    results = []
    for i, s in enumerate(services):
        res = audit_service(s, max_chain)
        if res is None:
            continue
        res["index"] = i
        results.append(res)
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        counts[r["severity"]] += 1
    findings = [r for r in results if r["signal"] == "unquoted-space"]
    return {
        "schema": SCHEMA,
        "services": len(services),
        "severity_counts": counts,
        "finding_count": len(findings),
        "findings": findings,
        "info_count": counts["info"],
        "clean_count": len(services) - len(results),
        "note": "offline: writability direktori TIDAK diverifikasi — "
                "unquoted-space = lead medium (T1574.009); konfirmasi "
                "dengan icacls/accesschk di host",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True,
                    help="dump service (JSON/NDJSON/teks sc qc/.reg)")
    ap.add_argument("--max-chain", type=int, default=_MAX_CHAIN_DEFAULT,
                    help="batas kandidat exe per temuan (default 6)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        result = triage_text(text, max_chain=args.max_chain)
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
