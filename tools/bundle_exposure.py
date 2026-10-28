"""[F49+F50] Bundle exposure audit — "apa yang akan dilihat reverse-
engineer di bundle kamu" (sisi defensif dari kelas tool RE seperti
rea; CLEAN-ROOM, NOL jaringan, read-only).

Input: satu file (--file) atau POHON bundle (--dir: hasil build klien,
Electron asar unpack, apk assets, dist/). Output: permukaan yang TER
ekspos secara statis:
  - URL absolut (https?://...) -> inventaris L0;
  - path API literal ("/api/...", "/v2/...", "/auth/...") -> L0;
  - string ber-bentuk secret (sk_live_, AKIA, ghp_, xoxb, AIza) dan
    variabel bernama secret/api-key/password dgn nilai literal -> L1
    lead (verifikasi manual: bisa placeholder);
  - flag debug/admin di kode klien -> L1 (CWE-489);
  - FILE .map (sourcemap) yang ikut ter-deploy -> L1 (CWE-540): source
    asli pra-minify + komentar terekspos; isinya ikut diaudit.
Semua signature KETAT (zero-FP). Temuan lintas-file DI-DEDUP (satu
baris per fakta unik, daftar file di extra.files). Kode klien TIDAK
bisa disembunyikan dari analisis statis — nilai alat ini menunjukkan
paparan SEBELUM orang lain melihatnya.

Pemakaian:
  python tools/bundle_exposure.py --file app.bundle.js --out f.json
  python tools/bundle_exposure.py --dir dist/ --out f.json
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

MAX_FILE_BYTES = 4_000_000
MAX_FILES = 2000
MAX_ROWS_PER_CLASS = 25
SCAN_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json",
            ".map", ".py", ".html"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             "target"}

_RE_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{6,180}")
_RE_API_PATH = re.compile(
    r"[\"'`](?:/[A-Za-z0-9._{}?=&-]+)*/"
    r"(?:api|v[0-9]+|auth|admin|internal)"
    r"(?:/[A-Za-z0-9._{}?=&-]+)*[\"'`]", re.I)
_RE_SECRET = re.compile(
    r"\b(sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|"
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|"
    r"xox[bap]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})")
_RE_SECRET_VAR = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[\"']"
    r"([^\"']{12,120})[\"']\s*;", re.I)
_RE_SECRET_NAME = re.compile(
    r"\b(secret|apikey|api_key|password|passwd|token|privatekey|"
    r"private_key)s?\b", re.I)
_RE_DEBUG_FLAG = re.compile(
    r"\b(?:const|let|var)\s+(is[A-Z]\w*(?:Admin|Debug|Backdoor)\w*|"
    r"(?:adminMode|debugMode|backdoor)\w*)\s*=\s*(true|1)\b")


def _lead(rel: str, title: str, desc: str, cwe: str | None,
          extra: dict) -> dict:
    return make_finding(
        tool="bundle-exposure", title=title, severity="medium",
        description=desc,
        recommendation="Pindahkan ke server-side / karantina / rotasi "
                       "bila nyata; kode klien tidak bisa dirahasiakan "
                       "dari analisis statis.",
        cwe=cwe, target_url=f"bundle:{rel}",
        evidence_kind="file-manifest", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1,
        extra={"category": "EXPOSURE", **extra})


def _scan_text(text: str) -> dict:
    """Signature ketat atas satu konten -> fakta terpisah per kelas."""
    return {
        "urls": sorted({m.group(0).rstrip(".,;")
                        for m in _RE_URL.finditer(text)}),
        "api_paths": sorted({m.group(0).strip("\"'`")
                             for m in _RE_API_PATH.finditer(text)}),
        "secrets": sorted({m.group(0) for m in _RE_SECRET.finditer(text)}),
        "secret_vars": [(m.group(1), m.group(2))
                        for m in _RE_SECRET_VAR.finditer(text)
                        if _RE_SECRET_NAME.search(m.group(1))],
        "flags": sorted({m.group(1)
                         for m in _RE_DEBUG_FLAG.finditer(text)}),
    }


def _rows_from_facts(rel: str, facts: dict) -> list[dict]:
    rows: list[dict] = []

    def _inv(title, desc, kind, items):
        rows.append(make_finding(
            tool="bundle-exposure", title=title, severity="info",
            description=desc, recommendation="", cwe=None,
            target_url=f"bundle:{rel}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "kind": kind,
                   "items": items[:MAX_ROWS_PER_CLASS]}))

    if facts["urls"]:
        _inv(f"{len(facts['urls'])} URL absolut ter-ekspos di bundle",
             "URL tertanam literal (server/API pihak ketiga) — terbaca "
             "siapa pun yang memegang bundle: "
             + ", ".join(facts["urls"][:8])
             + ("…" if len(facts["urls"]) > 8 else ""),
             "urls", facts["urls"])
    if facts["api_paths"]:
        _inv(f"{len(facts['api_paths'])} path API literal ter-ekspos",
             "Endpoint tertanam literal di kode klien (peta API bisa "
             "dibangun dari sini): "
             + ", ".join(facts["api_paths"][:10])
             + ("…" if len(facts["api_paths"]) > 10 else ""),
             "api_paths", facts["api_paths"])
    for s in facts["secrets"][:MAX_ROWS_PER_CLASS]:
        rows.append(_lead(
            rel, "Kandidat secret ber-format layanan di bundle",
            f"String cocok format kunci layanan ({s[:8]}…) — verifikasi "
            "manual: nyata atau placeholder.",
            "CWE-798", {"kind": "secret-literal",
                        "preview": s[:8] + "…"}))
    for name, val in facts["secret_vars"][:MAX_ROWS_PER_CLASS]:
        rows.append(_lead(
            rel, f"Variabel '{name}' bernilai literal ter-ekspos",
            f"Variabel yang dinamai secret/api-key/password diisi nilai "
            f"literal ({val[:6]}…) — nama + nilai sama-sama terbaca.",
            "CWE-798", {"kind": "secret-var", "var": name,
                        "preview": val[:6] + "…"}))
    if facts["flags"]:
        rows.append(_lead(
            rel, f"Flag debug/admin aktif di kode klien: "
                 f"{', '.join(facts['flags'])}",
            "Flag bernama admin/debug/backdoor bernilai true — jalur "
            "istimewa yang bisa diaktifkan siapa pun.",
            "CWE-489", {"kind": "debug-flag", "flags": facts["flags"]}))
    return rows


def audit_bundle(path: Path) -> tuple[list[dict], dict]:
    """Satu file -> (rows, meta) kontrak (kompatibel F49)."""
    if not path.is_file():
        return [], {"error": f"file tidak ada: {path}"}
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], {"error": f"file terlalu besar (> {MAX_FILE_BYTES}B)"}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], {"error": repr(exc)[:120]}
    facts = _scan_text(text)
    rows = _rows_from_facts(path.name, facts)
    if not rows:
        rows.append(make_finding(
            tool="bundle-exposure",
            title="Tidak ada permukaan ter-ekspos yang cocok signature",
            severity="info",
            description=f"{path.name}: tanpa URL absolut, path API "
                        "literal, kandidat secret ber-format, atau flag "
                        "debug — (AMAN/inventaris, signature ketat).",
            target_url=f"bundle:{path.name}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    meta = {**{k: len(v) if isinstance(v, list) else v
               for k, v in facts.items()},
            "exposures": sum(1 for r in rows
                             if r.get("category") == "EXPOSURE")}
    return rows, meta


def _iter_bundle_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if Path(fn).suffix in SCAN_EXT:
                files.append(Path(dirpath) / fn)
                if len(files) >= MAX_FILES:
                    return files
    return files


def _dedup(rows: list[dict]) -> list[dict]:
    """Temuan lintas-file digabung: satu baris per (kind, identitas),
    daftar file di extra.files; inventaris SURFACE digabung per kind
    (item bounded 50)."""
    leads: dict[tuple, dict] = {}
    surface: dict[str, dict] = {}
    order: list[dict] = []
    for r in rows:
        cat = r.get("category")
        rel = str(r.get("target_url", "")).removeprefix("bundle:")
        if cat == "EXPOSURE":
            key = (r.get("kind"), r.get("preview"), r.get("var"),
                   tuple(r.get("flags") or []), r["title"])
            if key not in leads:
                r = dict(r)
                r["files"] = [rel]
                leads[key] = r
                order.append(r)
            elif rel not in leads[key]["files"]:
                leads[key]["files"].append(rel)
        elif cat == "SURFACE":
            kind = r.get("kind")
            if kind not in surface:
                r = dict(r)
                r["items"] = list(r.get("items") or [])
                r["files"] = [rel]
                surface[kind] = r
                order.append(r)
            else:
                acc = surface[kind]
                for item in (r.get("items") or []):
                    if item not in acc["items"]:
                        acc["items"].append(item)
                if rel not in acc["files"]:
                    acc["files"].append(rel)
    for acc in surface.values():
        acc["items"] = acc["items"][:50]
    return order


def audit_tree(root: Path, restore_dir: Path | None = None
               ) -> tuple[list[dict], dict]:
    """Pohon bundle -> (rows, meta): per-file scan + lead sourcemap
    (.map ber-sourcesContent = source asli terekspos, isinya ikut
    diaudit; bila restore_dir diisi, source asli DITULIS ke folder
    audit = artefak fisik yang bisa direcover attacker — path
    traversal di entri sources DITOLAK, disiplin lfi) + dedup
    lintas-file. Fail-closed: root tidak ada."""
    if not root.is_dir():
        return [], {"error": f"folder tidak ada: {root}"}
    files = _iter_bundle_files(root)
    truncated = len(files) >= MAX_FILES
    all_rows: list[dict] = []
    files_with_facts = 0
    sourcemaps = 0
    restored = 0
    restore_blocked = 0
    for f in files:
        rel = f.relative_to(root).as_posix()
        try:
            if f.stat().st_size > MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        facts = _scan_text(text)
        has_content = any(facts.values())
        if f.suffix == ".map":
            try:
                doc = json.loads(text)
            except Exception:  # noqa: BLE001
                doc = None
            if isinstance(doc, dict) and doc.get("sourcesContent"):
                sourcemaps += 1
                has_content = True
                all_rows.append(_lead(
                    rel, "Sourcemap (.map) ikut ter-deploy",
                    "Sourcemap membawa sourcesContent — source ASLI "
                    "pra-minify (nama variabel, komentar, struktur) "
                    "terekspos. Isinya ikut diaudit.",
                    "CWE-540", {"kind": "sourcemap",
                                "sources": len(doc["sourcesContent"])}))
                if restore_dir is not None:
                    base = (restore_dir / rel).with_suffix("")
                    names = doc.get("sources") or []
                    for i, src in enumerate(doc["sourcesContent"][:10]):
                        if not isinstance(src, str):
                            continue
                        # anti-traversal (disiplin lfi): entri sources
                        # yang membawa "..", drive, atau path absolut
                        # DITOLAK — tidak pernah keluar dari base
                        name = (names[i] if i < len(names)
                                else f"source_{i}").replace("\\", "/")
                        raw_parts = [p for p in name.split("/") if p]
                        parts = [p for p in raw_parts
                                 if p not in (".", "..")
                                 and ":" not in p]
                        if not parts or len(parts) != len(raw_parts):
                            restore_blocked += 1
                            continue
                        dst = base.joinpath(*parts)
                        if not dst.resolve().is_relative_to(
                                base.resolve()):
                            restore_blocked += 1
                            continue
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_text(src, encoding="utf-8")
                        restored += 1
                for i, src in enumerate(doc["sourcesContent"][:10]):
                    if isinstance(src, str):
                        sub = _scan_text(src)
                        if any(sub.values()):
                            files_with_facts += 1
                        all_rows.extend(
                            _rows_from_facts(f"{rel}#sources[{i}]", sub))
                continue
        if has_content:
            files_with_facts += 1
            all_rows.extend(_rows_from_facts(rel, facts))
    rows = _dedup(all_rows)
    if not rows:
        rows.append(make_finding(
            tool="bundle-exposure",
            title="Tidak ada permukaan ter-ekspos yang cocok signature",
            severity="info",
            description=f"{len(files)} file diperiksa (batas "
                        f"{MAX_FILES}) — tanpa URL absolut, path API "
                        "literal, kandidat secret ber-format, flag "
                        "debug, atau sourcemap ter-deploy "
                        "(AMAN/inventaris, signature ketat).",
            target_url=f"bundle:{root.name}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    exposures = sum(1 for r in rows if r.get("category") == "EXPOSURE")
    meta = {"root": str(root), "files_found": len(files),
            "truncated": truncated, "files_with_facts": files_with_facts,
            "sourcemaps": sourcemaps, "exposures": exposures,
            "restored": restored, "restore_blocked": restore_blocked}
    return rows, meta


# ---------- F52: arsip kemasan (asar Electron + APK/zip) ----------

def _scan_entry(name: str, data: bytes) -> list[dict]:
    """Satu entri arsip -> rows (provenance <arsip>#<entry>). Entri
    .map ber-sourcesContent = lead sourcemap; entri binary-class
    (dex/so/bin) lewat strings surface."""
    text_ext = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json",
                ".map", ".html", ".xml", ".py"}
    bin_ext = {".dex", ".so", ".bin", ".dat", ".dll", ".exe"}
    suffix = Path(name).suffix.lower()
    rel = name
    rows: list[dict] = []
    if suffix == ".map":
        try:
            doc = json.loads(data.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            doc = None
        if isinstance(doc, dict) and doc.get("sourcesContent"):
            rows.append(_lead(
                rel, "Sourcemap (.map) ikut ter-kemas di arsip",
                "Sourcemap membawa sourcesContent — source ASLI pra-"
                "minify terekspos di dalam arsip. Isinya ikut diaudit.",
                "CWE-540", {"kind": "sourcemap",
                            "sources": len(doc["sourcesContent"])}))
            for i, src in enumerate(doc["sourcesContent"][:10]):
                if isinstance(src, str):
                    rows.extend(_rows_from_facts(
                        f"{rel}#sources[{i}]", _scan_text(src)))
            return rows
    if suffix in bin_ext:
        import binary_strings_surface as bs
        tmp = Path(rel.replace("/", "_"))
        try:
            tmp.write_bytes(data)
            sub_rows, _ = bs.audit_binary(tmp)
        finally:
            tmp.unlink(missing_ok=True)
        for r in sub_rows:
            r = dict(r)
            r["target_url"] = f"bundle:{rel}"
            rows.append(r)
        return rows
    if suffix in text_ext:
        rows.extend(_rows_from_facts(
            rel, _scan_text(data.decode("utf-8", errors="replace"))))
    return rows


def _asar_parse(data: bytes) -> tuple[dict, int] | None:
    """Parse header asar (chromium pickle — layout disk asli:
    [0]=4, [4]=header_buf_len, [8]=4, [12]=json_len, [16..]=json,
    files mulai 8+header_buf_len). Return (header_doc, files_base)
    atau None (fail-closed)."""
    import struct
    if len(data) < 16:
        return None
    a, header_buf_len, b, json_size = struct.unpack_from("<IIII", data, 0)
    if a != 4 or b != 4 or json_size == 0:
        return None
    # header_buf = [4][4][json][pad4] -> len = 8 + json + pad (0..3)
    if not (8 + json_size <= header_buf_len <= 12 + json_size):
        return None
    if 16 + json_size > len(data):
        return None
    blob = data[16:16 + json_size]
    try:
        doc = json.loads(blob.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(doc, dict) or "files" not in doc:
        return None
    return doc, 8 + header_buf_len


def _asar_walk(node: dict, prefix: str, files_base: int, data: bytes):
    """Yield (entry_name, bytes) dari pohon header asar (bounded)."""
    stack = [(prefix, node)]
    seen = 0
    while stack:
        pre, children = stack.pop()
        for name, meta in (children.get("files") or {}).items():
            seen += 1
            if seen > MAX_FILES:
                return
            entry = f"{pre}/{name}" if pre else name
            if "files" in meta:
                stack.append((entry, meta))
            elif "offset" in meta and "size" in meta:
                try:
                    off = files_base + int(meta["offset"])
                    size = int(meta["size"])
                except (TypeError, ValueError):
                    continue
                if 0 < size <= MAX_FILE_BYTES and off >= 0:
                    yield entry, data[off:off + size]


def audit_archive(path: Path) -> tuple[list[dict], dict]:
    """Arsip kemasan (asar / apk / zip) -> (rows, meta): tiap entri
    teks + sourcemap + dex/so di-scan dgn signature yang sama,
    provenance <arsip>#<entry>, dedup lintas-entri. Fail-closed."""
    if not path.is_file():
        return [], {"error": f"file tidak ada: {path}"}
    suffix = path.suffix.lower()
    all_rows: list[dict] = []
    entries_scanned = 0
    try:
        if suffix == ".asar":
            data = path.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                return [], {"error": "asar terlalu besar"}
            parsed = _asar_parse(data)
            if parsed is None:
                return [], {"error": "header asar tidak dapat diurai "
                                     "(fail-closed)"}
            doc, files_base = parsed
            for entry, blob in _asar_walk(doc, "", files_base, data):
                entries_scanned += 1
                all_rows.extend(_scan_entry(entry, blob))
        elif suffix in (".apk", ".zip"):
            import zipfile
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:MAX_FILES]:
                    if info.is_dir():
                        continue
                    entries_scanned += 1
                    all_rows.extend(_scan_entry(
                        info.filename, zf.read(info.filename)))
        elif suffix == ".crx":
            # CRX3 (Chrome extension): magic Cr24 + versi + panjang
            # header (protobuf) + ZIP payload. Fail-closed bila ZIP
            # tidak ditemukan di offset yang dihitung.
            import io
            import zipfile
            data = path.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                return [], {"error": "crx terlalu besar"}
            if data[:4] != b"Cr24":
                return [], {"error": "magic Cr24 tidak ditemukan "
                                     "(fail-closed)"}
            version = int.from_bytes(data[4:8], "little")
            header_len = int.from_bytes(data[8:12], "little")
            zip_start = 12 + header_len
            if (version not in (2, 3) or zip_start + 4 > len(data)
                    or data[zip_start:zip_start + 2] != b"PK"):
                return [], {"error": "offset ZIP CRX tidak valid "
                                     "(fail-closed)"}
            with zipfile.ZipFile(io.BytesIO(data[zip_start:])) as zf:
                for info in zf.infolist()[:MAX_FILES]:
                    if info.is_dir():
                        continue
                    entries_scanned += 1
                    all_rows.extend(_scan_entry(
                        info.filename, zf.read(info.filename)))
        else:
            return [], {"error": f"format arsip tidak didukung: {suffix}"}
    except (zipfile.BadZipFile, OSError) as exc:
        return [], {"error": repr(exc)[:160]}
    rows = _dedup(all_rows)
    if not rows:
        rows.append(make_finding(
            tool="bundle-exposure",
            title="Tidak ada permukaan ter-ekspos di arsip",
            severity="info",
            description=f"{entries_scanned} entri diperiksa — tanpa URL "
                        "absolut, path API literal, kandidat secret, "
                        "flag debug, atau sourcemap (AMAN/inventaris).",
            target_url=f"bundle:{path.name}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    meta = {"file": str(path), "entries_scanned": entries_scanned,
            "exposures": sum(1 for r in rows
                             if r.get("category") == "EXPOSURE")}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="satu file bundle")
    group.add_argument("--dir", help="folder bundle (walk, bounded)")
    ap.add_argument("--restore", default=None,
                    help="folder utk MENULIS source asli hasil restore "
                         "sourcemap (artefak 'yang bisa direcover "
                         "attacker'); anti-traversal aktif")
    ap.add_argument("--out", default="findings/bundle-exposure.json")
    args = ap.parse_args()

    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"file tidak ada: {p} (fail-closed)", file=sys.stderr)
            return 2
        if p.suffix.lower() in (".asar", ".apk", ".zip", ".crx"):
            rows, meta = audit_archive(p)
        else:
            rows, meta = audit_bundle(p)
    else:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"folder tidak ada: {d} (fail-closed)", file=sys.stderr)
            return 2
        rows, meta = audit_tree(
            d, restore_dir=Path(args.restore) if args.restore else None)
    write_findings(args.out, rows,
                   {**meta, "run": "bundle-exposure",
                    "safety_class": "read-only", "requests": 0})
    print(f"bundle-exposure: exposures={meta.get('exposures')} "
          f"restored={meta.get('restored', 0)} "
          f"({meta.get('file') or meta.get('root')}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
