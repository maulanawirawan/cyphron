"""[F30] Code-map (fase 3 exploit tier) — attack-surface.json dari
source code repo target (docs/EXPLOIT-TIER.md).

Analisis STATIS read-only, NOL request, NOL eksekusi kode target:
  - routes      : Flask/FastAPI/Django (AST python) + express-style
                  JS/TS (regex) — method, path, file:line, auth flag
  - auth        : decorator/middleware autentikasi per route
  - uploads     : handler file upload (UploadFile/FileStorage/
                  request.FILES/multer)
  - admin       : panel admin (Django admin, blueprint "admin",
                  path /admin)
  - models      : definisi model/DB (models.Model, __tablename__,
                  mongoose.schema, prisma model)
  - secrets     : kandidat hardcode (regex konservatif; L-x kandidat,
                  bukan temuan — verifikasi manual)

Reconciler (--reconcile findings.json): petakan lead (target_url) ->
route di surface (path match) -> laporan JSON lead_id -> {route_file,
line, has_auth} untuk prioritisasi manual. findings.json TIDAK diubah.

Batas: skip .git/node_modules/venv/dist/build, maks --max-files file,
maks 256 KB/file. Bahasa v1: Python (AST), JS/TS + PHP-lite (regex).
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build",
             "__pycache__", "target", ".next", "vendor"}
MAX_FILE_BYTES = 262_144

PY_ROUTE_DECOS = re.compile(
    r"@?\w+\.(route|get|post|put|patch|delete|head|options)"
    r"\s*\(\s*[\"']([^\"']+)[\"']", re.S)
PY_METHODS_KW = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
PY_AUTH_DECOS = ("login_required", "permission_required", "auth_required",
                 "requires_auth", "jwt_required", "admin_required",
                 "is_admin", "staff_member_required", "api_view")
JS_ROUTE = re.compile(
    r"\b(?:app|router)\.(get|post|put|patch|delete|all|use)"
    r"\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", re.S)
JS_AUTH = re.compile(r"\b(auth|authMiddleware|requireAuth|isAuth|"
                     r"ensureLoggedIn|passport|jwt)\b", re.I)
UPLOAD_PY = ("UploadFile", "FileStorage", "request.FILES", "files[",
             "request.files")
UPLOAD_JS = ("multer", "req.files", "file.stream", "busboy")
MODEL_PY = ("models.Model", "__tablename__", "Column(", "Base)")
MODEL_JS = ("mongoose.Schema", "prisma.model", "Sequelize.define")
SECRET_PATTERNS = re.compile(
    r"(?i)\b(api[_-]?key|secret\w*|password|passwd|token\w*|"
    r"aws_access\w*)\s*[:=]\s*[\"'][A-Za-z0-9_\-/+=]{12,}[\"']")
ADMIN_HINTS = ("admin", "dashboard", "backoffice", "manage")


def _iter_files(repo: Path, max_files: int) -> list[Path]:
    files: list[Path] = []
    for p in sorted(repo.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in (".py", ".js", ".ts", ".mjs", ".cjs",
                                ".php"):
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(p)
            if len(files) >= max_files:
                break
    return files


def map_python(path: Path, rel: str, src: str) -> dict:
    """AST python: route decorator + auth + model + upload + secret."""
    routes: list[dict] = []
    secrets_c: list[dict] = []
    lines = src.splitlines()
    for i, line in enumerate(lines, 1):
        for m in SECRET_PATTERNS.finditer(line):
            secrets_c.append({"file": rel, "line": i,
                              "kind": m.group(1).lower(),
                              "value_head": line.strip()[:60]})
    try:
        tree = ast.parse(src)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                continue
            deco_srcs = []
            for d in node.decorator_list:
                try:
                    deco_srcs.append(ast.unparse(d))
                except Exception:
                    deco_srcs.append("")
            auth = any(a.lower() in (d or "").lower()
                       for d in deco_srcs for a in PY_AUTH_DECOS)
            seg = "\n".join(lines[node.lineno - 1:
                                  (node.end_lineno or node.lineno)])
            upload = any(u in seg for u in UPLOAD_PY) or \
                any(u in (d or "") for d in deco_srcs
                    for u in UPLOAD_PY)
            for d in deco_srcs:
                m = PY_ROUTE_DECOS.search(d)
                if m:
                    if m.group(1).lower() == "route":
                        kw = PY_METHODS_KW.search(d)
                        methods = [x.strip(" \"'").upper()
                                   for x in kw.group(1).split(",")
                                   if x.strip()] if kw else ["GET"]
                    else:
                        methods = [m.group(1).upper()]
                    routes.append({
                        "path": m.group(2),
                        "methods": methods,
                        "file": rel, "line": node.lineno,
                        "handler": node.name,
                        "auth": auth, "upload": upload})
    models = []
    for m in re.finditer(r"class\s+\w+\([^)]*(models\.Model|Base)\)",
                         src):
        line = src[:m.start()].count("\n") + 1
        models.append({"file": rel, "line": line,
                       "decl": src[m.start():m.end()][:80]})
    if "__tablename__" in src and not models:
        models.append({"file": rel, "line":
                       src[:src.index("__tablename__")].count("\n") + 1,
                       "decl": "__tablename__"})
    return {"routes": routes, "models": models, "secrets": secrets_c}


def map_text(rel: str, src: str, kind: str) -> dict:
    """Regex utk JS/TS/PHP: routes, upload, model, secret."""
    routes: list[dict] = []
    lines = src.splitlines()
    for i, line in enumerate(lines, 1):
        m = JS_ROUTE.search(line)
        if m:
            verb = m.group(1).upper()
            routes.append({
                "path": m.group(2), "methods": [verb],
                "file": rel, "line": i, "handler": "",
                "auth": bool(JS_AUTH.search(line)),
                "upload": any(u in line for u in UPLOAD_JS)})
    models = []
    for i, line in enumerate(lines, 1):
        if any(mk in line for mk in MODEL_JS):
            models.append({"file": rel, "line": i,
                           "decl": line.strip()[:80]})
    secrets_c = []
    for i, line in enumerate(lines, 1):
        for m in SECRET_PATTERNS.finditer(line):
            secrets_c.append({"file": rel, "line": i,
                              "kind": m.group(1).lower(),
                              "value_head": line.strip()[:60]})
    _ = kind
    return {"routes": routes, "models": models,
            "secrets": secrets_c}


def scan_repo(repo: Path, max_files: int) -> dict:
    surface = {"repo": str(repo), "routes": [], "uploads": [],
               "admin": [], "models": [], "secrets": [],
               "files_scanned": 0}
    for p in _iter_files(repo, max_files):
        rel = str(p.relative_to(repo)).replace("\\", "/")
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        surface["files_scanned"] += 1
        if p.suffix == ".py":
            r = map_python(p, rel, src)
        else:
            r = map_text(rel, src, p.suffix)
        surface["routes"].extend(r["routes"])
        surface["models"].extend(r["models"])
        surface["secrets"].extend(r.get("secrets", []))
        if p.suffix == ".py":
            body = src
        else:
            body = src
        if any(u in body for u in (UPLOAD_PY + UPLOAD_JS)) and \
                not any(rt.get("upload") for rt in r["routes"]):
            for i, line in enumerate(src.splitlines(), 1):
                if any(u in line for u in (UPLOAD_PY + UPLOAD_JS)):
                    surface["uploads"].append({"file": rel, "line": i,
                                               "decl": line.strip()[:80]})
                    break
        low_rel = rel.lower()
        if any(h in low_rel for h in ADMIN_HINTS) or any(
                (rt["path"].lower().startswith("/admin"))
                for rt in r["routes"]):
            surface["admin"].append({"file": rel,
                                     "routes": [rt["path"] for rt in
                                                r["routes"]] or None})
    # dedup admin entries by file
    seen_admin = set()
    surface["admin"] = [a for a in surface["admin"]
                        if a["file"] not in seen_admin
                        and not seen_admin.add(a["file"])]
    return surface


def reconcile(surface: dict, findings_path: Path) -> dict:
    """Petakan lead (target_url) -> route surface (path match).
    Output laporan; findings.json TIDAK diubah."""
    doc = json.loads(findings_path.read_text(encoding="utf-8"))
    report = {"matched": [], "unmatched": 0, "routes_total":
              len(surface["routes"])}
    for f in doc.get("findings", []):
        if not isinstance(f, dict) or f.get("verdict", 0) < 1:
            continue
        tu = (f.get("target_url") or "")
        m = re.match(r"https?://[^/]+(/[^?#]*)", tu)
        if not m:
            continue
        path = m.group(1)
        hits = [rt for rt in surface["routes"]
                if rt["path"] == path or path.startswith(
                    rt["path"].rstrip("/") + "/")]
        if hits:
            report["matched"].append({
                "lead_id": (f.get("id") or "")[:16],
                "title": f.get("title", "")[:100],
                "path": path,
                "route_file": hits[0]["file"],
                "line": hits[0]["line"],
                "has_auth": hits[0]["auth"],
                "upload": hits[0].get("upload", False),
                "note": ("route TANPA auth terlihat — prioritas cek "
                         "akses kontrol manual" if not hits[0]["auth"]
                         else "route ber-auth; cek kelemahan di dalam")})
        else:
            report["unmatched"] += 1
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True,
                    help="path source code repo target (milik sendiri "
                         "atau terotorisasi; read-only)")
    ap.add_argument("--out", required=True, help="attack-surface.json")
    ap.add_argument("--max-files", type=int, default=2000)
    ap.add_argument("--reconcile", default="",
                    help="findings.json untuk dipetakan ke route")
    ap.add_argument("--reconcile-out", default="")
    args = ap.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"repo tidak ada: {repo} (fail-closed)", file=sys.stderr)
        return 2
    surface = scan_repo(repo, args.max_files)
    out = Path(args.out)
    out.write_text(json.dumps(surface, ensure_ascii=False, indent=1)
                   + "\n", encoding="utf-8")
    print(f"[code-map] {surface['files_scanned']} file -> "
          f"{len(surface['routes'])} route "
          f"({sum(1 for r in surface['routes'] if r['auth'])} ber-auth), "
          f"{len(surface['uploads'])} upload, {len(surface['admin'])} "
          f"admin, {len(surface['models'])} model, "
          f"{len(surface['secrets'])} kandidat secret -> {out}")
    if args.reconcile:
        rp = Path(args.reconcile)
        if not rp.exists():
            print(f"findings tidak ada: {rp} (fail-closed)",
                  file=sys.stderr)
            return 2
        report = reconcile(surface, rp)
        rout = Path(args.reconcile_out) if args.reconcile_out else \
            out.with_name(out.stem + "-reconcile.json")
        rout.write_text(json.dumps(report, ensure_ascii=False, indent=1)
                        + "\n", encoding="utf-8")
        print(f"[code-map] reconcile: {len(report['matched'])} lead "
              f"cocok ke route, {report['unmatched']} tidak -> {rout}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
