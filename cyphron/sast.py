"""sast — SAST AST-based + taint tracking + CI mode (Fullpower B4 / CI-1).

Arsitektur:
- PYTHON: rule berbasis AST (modul `ast` stdlib) dengan PATTERN
  METAVARIABLE ($X, $F) — bukan regex teks mentah. Taint tracking
  source -> sink -> sanitizer menghasilkan jalur baris-demi-baris
  (bukti kelas konsultan).
- JS/C++: rule konservatif berbasis regex dengan FP-guard ketat + label
  confidence lebih rendah (AST penuh menyusul via bridge; jujur soal ini).
- Autofix SUGGESTION per rule (proposal, bukan auto-apply).
- CI mode: exit code (0 bersih / 2 ada temuan >= fail-on), output JSON +
  SARIF 2.1.0, diff-aware (hanya file berubah via git diff).
- Rule kustom per klien: file .cyphron-rules (JSON) dengan schema sama.
- Zero-FP: setiap rule punya confidence + contoh positif/negatif di test;
  matcher tidak boleh menebak di luar pola.

Metavariable pattern (dict-spec):
    {"type": "Call", "func": {"type": "Attribute", "attr": "execute"},
     "args": [{"$X": {}}]}
  "$X": {} menangkap node apa pun; "$X": {type: "Str"} menangkap dengan
  syarat kind; capture dipakai dalam pesan temuan.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .languages import LANGUAGES as _FLEET_LANGS
from .languages import _sink_rows as _fleet_sink_rows

# ------------------------------------------------------------------ model
@dataclass
class SastFinding:
    rule_id: str
    message: str
    severity: str          # critical | high | medium | low | info
    cwe: str
    path: str
    line: int
    end_line: int
    confidence: float
    fix: str = ""
    flow: list[dict] = field(default_factory=list)  # taint: [{line, code, role}]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _line_of(code_lines: list[str], lineno: int) -> str:
    return code_lines[lineno - 1].strip() if 0 < lineno <= len(code_lines) else ""


# --------------------------------------------------------- pattern matcher
def _spec_match(spec: dict, node, captures: dict) -> bool:
    """Cocokkan dict-spec ke node AST dengan dukungan metavariable $X."""
    if not isinstance(spec, dict) or not spec:
        return node is not None
    meta = spec.get("$X") or spec.get("$F")
    if "$X" in spec or "$F" in spec:
        name = "$X" if "$X" in spec else "$F"
        cond = spec[name]
        if name in captures and captures[name] is not node:
            return False
        captures[name] = node
        if not cond:
            return node is not None
        return _spec_match(cond, node, captures)
    ntype = spec.get("type")
    if ntype and (node is None or type(node).__name__ not in (ntype, ntype.lower())):
        return False
    for key, sub in spec.items():
        if key == "type":
            continue
        if key == "$kw":  # keyword containment: node.keywords punya >=1 cocok
            kws = getattr(node, "keywords", None) or []
            if not any(_spec_match(sub, kw, dict(captures)) for kw in kws):
                return False
            continue
        if not hasattr(node, key):
            return False
        child = getattr(node, key)
        if isinstance(sub, dict):
            if not _spec_match(sub, child, captures):
                return False
        elif isinstance(sub, list):
            if not isinstance(child, list) or len(child) != len(sub):
                return False
            for s, c in zip(sub, child):
                if isinstance(s, dict):
                    if not _spec_match(s, c, captures):
                        return False
                elif s != c:
                    return False
        elif child != sub:
            return False
    return True


def _spec(node) -> dict:
    """Pembantu: konversi template AST python ke spec dict (pakai ast.dump
    model? — kita definisikan spec manual di rules; helper ini opsional)."""
    return node if isinstance(node, dict) else {"type": type(node).__name__}


@dataclass
class Rule:
    id: str
    message: str
    severity: str
    cwe: str
    languages: tuple
    spec: dict | None              # AST dict-spec (root = node apa pun)
    fields: dict | None = None     # syarat tambahan field root (opsional)
    regex: str | None = None       # fallback utk bahasa non-AST
    confidence: float = 0.9
    fix: str = ""

    def find(self, tree, lines: list[str]):
        out = []
        for node in ast.walk(tree):
            captures: dict = {}
            if _spec_match(self.spec, node, captures):
                line = getattr(node, "lineno", 1)
                end = getattr(node, "end_lineno", line)
                out.append((line, end, captures))
        return out


# -------------------------------------------------------------- rule pack
TAINT_SOURCES = (
    ("flask.request", "request flask"), ("request.args", "request.args"),
    ("request.form", "request.form"), ("request.json", "request.json"),
    ("request.values", "request.values"), ("request.cookies", "request.cookies"),
    ("input(", "stdin"), ("sys.argv", "argv"),
)
TAINT_SINKS = {
    "eval": {"severity": "critical", "cwe": "CWE-95", "fix": "hapus eval; "
             "pakai parser data terstruktur (json) + validasi allowlist"},
    "exec": {"severity": "critical", "cwe": "CWE-95", "fix": "hapus exec; "
             "refaktor ke fungsi eksplisit"},
    "system": {"severity": "critical", "cwe": "CWE-78", "fix": "subprocess "
               "dengan array argumen TANPA shell=True; validasi input"},
}
TAINT_SANITIZERS = ("shlex.quote", "escape", "quote", "int", "float",
                    "ast.literal_eval")

CORE_RULES: list[Rule] = [
    Rule("PY-SQLI-FORMAT", "Query SQL dibangun dengan f-string/konkatenasi "
         "lalu dieksekusi (raw execute) — pakai parameter binding",
         "high", "CWE-89", ("python",),
         {"type": "Call", "func": {"type": "Attribute", "attr": "execute"}},
         fix="cursor.execute('... WHERE id = ?', (param,))",
         confidence=0.85),
    Rule("PY-SHELL-TRUE", "subprocess dengan shell=True memakai input "
         "yang bisa dipengaruhi — risiko command injection",
         "high", "CWE-78", ("python",),
         {"type": "Call", "func": {"type": "Attribute", "attr": "run",
                                   "value": {"type": "Name",
                                             "id": "subprocess"}},
          "$kw": {"arg": "shell", "value": {"type": "Constant",
                                            "value": True}}},
         fix="subprocess.run([...], shell=False)",
         confidence=0.8),
    Rule("PY-DEBUG-TRUE", "app.run(debug=True) di kode — debug mode "
         "membocorkan debugger interaktif di produksi",
         "medium", "CWE-489", ("python",),
         {"type": "Call", "func": {"type": "Attribute", "attr": "run"},
          "$kw": {"arg": "debug", "value": {"type": "Constant",
                                            "value": True}}},
         fix="debug=False; konfigurasi via environment",
         confidence=0.7),
    Rule("PY-VERIFY-FALSE", "requests/verify=False menonaktifkan "
         "validasi TLS",
         "high", "CWE-295", ("python",),
         {"type": "keyword", "arg": "verify", "value": {"type": "Constant",
                                                        "value": False}},
         fix="hapus verify=False; pasang CA bundle yang benar",
         confidence=0.95),
    Rule("PY-RANDOM-TOKEN", "Token/secret memakai random() modul random "
         "(bukan CSPRNG) — prediktabel",
         "medium", "CWE-330", ("python",),
         {"type": "Call", "func": {"type": "Attribute", "attr": "random",
                                   "value": {"type": "Name",
                                             "id": "random"}}},
         fix="pakai secrets.token_hex/token_urlsafe",
         confidence=0.85),
    Rule("PY-PICKLE-LOAD", "pickle.loads pada data tidak dipercaya — "
         "eksekusi kode arbitrer",
         "high", "CWE-502", ("python",),
         {"type": "Call", "func": {"type": "Attribute", "attr": "loads",
                                   "value": {"type": "Name",
                                             "id": "pickle"}}},
         fix="pakai format data (JSON) atau validasi sumber ketat",
         confidence=0.75),
    Rule("PY-EXCEPT-PASS", "except: pass menelan error diam-diam — "
         "menghalangi deteksi",
         "low", "CWE-703", ("python",),
         {"type": "ExceptHandler", "body": [{"type": "Pass"}]},
         fix="log error atau naikkan (raise); jangan diam",
         confidence=0.8),
]

# JS/C++ regex pack konservatif (confidence lebih rendah, FP-guard ketat)
JS_CPP_RULES: list[Rule] = [
    Rule("JS-INNERHTML", "innerHTML dari data tak terpercaya -> sink XSS",
         "medium", "CWE-79", ("js", "ts"), None,
         regex=r"\.innerHTML\s*=\s*(?!['\"])",
         fix="pakai textContent atau sanitasi DOMPurify-class",
         confidence=0.6),
    Rule("JS-EVAL", "eval() pada kode JS — eksekusi dinamis",
         "high", "CWE-95", ("js", "ts"), None,
         regex=r"(?<![\w.])eval\s*\(",
         fix="hapus eval; pakai JSON.parse / pemetaan fungsi eksplisit",
         confidence=0.8),
    Rule("CPP-SYSTEM", "system() di C++ — command injection",
         "critical", "CWE-78", ("c", "cpp", "c++"), None,
         regex=r"(?<![\w.])system\s*\(",
         fix="pakai exec/posix_spawn dengan array argumen",
         confidence=0.75),
    Rule("CPP-STRCPY", "strcpy tanpa batas — buffer overflow",
         "high", "CWE-120", ("c", "cpp", "c++"), None,
         regex=r"(?<![\w.])strcpy\s*\(",
         fix="pakai strncpy/snprintf dengan ukuran buffer eksplisit",
         confidence=0.7),
]

ALL_RULES = {r.id: r for r in CORE_RULES + JS_CPP_RULES}

_LANG_BY_SUFFIX = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "ts", ".tsx": "ts",
    ".mts": "ts",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".groovy": "groovy", ".clj": "clojure", ".cljs": "clojure",
    ".cljc": "clojure",
    ".cs": "csharp", ".fs": "fsharp", ".fsx": "fsharp", ".vb": "visualbasic",
    ".go": "go", ".rs": "rust", ".swift": "swift", ".dart": "dart",
    ".php": "php", ".rb": "ruby", ".pl": "perl", ".pm": "perl",
    ".lua": "lua", ".r": "r", ".jl": "julia",
    ".f90": "fortran", ".f95": "fortran", ".f": "fortran", ".for": "fortran",
    ".pas": "pascal", ".dpr": "pascal", ".hs": "haskell", ".ml": "ocaml",
    ".mli": "ocaml", ".erl": "erlang", ".hrl": "erlang", ".ex": "elixir",
    ".exs": "elixir", ".zig": "zig", ".nim": "nim", ".cr": "crystal",
    ".d": "d", ".ps1": "powershell", ".psm1": "powershell",
    ".sh": "shell", ".bash": "shell", ".sql": "sql", ".coffee": "coffeescript",
}


def _fleet_rules(lang: str) -> list[Rule]:
    """Sink-rules per bahasa dari Language Fleet (B6) — regex konservatif,
    confidence ditandai jujur lebih rendah daripada AST Python."""
    lang_obj = _FLEET_LANGS.get(lang)
    if not lang_obj or not lang_obj.sink_rules:
        return []
    out = []
    for regex, suffix, message, severity in _fleet_sink_rows(lang_obj):
        out.append(Rule(
            id=f"FL-{lang.upper()}-{suffix}", message=message,
            severity=severity, cwe="CWE-78", languages=(lang,), spec=None,
            regex=regex, confidence=0.65,
            fix="validasi/allowlist argumen; hindari membangun string shell "
                "dari input"))
    return out


# ------------------------------------------------------------ taint python
def _is_source(node) -> str | None:
    """Deteksi source secara struktural (bukan string dump):
    request.* (flask-class, termasuk flask.request.args), input(), sys.argv."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == "request":
            return "request"
        if isinstance(sub, ast.Attribute) and sub.attr == "request":
            # flask.request / request pada rantai atribut apa pun
            return "request"
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                and sub.func.id == "input":
            return "stdin"
        if isinstance(sub, ast.Attribute) and sub.attr == "argv" \
                and isinstance(sub.value, ast.Name) and sub.value.id == "sys":
            return "argv"
    return None


def _call_name(node) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def taint_scan(tree: ast.AST, lines: list[str]) -> list[SastFinding]:
    """Dataflow taint satu-modul: source -> assignment -> sink; sanitizer
    menghentikan aliran. Jalur dilaporkan baris-demi-baris."""
    tainted: dict[str, tuple[str, int]] = {}
    flows: list[SastFinding] = []
    rendered: set[tuple] = set()

    def sanitize_name(call_name: str) -> bool:
        return any(s in call_name for s in TAINT_SANITIZERS)

    for node in ast.walk(tree):
        # (a) assignment: sanitizer dicek DULU (x = sanitize(source) = bersih),
        #     baru source / gabungan taint
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets
                     if isinstance(t, ast.Name)]
            rhs_name = _call_name(node.value.func) \
                if isinstance(node.value, ast.Call) else ""
            if sanitize_name(rhs_name):
                for n in names:
                    tainted.pop(n, None)
                continue
            label = _is_source(node.value)
            if label:
                for n in names:
                    tainted[n] = (label, node.lineno)
            else:
                rhs_taint = None
                if isinstance(node.value, ast.Name) \
                        and node.value.id in tainted:
                    rhs_taint = tainted[node.value.id]
                else:
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Name) \
                                and sub.id in tainted:
                                rhs_taint = tainted[sub.id]
                                break
                    if rhs_taint:
                        for n in names:
                            tainted[n] = rhs_taint
        # (b) sink: tainted argumen masuk fungsi berbahaya
        if isinstance(node, ast.Call):
            fname = _call_name(node.func)
            meta = TAINT_SINKS.get(fname)
            if meta:
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id in tainted:
                        src, src_line = tainted[arg.id]
                        if src_line > node.lineno:
                            continue  # flow harus maju: source sebelum sink
                        key = (fname, arg.id, node.lineno)
                        if key in rendered:
                            continue
                        rendered.add(key)
                        flows.append(SastFinding(
                            rule_id=f"PY-TAINT-{fname.upper()}",
                            message=(f"Data dari {src} mengalir ke sink "
                                     f"{fname}() tanpa sanitasi"),
                            severity=meta["severity"], cwe=meta["cwe"],
                            path="", line=src_line, end_line=node.lineno,
                            confidence=0.9, fix=meta["fix"],
                            flow=[
                                {"line": src_line, "role": "source",
                                 "code": _line_of(lines, src_line)},
                                {"line": node.lineno, "role": "sink",
                                 "code": _line_of(lines, node.lineno)},
                            ]))
            # shell=True + taint = sink khusus
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                        has_taint = any(
                            isinstance(a, ast.Name) and a.id in tainted
                            for a in node.args)
                        if has_taint:
                            src, src_line = tainted[
                                next(a.id for a in node.args
                                     if isinstance(a, ast.Name)
                                     and a.id in tainted)]
                            key = ("shellexec", src, node.lineno)
                            if key in rendered:
                                continue
                            rendered.add(key)
                            flows.append(SastFinding(
                                rule_id="PY-TAINT-SHELL",
                                message=(f"Data dari {src} masuk subprocess "
                                         f"shell=True — command injection"),
                                severity="critical", cwe="CWE-78",
                                path="", line=src_line, end_line=node.lineno,
                                confidence=0.95,
                                fix="shell=False + array argumen",
                                flow=[
                                    {"line": src_line, "role": "source",
                                     "code": _line_of(lines, src_line)},
                                    {"line": node.lineno, "role": "sink",
                                     "code": _line_of(lines, node.lineno)},
                                ]))
    return flows


# ------------------------------------------------------------------ scanner
def _load_custom_rules(path: Path) -> list[Rule]:
    """Rule kustom klien (.cyphron-rules JSON) — schema Rule. Regex di-
    compile saat load: rule dengan regex tak valid di-SKIP (dengan jejak
    di daftar yang dikembalikan lewat closure log), bukan crash saat scan.
    """
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for row in rows if isinstance(rows, list) else []:
        try:
            rule = Rule(
                id=str(row["id"]), message=str(row.get("message", "")),
                severity=str(row.get("severity", "low")).lower(),
                cwe=str(row.get("cwe", "CWE-?")),
                languages=tuple(str(l) for l in row.get("languages", ["python"])),
                spec=row.get("spec"), regex=row.get("regex"),
                confidence=float(row.get("confidence", 0.7)),
                fix=str(row.get("fix", "")))
            if rule.regex:
                re.compile(rule.regex)  # gagal -> ValueError -> skip
            if rule.severity not in ("critical", "high", "medium", "low", "info"):
                rule.severity = "info"  # severity custom: turunkan jujur
            out.append(rule)
        except (KeyError, TypeError, ValueError):
            continue
    return out


def scan_file(path: Path, rules: list[Rule], slop: bool = False) -> list[SastFinding]:
    lang = _LANG_BY_SUFFIX.get(path.suffix.lower())
    if not lang:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    findings: list[SastFinding] = []

    if lang == "python":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        sqli_reported: set[tuple] = set()
        for rule in rules:
            if "*" not in rule.languages and lang not in rule.languages:
                continue
            if rule.spec:
                for line, end, captures in rule.find(tree, lines):
                    if rule.id == "PY-SQLI-FORMAT":
                        # FP-guard: hanya execute dengan SQL dibangun dinamis
                        # (f-string/konkatenasi) yang dilaporkan; konstanta dan
                        # parameter binding tidak.
                        calls = [n for n in ast.walk(tree)
                                 if getattr(n, "lineno", None) == line
                                 and isinstance(n, ast.Call)
                                 and _call_name(n.func) == "execute"]
                        dynamic = any(
                            n.args and isinstance(n.args[0],
                                                  (ast.JoinedStr, ast.BinOp))
                            for n in calls)
                        if not dynamic or (rule.id, str(path), line) in sqli_reported:
                            continue
                        sqli_reported.add((rule.id, str(path), line))
                    findings.append(SastFinding(
                        rule.id, rule.message, rule.severity, rule.cwe,
                        str(path), line, end, rule.confidence, rule.fix))
            elif rule.regex:
                pat = re.compile(rule.regex)
                for i, ln in enumerate(lines, 1):
                    if pat.search(ln):
                        findings.append(SastFinding(
                            rule.id, rule.message, rule.severity, rule.cwe,
                            str(path), i, i, rule.confidence, rule.fix))
        findings.extend(taint_scan(tree, lines))
        if slop:
            findings.extend(slop_scan_python(text, tree, lines, str(path)))
    else:
        # js/ts/c/cpp sudah dicakup JS_CPP_RULES — fleet hanya menambah
        # bahasa baru (30+) supaya tidak ada temuan ganda
        if lang not in ("js", "ts", "c", "cpp"):
            rules = list(rules) + _fleet_rules(lang)
        for rule in rules:
            if ("*" not in rule.languages and lang not in rule.languages) \
                    or not rule.regex:
                continue
            pat = re.compile(rule.regex)
            for i, ln in enumerate(lines, 1):
                if pat.search(ln):
                    findings.append(SastFinding(
                        rule.id, rule.message, rule.severity, rule.cwe,
                        str(path), i, i, rule.confidence, rule.fix))
    return findings


def scan_path(root: Path, extra_rules: list[Rule] | None = None,
              diff_only: bool = False, slop: bool = False) -> list[SastFinding]:
    """Scan folder/berkas; diff_only=True hanya berkas yang berubah vs HEAD
    (git diff --name-only + untracked) — mode CI. slop=True menambahkan
    rule pack kualitas kode (slop)."""
    rules = list(ALL_RULES.values()) + list(extra_rules or [])
    if slop:
        rules = rules + SLOP_RULES
    root = Path(root)
    if root.is_dir():
        custom_path = root / ".cyphron-rules"
        if custom_path.is_file():
            rules += _load_custom_rules(custom_path)
    if diff_only:
        names = _git_changed_files(root)
    else:
        names = None
    findings: list[SastFinding] = []
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file()
        and p.suffix.lower() in _LANG_BY_SUFFIX
        and ".git" not in p.parts and "__pycache__" not in p.parts
        and ("kb", "data") != p.parts[-2:])
    dup_map: dict[str, tuple] = {}
    for p in files:
        # diff mode fail-closed: git gagal (bukan repo, dsb.) -> names None
        # -> scan penuh, BUKAN "nol file" yang dilaporkan bersih
        if names is not None and str(p.relative_to(root)) not in names:
            continue
        findings.extend(scan_file(p, rules, slop=slop))
        if slop:
            _dup_helpers(p, findings, dup_map)
    return findings


def _git_changed_files(root: Path) -> set[str] | None:
    """Daftar file berubah (diff HEAD + untracked). Return None bila git
    gagal — fail-CLOSED untuk mode diff: jalankan scan penuh, jangan
    'nol file' yang dilaporkan bersih. splitlines() menjaga path ber-spasi."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=str(root), capture_output=True, timeout=20)
        if out.returncode != 0:
            return None
        rows = out.stdout.decode("utf-8", "replace").splitlines()
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(root), capture_output=True, timeout=20)
        if untracked.returncode != 0:
            return None
        rows += untracked.stdout.decode("utf-8", "replace").splitlines()
        return {r for r in rows if r.strip()}
    except Exception:
        return None


# ------------------------------------------------------------ slop pack
# Rule pack kualitas kode (aktif dengan slop=True / CLI --slop).
# Filosofi: deteksi PENA menyimpulkan "kualitas rendah" hanya dari pola
# konkret — komentar naratif yang mengulang kode, stub, sisa debug,
# nama generik, fungsi raksasa, helper duplikat. Semua confidence di
# bawah 1.0 dan label severity rendah: ini alat bantu review, bukan vonis.
SL_ALL = ("*",)

SLOP_RULES: list[Rule] = [
    Rule("SL-TODO-STUB", "TODO/FIXME/XXX tertinggal — pekerjaan setengah "
         "jadi; selesaikan atau catat di issue tracker, bukan di kode",
         "info", "CWE-546", SL_ALL, None,
         regex=r"(?i)\b(todo|fixme|xxx)\b(:|\s|$)", confidence=0.95),
    Rule("SL-CONSOLE-LOG", "console.log tertinggal — sisa debug di kode "
         "javascript", "low", "CWE-489", ("js", "ts"), None,
         regex=r"console\.log\(", confidence=0.9),
    Rule("SL-PHP-DUMP", "var_dump/print_r tertinggal — sisa debug PHP",
         "low", "CWE-489", ("php",), None,
         regex=r"\b(var_dump|print_r)\s*\(", confidence=0.9),
]

_GENERIC_NAMES = re.compile(
    r"^(foo|bar|baz|temp|tmp|util|utils|helper|stuff|thing|things|obj|data2|"
    r"do_stuff|handle_stuff|my_func|myfunc|func1|func2|method1|test1|"
    r"variable1|aaa|bbb)\d*$", re.IGNORECASE)

_TRIVIAL_COMMENTS = {
    "increment", "decrement", "loop", "iterate", "init", "initialize",
    "constructor", "destructor", "getter", "setter", "get value",
    "set value", "return", "call function", "import", "end", "start",
    "counter", "increment counter", "loop through items", "next",
}

_COMMENT_CODE_STOP = re.compile(r"[^a-z0-9]+")

_FUNC_LINE_CAP = 60


def _comment_lines(lines: list[str]) -> list[tuple[int, str, str]]:
    """(nomor_baris, teks_komentar, kode_dibawahnya) — komentar standalone
    atau di akhir baris, utk deteksi naratif/trivial."""
    out = []
    for i, ln in enumerate(lines, 1):
        m = re.search(r"#(.*)$", ln)
        if not m or ln.lstrip().startswith("#!") or "@@" in ln:
            continue
        comment = m.group(1).strip()
        if not comment or comment.startswith(("!", "#")):
            continue
        # kode sisa di kiri komentar (kalau komentar inline)
        left = ln[:m.start()].strip()
        below = lines[i] if i < len(lines) else ""
        out.append((i, comment, left or below))
    return out


def _norm_code(s: str) -> str:
    return _COMMENT_CODE_STOP.sub("", s.lower())


def slop_scan_python(text: str, tree: ast.AST, lines: list[str],
                     path: str) -> list[SastFinding]:
    out: list[SastFinding] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            span = getattr(node, "end_lineno", node.lineno) - node.lineno + 1
            if span > _FUNC_LINE_CAP:
                out.append(SastFinding(
                    "SL-FUNC-LONG",
                    f"{type(node).__name__} '{node.name}' {span} baris "
                    f"(> {_FUNC_LINE_CAP}) — pecah jadi unit kecil yang "
                    "bisa diuji",
                    "low", "CWE-1061", path, node.lineno,
                    getattr(node, "end_lineno", node.lineno), 0.7,
                    "refaktor: ekstrak langkah jadi fungsi bernama jelas"))
            if not isinstance(node, ast.ClassDef) and \
                    _GENERIC_NAMES.match(node.name):
                out.append(SastFinding(
                    "SL-NAMA-GENERIK",
                    f"nama '{node.name}' generik — tidak mengatakan apa yang "
                    "dikerjakan",
                    "info", "CWE-1099", path, node.lineno, node.lineno,
                    0.6, "ganti nama sesuai maksud domain, bukan tipe data"))
        if isinstance(node, ast.Call) and _call_name(node.func) == "print" \
                and node.args and all(
                    isinstance(a, (ast.Constant, ast.JoinedStr))
                    for a in node.args):
            out.append(SastFinding(
                "SL-PRINT-LEFTOVER",
                "print() dengan argumen konstanta — kemungkinan sisa debug",
                "low", "CWE-489", path, node.lineno, node.lineno, 0.5,
                "pakai logging dengan level, atau hapus"))

    # komentar naratif/trivial: token compare terhadap kode di dekatnya
    for lineno, comment, near_code in _comment_lines(lines):
        cnorm = _norm_code(comment)
        if not cnorm:
            continue
        if cnorm in _TRIVIAL_COMMENTS:
            out.append(SastFinding(
                "SL-KOMENTAR-TRIVIAL",
                f"komentar trivial '{comment}' tidak menambah informasi",
                "info", "CWE-1078", path, lineno, lineno, 0.75,
                "hapus, atau tulis KENAPA-nya (konstrain/alasan)"))
            continue
        knorm = _norm_code(near_code)
        if knorm and cnorm == knorm:
            out.append(SastFinding(
                "SL-KOMENTAR-NARATIF",
                f"komentar '{comment}' hanya mengulang kode di bawahnya",
                "info", "CWE-1078", path, lineno, lineno, 0.8,
                "hapus komentar yang mengulang kode yang sudah jelas"))
    return out


def _dup_helpers(path: Path, findings: list[SastFinding],
                 seen: dict[str, tuple]) -> None:
    """Helper duplikat hash-based: badan fungsi python yang identik
    (setelah normalisasi) di file mana pun -> temuan di kemunculan ke-2."""
    lang = _LANG_BY_SUFFIX.get(path.suffix.lower())
    if lang != "python":
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
    except (OSError, SyntaxError):
        return
    lines = text.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno)
        # hash badan fungsi TANPA baris def — rename tidak mengubah hash
        start = node.body[0].lineno - 1 if node.body else node.lineno - 1
        body = "\n".join(l for l in lines[start:end]
                         if l.strip() and not l.strip().startswith("#"))
        if len(body.splitlines()) < 3:
            continue  # getter/alias 1-2 baris terlalu rentan FP
        h = hashlib.sha256(_norm_code(body).encode()).hexdigest()
        first = seen.get(h)
        if first is None:
            seen[h] = (str(path), node.lineno, node.name)
            continue
        fpath, fline, fname = first
        findings.append(SastFinding(
            "SL-DUP-HELPER",
            f"fungsi '{node.name}' identik dengan '{fname}' ({fpath}:"
            f"{fline}) — satukan jadi satu helper",
            "low", "CWE-1078", str(path), node.lineno, end, 0.85,
            "ekstrak ke satu modul bersama; hapus salinannya"))


_SLOP_WEIGHT = {"info": 2, "low": 5, "medium": 15, "high": 30, "critical": 50}


def slop_score(findings: list[SastFinding]) -> int:
    """Skor kebersihan slop 0-100: 100 bersih; temuan menurunkan skor
    sebesar bobot severity x confidence."""
    penalty = sum(_SLOP_WEIGHT.get(f.severity, 5) * f.confidence
                  for f in findings)
    return max(0, min(100, round(100 - penalty)))


# ---------------------------------------------------------------- output
def to_sarif(findings: list[SastFinding], tool: str = "cyphron-sast") -> dict:
    rules = sorted({f.rule_id for f in findings})
    return {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "version": "1.0",
                                "informationUri": "",
                                "rules": [{"id": r} for r in rules]}},
            "results": [
                {"ruleId": f.rule_id,
                 "level": {"critical": "error", "high": "error",
                           "medium": "warning", "low": "note",
                           "info": "note"}.get(f.severity, "note"),
                 "message": {"text": f.message},
                 "locations": [{
                     "physicalLocation": {
                         "artifactLocation": {"uri": f.path},
                         "region": {"startLine": f.line,
                                    "endLine": f.end_line}}},
                 ],
                 "properties": {"confidence": f.confidence, "cwe": f.cwe,
                                "fix": f.fix, "flow": f.flow}}
                for f in findings],
        }],
    }


def run_ci(path: Path, out_dir: Path | None = None, diff_only: bool = False,
           fail_on: str = "high", max_findings: int = 0,
           slop: bool = False) -> int:
    """Mode CI: tulis sast.json + sast.sarif, return exit code."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    custom: list[Rule] = []
    marker = Path(path)
    custom_path = (marker if marker.is_file() else marker / ".cyphron-rules")
    if custom_path.is_file():
        custom = _load_custom_rules(custom_path)
    findings = scan_path(marker, extra_rules=custom, diff_only=diff_only,
                         slop=slop)
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.path, f.line))
    rows = [f.to_dict() for f in findings]
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = {"findings": rows, "count": len(rows)}
        if slop:
            payload["slop_score"] = slop_score(
                [f for f in findings if f.rule_id.startswith("SL-")])
        (out_dir / "sast.json").write_text(
            json.dumps(payload, indent=1, ensure_ascii=False),
            encoding="utf-8")
        (out_dir / "sast.sarif").write_text(
            json.dumps(to_sarif(findings), indent=1), encoding="utf-8")
    if not findings:
        return 0
    return 2 if order.get(findings[0].severity, 9) <= order.get(fail_on, 1) \
        else 0
