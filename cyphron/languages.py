"""languages — Language Fleet: registry 37 bahasa pemrograman (Fullpower B6).

Tiga kapabilitas:

1. DETEKSI OTOMATIS (zero-FP): tebak bahasa dari ekstensi + fingerprint isi
   (shebang, keyword khas, gaya komentar). Skor dihitung deterministik;
   bila dua kandidat terlalu berdekatan TANPA ekstensi, hasil = AMBIGU
   (dilabel, TIDAK ditebak) — disiplin ambiguity rejection yang sama
   dengan CVE matching.
2. RUNTIME FLEET (adapter): binary runtime per bahasa utk Engine Adapter
   Layer (B1) + deteksi versi terpasang di mesin (subprocess --version,
   timeout, tanpa instal apa pun).
3. LANG-SYNC: knowledge pack versioned — fingerprint + sink-rules dipakai
   sast.py; inventaris runtime+versi bisa ditulis ke JSON; auto-update
   = update pack ini via repo (hash tercatat), BUKAN instal kompiler.

Bahasa tercakup (36): python, javascript, typescript, java, kotlin, scala,
groovy, clojure, c, cpp, csharp, fsharp, visualbasic, go, rust, swift, dart,
php, ruby, perl, lua, r, julia, fortran, pascal, haskell, ocaml, erlang,
elixir, zig, nim, crystal, d, powershell, shell, sql.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Language:
    lid: str
    name: str
    exts: tuple[str, ...]
    fingerprints: tuple[tuple[str, float], ...] = ()  # (regex, weight)
    shebangs: tuple[str, ...] = ()
    runtime: tuple[str, ...] = ()     # binary kandidat utk eksekusi adapter
    version_flag: str = "--version"
    sink_rules: tuple[tuple[str, str, str, str], ...] = ()
    # sink_rules: (regex, rule_suffix, message, severity)


def _s(r: str, suffix: str, msg: str, sev: str = "high") -> tuple:
    return (r, suffix, msg, sev)


LANGUAGES: dict[str, Language] = {
    lang.lid: lang for lang in [
        Language("python", "Python", (".py", ".pyw"),
                 ((r"\bdef\s+\w+\s*\(", 3.0), (r"\bimport\s+\w+", 2.0),
                  (r"__name__\s*==", 3.0), (r"\belif\b", 2.0)),
                 shebangs=("python",), runtime=("python", "python3")),
        Language("javascript", "JavaScript", (".js", ".mjs", ".cjs"),
                 ((r"\bfunction\s+\w*\s*\(", 2.5), (r"\bconst\s+\w+\s*=", 2.0),
                  (r"console\.log\(", 2.0), (r"=>\s*{", 1.5)),
                 shebangs=("node",), runtime=("node", "nodejs"),
                 sink_rules=(
                     _s(r"(?<![\w.])eval\s*\(", "EVAL",
                        "eval() — eksekusi dinamis", "high"),
                     _s(r"\.innerHTML\s*=\s*(?!['\"])", "INNERHTML",
                        "innerHTML dari data dinamis — sink XSS", "medium"))),
        Language("typescript", "TypeScript", (".ts", ".tsx", ".mts"),
                 ((r"\binterface\s+\w+\s*{", 3.0),
                  (r":\s*(string|number|boolean)\b", 3.0),
                  (r"\bimplements\s+\w+", 2.0)),
                 runtime=("node", "tsx", "ts-node"),
                 sink_rules=(
                     _s(r"(?<![\w.])eval\s*\(", "EVAL",
                        "eval() — eksekusi dinamis", "high"))),
        Language("java", "Java", (".java",),
                 ((r"\bpublic\s+(static\s+)?(void|class)\b", 3.0),
                  (r"\bSystem\.out\.print", 2.5), (r"\bpackage\s+[\w.]+;", 2.0),
                  (r"@Override", 2.0)),
                 runtime=("javac", "java"), version_flag="-version",
                 sink_rules=(
                     _s(r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(", "RTEXEC",
                        "Runtime.exec — command injection", "critical"),
                     _s(r"new\s+ProcessBuilder\s*\(", "PROCBUILDER",
                        "ProcessBuilder — review argumen dari input", "medium"),
                     _s(r"new\s+ObjectInputStream\s*\(", "DESER",
                        "Java deserialization dari data tak dipercaya", "high"),
                     _s(r'getInstance\s*\(\s*"(MD5|SHA1)"', "WEAKHASH",
                        "Hash lemah (MD5/SHA1) untuk kebutuhan keamanan", "medium"))),
        Language("kotlin", "Kotlin", (".kt", ".kts"),
                 ((r"\bfun\s+\w+\s*\(", 3.0), (r"\bval\s+\w+\s*[:=]", 2.5),
                  (r"\bwhen\s*\(", 2.0)),
                 runtime=("kotlin", "kotlinc"),
                 sink_rules=(
                     _s(r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(", "RTEXEC",
                        "Runtime.exec — command injection", "critical"))),
        Language("scala", "Scala", (".scala",),
                 ((r"\bdef\s+\w+\s*\(", 2.0), (r"\bval\s+\w+\s*[:=]", 2.0),
                  (r"extends\s+App\b", 3.0)),
                 runtime=("scala", "scalac"),
                 sink_rules=(
                     _s(r"(?<![\w.])eval\s*\(", "EVAL",
                        "Eval dinamis (scala/groovy)", "high"))),
        Language("groovy", "Groovy", (".groovy",),
                 ((r"\bdef\s+\w+\s*=", 2.5), (r"\bprintln\s+", 1.5),
                  (r"\bclosure\b", 1.0)),
                 sink_rules=(
                     _s(r"(?<![\w.])Eval\.me\s*\(", "EVALME",
                        "Groovy Eval.me — eksekusi dinamis", "critical"),
                     _s(r'(?<![\w."])execute\s*\(', "EXECSHELL",
                        "Groovy shell execute", "high"))),
        Language("clojure", "Clojure", (".clj", ".cljs", ".cljc"),
                 ((r"\(defn\s", 3.0), (r"\(ns\s", 3.0), (r":require", 1.5)),
                 sink_rules=(
                     _s(r"\(sh\s", "SHELLSH",
                        "clojure.java.shell/sh — review argumen", "medium"))),
        Language("c", "C", (".c", ".h"),
                 ((r"#include\s*<\w+\.h>", 3.0), (r"\bprintf\s*\(", 1.5),
                  (r"\bmalloc\s*\(", 2.5)),
                 runtime=("gcc", "clang"),
                 sink_rules=(
                     _s(r"(?<![\w.])strcpy\s*\(", "STRCPY",
                        "strcpy tanpa batas — buffer overflow", "high"),
                     _s(r"(?<![\w.])gets\s*\(", "GETS",
                        "gets() dilarang (CWE-242)", "critical"),
                     _s(r"(?<![\w.])system\s*\(", "SYSTEM",
                        "system() — command injection", "critical"))),
        Language("cpp", "C++", (".cpp", ".cc", ".cxx", ".hpp", ".hh"),
                 ((r"#include\s*<(iostream|vector|string)>", 3.0),
                  (r"\bstd::", 3.0), (r"\bnamespace\s+\w+", 2.0)),
                 runtime=("g++", "clang++"),
                 sink_rules=(
                     _s(r"(?<![\w.])system\s*\(", "SYSTEM",
                        "system() — command injection", "critical"),
                     _s(r"(?<![\w.])strcpy\s*\(", "STRCPY",
                        "strcpy tanpa batas", "high"))),
        Language("csharp", "C#", (".cs",),
                 ((r"\busing\s+System", 3.0), (r"\bnamespace\s+[\w.]+", 2.5),
                  (r"\bpublic\s+(class|void|static)\b", 2.0)),
                 runtime=("dotnet", "csc", "mcs"),
                 sink_rules=(
                     _s(r"Process\.Start\s*\(", "PROCSTART",
                        "Process.Start — review argumen dari input", "medium"),
                     _s(r"cmd\.exe\s*/c", "CMDSHELL",
                        "cmd /c dari kode — command injection", "critical"),
                     _s(r"BinaryFormatter\s*\.\s*Deserialize", "DESER",
                        "BinaryFormatter deserialization (CWE-502)", "critical"))),
        Language("fsharp", "F#", (".fs", ".fsx"),
                 ((r"\blet\s+(mutable\s+)?\w+\s*=", 2.5),
                  (r"\bopen\s+System", 3.0)),
                 runtime=("dotnet", "fsi")),
        Language("visualbasic", "Visual Basic .NET", (".vb",),
                 ((r"\bModule\s+\w+", 3.0), (r"\bDim\s+\w+\s+As\s+", 3.0),
                  (r"\bSub\s+\w+\s*\(", 2.5)),
                 runtime=("dotnet", "vbc"),
                 sink_rules=(
                     _s(r"Shell\s*\(", "SHELLCALL",
                        "VB Shell() — review argumen", "high"))),
        Language("go", "Go", (".go",),
                 ((r"\bpackage\s+\w+", 3.0), (r"\bfunc\s+\w+\s*\(", 2.5),
                  (r":=\s*", 1.0), (r"\bfmt\.(Print|Sprintf)", 2.0)),
                 runtime=("go",),
                 sink_rules=(
                     _s(r"exec\.Command\s*\(", "EXECCMD",
                        "os/exec Command — review argumen dari input", "high"),
                     _s(r"syscall\.Exec\s*\(", "SYSEXEC",
                        "syscall.Exec — eksekusi langsung", "critical"))),
        Language("rust", "Rust", (".rs",),
                 ((r"\bfn\s+\w+\s*\(", 2.5), (r"\blet\s+(mut\s+)?\w+\s*=", 2.5),
                  (r"\bmatch\s+\w+\s*{", 2.0), (r"::new\s*\(", 1.5)),
                 runtime=("rustc", "cargo"),
                 sink_rules=(
                     _s(r"std::process::Command|Command::new\s*\(", "PROCCMD",
                        "Command::new — review argumen dari input", "medium"))),
        Language("swift", "Swift", (".swift",),
                 ((r"\bfunc\s+\w+\s*\(", 2.5), (r"\blet\s+\w+\s*[:=]", 2.0),
                  (r"\bimport\s+(Foundation|UIKit|SwiftUI)", 3.0)),
                 runtime=("swift",),
                 sink_rules=(
                     _s(r"\bProcess\s*\(|posix_spawn\s*\(", "PROCSWIFT",
                        "Process/posix_spawn — review argumen", "medium"))),
        Language("dart", "Dart", (".dart",),
                 ((r"\bvoid\s+main\s*\(", 2.5), (r"\bfinal\s+\w+\s*=", 2.0),
                  (r"\bimport\s+'package:", 3.0)),
                 runtime=("dart",),
                 sink_rules=(
                     _s(r"Process\.(run|start)\s*\(", "PROCDART",
                        "Process.run/start — review argumen", "medium"))),
        Language("php", "PHP", (".php",),
                 ((r"<\?php", 4.0), (r"\$\w+\s*=", 1.5), (r"->\w+\s*\(", 1.0),
                  (r"\bfunction\s+\w+\s*\(", 2.0)),
                 runtime=("php",),
                 sink_rules=(
                     _s(r"(?<![\w.])eval\s*\(", "EVAL",
                        "eval() PHP — eksekusi dinamis", "critical"),
                     _s(r"\b(shell_exec|passthru|proc_open)\s*\(", "SHELL",
                        "Eksekusi shell PHP dari input", "critical"),
                     _s(r"\bunserialize\s*\(", "DESER",
                        "unserialize pada data tak dipercaya (CWE-502)", "high"),
                     _s(r"\binclude\s*\(\s*\$", "INCL",
                        "include variabel — LFI/RFI risk", "high"))),
        Language("ruby", "Ruby", (".rb",),
                 ((r"\bdef\s+\w+", 2.5), (r"\brequire\s+", 2.5),
                  (r"#\{[^}]*\}", 1.5)),
                 runtime=("ruby",),
                 sink_rules=(
                     _s(r"\b(system|exec)\s*\(", "SYSTEM",
                        "Kernel#system/exec dari input", "critical"),
                     _s(r"\bIO\.popen\s*|Open3\.(popen|capture)", "POPEN",
                        "popen/Open3 — review argumen", "high"))),
        Language("perl", "Perl", (".pl", ".pm"),
                 ((r"\buse\s+strict\b", 3.0), (r"\bmy\s+\$\w+\s*=", 2.5),
                  (r"@\w+", 0.5)),
                 shebangs=("perl",), runtime=("perl",),
                 sink_rules=(
                     _s(r"\b(system|exec)\s*\(", "SYSTEM",
                        "system/exec Perl dari input", "critical"),
                     _s(r"\bopen\s*\([^)]*\|", "OPENPIPE",
                        "open dengan pipe — command injection", "critical"))),
        Language("lua", "Lua", (".lua",),
                 ((r"\bfunction\s+\w+\s*\(", 2.0), (r"\blocal\s+\w+\s*=", 2.0),
                  (r"require\s+", 2.0)),
                 runtime=("lua", "luajit"),
                 sink_rules=(
                     _s(r"os\.execute\s*\(", "OSEXEC",
                        "os.execute — command injection", "critical"),
                     _s(r"io\.popen\s*\(", "IPOPEN",
                        "io.popen dari input", "high"))),
        Language("r", "R", (".r",),
                 ((r"<-\s*", 2.0), (r"\blibrary\s*\(", 2.5),
                  (r"\bfunction\s*\(", 1.5)),
                 runtime=("Rscript", "R"),
                 sink_rules=(
                     _s(r"\bsystem\s*\(|\bshell\s*\(", "SYSTEM",
                        "system/shell R dari input", "high"))),
        Language("julia", "Julia", (".jl",),
                 ((r"\bfunction\s+\w+", 2.5), (r"\bend\b", 0.3),
                  (r"using\s+\w+", 2.5)),
                 runtime=("julia",),
                 sink_rules=(
                     _s(r"\brun\s*\(`", "RUNCMD",
                        "run(backtick) — review interpolasi", "high"))),
        Language("fortran", "Fortran", (".f90", ".f95", ".f", ".for"),
                 ((r"(?i)\bprogram\s+\w+", 3.0),
                  (r"(?i)\bend\s+program\b", 3.0),
                  (r"(?i)\bimplicit\s+none\b", 3.0)),
                 runtime=("gfortran", "ifort"),
                 sink_rules=(
                     _s(r"(?i)\bCALL\s+SYSTEM\s*\(", "SYSTEM",
                        "CALL SYSTEM Fortran — command injection", "critical"))),
        Language("pascal", "Pascal/Delphi", (".pas", ".dpr"),
                 ((r"(?i)\bprogram\s+\w+;", 3.0), (r"(?i)\bbegin\b", 1.0),
                  (r"(?i)\bend\.", 2.0)),
                 runtime=("fpc",),
                 sink_rules=(
                     _s(r"(?i)ExecuteProcess\s*\(", "EXECPROC",
                        "ExecuteProcess — review argumen", "high"))),
        Language("haskell", "Haskell", (".hs",),
                 ((r"\bmodule\s+\w+", 2.5), (r"\bimport\s+qualified\b", 3.0),
                  (r"::\s*[A-Z]\w*\s*->", 3.0)),
                 runtime=("ghc", "runghc", "stack"),
                 sink_rules=(
                     _s(r"\b(readProcess|callCommand|callProcess)\s*",
                        "PROCHS",
                        "System.Process dari input — review", "high"))),
        Language("ocaml", "OCaml", (".ml", ".mli"),
                 ((r"\blet\s+\w+\s*=", 1.5), (r"\bmatch\s+.*\bwith\b", 3.0),
                  (r";;", 1.0)),
                 runtime=("ocaml", "ocamlopt"),
                 sink_rules=(
                     _s(r"Sys\.command\s*", "SYSCMD",
                        "Sys.command dari input", "high"))),
        Language("erlang", "Erlang", (".erl", ".hrl"),
                 ((r"-module\s*\(", 4.0), (r"-export\s*\(", 4.0),
                  (r"->\s*$", 0.5)),
                 runtime=("erl", "erlc"),
                 sink_rules=(
                     _s(r"os:cmd\s*\(", "OSCMD",
                        "os:cmd — command injection", "critical"))),
        Language("elixir", "Elixir", (".ex", ".exs"),
                 ((r"\bdefmodule\s+\w+", 4.0), (r"\bdef\s+\w+", 2.0)),
                 runtime=("elixir", "iex"),
                 sink_rules=(
                     _s(r"System\.cmd\s*\(", "SYSCMD",
                        "System.cmd dari input — review", "high"),
                     _s(r":os\.cmd\s*\(", "OSCMD",
                        ":os.cmd — command injection", "critical"))),
        Language("zig", "Zig", (".zig",),
                 ((r"\bconst\s+\w+\s*=\s*@import", 4.0),
                  (r"\bpub\s+fn\s+\w+", 3.0), (r"!void\b", 2.5)),
                 runtime=("zig",),
                 sink_rules=(
                     _s(r"std\.process\.Child", "CHILDZIG",
                        "std.process.Child — review argumen", "medium"))),
        Language("nim", "Nim", (".nim",),
                 ((r"\bproc\s+\w+\s*\(", 3.0), (r"\bimport\s+\w+", 2.0),
                  (r"\becho\s+", 1.0)),
                 runtime=("nim",),
                 sink_rules=(
                     _s(r"\b(execCmd|execShellCmd|startProcess)\s*\(",
                        "EXECNIM",
                        "exec/startProcess Nim — review argumen", "high"))),
        Language("crystal", "Crystal", (".cr",),
                 ((r"\bdef\s+\w+", 2.0), (r"\bputs\s+", 1.0),
                  (r"\brequire\s+", 2.0)),
                 runtime=("crystal",),
                 sink_rules=(
                     _s(r"\b(system|Process\.run)\s*\(", "SYSTEM",
                        "system/Process.run Crystal dari input", "high"))),
        Language("d", "D", (".d",),
                 ((r"\bimport\s+std\.\w+", 3.5), (r"\bvoid\s+main\s*\(", 2.5),
                  (r"\bimmutable\b|\bauto\s+\w+\s*=", 1.5)),
                 runtime=("dmd", "gdc", "ldc2"),
                 sink_rules=(
                     _s(r"std\.process\.executeShell", "EXECHELL",
                        "executeShell D dari input", "critical"))),
        Language("powershell", "PowerShell", (".ps1", ".psm1"),
                 ((r"\$\w+\s*=", 1.0), (r"\b(Get-|Set-|New-|Invoke-)\w+", 3.5),
                  (r"\[string\]|\[int\]", 2.0)),
                 runtime=("powershell", "pwsh"),
                 sink_rules=(
                     _s(r"\b(Invoke-Expression|iex)\s+", "IEX",
                        "Invoke-Expression — eksekusi dinamis", "critical"),
                     _s(r"-EncodedCommand\b", "ENCCMD",
                        "EncodedCommand = teknik obfuskasi/sleep-dodge",
                        "high"))),
        Language("shell", "Shell/Bash", (".sh", ".bash"),
                 ((r"^#!/bin/(ba)?sh", 4.0), (r"\bfi\b", 0.5),
                  (r"\$\{\w+\}", 1.0), (r"\becho\s+", 0.5)),
                 shebangs=("sh", "bash"), runtime=("bash", "sh"),
                 sink_rules=(
                     _s(r"(?<![\w.])eval\s+", "EVALSH",
                        "eval shell dari input", "critical"),
                     _s(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh\b",
                        "CURLBASH",
                        "curl|bash — eksekusi remote tanpa pinning", "critical"))),
        Language("sql", "SQL", (".sql",),
                 ((r"\bSELECT\b.*\bFROM\b", 3.0), (r"\bINSERT\s+INTO\b", 3.0),
                  (r"\bCREATE\s+(TABLE|VIEW)\b", 2.5)),
                 sink_rules=(
                     _s(r"EXEC\s*\(\s*@|sp_executesql\s*\+", "DYNSQL",
                        "Dynamic SQL EXEC dari string konkatenasi", "high"))),
        Language("coffeescript", "CoffeeScript", (".coffee",),
                 ((r"\b->\s*$", 2.0), (r"\bconsole\.log\b", 1.0),
                  (r"@\w+\s*=", 1.0)),
                 runtime=("coffee",)),
    ]
}

_EXT_MAP: dict[str, str] = {
    ext: lid for lid, lang in LANGUAGES.items() for ext in lang.exts
}


def _sink_rows(lang: Language) -> list[tuple[str, str, str, str]]:
    """Normalisasi sink_rules: entry satu-rule tanpa trailing comma bisa
    tersimpan sebagai 4-tuple flat — kembalikan selalu list 4-tuple."""
    rows = lang.sink_rules
    if not rows:
        return []
    if isinstance(rows[0], str):
        return [tuple(rows)]  # type: ignore[arg-type]
    return [tuple(t) for t in rows]  # type: ignore[arg-type]


# --------------------------------------------------------------- deteksi
def detect_language(text: str, filename: str | None = None,
                    threshold_gap: float = 2.0) -> dict:
    """Deteksi bahasa dengan skor deterministik; ambigu DITOLAK.

    Return {language, confidence, ambiguous, candidates: [...]}.
    Ekstensi = sinyal kuat; fingerprint isi + shebang menambah skor.
    Tanpa ekstensi dan dua kandidat teratas berjarak < threshold_gap ->
    ambiguous=True (zero-FP: tidak menebak)."""
    scores: dict[str, float] = {}
    ext = None
    if filename:
        ext = ("." + filename.rsplit(".", 1)[-1].lower()
               if "." in filename else None)
        if ext in _EXT_MAP:
            scores[_EXT_MAP[ext]] = scores.get(_EXT_MAP[ext], 0.0) + 10.0
    head = text[:2000] if text else ""
    for lid, lang in LANGUAGES.items():
        score = scores.get(lid, 0.0)
        for pat, w in lang.fingerprints:
            try:
                if re.search(pat, head, re.M):
                    score += w
            except re.error:
                continue
        for sh in lang.shebangs:
            if head.startswith("#!") and sh in head.splitlines()[0]:
                score += 6.0
        if score > 0:
            scores[lid] = score
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    candidates = [{"language": lid, "score": round(s, 2)}
                  for lid, s in ranked[:3]]
    if not candidates:
        return {"language": None, "confidence": 0.0, "ambiguous": True,
                "candidates": [],
                "reason": "tidak ada indikator bahasa yang dikenal"}
    top_lid, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0.0
    ambiguous = (ext not in _EXT_MAP and second_score > 0
                 and (top_score - second_score) < threshold_gap)
    if ambiguous:
        return {"language": None, "confidence": 0.0, "ambiguous": True,
                "candidates": candidates,
                "reason": "dua kandidat terlalu berdekatan tanpa ekstensi"}
    confidence = min(0.99, top_score / (top_score + 6.0)) if top_score else 0.0
    return {"language": top_lid, "confidence": round(confidence, 2),
            "ambiguous": False, "candidates": candidates}


# ----------------------------------------------------------- runtime fleet
def runtime_versions(timeout: float = 5.0) -> dict[str, dict]:
    """Deteksi runtime terpasang + versinya (subprocess --version; TANPA
    instal/mutasi apa pun)."""
    out: dict[str, dict] = {}
    versions_cache: dict[str, str | None] = {}
    for lid, lang in sorted(LANGUAGES.items()):
        if not lang.runtime:
            out[lid] = {"binary": None, "version": None}
            continue
        binary = None
        for cand in lang.runtime:
            p = shutil.which(cand)
            if p:
                binary = p
                break
        if binary is None:
            out[lid] = {"binary": None, "version": None}
            continue
        if binary not in versions_cache:
            try:
                proc = subprocess.run([binary, lang.version_flag],
                                      capture_output=True, timeout=timeout)
                first = (proc.stdout.decode("utf-8", "replace").strip()
                         or proc.stderr.decode("utf-8", "replace").strip())
                versions_cache[binary] = \
                    first.splitlines()[0][:80] if first else ""
            except (OSError, subprocess.TimeoutExpired):
                versions_cache[binary] = None
        out[lid] = {"binary": binary, "version": versions_cache[binary]}
    return out


# ---------------------------------------------------------------- lang-sync
def knowledge_hash(source_path: Path | None = None) -> str:
    """Hash knowledge pack (file ini) — pin versi deteksi+rules."""
    src = source_path or Path(__file__)
    return hashlib.sha256(src.read_bytes()).hexdigest()[:16]


def sync_inventory(out_path: Path | None = None) -> dict:
    """lang-sync: hash knowledge + inventaris runtime terpasang + versi."""
    inv = {
        "knowledge_sha256_16": knowledge_hash(),
        "languages": len(LANGUAGES),
        "runtimes": runtime_versions(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(inv, indent=1, ensure_ascii=False),
                            encoding="utf-8")
    return inv


def installed_count(inventory: dict) -> tuple[int, int]:
    runtimes = inventory.get("runtimes", {})
    have = sum(1 for r in runtimes.values() if r.get("binary"))
    return have, len(runtimes)
