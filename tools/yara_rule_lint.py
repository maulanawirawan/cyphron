r"""[SAFETY: read-only] yara_rule_lint — linter kualitas aturan YARA/YARA-X.

Port konsep dari antrean SKILL-PORT-QUEUE #0097 (trailofbits/skills
plugin 'yara-authoring', skill 'yara-rule-authoring' — prinsip: string
harus menghasilkan atom 4-byte, sasar keluarga spesifik bukan kategori,
uji lawan goodware, short-circuit cek murah dulu, metadata = dokumentasi;
atribusi ide). Dibangun FROM SCRATCH: tokenizer aturan, daftar string
rawan-FP, dan seluruh aturan lint ditulis sendiri — tidak menyalin
yara_lint.py/atom_analyzer.py milik plugin tersebut. Lisensi secai:
PolyForm NC.

Input -> mekanisme -> output:
  - Input : file .yar/.yara atau direktori (read-only, NOL jaringan,
            tidak mengeksekusi aturan — hanya parsing teks).
  - Mekanisme: tokenizer kecil (komentar //, /* */; string teks "…";
            blok hex { … }; regex /…/ di seksi strings) -> model per-rule
            (nama, tag, meta, strings, kondisi) -> 10 cek deterministik.
  - Output: daftar lead {rule, line, check, severity, message} + meta.

Cek (presisi dulu — semua verdict = LEAD, bukan klaim):
  nama-sintaks     (high) : nama rule melanggar ident YARA — tidak akan
                            compile.
  nama-konvensi    (info) : tanpa '_' — konvensi keluarga (PREFIX_KELUARGA).
  metadata-hampa   (info) : seksi meta: absen — metadata = dokumentasi.
  string-pendek    (medium): string < 4 byte efektif — tanpa atom 4-byte,
                            YARA jatuh ke verifikasi lambat.
  hex-berulang     (medium): semua pasangan hex identik (mis. AA AA AA AA)
                            — atom lemah.
  string-umum      (info) : nama API/path Windows klasik yang juga dipakai
                            packer/installer — rawan FP tanpa konteks unik.
  overfit-string   (info) : > 6 string — tanda over-fitting.
  urutan-kondisi   (medium): cek murah (filesize/uintNN/entrypoint) ada
                            TAPI ditulis SETELAH pencocokan string —
                            short-circuit dilanggar.
  baca-past-eof    (info) : uintNN(offset>0) tanpa guard filesize di
                            kondisi — baca melewati EOF = undefined
                            (false-negative senyap).
  ref-string-hampa (high) : kondisi merujuk $id yang tak didefinisikan.

Fail-closed: kutip tak tertutup / kurung tak seimbang / nilai string
hampa = file-unparsed — dicatat sebagai lead high "file-unparsed"
(TIDAK pernah dihitung bersih), baik input file tunggal maupun
direktori. Exit: 0 bersih; 1 ada temuan >= --fail-on (default info);
2 error input (sumber tidak ada / tidak ada file .yar).

Pemakaian:
  python tools/yara_rule_lint.py --source rules.yar
  python tools/yara_rule_lint.py --source rules/ --json hasil.json --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secai.yara-rule-lint/1"

EXT = {".yar", ".yara"}

# Nama API/path Windows klasik — packer, installer, dan malware lazim
# memanggilnya juga; sebagai string tunggal mereka rawan FP (ditulis
# sendiri dari pengetahuan umum, bukan disalin dari plugin mana pun).
RAWAN_FP = frozenset({
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualfree",
    "createremotethread", "writeprocessmemory", "readprocessmemory",
    "loadlibrarya", "loadlibraryw", "loadlibrary", "getprocaddress",
    "createfilea", "createfilew", "shellexecutea", "shellexecutew",
    "winexec", "creatprocessa", "createremotethreadex", "gettickcount",
    "isdebuggerpresent", "kernel32.dll", "c:\\windows\\",
})

CHEAP_RE = re.compile(r"\bfilesize\b|\buint(8|16|32)(be)?\s*\(|\bentrypoint\b")
STRING_MATCH_RE = re.compile(r"\$[A-Za-z0-9_*#?-]+|\b(any|all|\d+)\s+of\b")
UINT_RE = re.compile(r"\buint(8|16|32)(be)?\s*\(\s*(\d+)\s*\)")
HEX_TOKEN_RE = re.compile(r"\??[0-9A-Fa-f]{2}")


class ParseError(ValueError):
    """Aturan tidak bisa diparse (kutip/kurung tak seimbang, dsb.)."""


class Rule:
    def __init__(self, name: str, line: int, tags: list[str]) -> None:
        self.name = name
        self.line = line
        self.tags = tags
        self.has_meta = False
        self.strings: list[dict[str, Any]] = []   # {id,kind,value,line}
        self.condition = ""
        self.condition_line = 0


class Lexer:
    """Tokenizer minimal aturan YARA — cukup untuk lint (bukan compiler)."""

    def __init__(self, text: str) -> None:
        self.t = text
        self.i = 0
        self.line = 1
        self.n = len(text)

    def _adv(self, k: int = 1) -> str:
        c = self.t[self.i:self.i + k]
        self.line += c.count("\n")
        self.i += k
        return c

    def _skip_ws(self, skip_comments: bool = True) -> None:
        while self.i < self.n:
            c = self.t[self.i]
            if c in " \t\r\n":
                self._adv()
            elif skip_comments and c == "/" and self.t[self.i + 1:self.i + 2] == "/":
                while self.i < self.n and self.t[self.i] != "\n":
                    self._adv()
            elif skip_comments and c == "/" and self.t[self.i + 1:self.i + 2] == "*":
                start = self.line
                self._adv(2)
                while self.i < self.n and self.t[self.i:self.i + 2] != "*/":
                    self._adv()
                if self.i >= self.n:
                    raise ParseError(f"komentar /* tidak ditutup (mulai baris {start})")
                self._adv(2)
            else:
                return

    def read_string(self) -> str:
        """Baca literal teks "…" — fail-closed pada kutip tak tertutup."""
        start_line = self.line
        self._adv()  # buka kutip
        out: list[str] = []
        while self.i < self.n:
            c = self._adv()
            if c == "\\" and self.i < self.n:
                out.append(c + self._adv())
                continue
            if c == '"':
                return "".join(out)
            if c == "\n":
                raise ParseError(f"kutip tidak ditutup sebelum akhir baris {start_line}")
            out.append(c)
        raise ParseError(f"kutip tidak ditutup (mulai baris {start_line})")

    def read_hex_block(self) -> str:
        """Baca blok hex { … } — boleh multiline, komentar di dalam ok."""
        start_line = self.line
        depth = 0
        out: list[str] = []
        while self.i < self.n:
            self._skip_ws()
            if self.i >= self.n:
                break
            c = self._adv()
            out.append(c)
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return "".join(out)
        raise ParseError(f"blok hex {{ }} tidak ditutup (mulai baris {start_line})")

    def read_regex(self) -> str:
        start_line = self.line
        self._adv()  # '/'
        out: list[str] = []
        while self.i < self.n:
            c = self._adv()
            if c == "\\" and self.i < self.n:
                out.append(c + self._adv())
                continue
            if c == "/":
                # modifier regex (i, s, m, dsb.) diikuti sampai EOL
                while self.i < self.n and self.t[self.i] not in "\r\n":
                    self._adv()
                return "".join(out)
            if c == "\n":
                raise ParseError(f"regex tidak ditutup (mulai baris {start_line})")
            out.append(c)
        raise ParseError(f"regex tidak ditutup (mulai baris {start_line})")


def _ident(s: str) -> str:
    return re.match(r"[A-Za-z_][A-Za-z0-9_]*", s) is not None


def parse_rules(text: str) -> list[Rule]:
    """Parse semua rule — gagal keras bila struktur tidak bisa dibaca."""
    lx = Lexer(text)
    rules: list[Rule] = []
    while True:
        lx._skip_ws()
        if lx.i >= lx.n:
            break
        c = lx.t[lx.i]
        if c == '"':                       # import "..."
            lx.read_string()
            continue
        if lx.t[lx.i:].startswith("//") or lx.t[lx.i:].startswith("/*"):
            lx._skip_ws()
            continue
        m = re.match(r"(?:global\s+|private\s+)*rule\s+([A-Za-z0-9_]+)",
                     lx.t[lx.i:])
        if not m:
            if re.match(r"(?:global\s+|private\s+)*rule(\s|$)", lx.t[lx.i:]):
                raise ParseError(f"nama rule tidak terbaca (baris {lx.line})")
            # token lain di level atas: lewati satu baris (mis. sisa import)
            nxt = lx.t.find("\n", lx.i)
            if nxt == -1:
                break
            lx._adv(nxt - lx.i)
            continue
        name = m.group(1)
        line = lx.line
        lx._adv(m.end())
        tags: list[str] = []
        lx._skip_ws()
        if lx.i < lx.n and lx.t[lx.i] == ":":
            lx._adv()
            while True:
                lx._skip_ws()
                t = re.match(r"[A-Za-z_][A-Za-z0-9_]*", lx.t[lx.i:])
                if not t:
                    break
                tags.append(t.group(0))
                lx._adv(t.end())
        lx._skip_ws()
        if lx.i >= lx.n or lx.t[lx.i] != "{":
            raise ParseError(f"rule {name}: kurung pembuka '{{' tidak ditemukan (baris {line})")
        lx._adv()
        rules.append(_parse_body(lx, Rule(name, line, tags)))
    return rules


def _parse_body(lx: Lexer, rule: Rule) -> Rule:
    section = ""
    seen_ids: set[str] = set()
    while True:
        lx._skip_ws()
        if lx.i >= lx.n:
            raise ParseError(f"rule {rule.name}: '}}' penutup tidak ditemukan")
        c = lx.t[lx.i]
        if c == "}":
            lx._adv()
            return rule
        if c == '"':
            lx.read_string()
            continue
        m = re.match(r"(meta|strings|condition)\s*:", lx.t[lx.i:])
        if m:
            section = m.group(1)
            if section == "meta":
                rule.has_meta = True
            lx._adv(m.end())
            continue
        if section == "strings" and c == "$":
            sm = re.match(r"\$([A-Za-z0-9_?#*-]+)\s*=", lx.t[lx.i:])
            if not sm:
                raise ParseError(f"rule {rule.name}: deklarasi string tidak terbaca "
                                 f"(baris {lx.line})")
            sid, sline = sm.group(1), lx.line
            lx._adv(sm.end())
            lx._skip_ws()
            if lx.i >= lx.n:
                raise ParseError(f"rule {rule.name}: string ${sid} tanpa nilai")
            c2 = lx.t[lx.i]
            if c2 == '"':
                val = lx.read_string()
                kind = "text"
            elif c2 == "{":
                val = lx.read_hex_block()
                kind = "hex"
            elif c2 == "/":
                val = lx.read_regex()
                kind = "regex"
            else:
                raise ParseError(f"rule {rule.name}: nilai string ${sid} tidak "
                                 f"dikenal (baris {sline})")
            # lewati modifier sampai akhir baris ('}' = rule satu-baris)
            while lx.i < lx.n and lx.t[lx.i] not in "\r\n" and lx.t[lx.i] != "}":
                lx._adv()
            rule.strings.append({"id": f"${sid}", "kind": kind,
                                 "value": val, "line": sline})
            seen_ids.add(f"${sid}")
            continue
        if section == "condition":
            # kumpulkan ekspresi kondisi sampai '}' penutup rule (depth 1);
            # komentar di dalam kondisi dilewati agar '}' di komentar tidak
            # dianggap penutup
            start = lx.i
            cond_line = lx.line
            while lx.i < lx.n and lx.t[lx.i] != "}":
                if lx.t[lx.i] == '"':
                    lx.read_string()
                    continue
                if lx.t[lx.i] == "/" and lx.t[lx.i + 1:lx.i + 2] == "/":
                    while lx.i < lx.n and lx.t[lx.i] != "\n":
                        lx._adv()
                    continue
                if lx.t[lx.i] == "/" and lx.t[lx.i + 1:lx.i + 2] == "*":
                    lx._adv(2)
                    while lx.i < lx.n and lx.t[lx.i:lx.i + 2] != "*/":
                        lx._adv()
                    lx._adv(2)
                    continue
                lx._adv()
            rule.condition = lx.t[start:lx.i]
            rule.condition_line = cond_line
            continue
        # token lain (nama modifier meta, angka, dsb.) — lewati satu token
        tm = re.match(r"[A-Za-z0-9_.\-]+|\S", lx.t[lx.i:])
        lx._adv(tm.end())


def _effective_len(text: str) -> int:
    """Panjang efektif string teks: pasangan escape dihitung 1 byte."""
    n = 0
    i = 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            i += 2
        else:
            i += 1
        n += 1
    return n


def _hex_pairs(block: str) -> list[str]:
    inner = block.strip().lstrip("{").rstrip("}")
    inner = re.sub(r"/\*.*?\*/", " ", inner, flags=re.S)
    return [t for t in HEX_TOKEN_RE.findall(inner)]


def lint_rule(rule: Rule) -> list[dict[str, Any]]:
    """10 cek deterministik atas satu rule — semua verdict LEAD."""
    out: list[dict[str, Any]] = []

    def add(check: str, sev: str, msg: str, line: int | None = None) -> None:
        out.append({"rule": rule.name, "check": check, "severity": sev,
                    "message": msg, "line": line if line is not None else rule.line})

    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", rule.name):
        add("nama-sintaks", "high",
            f"nama rule '{rule.name}' melanggar ident YARA — tidak akan compile")
    if "_" not in rule.name:
        add("nama-konvensi", "info",
            "nama tanpa '_' — konvensi sasar keluarga spesifik: PREFIX_KELUARGA_deskripsi")
    if not rule.has_meta:
        add("metadata-hampa", "info",
            "seksi meta: absen — metadata (author/family/date/reference) = dokumentasi")
    if len(rule.strings) > 6:
        add("overfit-string", "info",
            f"{len(rule.strings)} string (> 6) — tanda over-fitting; pilih 4-6 "
            f"indikator terkuat")
    defined = {s["id"] for s in rule.strings}
    for s in rule.strings:
        if s["kind"] == "text":
            eff = _effective_len(s["value"])
            if eff < 4:
                add("string-pendek", "medium",
                    f"{s['id']} = \"{s['value']}\" ({eff} byte) — tanpa atom "
                    f"4-byte, matching jatuh ke verifikasi lambat", s["line"])
            if s["value"].lower() in RAWAN_FP:
                add("string-umum", "info",
                    f"{s['id']} string umum (dipakai packer/installer juga) — "
                    f"rawan FP; cari konteks unik keluarga", s["line"])
        elif s["kind"] == "hex":
            pairs = _hex_pairs(s["value"])
            real = [p for p in pairs if "?" not in p]
            if len(real) < 4:
                add("string-pendek", "medium",
                    f"{s['id']} blok hex hanya {len(real)} byte eksplisit — "
                    f"atom < 4 byte", s["line"])
            elif real and len(set(p.upper() for p in real)) == 1:
                add("hex-berulang", "medium",
                    f"{s['id']} semua byte identik ({real[0]} diulang) — atom "
                    f"lemah", s["line"])
    cond = rule.condition
    if cond.strip():
        sm = STRING_MATCH_RE.search(cond)
        cm = CHEAP_RE.search(cond)
        if sm and cm and sm.start() < cm.start():
            add("urutan-kondisi", "medium",
                "cek murah (filesize/uintNN/entrypoint) ditulis SETELAH "
                "pencocokan string — short-circuit dilanggar, pindahkan ke depan",
                rule.condition_line)
        if cm and "filesize" not in cond:
            offs = [int(g[2]) for g in UINT_RE.findall(cond)]
            offs = [o for o in offs if o > 0]
            if offs:
                add("baca-past-eof", "info",
                    f"uintNN di offset > 0 ({', '.join(map(str, offs))}) tanpa "
                    f"guard filesize — baca melewati EOF = undefined "
                    f"(false-negative senyap)", rule.condition_line)
        for ref in set(re.findall(r"\$[A-Za-z0-9_?#*-]+", cond)):
            if ref not in defined and ref not in ("$*",):
                add("ref-string-hampa", "high",
                    f"kondisi merujuk {ref} yang tidak didefinisikan di seksi "
                    f"strings — tidak akan compile", rule.condition_line)
    return out


def lint_source(text: str, filename: str) -> tuple[list[dict[str, Any]], dict]:
    """Lint satu file — ParseError dibiarkan naik (penelepon memutuskan)."""
    rules = parse_rules(text)
    findings: list[dict[str, Any]] = []
    for r in rules:
        for f in lint_rule(r):
            findings.append({"file": filename, **f})
    return findings, {"rules": len(rules)}


def iter_source(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.suffix.lower() in EXT and p.is_file())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Linter kualitas aturan YARA/YARA-X (read-only, nol "
                    "jaringan, aturan tidak dieksekusi).")
    ap.add_argument("--source", required=True, help="file .yar/.yara atau direktori")
    ap.add_argument("--fail-on", choices=["info", "medium", "high"], default="info",
                    help="ambang exit 1 (default: info = semua lead)")
    ap.add_argument("--json", metavar="OUT", help="tulis hasil ke file JSON")
    args = ap.parse_args(argv)

    root = Path(args.source)
    if not root.exists():
        print(f"ERROR: sumber tidak ada: {root}", file=sys.stderr)
        return 2

    threshold = {"info": 0, "medium": 1, "high": 2}[args.fail_on]
    findings: list[dict[str, Any]] = []
    files = iter_source(root)
    meta: dict[str, Any] = {"schema": SCHEMA, "files": 0, "rules": 0,
                            "unparsed": 0}
    if not files:
        print(f"ERROR: tidak ada file {'/'.join(sorted(EXT))} di {root}",
              file=sys.stderr)
        return 2
    for f in files:
        meta["files"] += 1
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            findings.append({"file": str(f), "rule": "-", "check": "file-unparsed",
                             "severity": "high", "line": 0,
                             "message": f"file tidak bisa dibaca: {e}"})
            meta["unparsed"] += 1
            continue
        try:
            fd, fm = lint_source(text, str(f))
        except ParseError as e:
            findings.append({"file": str(f), "rule": "-", "check": "file-unparsed",
                             "severity": "high", "line": 0,
                             "message": f"tidak bisa diparse (TIDAK dinilai): {e}"})
            meta["unparsed"] += 1
            continue
        meta["rules"] += fm["rules"]
        findings.extend(fd)

    sev_rank = {"info": 0, "medium": 1, "high": 2}
    counted = [x for x in findings if sev_rank[x["severity"]] >= threshold]
    meta["findings"] = len(findings)
    meta["counted"] = len(counted)
    for x in findings:
        print(f"[{x['severity']:>6}] {x['file']}:{x['line']} {x['rule']} "
              f"{x['check']}: {x['message']}")
    print(f"RINGKAS: {meta['files']} file, {meta['rules']} rule, "
          f"{meta['unparsed']} unparsed, {len(findings)} lead "
          f"({len(counted)} >= ambang {args.fail_on})")

    if args.json:
        Path(args.json).write_text(
            json.dumps({"schema": SCHEMA, "meta": meta, "findings": findings},
                       ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 1 if counted else 0


if __name__ == "__main__":
    sys.exit(main())
