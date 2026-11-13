"""[AUDIT: static] solidity_static_audit — pindai sumber .sol untuk 10
kelas bug statis: LEAD ber-eviden, maksimal L2 — TANPA compiler
Solidity, TANPA eksekusi, TANPA jaringan (murni analisis teks/struktur
sumber).

Kenapa secai butuh: repo belum punya ranah .sol/web3 sama sekali
(pembagian ranah ABH-PORT: web3/.sol/token = item W2). Kontrak "no proof,
no report" dipertahankan: tool ini HANYA menghasilkan LEAD ber-eviden —
setiap temuan membawa baris + potongan kode sumber sebagai bukti, status
"unconfirmed", verdict maksimal L2 (REPRODUCED secara struktur teks, bukan
klaim "vulnerable" — klaim itu butuh eksekusi/PoC yang jelas di luar tool).

10 kelas yang dipindai (id kelas -> pola):
  1. REENTRANCY            — external call (.call{value}/transfer/send/
                             safeTransfer) sebelum update state di fungsi
                             yang sama (pola CEI terbalik).
  2. TX_ORIGIN_AUTH        — tx.origin dipakai sebagai pembanding auth.
  3. UNCHECKED_CALL_RETURN — return value external call (send/transfer/
                             call) diabaikan sebagai statement.
  4. DELEGATECALL_DYNAMIC  — delegatecall dengan target tidak konstan
                             (parameter/storage mutable).
  5. SELFDESTRUCT_PRESENT  — selfdestruct/suicide di sumber (kehadiran
                             deterministik; dampak butuh konteks).
  6. PRAGMA_UNCHECKED_ARITHMETIC — pragma < 0.8.0 (aritmetika tak
                             ter-check pada rentang compiler tersebut).
  7. CRITICAL_UNGUARDED    — fungsi kritikal (withdraw/mint/upgrade/...)
                             publik tanpa guard akses apa pun di
                             signature atau body (termasuk initialize
                             tanpa initializer/_disableInitializers).
  8. ORACLE_STALENESS      — latestRoundData tanpa cek updatedAt/staleness,
                             getPriceUnsafe tanpa cek conf, spot price
                             (slot0/getReserves) dipakai untuk harga.
  9. ORDERING_MEV          — amountOutMin=0, swap tanpa deadline,
                             block.timestamp sebagai sumber keputusan/
                             entropi (tx ordering dependence).
 10. PRAGMA_FLOATING       — pragma solidity ^/>=/  *  (floating, tanpa pin
                             versi persis).

Selector diekstrak ringan: signature kanonik ABI dari deklarasi function,
di-hash Keccak-256 (implementasi murni Python di file ini, self-test
terhadap vektor resmi saat startup — gagal = exit 2 internal, fail-closed).
Tipe tuple/struct tidak diekspansi ABI offline -> selector NULL + alasan
(jujur, tidak ditebak).

Severity & verdict (kontrak secai core/findings.py):
  - semua finding: status "unconfirmed", verdict 1 (L1 SUSPECTED - LEAD)
    atau 2 (L2 REPRODUCED - LEAD), reportable=false.
  - L2 = struktur teks deterministik (mis. pragma ^, tx.origin di require);
    L1 = pola tidak pasti/bergantung konteks -> CATATAN eksplisit di field
    "note" + confidence lebih rendah. Tidak ada kelas yang memaksa klaim.

Fail-closed:
  - target tidak ada / bukan file-dir, file tak terbaca, tidak ada .sol
    ditemukan, atau self-test keccak gagal -> exit 2 (TIDAK keluar hasil
    kosong yang terkesan "scan sukses aman").
  - komentar/string dilucuti dulu (anti-FP dari teks di komentar).

Batas jujur (ditulis di output "limits"):
  - tanpa compiler/type-checker: nama variabel bisa salah kutip, pola
    lintas-kontrak & pewarisan TIDAK dianalisis (interface dipotong).
  - offline: tidak ada data on-chain, harga, likuiditas, atau verifikasi
    bytecode. Live-verify wajib sebelum klaim apa pun dinaikkan.

Pemakaian:
  python tools/solidity_static_audit.py contracts/ --recursive --json
  python tools/solidity_static_audit.py Token.sol --out hasil.json
  python tools/solidity_static_audit.py contracts/ --fail-on medium
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# tag verdict dari satu pintu kontrak findings repo (core/findings.py)
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
from findings import verdict_tag  # noqa: E402

SCHEMA = "secai.solidity_static_audit.v1"
TOOL = "solidity_static_audit"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Keccak-256 (murni Python; Ethereum selector) ─────────────────────────────
#
# hashlib.sha3_256 BUKAN Keccak-256 (padding 0x06 vs 0x01) — jadi diimplement
# sendiri, diverifikasi self-test terhadap vektor resmi (fail-closed).

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# rotasi rho per [x][y]
_KECCAK_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_M64 = (1 << 64) - 1

KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
KECCAK_ABC = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def _rol(v: int, n: int) -> int:
    n %= 64
    if n == 0:
        return v & _M64
    return ((v << n) | (v >> (64 - n))) & _M64


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (padding 0x01, rate 136 byte) — murni stdlib."""
    lanes = [[0] * 5 for _ in range(5)]
    rate = 136

    def absorb(block: bytes) -> None:
        for i in range(rate // 8):  # i = x + 5*y
            x, y = i % 5, i // 5
            off = i * 8
            lanes[x][y] ^= int.from_bytes(block[off:off + 8], "little")

    def keccak_f() -> None:
        for rc in _KECCAK_RC:
            c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3]
                 ^ lanes[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    lanes[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = _rol(lanes[x][y],
                                                     _KECCAK_ROT[x][y])
            for x in range(5):
                for y in range(5):
                    lanes[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y])
                                             & b[(x + 2) % 5][y]) & _M64
            lanes[0][0] ^= rc

    padded = bytearray(data)
    padded.append(0x01)  # padding keccak (bukan SHA-3 0x06)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    for i in range(0, len(padded), rate):
        absorb(bytes(padded[i:i + rate]))
        keccak_f()
    out = bytearray()
    for i in range(4):  # 4 lane x 8 byte = 32 byte
        x, y = i % 5, i // 5
        out += lanes[x][y].to_bytes(8, "little")
    return bytes(out)


def _keccak_selftest() -> None:
    for data, expect in ((b"", KECCAK_EMPTY), (b"abc", KECCAK_ABC)):
        got = keccak256(data).hex()
        if got != expect:
            raise RuntimeError(
                f"self-test keccak gagal: {data!r} -> {got}, "
                f"harusnya {expect}")


# ── Lucuti komentar & string (struktur baris/kolom dipertahankan) ────────────

def strip_comments_strings(src: str) -> str:
    """Kembalikan salinan sumber dengan isi komentar & string literal
    dijadikan spasi — nomor baris tetap sinkron dengan sumber asli."""
    out: list[str] = []
    i, n = 0, len(src)
    mode = "code"
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if mode == "code":
            if ch == "/" and nxt == "/":
                mode = "line"
                out.append("  ")
                i += 2
                continue
            if ch == "/" and nxt == "*":
                mode = "block"
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                mode = "dq"
                out.append(" ")
                i += 1
                continue
            if ch == "'":
                mode = "sq"
                out.append(" ")
                i += 1
                continue
            out.append(ch)
            i += 1
        elif mode == "line":
            if ch == "\n":
                mode = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif mode == "block":
            if ch == "*" and nxt == "/":
                mode = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        else:  # dq / sq (string literal)
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if (mode == "dq" and ch == '"') or (mode == "sq" and ch == "'"):
                mode = "code"
                out.append(" ")
            else:
                out.append("\n" if ch == "\n" else " ")
            i += 1
    return "".join(out)


# ── Ekstraksi struktur ringan ────────────────────────────────────────────────

_FN_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+([A-Za-z_$][\w$]*)")
_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_$][\w$]*)")
_PARAM_CLEAN_RE = re.compile(
    r"\b(?:memory|calldata|storage|indexed|payable)\b")
_VIS_RE = re.compile(
    r"\b(public|external|internal|private)\b")

_KNOWN_GUARD_MODIFIERS = (
    "onlyowner", "onlyadmin", "onlygovernance", "onlyrole", "onlyauthorized",
    "onlyowneroroperator", "requiresauth", "auth", "restricted", "guarded",
)


def _brace_block(text: str, open_idx: int) -> tuple[int, int]:
    """Dari posisi '{', kembalikan (index penutup, jumlah baris sampai sana)."""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return len(text) - 1


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_span(text: str, start: int, end: int) -> tuple[int, int]:
    return _line_of(text, start), _line_of(text, end)


class FunctionDef:
    """Fungsi Solidity hasil ekstraksi ringan."""

    def __init__(self, name: str, params_raw: str, head: str,
                 body: str, line: int, end_line: int, contract: str) -> None:
        self.name = name
        self.params_raw = params_raw
        self.head = head          # teks dari 'function' sampai '{'
        self.body = body          # teks stripped dalam { }
        self.line = line
        self.end_line = end_line
        self.contract = contract
        self.visibility = ""
        self.modifiers: list[str] = []
        self._parse_head()

    def _parse_head(self) -> None:
        m = _VIS_RE.search(self.head)
        self.visibility = m.group(1) if m else "public"
        after = self.head[m.end():] if m else ""
        for tok in re.findall(r"[A-Za-z_$][\w$]*", after):
            low = tok.lower()
            if low in ("view", "pure", "virtual", "override", "payable",
                       "returns"):
                continue
            self.modifiers.append(tok)

    @property
    def signature_head(self) -> str:
        return f"function {self.name}({self.params_raw})"

    def has_guard(self) -> bool:
        """Guard akses = modifier hanya-owner di head, ATAU cek auth
        eksplisit di body. False = TIDAK ADA tanda guard (bisa jadi guard
        diwariskan dari base contract yang tidak ikut dipindai)."""
        for mod in self.modifiers:
            low = mod.lower()
            if low in _KNOWN_GUARD_MODIFIERS or low.startswith("only"):
                return True
        body = self.body
        if re.search(r"msg\.sender\s*==|_msgSender\(\)\s*==|_checkOwner\("
                     r"|requireOwner|_requireAdmin|hasRole\(|_checkRole\("
                     r"|onlyRole\b", body):
            return True
        return False


def canonical_signature(name: str, params_raw: str) -> str | None:
    """Signature kanonik ABI utk tipe elementer (+array/instansinya).
    Tuple/struct/mapping TIDAK diekspansi -> None (jujur, tidak ditebak)."""
    if not params_raw.strip():
        return f"{name}()"
    parts = [p.strip() for p in params_raw.split(",")]
    types: list[str] = []
    for part in parts:
        if not part:
            return None
        clean = _PARAM_CLEAN_RE.sub(" ", part)
        tokens = clean.split()
        if not tokens:
            return None
        ttype = tokens[0]
        # array suffix (uint256[] / uint256[3]) boleh; tuple "(" tidak
        if "(" in ttype or "mapping" in ttype:
            return None
        m = re.match(r"^([A-Za-z_$][\w$]*)((?:\[[^\]]*\])*)$", ttype)
        if not m:
            return None
        base, suffix = m.group(1), m.group(2)
        if base == "uint":
            base = "uint256"
        elif base == "int":
            base = "int256"
        known = re.match(
            r"^(u?int\d{1,3}|address|bool|bytes\d{0,2}|string|function|"
            r"bytes|fixed[0-8x]*|ufixed[0-8x]*)$", base)
        if not known:
            return None  # kemungkinan struct/enum/kontrak — tidak ditebak
        types.append(base + suffix)
    return f"{name}({','.join(types)})"


def extract_functions(stripped: str) -> list[FunctionDef]:
    fns: list[FunctionDef] = []
    contracts: list[tuple[str, int, int]] = []
    for m in _CONTRACT_RE.finditer(stripped):
        brace = stripped.find("{", m.end())
        if brace == -1:
            continue
        close = _brace_block(stripped, brace)
        contracts.append((m.group(1), m.start(), close))
    for m in _FN_RE.finditer(stripped):
        open_idx = stripped.find("{", m.end())
        # fungsi tanpa body (interface) — lewati untuk analisis, tetap catat
        semi = stripped.find(";", m.end())
        if open_idx == -1 or (semi != -1 and semi < open_idx):
            continue
        close = _brace_block(stripped, open_idx)
        contract = next((c[0] for c in contracts
                         if c[1] < m.start() < c[2]), "")
        line, end_line = _line_span(stripped, m.start(), close)
        body = stripped[open_idx + 1:close]
        fns.append(FunctionDef(m.group(1), m.group(2), stripped[m.start():open_idx],
                               body, line, end_line, contract))
    return fns


def extract_modifiers(stripped: str) -> set[str]:
    return set(_MODIFIER_DEF_RE.findall(stripped))


# ── Kerangka temuan ──────────────────────────────────────────────────────────

def _lead_id(f: dict) -> str:
    basis = "|".join([TOOL, f["class_id"], f["title"], f["file"],
                      str(f["line"])])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def make_lead(class_id: str, title: str, severity: str, verdict: int,
              file_path: str, line: int, snippet: str, rationale: str,
              verify_hint: str, note: str = "",
              confidence: float | None = None) -> dict:
    if verdict not in (1, 2):
        raise ValueError("static audit hanya mengeluarkan lead L1/L2")
    conf = confidence if confidence is not None else (0.8 if verdict == 2
                                                      else 0.5)
    tag = verdict_tag(verdict)  # satu pintu kontrak verdict repo
    return {
        "class_id": class_id,
        "title": title,
        "severity": severity,
        "status": "unconfirmed",
        "verdict": verdict,
        "verdict_tag": tag,
        "reportable": False,
        "confidence": round(conf, 2),
        "file": file_path,
        "line": line,
        "snippet": snippet.strip()[:800],
        "rationale": rationale,
        "verify_hint": verify_hint,
        "note": note,
    }


def _snippet_of(lines: list[str], line_no: int, context: int = 2) -> str:
    lo = max(0, line_no - 1 - context)
    hi = min(len(lines), line_no + context)
    return "\n".join(lines[lo:hi])


# ── Detektor per kelas ───────────────────────────────────────────────────────

_EXT_CALL_RE = re.compile(
    r"(?:[\w\]\)$.]+|\w+\([^()]*\))\.(?:call\{[^}]*\}|call\(|"
    r"transfer\(|send\(|safeTransfer(?:From)?\()")
_STATE_WRITE_RE = re.compile(
    r"^\s*([A-Za-z_$][\w$]*)\s*(\[[^\]]*\])?\s*(?:\+=|-=|\*=|/=|=)(?!=)")
_LOCAL_DECL_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|bool|address|bytes\d*|string|bytes|"
    r"(?:[A-Za-z_$][\w$]*)\.(?:Transfer|Struct)|[A-Za-z_$][\w$]*)"
    r"\s+(?:memory\s+|storage\s+|calldata\s+)?[A-Za-z_$][\w$]*"
    r"\s*(?:=[^=]|\s*;)")


def check_reentrancy(fn: FunctionDef, rel: str, lines: list[str]) -> list[dict]:
    out: list[dict] = []
    body_lines = fn.body.splitlines()
    # posisi external call & state-write (offset baris relatif ke file)
    base = fn.line
    call_idx: list[tuple[int, str]] = []
    write_idx: list[tuple[int, str]] = []
    locals_ = {p.strip().split()[-1].rstrip(")")
               for p in fn.params_raw.split(",") if p.strip()}
    for i, raw in enumerate(body_lines):
        ln = base + i
        if _EXT_CALL_RE.search(raw):
            call_idx.append((ln, raw))
        w = _STATE_WRITE_RE.match(raw)
        if w and not raw.strip().startswith(("require", "if", "for",
                                             "while", "return")):
            var = w.group(1)
            if _LOCAL_DECL_RE.match(raw) and not w.group(2):
                locals_.add(var)
            elif var not in locals_:
                write_idx.append((ln, raw))
    if not call_idx or not write_idx:
        return out
    first_write = min(w[0] for w in write_idx)
    after_calls = [c for c in call_idx if c[0] < first_write]
    if not after_calls:
        return out
    cl, crawl = after_calls[0]
    value_flow = bool(re.search(r"\.call\{|\.transfer\(|\.send\(|value:",
                                crawl))
    verdict = 2 if value_flow else 1
    sev = "medium" if value_flow else "low"
    out.append(make_lead(
        "REENTRANCY",
        f"External call sebelum update state di {fn.name}()",
        sev, verdict, rel, cl, _snippet_of(lines, cl),
        "Pola CEI terbalik: " + crawl.strip()[:120] + " dipanggil pada "
        f"baris {cl} sebelum penulisan state pertama di baris "
        f"{first_write} — jendela reentrancy mungkin terbuka.",
        "Tulis Foundry test: kontrak penyerang re-enter di callback, "
        "cek apakah saldo/state ganda dicairkan.",
        note=("state yang ditulis mungkin independen dari call ini — "
              "verifikasi dependensi data sebelum klaim."),
        confidence=0.7 if verdict == 2 else 0.4))
    return out


_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")


def check_tx_origin(rel: str, mlines: list[str],
                    orig: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, raw in enumerate(mlines, 1):
        if _TX_ORIGIN_RE.search(raw):
            auth_use = bool(re.search(
                r"require|if\s*\(|==|!=|assert|revert", raw))
            if auth_use:
                out.append(make_lead(
                    "TX_ORIGIN_AUTH",
                    "tx.origin dipakai sebagai pembanding otorisasi",
                    "high", 2, rel, i, _snippet_of(orig, i),
                    "tx.origin = penandatangani transaksi terluar; kontrak "
                    "perantara/phishing bisa memanfaatkan identitas ini.",
                    "Ganti msg.sender; atau tulis PoC phishing-kontrak "
                    "di Foundry (prank chain).",
                    confidence=0.85))
            else:
                out.append(make_lead(
                    "TX_ORIGIN_AUTH",
                    "tx.origin hadir di luar konteks auth (murni info)",
                    "low", 1, rel, i, _snippet_of(orig, i),
                    "tx.origin tidak dipakai untuk auth di baris ini, "
                    "tapi kehadirannya perlu ditinjau.",
                    "Pastikan tidak bocor ke logika keputusan.",
                    note="pola tidak pasti — bukan indikasi auth.",
                    confidence=0.3))
    return out


_UNCHECKED_STMT_RE = re.compile(
    r"^\s*(?:payable\s*\([^()]*\)|\w+\([^()]*\)|[\w\]\)$.]+)"
    r"\.(?:send|transfer|call)\s*[\({]")
_CAPTURED_RE = re.compile(r"\(bool\s|\(,|=\s*[\w\]\)$.]+\.(?:send|transfer|"
                          r"call)|require\(|if\s*\(|assert\(")


def check_unchecked_return(rel: str, mlines: list[str],
                           orig: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, raw in enumerate(mlines, 1):
        if not _UNCHECKED_STMT_RE.match(raw):
            continue
        if _CAPTURED_RE.search(raw):
            continue
        out.append(make_lead(
            "UNCHECKED_CALL_RETURN",
            "Return value external call diabaikan",
            "medium", 2, rel, i, _snippet_of(orig, i),
            "Statement " + raw.strip()[:80] + " tidak menangkap bool "
            "success; kegagalan call diam-diam diabaikan.",
            "Tangkap return: (bool ok, ) = ...; require(ok);",
            confidence=0.75))
    return out


_DELEGATECALL_RE = re.compile(r"([\w\]\)$.]+)\.delegatecall\s*\(")


def check_delegatecall(fn: FunctionDef, rel: str, lines: list[str],
                       const_names: set[str]) -> list[dict]:
    out: list[dict] = []
    param_names = {p.strip().split()[-1].rstrip(")")
                   for p in fn.params_raw.split(",") if p.strip()}
    body_lines = fn.body.splitlines()
    for i, raw in enumerate(body_lines, 1):
        m = _DELEGATECALL_RE.search(raw)
        if not m:
            continue
        recv = m.group(1).split(".")[-1].strip()
        fixed = (recv in const_names or recv.isupper()
                 or recv.startswith("_IMPL") or recv == "address"
                 or "0x" in m.group(1) or "this" == recv.split("(")[0])
        ln = fn.line + i - 1
        if fixed:
            out.append(make_lead(
                "DELEGATECALL_DYNAMIC",
                "delegatecall dengan target konstan (tinjau implementasi)",
                "low", 1, rel, ln, _snippet_of(lines, ln),
                f"Target {m.group(1)} tampak konstan/immutable — "
                "delegatecall tetap menjalankan kode asing di storage ini; "
                "pastikan implementasi diaudit dan slot EIP-1967 benar.",
                "Audit kontrak implementasi + verifikasi slot proxy.",
                note="target tampak tetap — bukan temuan dinamis.",
                confidence=0.3))
        else:
            reason = "parameter fungsi" if recv in param_names else \
                     "variabel storage/non-konstan"
            out.append(make_lead(
                "DELEGATECALL_DYNAMIC",
                "delegatecall dengan target dinamis",
                "high", 2, rel, ln, _snippet_of(lines, ln),
                f"Target delegatecall ({recv}) berasal dari {reason} — "
                "kode arbitrer bisa dieksekusi dalam konteks storage "
                "kontrak ini.",
                "Buktikan di Foundry: deploy kontrak jahat, set target, "
                "panggil — lihat storage/owner berubah.",
                confidence=0.8))
    return out


_SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")


def check_selfdestruct(rel: str, mlines: list[str],
                       orig: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, raw in enumerate(mlines, 1):
        if _SELFDESTRUCT_RE.search(raw):
            out.append(make_lead(
                "SELFDESTRUCT_PRESENT",
                "selfdestruct hadir di sumber",
                "low", 2, rel, i, _snippet_of(orig, i),
                "selfdestruct menghancurkan state & mengirim saldo paksa; "
                "kehadirannya perlu justifikasi (pabrik/upgrade lama?).",
                "Tinjau siapa yang bisa mencapai jalur ini (auth path).",
                note=("sejak EIP-6780 (Dencun), efek penghapusan kode hanya "
                      "aktif bila dipanggil di transaksi pembuatan kontrak; "
                      "pengiriman saldo tetap terjadi."),
                confidence=0.7))
    return out


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_SPEC_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _pragma_versions(spec: str) -> list[tuple[int, int, int]]:
    vers = []
    for m in _SPEC_VERSION_RE.finditer(spec):
        major, minor, patch = int(m.group(1)), int(m.group(2)), \
            int(m.group(3) or 0)
        vers.append((major, minor, patch))
    return vers


def check_pragma(rel: str, mlines: list[str],
                 orig: list[str]) -> tuple[list[dict], list[str]]:
    out: list[dict] = []
    specs: list[str] = []
    for i, raw in enumerate(mlines, 1):
        m = _PRAGMA_RE.search(raw)
        if not m:
            continue
        spec = m.group(1).strip()
        specs.append(spec)
        vers = _pragma_versions(spec)
        if not vers:
            out.append(make_lead(
                "PRAGMA_FLOATING",
                "Pragma tidak bisa diparse (fail-closed jadi lead)",
                "low", 1, rel, i, _snippet_of(orig, i, 1),
                f"Spec '{spec}' tidak mengandung versi numerik yang "
                "dikenali — compiler efektif tidak pasti.",
                "Tulis pin persis, mis. pragma solidity 0.8.24;",
                note="parser ringan; spec mungkin valid Solidity.",
                confidence=0.4))
            continue
        lowest = min(vers)
        if lowest < (0, 8, 0):
            has_safemath = bool(re.search(r"\bSafeMath\b",
                                          "\n".join(mlines)))
            out.append(make_lead(
                "PRAGMA_UNCHECKED_ARITHMETIC",
                f"Pragma mengizinkan compiler < 0.8.0 (aritmetika tak "
                f"ter-check)",
                "medium", 2, rel, i, _snippet_of(orig, i, 1),
                f"Spec '{spec}' mencakup versi di bawah 0.8.0; overflow/"
                "underflow tidak otomatis direvert pada rentang itu.",
                "Cek penggunaan SafeMath dan naikkan pin >= 0.8.0.",
                note=("SafeMath terdeteksi di file — mitigasi parsial bila "
                      "dipakai konsisten." if has_safemath else
                      "SafeMath tidak terdeteksi — semua aritmetika "
                      "berisiko overflow di rentang compiler ini."),
                confidence=0.8 if not has_safemath else 0.55))
        if any(sym in spec for sym in ("^", ">=", "*")):
            out.append(make_lead(
                "PRAGMA_FLOATING",
                "Floating pragma (versi tidak di-pin persis)",
                "low", 2, rel, i, _snippet_of(orig, i, 1),
                f"Spec '{spec}' membuka rentang compiler; versi deploy bisa "
                "berbeda dari versi yang diaudit (bug compiler spesifik).",
                "Pin exact: pragma solidity 0.8.24;",
                confidence=0.8))
    return out, specs


_CRITICAL_NAME_RE = re.compile(
    r"^(withdraw|drain|sweep|emergency|upgrade|mint|finalize|migrate|"
    r"rescue|force|claim|execute|withdrawal|initialize)", re.IGNORECASE)


_SELF_SERVICE_RE = re.compile(r"\[\s*msg\.sender\s*\]")
_POOL_DRAIN_RE = re.compile(
    r"\.(?:send|transfer|call)\s*[\({][^;\n]*address\(this\)\.balance"
    r"|\.(?:send|transfer|call)\s*[\({][^;\n]*total(?:Assets|Balance)")


def check_access_control(fn: FunctionDef, rel: str, lines: list[str],
                         defined_modifiers: set[str]) -> list[dict]:
    out: list[dict] = []
    if not _CRITICAL_NAME_RE.match(fn.name):
        return out
    if fn.visibility not in ("public", "external"):
        return out
    guarded = fn.has_guard() or any(
        mod.lower().startswith("only") or mod in defined_modifiers
        for mod in fn.modifiers)
    mutates = bool(re.search(r"(\+=|-=|\*=|/=(?!=))|[^=!<>]=(?!=)",
                             fn.body)) or bool(re.search(
        r"\.(?:transfer|send|call|mint|burn)\s*[\({]", fn.body))
    if guarded or not mutates:
        return out
    # Self-service (semua penulisan berkunci msg.sender, tanpa menguras
    # pool bersama) = pola wajar utk withdraw milik sendiri — bukan lead
    # akses; drain pool bersama tetap ditandai.
    self_service = bool(_SELF_SERVICE_RE.search(fn.body))
    pool_drain = bool(_POOL_DRAIN_RE.search(fn.body))
    if self_service and not pool_drain:
        return out
    is_initialize = fn.name.lower() == "initialize"
    out.append(make_lead(
        "CRITICAL_UNGUARDED",
        f"Fungsi kritikal {fn.name}() publik tanpa guard akses terlihat",
        "high" if is_initialize or fn.name.lower().startswith(
            ("withdraw", "drain", "sweep", "upgrade")) else "medium",
        2, rel, fn.line, _snippet_of(lines, fn.line, 3),
        f"{fn.signature_head} ... — visibility {fn.visibility}, mutasi "
        "state/transfer aset, dan TIDAK ada guard (modifier only*/cek "
        "msg.sender) di signature maupun body yang dipindai."
        + (" Ia menguras saldo pool kontrak secara keseluruhan."
           if pool_drain else ""),
        "Verifikasi manual: apakah guard diwariskan dari base contract "
        "yang tidak ikut dipindai? Jika tidak, tulis PoC panggil langsung.",
        note=("pindai ringan tidak mengikuti pewarisan — guard bisa ada di "
              "kontrak induk (salah positif mungkin; cek 'is' clause)."),
        confidence=0.6 if "is " in "\n".join(lines[:fn.line]) else 0.7))
    return out


_ROUND_DATA_RE = re.compile(r"latestRoundData\s*\(")
_PYTH_RE = re.compile(r"getPriceUnsafe\s*\(|getPrice\s*\(")
_STALE_CHECK_RE = re.compile(
    r"updatedAt|answeredInRound|startedAt|MAX_AGE|maxAge|staleness|"
    r"block\.timestamp\s*-\s*\w+\s*[<>]=")


def check_oracle(fn: FunctionDef, rel: str, lines: list[str]) -> list[dict]:
    out: list[dict] = []
    body = fn.body
    ln = fn.line
    if _ROUND_DATA_RE.search(body):
        if not _STALE_CHECK_RE.search(body):
            out.append(make_lead(
                "ORACLE_STALENESS",
                "latestRoundData tanpa cek staleness di " + fn.name + "()",
                "medium", 2, rel, ln, _snippet_of(lines, ln, 3),
                "latestRoundData dipanggil tanpa membaca/cek updatedAt "
                "(atau answeredInRound) — harga basi bisa dipakai tanpa "
                "batas waktu saat feed macet.",
                "Ambil updatedAt, require(block.timestamp - updatedAt "
                "<= MAX_AGE) + require(answeredInRound >= roundId).",
                confidence=0.75))
        if not re.search(r"[a-zA-Z_$][\w$]*\s*(?:<=|<)\s*0"
                         r"|>\s*0\s*[,)]", body):
            out.append(make_lead(
                "ORACLE_STALENESS",
                "Harga feed tidak di-validasi > 0 di " + fn.name + "()",
                "low", 1, rel, ln, _snippet_of(lines, ln, 3),
                "Tidak terlihat cek harga positif — round kosong/feed "
                "error bisa mengembalikan 0 atau negatif.",
                "require(price > 0).",
                note="pola tidak pasti (cek bisa pakai nama lain).",
                confidence=0.4))
    if _PYTH_RE.search(body) and not re.search(r"\bconf\b|confidence",
                                               body):
        out.append(make_lead(
            "ORACLE_STALENESS",
            "Pyth price tanpa cek confidence interval di " + fn.name + "()",
            "medium", 2, rel, ln, _snippet_of(lines, ln, 3),
            "getPriceUnsafe/getPrice dipakai tanpa memeriksa conf — harga "
            "dengan interval kepercayaan lebar tetap diterima.",
            "require(p.conf * 10 <= uint64(p.price)).",
            confidence=0.7))
    if re.search(r"\.slot0\s*\(|getReserves\s*\(\)", body) and re.search(
            r"price|amountOut|quote|convert", body, re.IGNORECASE):
        out.append(make_lead(
            "ORACLE_STALENESS",
            "Spot price DEX dipakai sebagai harga (" + fn.name + "())",
            "medium", 1, rel, ln, _snippet_of(lines, ln, 3),
            "slot0()/getReserves() memberi harga spot yang bisa digeser "
            "flash loan dalam satu transaksi.",
            "Pakai TWAP window >= 30 menit atau oracle independen; "
            "verifikasi dengan simulasipinjam-kilat.",
            note="pola tidak pasti — konteks pemakaian perlu ditinjau.",
            confidence=0.5))
    return out


_MEV_ZERO_MIN_RE = re.compile(
    r"amountOutMin\s*,\s*0\s*[,)]|amountOutMIN\s*,\s*0\s*[,)]"
    r"|For(?:Tokens|ETH)\w*\s*\(\s*[^,()]+,\s*0\s*,")
_SWAP_RE = re.compile(r"swapExact(?:Tokens|ETH)For")
_MEV_TS_RANDOM_RE = re.compile(
    r"(?:=\s*block\.timestamp[^;\n]*%|%\s*block\.timestamp|"
    r"block\.timestamp\s*%\s*\d|uint256\s+rand|randomness\s*=\s*block)")


def check_ordering_mev(rel: str, mlines: list[str],
                       orig: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, raw in enumerate(mlines, 1):
        # window statement multi-baris: deadline/argumen sering di
        # baris lanjutan pemanggilan (anti-FP deklarasi interface).
        window = "\n".join(mlines[i - 1:min(len(mlines), i + 6)])
        if _SWAP_RE.search(raw):
            if _MEV_ZERO_MIN_RE.search(window):
                out.append(make_lead(
                    "ORDERING_MEV",
                    "Swap dengan amountOutMin = 0",
                    "medium", 2, rel, i, _snippet_of(orig, i, 3),
                    "amountOutMin=0 membuat transaksi mudah disandwich "
                    "(sandwich-able) — slippage tak terbatas berarti "
                    "rugi penuh.",
                    "Hitung min dari pool + toleransi; uji di fork dengan "
                    "pool digeser dulu.",
                    confidence=0.8))
            elif "deadline" not in window:
                out.append(make_lead(
                    "ORDERING_MEV",
                    "Swap router tanpa parameter deadline",
                    "low", 1, rel, i, _snippet_of(orig, i, 3),
                    "Swap tanpa deadline bisa dieksekusi jauh setelah "
                    "disetujui (stale price).",
                    "Tambahkan deadline = block.timestamp + N.",
                    note="deadline mungkin diatur default router.",
                    confidence=0.4))
    joined = "\n".join(mlines)
    if _MEV_TS_RANDOM_RE.search(joined):
        for i, raw in enumerate(mlines, 1):
            if re.search(r"block\.timestamp|blockhash\s*\(", raw) and \
                    re.search(r"%|rand|random|seed|nonce", raw,
                              re.IGNORECASE):
                out.append(make_lead(
                    "ORDERING_MEV",
                    "block.timestamp/blockhash sebagai entropi keputusan",
                    "medium", 2, rel, i, _snippet_of(orig, i),
                    "Validator/miner bisa menggeser timestamp/memilih "
                    "hash — hasil 'acak' dipengaruhi pihak yang memesan "
                    "transaksi.",
                    "Pakai VRF/commit-reveal; demo manipulasi di Foundry "
                    "dengan vm.warp.",
                    confidence=0.65))
                break
    return out


# ── Orkestrasi scan per file ─────────────────────────────────────────────────

def scan_source(rel: str, source: str) -> tuple[list[dict], dict]:
    stripped = strip_comments_strings(source)
    mlines = stripped.splitlines()      # baris utk pencocokan (anti-FP)
    orig_lines = source.splitlines()    # baris asli utk bukti/snippet
    fns = extract_functions(stripped)
    defined_modifiers = extract_modifiers(stripped)
    const_names = set(re.findall(
        r"\b(?:[A-Za-z_$][\w$]*)\s+(?:public\s+)?(?:constant|immutable)\b",
        stripped))
    findings: list[dict] = []
    for fn in fns:
        findings += check_reentrancy(fn, rel, orig_lines)
        findings += check_delegatecall(fn, rel, orig_lines, const_names)
        findings += check_access_control(fn, rel, orig_lines,
                                         defined_modifiers)
        findings += check_oracle(fn, rel, orig_lines)
    findings += check_tx_origin(rel, mlines, orig_lines)
    findings += check_unchecked_return(rel, mlines, orig_lines)
    findings += check_selfdestruct(rel, mlines, orig_lines)
    pragma_f, specs = check_pragma(rel, mlines, orig_lines)
    findings += pragma_f
    findings += check_ordering_mev(rel, mlines, orig_lines)

    # selector table
    functions: list[dict] = []
    for fn in fns:
        sig = canonical_signature(fn.name, fn.params_raw)
        sel = None
        if sig:
            sel = "0x" + keccak256(sig.encode()).hex()[:8]
        functions.append({
            "name": fn.name, "signature": sig, "selector": sel,
            "line": fn.line, "visibility": fn.visibility,
            "contract": fn.contract,
        })
    return findings, {
        "functions": functions,
        "pragma_specs": specs,
        "contracts": sorted(set(fn.contract for fn in fns if fn.contract)),
    }


def collect_sol_files(target: Path, recursive: bool,
                      exclude: set[str]) -> list[Path]:
    if target.is_file():
        return [target]
    it = target.rglob("*.sol") if recursive else target.glob("*.sol")
    files = [p for p in it if not any(part in exclude for part in p.parts)]
    return sorted(files)


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="solidity_static_audit — 10 kelas bug statis pada "
                    "sumber .sol; lead ber-eviden maks L2; tanpa compiler, "
                    "tanpa eksekusi, tanpa jaringan (fail-closed).")
    ap.add_argument("target", help="file .sol atau direktori")
    ap.add_argument("--recursive", "-r", action="store_true",
                    help="pindai direktori secara rekursif")
    ap.add_argument("--exclude", nargs="*", default=[],
                    help="nama direktori yang dilewati")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=("low", "medium", "high", "any"),
                    help="exit 1 bila ada temuan seberat itu "
                         "(any = semua kecuali info)")
    ap.add_argument("--quiet", action="store_true",
                    help="cetak ringkasan saja")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    try:
        _keccak_selftest()
    except RuntimeError as exc:
        print(f"[sol-audit] gagal internal: {exc}", file=sys.stderr)
        return 2
    args = _parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        print(f"[sol-audit] gagal: target tidak ada: {target}",
              file=sys.stderr)
        return 2
    files = collect_sol_files(target, args.recursive,
                              set(args.exclude) |
                              {"node_modules", "lib", ".git", "test",
                               "tests", "mock", "mocks", "out", "cache"})
    if not files:
        print("[sol-audit] gagal: tidak ada file .sol ditemukan — "
              "tidak boleh melaporkan scan kosong sebagai sukses",
              file=sys.stderr)
        return 2
    all_findings: list[dict] = []
    errors: list[str] = []
    file_meta: dict[str, dict] = {}
    for f in files:
        try:
            source = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{f}: {exc}")
            continue
        rel = str(f)
        findings, meta = scan_source(rel, source)
        for fd in findings:
            fd["id"] = _lead_id(fd)
        all_findings += findings
        file_meta[rel] = meta
    if errors:
        for e in errors:
            print(f"[sol-audit] error baca: {e}", file=sys.stderr)
        return 2  # fail-closed: jangan lapor hasil parsial sebagai sukses
    sev_rank = {f["severity"] for f in all_findings}
    order = [s for s in SEVERITY_ORDER if s in sev_rank]
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                     f["class_id"], f["line"]))
    by_class: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_verdict: dict[int, int] = {}
    for f in all_findings:
        by_class[f["class_id"]] = by_class.get(f["class_id"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_verdict[f["verdict"]] = by_verdict.get(f["verdict"], 0) + 1
    result = {
        "schema": SCHEMA,
        "tool": TOOL,
        "target": str(target),
        "files_scanned": len(files),
        "summary": {
            "total": len(all_findings),
            "by_class": by_class,
            "by_severity": by_sev,
            "by_verdict": {f"L{v}": c for v, c in sorted(by_verdict.items())},
            "severities_present": order,
        },
        "findings": all_findings,
        "functions_by_file": {k: v["functions"] for k, v in
                              file_meta.items()},
        "pragma_specs": {k: v["pragma_specs"] for k, v in
                         file_meta.items()},
        "contracts": {k: v["contracts"] for k, v in file_meta.items()},
        "limits": [
            "analisis teks/struktur statis; TANPA compiler Solidity dan "
            "TANPA eksekusi — tidak ada klaim 'vulnerable'; semua temuan "
            "= lead maks L2 dengan status unconfirmed",
            "pewarisan lintas-kontrak & interface TIDAK diikuti — guard "
            "bisa ada di kontrak induk yang tidak ikut dipindai",
            "tidak ada data on-chain/harga/likuiditas di tool ini; "
            "verifikasi live wajib sebelum naik verdict",
            "selector = keccak256(signature kanonik)[:4]; tuple/struct/"
            "mapping -> selector null (butuh ekspansi ABI penuh)",
        ],
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    dist = ", ".join(f"{k}={v}" for k, v in s["by_class"].items())
    print(f"[sol-audit] {len(files)} file .sol; "
          f"{s['total']} lead ({dist or 'bersih'}); "
          f"sev={order or '-'}")
    if not args.quiet:
        for f in all_findings[:12]:
            print(f"  [{f['severity']:6}] {f['verdict_tag']:22} "
                  f"{f['class_id']:28} {f['file']}:{f['line']}")
        if len(all_findings) > 12:
            print(f"  ... {len(all_findings) - 12} lead lagi "
                  f"(--out utk lengkap)")
    if args.fail_on:
        floor = 4 if args.fail_on == "any" else SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f["severity"], 9) <= floor
               for f in all_findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
