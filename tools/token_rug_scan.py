"""[AUDIT: static] token_rug_scan — postur rug-token dari SUMBER kontrak
(.sol): vektor mint, blacklist, proxy/upgradeability, fee, anti-whale,
pola honeypot, sinyal fake-renounce, kontrol LP — plus CATATAN jujur utk
klaim LP/lock yang tidak bisa diverifikasi offline.

Ranah (ANTI-TABRAKAN ABH-PORT): semua .sol/token = W2. Tool ini TIDAK
mengklaim harga, kedalaman likuiditas, distribusi holder, riwayat
deployer, atau state authority on-chain — semuanya butuh data live
(di luar tool; dicatat eksplisit di "offline_limits" output). Klaim
LP/lock yang hanya TERTULIS di sumber dikeluarkan sebagai note (verdict
L0 OBSERVED) dengan peringatan "deklarasi source != kunci on-chain".

Kategori yang dipindai (id -> pola):
  1. MINT_UNBOUNDED          — mint()/  _mint( tanpa cap supply di fungsi
                               yang sama; _balances[..] += / totalSupply
                               += langsung (manipulasi pasokan).
  2. BLACKLIST_CONTROL       — var/setter blacklist; ada di jalur transfer
                               -> bisa memblokir jual (honeypot vektor).
  3. PROXY_UPGRADEABILITY    — delegatecall, upgradeTo/UUPS/ERC1967/
                               Transparent, initialize() tanpa
                               _disableInitializers / initializer.
  4. FEE_UNBOUNDED           — setter fee/tax tanpa batas require <= MAX;
                               exclusion-fee mapping.
  5. WHALE_GUARD_BYPASSABLE  — setter maxTx/maxWallet tanpa floor, atau
                               saklar removeLimits/disableLimits.
  6. HONEYPOT_SELL_PATTERN   — toggle trading yang bisa dimatikan lagi,
                               jalur jual dibatasi logic khusus, override
                               approve tanpa super/_approve, cooldown tak
                               berbatas.
  7. FAKE_RENOUNCE_SIGNALS   — renounceOwnership di-override, variabel
                               admin bayangan, selfdestruct.
  8. LP_CONTROL              — setPair/setRouter/migrate/emergencyWithdraw/
                               rescueTokens (drain/migrasi likuiditas).
  9. LP_LOCK_NOTE            — sebutan LP lock/locker di source -> note
                               jujur (bukan klaim aman).

Kontrak verdict (core/findings.py): lead = status "unconfirmed", verdict
L1/L2 (maks L2 — tanpa eksekusi tidak ada klaim "vulnerable"); note
LP-lock = verdict 0 (OBSERVED — teks memang ada). Pola tak pasti selalu
disertai "note" eksplisit + confidence rendah.

Fail-closed:
  - target tidak ada, file tak terbaca, tidak ada .sol ditemukan, atau
    self-test keccak gagal -> exit 2 (tidak ada "scan aman" palsu).
  - komentar/string dilucuti (anti-FP dari teks di komentar).

Pemakaian:
  python tools/token_rug_scan.py Token.sol --json
  python tools/token_rug_scan.py contracts/ -r --out rug.json
  python tools/token_rug_scan.py Token.sol --fail-on high
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.token_rug_scan.v1"
TOOL = "token_rug_scan"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# reuse engine dari solidity_static_audit (tool saudari, satu ranah W2)
# + tag verdict dari satu pintu core (kontrak findings repo)
_TOOLS_DIR = Path(__file__).resolve().parent
_ROOT = _TOOLS_DIR.parent
for _p in (str(_TOOLS_DIR), str(_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from solidity_static_audit import (  # noqa: E402
    FunctionDef, _keccak_selftest, extract_functions,
    strip_comments_strings,
)
from findings import verdict_tag  # noqa: E402

# ── Kerangka temuan ──────────────────────────────────────────────────────────


def _lead_id(class_id: str, rel: str, line: int) -> str:
    basis = "|".join([TOOL, class_id, rel, str(line)])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def make_lead(class_id: str, title: str, severity: str, verdict: int,
              file_path: str, line: int, snippet: str, rationale: str,
              verify_hint: str, note: str = "",
              confidence: float | None = None) -> dict:
    if verdict not in (0, 1, 2):
        raise ValueError("token_rug_scan hanya mengeluarkan L0/L1/L2")
    if confidence is None:
        confidence = {0: 1.0, 1: 0.5, 2: 0.75}[verdict]
    tag = verdict_tag(verdict)  # satu pintu kontrak verdict repo
    return {
        "class_id": class_id,
        "title": title,
        "severity": severity,
        "status": "unconfirmed",
        "verdict": verdict,
        "verdict_tag": tag,
        "reportable": False,
        "confidence": round(confidence, 2),
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


_STD_MOVER_RE = re.compile(
    r"^(?:mint|_mint|burn|_burn|transfer|transferFrom|_transfer|_update|"
    r"_spendAllowance|_beforeTokenTransfer|_afterTokenTransfer)$")


def _fn_body_lines(fns: list[FunctionDef], only_standard: bool = False) -> \
        set[int]:
    """Himpunan nomor baris yang berada di body fungsi (opsional: hanya
    fungsi pemindah-pasokan standar ERC20) — untuk anti-FP konteks."""
    out: set[int] = set()
    for fn in fns:
        if only_standard and not _STD_MOVER_RE.match(fn.name):
            continue
        out.update(range(fn.line, fn.end_line + 1))
    return out


# ── Pola per kategori ────────────────────────────────────────────────────────

_MINT_FN_RE = re.compile(r"\bfunction\s+\w*mint\w*\s*\(", re.IGNORECASE)
_MINT_CALL_RE = re.compile(r"_mint\s*\(")
_CAP_RE = re.compile(
    r"(?:require|if)\s*\([^;]*(?:maxSupply|MAX_SUPPLY|MAX_TOTAL|"
    r"MAX_BALANCE|maxBalance|cap)"
    r"|totalSupply\(\)\s*\+\s*\w+\s*<=|_totalSupply\s*\+\s*\w+\s*<=",
    re.IGNORECASE)
_DIRECT_BAL_RE = re.compile(r"_balances\s*\[[^\]]+\]\s*\+=")
_DIRECT_TS_RE = re.compile(r"\b_totalSupply?\s*\+=|totalSupply\s*\+=")


def check_mint(fns: list[FunctionDef], rel: str, orig: list[str],
               mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    std_lines = _fn_body_lines(fns, only_standard=True)
    # pemetaan baris -> fungsi non-standar pemilik baris (untuk konteks)
    nonstd = [(fn.name, range(fn.line, fn.end_line + 1)) for fn in fns
              if not _STD_MOVER_RE.match(fn.name)]

    def _owner_of(ln: int) -> str:
        for name, span in nonstd:
            if ln in span:
                return name
        return ""

    for fn in fns:
        if not (_MINT_FN_RE.search(fn.head) or _MINT_CALL_RE.search(fn.body)):
            continue
        if fn.name in ("_mint", "_burn", "_mintBatch"):
            continue
        has_cap = bool(_CAP_RE.search(fn.body))
        ln = fn.line
        if has_cap:
            out.append(make_lead(
                "MINT_UNBOUNDED",
                f"Mint dengan tanda cap di {fn.name}() — verifikasi "
                f"kelengkapannya",
                "low", 1, rel, ln, _snippet_of(orig, ln, 3),
                "Ada konstanta cap/syarat supply di body — pastikan SEMUA "
                "jalur mint melewatinya (sibling check).",
                "Cek semua pemanggil _mint/ mint lain di kontrak.",
                note="cap terdeteksi — bukan vektor tanpa batas.",
                confidence=0.35))
        else:
            out.append(make_lead(
                "MINT_UNBOUNDED",
                f"Mint tanpa cap supply di {fn.name}()",
                "high", 2, rel, ln, _snippet_of(orig, ln, 3),
                f"{fn.name}() mencetak pasokan baru tanpa batas "
                "MAX_SUPPLY yang terlihat di body — pemegang authority "
                "bisa menambah pasokan kapan pun (dilusi holder).",
                "Tulis test: panggil mint berulang, cek totalSupply "
                "melewati anggaran publik; verifikasi siapa yang punya "
                "akses (authority path).",
                confidence=0.7))
    for i, raw in enumerate(mlines, 1):
        if _DIRECT_BAL_RE.search(raw) and i not in std_lines:
            out.append(make_lead(
                "MINT_UNBOUNDED",
                "Manipulasi saldo langsung di luar fungsi pemindah "
                "standar (" + ("di %s()" % _owner_of(i)
                               if _owner_of(i) else "level kontrak") + ")",
                "critical", 2, rel, i, _snippet_of(orig, i),
                "_balances[..] += di luar alur _mint/transfer standar — "
                "pasokan bisa dinaikkan diam-diam tanpa event Transfer.",
                "Buktikan: panggil fungsi pemilik jalur ini, bandingkan "
                "totalSupply vs sum(saldo).",
                confidence=0.8))
        if _DIRECT_TS_RE.search(raw):
            out.append(make_lead(
                "MINT_UNBOUNDED",
                "Manipulasi totalSupply langsung",
                "critical", 2, rel, i, _snippet_of(orig, i),
                "totalSupply diubah langsung tanpa _mint/_burn — "
                "akuntansi pasokan bisa desinkron (rebase tersembunyi).",
                "Audit setiap penulisan ini; harus lewat _mint/_burn.",
                confidence=0.8))
    return out


_BLACKLIST_VAR_RE = re.compile(
    r"\b(?:_?isBlacklisted|_?blacklisted|_?blacklist|isBot|_?bots|"
    r"_?blocked|_?feeWhite?listBlack)\s*(?:\[|mapping)", re.IGNORECASE)
_BLACKLIST_SETTER_RE = re.compile(
    r"\bfunction\s+(?:set(?:Blacklist|Bot|Blocked)|add(?:Blacklist|Bot)|"
    r"blacklist|unblacklist|blockAddress|removeBlacklist)\w*\s*\(",
    re.IGNORECASE)
_BLACKLIST_USE_RE = re.compile(
    r"(?:isBlacklisted|blacklist|isBot|_bots|blocked)\s*\[", re.IGNORECASE)


def check_blacklist(fns: list[FunctionDef], rel: str, orig: list[str],
                    mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    in_fn = _fn_body_lines(fns)
    var_lines = [i for i, raw in enumerate(mlines, 1)
                 if _BLACKLIST_VAR_RE.search(raw) and i not in in_fn]
    setter_lines = [fn.line for fn in fns
                    if _BLACKLIST_SETTER_RE.search(fn.head)]
    used_in_transfer = any(
        _BLACKLIST_USE_RE.search(fn.body) and re.search(
            r"transfer|_beforeToken|_update", fn.name, re.IGNORECASE)
        for fn in fns)
    for i in var_lines:
        out.append(make_lead(
            "BLACKLIST_CONTROL",
            "Struktur data blacklist hadir",
            "high" if used_in_transfer else "medium", 2, rel, i,
            _snippet_of(orig, i),
            "Kontrak menyimpan daftar alamat yang dibatasi. Bila bisa diisi "
            "pemilik, jual semua holder bisa diblokir (honeypot).",
            "Cek siapa penulisnya + apakah DEX pair bisa masuk daftar.",
            note=("dipakai di jalur transfer — vektor blokir-jual "
                  "aktif." if used_in_transfer else
                  "belum terlihat dipakai di jalur transfer."),
            confidence=0.8 if used_in_transfer else 0.55))
    for i in setter_lines:
        out.append(make_lead(
            "BLACKLIST_CONTROL",
            "Setter blacklist tersedia",
            "high" if used_in_transfer else "medium", 2, rel, i,
            _snippet_of(orig, i, 3),
            "Fungsi pengubah blacklist — kombinasi dgn jalur transfer = "
            "saku blokir-jual sewaktu-waktu.",
            "Tulis test: owner menandai pair, cek transfer revert.",
            confidence=0.75))
    return out


_PROXY_RE = re.compile(
    r"\bdelegatecall\b|UUPS|TransparentUpgradeable|ERC1967|upgradeTo|"
    r"\bProxy\b|_IMPLEMENTATION_SLOT|beacon", re.IGNORECASE)
_INITIALIZE_RE = re.compile(r"\bfunction\s+initialize\s*\(")
_DISABLE_INIT_RE = re.compile(r"_disableInitializers\s*\(")
_INITIALIZER_MOD_RE = re.compile(r"\binitializer\b|onlyProxy|reinitializer")


def check_proxy(fns: list[FunctionDef], rel: str, orig: list[str],
                mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    joined = "\n".join(mlines)
    for i, raw in enumerate(mlines, 1):
        if _PROXY_RE.search(raw):
            out.append(make_lead(
                "PROXY_UPGRADEABILITY",
                "Marker upgradeability/proxy hadir",
                "medium", 2, rel, i, _snippet_of(orig, i),
                "Kontrak memakai pola proxy/upgrade — logika bisa diganti "
                "setelah launch oleh pemegang admin proxy.",
                "Identifikasi admin proxy on-chain + timelock/multisig; "
                "tanpa itu = vektor ganti-aturan penuh.",
                confidence=0.65))
    for fn in fns:
        if not _INITIALIZE_RE.search(fn.head):
            continue
        guarded = bool(_INITIALIZER_MOD_RE.search(fn.head)
                       or _DISABLE_INIT_RE.search(fn.body)
                       or fn.has_guard()
                       or any(m.lower().startswith("only")
                              for m in fn.modifiers))
        if not guarded:
            out.append(make_lead(
                "PROXY_UPGRADEABILITY",
                "initialize() tanpa proteksi initializer terlihat",
                "high", 2, rel, fn.line, _snippet_of(orig, fn.line, 3),
                "initialize() publik tanpa modifier initializer/onlyProxy "
                "atau _disableInitializers — siapa pun bisa mengambil "
                "state owner (Wormhole-class).",
                "Panggil initialize() dgn alamatmu di fork; jika sukses = "
                "takeover konfirmasi.",
                note="guard bisa diwariskan dari base yang tak dipindai.",
                confidence=0.6))
    if _DISABLE_INIT_RE.search(joined):
        out.append(make_lead(
            "PROXY_UPGRADEABILITY",
            "_disableInitializers ada — implementasi mengunci diri",
            "low", 0, rel,
            next(i for i, raw in enumerate(mlines, 1)
                 if _DISABLE_INIT_RE.search(raw)),
            "", "Implementasi melindungi diri dari init langsung — baik.",
            "Verifikasi versi OZ >= 4.9 di lockfile deployment.",
            note="catatan positif; bukan klaim aman menyeluruh.",
            confidence=1.0))
    return out


_FEE_SETTER_RE = re.compile(
    r"\bfunction\s+set(?:Fees?|Tax(?:es)?|BuyFee|SellFee|FeesBps|"
    r"MarketingFee|DevFee|LiquidityFee)\w*\s*\(", re.IGNORECASE)
_FEE_BOUND_RE = re.compile(r"require\s*\([^)]*(?:<=|<)\s*(?:MAX|max|\d{1,2})")
_FEE_EXCLUDE_RE = re.compile(
    r"isExcludedFromFee|_isExcluded|excludeFromFee|_feeExcluded",)


def check_fee(fns: list[FunctionDef], rel: str, orig: list[str],
              mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    for fn in fns:
        if not _FEE_SETTER_RE.search(fn.head):
            continue
        bounded = bool(_FEE_BOUND_RE.search(fn.body))
        out.append(make_lead(
            "FEE_UNBOUNDED",
            f"Setter fee {fn.name}() "
            + ("berbatas (tetap bisa diubah)" if bounded
               else "TANPA batas terlihat"),
            "medium" if bounded else "high", 2 if not bounded else 1,
            rel, fn.line, _snippet_of(orig, fn.line, 3),
            ("Ada require <= batas kecil di body — fee tetap milik owner "
             "tapi terbatas." if bounded else
             "Tidak terlihat require fee <= MAX — fee bisa dinaikkan ke "
             "99-100% (jual = rugi total) setelah likuiditas terkumpul."),
            ("Baca nilai MAX + siapa yang bisa set; cek juga setter "
             "terpisah buy/sell." if bounded else
             "Buktikan di fork: set fee 99%, jalur jual holder habis."),
            note=("batas dikenali via pola require — verifikasi nilai "
                  "aslinya." if bounded else
                  "batas bisa memakai nama lain (salah negatif mungkin)."),
            confidence=0.7 if not bounded else 0.4))
    for i, raw in enumerate(mlines, 1):
        if _FEE_EXCLUDE_RE.search(raw):
            out.append(make_lead(
                "FEE_UNBOUNDED",
                "Daftar pengecualian fee hadir",
                "medium", 2, rel, i, _snippet_of(orig, i),
                "Alamat tertentu bebas fee — pemilik bisa jual tanpa pajak "
                "sementara holder terpajak (asimetri rug).",
                "Cek apakah owner/pair masuk daftar pengecualian default.",
                confidence=0.6))
    return out


_MAXTX_VAR_RE = re.compile(
    r"\b_?max(?:Tx|Transaction)Amount|maxWallet(?:Amount|Size)?\b",
    re.IGNORECASE)
_LIMITS_SETTER_RE = re.compile(
    r"\bfunction\s+(?:setMax(?:Tx|Wallet|Transaction)\w*|removeLimits|"
    r"disableLimits|setLimitsEnabled|updateMaxTx\w*)\s*\(",
    re.IGNORECASE)
_LIMITS_FLOOR_RE = re.compile(
    r"require\s*\([^)]*(?:>=\s*\d|_tTotal\s*/|totalSupply\s*\(\)\s*/)")
_LIMITS_OFF_RE = re.compile(
    r"removeLimits|disableLimits|limitsEnabled\s*=\s*false|"
    r"_limitsEnabled\s*=\s*false")


def check_whale(fns: list[FunctionDef], rel: str, orig: list[str],
                mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    in_fn = _fn_body_lines(fns)
    var_lines = [i for i, raw in enumerate(mlines, 1)
                 if _MAXTX_VAR_RE.search(raw) and "=" in raw
                 and i not in in_fn]
    for fn in fns:
        if _LIMITS_SETTER_RE.search(fn.head):
            floored = bool(_LIMITS_FLOOR_RE.search(fn.body))
            off_switch = bool(_LIMITS_OFF_RE.search(fn.body))
            sev = "medium" if floored else "high"
            out.append(make_lead(
                "WHALE_GUARD_BYPASSABLE",
                f"Setter batas transaksi {fn.name}() "
                + ("berfloor" if floored else "tanpa floor terlihat"),
                sev, 2 if not floored else 1, rel, fn.line,
                _snippet_of(orig, fn.line, 3),
                ("Batas maxTx/maxWallet punya floor relatif supply — "
                 "tetap cek nilainya." if floored else
                 "Batas bisa diturunkan tanpa floor (bahkan 0 = blokir "
                 "semua jual, atau dibesarkan tanpa batas)."),
                "Panggil setter dgn nilai ekstrem di fork; lihat transfer "
                "terblokir/kebebasan penuh.",
                note=("floor terdeteksi via pola require — verifikasi "
                      "angka." if floored else
                      "floor bisa ditulis dengan pola lain."),
                confidence=0.7 if not floored else 0.4))
            if off_switch:
                out.append(make_lead(
                    "WHALE_GUARD_BYPASSABLE",
                    "Saklar mematikan batas anti-whale di tangan owner",
                    "medium", 2, rel, fn.line, _snippet_of(orig, fn.line, 3),
                    "Fungsi ini bisa mematikan batas transaksi — perlindungan "
                    "anti-whale bersifat sementara.",
                    "Catat event saklar + verifikasi one-way atau dua arah.",
                    confidence=0.7))
    for i in var_lines[:1]:
        out.append(make_lead(
            "WHALE_GUARD_BYPASSABLE",
            "Batas maxTx/maxWallet dideklarasikan",
            "low", 1, rel, i, _snippet_of(orig, i),
            "Ada batas ukuran transaksi — periksa apakah bisa dimatikan "
            "owner (lihat setter).",
            "Ikuti setter-nya; batas permanen = aman-kan catatan.",
            note="deklarasi saja — belum tentu vektor.",
            confidence=0.3))
    return out


_TRADING_TOGGLE_RE = re.compile(
    r"\b(?:tradingEnabled|tradingActive|_tradingOpen|canTrade|"
    r"tradingOpen|isTradingEnabled)\b", re.IGNORECASE)
_SELL_PATH_RE = re.compile(
    r"(?:to|recipient|_to)\s*==\s*(?:uniswapV2Pair|pancakePair|_pair|pair)\b"
    r"|(?:isSell|sellLimit|canSell|maxSell|_sellAllowed)", re.IGNORECASE)
_APPROVE_OVERRIDE_RE = re.compile(
    r"\bfunction\s+approve\s*\([^)]*\)\s*[^{]*\b(?:override|virtual)\b")
_COOLDOWN_RE = re.compile(
    r"\b(?:cooldown|_lastSell|_lastTx|tradeCooldown)\s*\[|"
    r"\bcooldown[A-Za-z]*\s*=\s*\d", re.IGNORECASE)


def check_honeypot(fns: list[FunctionDef], rel: str, orig: list[str],
                   mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    joined = "\n".join(mlines)
    toggle_lines = [i for i, raw in enumerate(mlines, 1)
                    if _TRADING_TOGGLE_RE.search(raw)]
    for fn in fns:
        if not re.search(r"(?:enable|set|open|start)\w*[Tt]rading|"
                         r"openTrading", fn.name):
            continue
        param_bool = bool(re.search(r"\bbool\s+\w+", fn.params_raw))
        body_sets = bool(re.search(r"=\s*(?:true|false|\w+)", fn.body))
        if param_bool or re.search(r"false|!=", fn.body) or body_sets:
            out.append(make_lead(
                "HONEYPOT_SELL_PATTERN",
                f"Saklar trading {fn.name}() bisa dua arah terlihat",
                "medium", 1, rel, fn.line, _snippet_of(orig, fn.line, 3),
                "Toggle trading tampak menerima nilai/menyetel ulang — "
                "jual bisa DITUTUP lagi setelah terbuka (honeypot stop).",
                "Baca body: apakah hanya true->true satu arah? Tulis test "
                "setel false lalu transfer.",
                note="pola tidak pasti — perlu baca body penuh.",
                confidence=0.45))
    if toggle_lines and not any(re.search(r"enable|open|start", f.name)
                                for f in fns):
        out.append(make_lead(
            "HONEYPOT_SELL_PATTERN",
            "Flag trading ada tanpa fungsi pembuka terlihat",
            "low", 1, rel, toggle_lines[0], _snippet_of(orig,
                                                        toggle_lines[0]),
            "Flag trading diatur dari tempat lain (constructor/interaksi "
            "lain) — asal-usulnya tak terlacak dari file ini.",
            "Temukan penyetel flag di seluruh proyek.",
            note="pola tidak pasti.", confidence=0.3))
    for fn in fns:
        if re.search(r"transfer|_update", fn.name, re.IGNORECASE) and \
                _SELL_PATH_RE.search(fn.body):
            ln = fn.line + next(
                j for j, bl in enumerate(fn.body.splitlines())
                if _SELL_PATH_RE.search(bl))
            out.append(make_lead(
                "HONEYPOT_SELL_PATTERN",
                f"Jalur jual punya cabang logic khusus di {fn.name}()",
                "medium", 2, rel, ln, _snippet_of(orig, ln),
                "Transfer ke pair dibedakan dari transfer biasa — "
                "tempat klasik sembunyinya blokir-jual/fee ekstra.",
                "Cek setiap cabang dgn pair: revert? fee besar? blacklist?",
                confidence=0.55))
    for i, raw in enumerate(mlines, 1):
        if _APPROVE_OVERRIDE_RE.search(raw):
            body_open = "\n".join(lines[i:i + 6])
            delegating = bool(re.search(r"super\.approve|_approve\(",
                                        body_open))
            out.append(make_lead(
                "HONEYPOT_SELL_PATTERN",
                "approve() di-override "
                + ("(mendelegasikan ke super)" if delegating
                   else "tanpa delegasi super terlihat"),
                "medium" if delegating else "high",
                1 if delegating else 2, rel, i, _snippet_of(orig, i, 3),
                ("Override approve tetap jalan ke _approve — risiko "
                 "rendah, tetap tinjau." if delegating else
                 "approve() override TANPA panggil super/_approve yang "
                 "terlihat — persetujuan router bisa diam-diam gagal/"
                 "dibatalkan (jual tak bisa dilakukan)."),
                "Bandingkan allowance sebelum/sesudah approve di fork.",
                note="6 baris pertama body diperiksa saja.",
                confidence=0.5 if delegating else 0.65))
        if _COOLDOWN_RE.search(raw):
            out.append(make_lead(
                "HONEYPOT_SELL_PATTERN",
                "Cooldown transfer/jual hadir",
                "medium", 1, rel, i, _snippet_of(orig, i),
                "Jeda antar-transaksi bisa dipakai memblokir jual bila "
                "nilai ambangnya dikendalikan owner.",
                "Cek setter cooldown: berbatas? sekali set?",
                note="pola tidak pasti.", confidence=0.4))
    if _TRADING_TOGGLE_RE.search(joined) and _BLACKLIST_USE_RE.search(joined):
        out.append(make_lead(
            "HONEYPOT_SELL_PATTERN",
            "Kombinasi flag trading + blacklist di satu kontrak",
            "high", 2, rel, toggle_lines[0] if toggle_lines else 1,
            _snippet_of(orig, toggle_lines[0] if toggle_lines else 1, 1),
            "Postur gabungan: kontrol buka/tutup jual + daftar blokir — "
            "dua mekanisme honeypot independen dalam satu token.",
            "Uji dua-duanya di fork; anggap holder terkunci sampai "
            "terbukti sebaliknya.",
            confidence=0.7))
    return out


_RENOUNCE_OVERRIDE_RE = re.compile(
    r"\bfunction\s+renounceOwnership\s*\([^)]*\)\s*[^{]*override\b")
_SHADOW_ADMIN_RE = re.compile(
    r"\b_?shadowAdmin|_?backupOwner|_?secondOwner|_?hiddenOwner|"
    r"_?realOwner|_?masterAdmin", re.IGNORECASE)


def check_fake_renounce(rel: str, orig: list[str],
                        mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, raw in enumerate(mlines, 1):
        if _RENOUNCE_OVERRIDE_RE.search(raw):
            window = "\n".join(mlines[i - 1:i + 8])
            transfers_zero = bool(re.search(
                r"_transferOwnership\s*\(\s*address\s*\(\s*0\s*\)|"
                r"owner\s*=\s*address\s*\(\s*0\s*\)", window))
            out.append(make_lead(
                "FAKE_RENOUNCE_SIGNALS",
                "renounceOwnership di-override "
                + ("(meneruskan ke nol — wajar)" if transfers_zero
                   else "TANPA transfer ke address(0) terlihat"),
                "medium" if transfers_zero else "critical",
                1 if transfers_zero else 2, rel, i,
                _snippet_of(orig, i, 4),
                ("Override tetap melepaskan ownership ke nol — tetap "
                 "verifikasi." if transfers_zero else
                 "Renounce di-override tanpa nol yang terlihat — "
                 "ownership mungkin TIDAK benar-benar dilepas "
                 "(fake renounce)."),
                "Panggil renounce lalu baca owner() di fork.",
                note="8 baris pertama body diperiksa saja.",
                confidence=0.4 if transfers_zero else 0.7))
        if _SHADOW_ADMIN_RE.search(raw):
            out.append(make_lead(
                "FAKE_RENOUNCE_SIGNALS",
                "Variabel admin bayangan hadir",
                "critical", 2, rel, i, _snippet_of(orig, i),
                "Ada nama variabel admin/owner kedua — kontrol bisa "
                "selamat dari renounce (hidden authority).",
                "Telusuri semua penulisan variabel ini + siapa yang "
                "bisa memakainya.",
                confidence=0.75))
    return out


_LP_CONTROL_RE = re.compile(
    r"\bfunction\s+(?:setPair|setNewPair|updatePair|changePair|setRouter|"
    r"updateRouter|changeRouter|migrate(?:LP|Liquidity)?|"
    r"emergencyWithdraw|forceWithdraw|rescueTokens|recoverTokens|"
    r"rescue(?:ETH|ERC20))\w*\s*\(", re.IGNORECASE)


def check_lp_control(fns: list[FunctionDef], rel: str,
                     orig: list[str]) -> list[dict]:
    out: list[dict] = []
    lp_ctx = re.compile(r"pair|router|liquid|lp|IERC20|token",
                        re.IGNORECASE)
    for fn in fns:
        if _LP_CONTROL_RE.search(fn.head) and lp_ctx.search(fn.body):
            out.append(make_lead(
                "LP_CONTROL",
                f"Fungsi kontrol likuiditas {fn.name}() tersedia",
                "high", 2, rel, fn.line, _snippet_of(orig, fn.line, 3),
                f"{fn.name}() dapat mengubah pair/router/menyelamatkan "
                "dana — di tangan pemilik = vektor drain/migrasi "
                "likuiditas.",
                "Cek guard + timelock; tulis skenario drain di fork.",
                confidence=0.65))
    return out


_LP_LOCK_NOTE_RE = re.compile(
    r"\b(?:lpLock|lockLP|lockLiquidity|liquidityLock|LPLocked|locker|"
    r"pinklock|pinksale|unicrypt|uncx|team\.finance|teamfinance|"
    r"mudra|tokenlocker|LPtimeLock|lockTime)\b", re.IGNORECASE)


def check_lp_note(rel: str, orig: list[str],
                  mlines: list[str]) -> list[dict]:
    out: list[dict] = []
    # Kelas ini sengaja mencocokkan baris ASLI (komentar termasuk):
    # klaim "LP akan dikunci" memang hidup di komentar/kode, dan note
    # justru harus menangkap janji tertulis — bukan pola teknis.
    for i, raw in enumerate(orig, 1):
        if _LP_LOCK_NOTE_RE.search(raw):
            out.append(make_lead(
                "LP_LOCK_NOTE",
                "Klaim LP lock tertulis di source (TAK TERVERIFIKASI "
                "offline)",
                "info", 0, rel, i, _snippet_of(orig, i, 1),
                "Sumber menyebut lock/locker LP. Deklarasi di kode/komentar "
                "BUKAN bukti on-chain — token nyata mungkin tak terkunci.",
                "Verifikasi di explorer: alamat locker, tx lock, "
                "kedaluwarsa, dan burn LP.",
                note=("note jujur, bukan klaim aman; tool TIDAK bisa "
                      "memverifikasi lock offline."),
                confidence=1.0))
    return out


# ── Orkestrasi ───────────────────────────────────────────────────────────────

def scan_source(rel: str, source: str) -> tuple[list[dict], dict]:
    stripped = strip_comments_strings(source)
    mlines = stripped.splitlines()   # baris utk pencocokan (anti-FP)
    orig = source.splitlines()       # baris asli utk bukti/snippet
    fns = extract_functions(stripped)
    findings: list[dict] = []
    findings += check_mint(fns, rel, orig, mlines)
    findings += check_blacklist(fns, rel, orig, mlines)
    findings += check_proxy(fns, rel, orig, mlines)
    findings += check_fee(fns, rel, orig, mlines)
    findings += check_whale(fns, rel, orig, mlines)
    findings += check_honeypot(fns, rel, orig, mlines)
    findings += check_fake_renounce(rel, orig, mlines)
    findings += check_lp_control(fns, rel, orig)
    findings += check_lp_note(rel, orig, mlines)
    # dedupe: kelas sama pada baris PERSIS sama = satu kejadian (yang
    # terparah dipertahankan); temuan beda baris tetap dilaporkan karena
    # bisa jadi bukti berbeda (mis. head fungsi vs penulisan di body).
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["line"]))
    kept: list[dict] = []
    for f in findings:
        dup = any(k["class_id"] == f["class_id"] and k["line"] == f["line"]
                  for k in kept)
        if not dup:
            kept.append(f)
    findings = kept
    for f in findings:
        f["id"] = _lead_id(f["class_id"], f["file"], f["line"])

    vectors: dict[str, bool] = {}
    for cls in ("MINT_UNBOUNDED", "BLACKLIST_CONTROL",
                "PROXY_UPGRADEABILITY", "FEE_UNBOUNDED",
                "WHALE_GUARD_BYPASSABLE", "HONEYPOT_SELL_PATTERN",
                "FAKE_RENOUNCE_SIGNALS", "LP_CONTROL", "LP_LOCK_NOTE"):
        vectors[cls] = any(f["class_id"] == cls and f["verdict"] >= 1
                           for f in findings)
    token_like = bool(re.search(
        r"\btotalSupply\b|_balances\s*\[|balanceOf\b|ERC20|_transfer\s*\(",
        stripped))
    return findings, {
        "vectors": vectors,
        "token_like_source": token_like,
        "contracts": sorted({fn.contract for fn in fns if fn.contract}),
    }


def collect_sol_files(target: Path, recursive: bool,
                      exclude: set[str]) -> list[Path]:
    if target.is_file():
        return [target]
    it = target.rglob("*.sol") if recursive else target.glob("*.sol")
    return sorted(p for p in it
                  if not any(part in exclude for part in p.parts))


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="token_rug_scan — postur rug-token dari sumber .sol; "
                    "lead ber-eviden maks L2 + note LP jujur; TANPA klaim "
                    "harga/likuiditas; nol jaringan (fail-closed).")
    ap.add_argument("target", help="file .sol atau direktori")
    ap.add_argument("--recursive", "-r", action="store_true",
                    help="pindai direktori secara rekursif")
    ap.add_argument("--exclude", nargs="*", default=[],
                    help="nama direktori yang dilewati")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    ap.add_argument("--fail-on", choices=("medium", "high", "any"),
                    help="exit 1 bila ada temuan seberat itu "
                         "(any = semua kecuali info)")
    ap.add_argument("--quiet", action="store_true",
                    help="cetak ringkasan saja")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    try:
        _keccak_selftest()
    except RuntimeError as exc:
        print(f"[rug-scan] gagal internal: {exc}", file=sys.stderr)
        return 2
    args = _parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        print(f"[rug-scan] gagal: target tidak ada: {target}",
              file=sys.stderr)
        return 2
    files = collect_sol_files(target, args.recursive,
                              set(args.exclude) |
                              {"node_modules", "lib", ".git", "test",
                               "tests", "mock", "mocks", "out", "cache"})
    if not files:
        print("[rug-scan] gagal: tidak ada file .sol ditemukan — "
              "tidak boleh melaporkan scan kosong sebagai sukses",
              file=sys.stderr)
        return 2
    all_findings: list[dict] = []
    errors: list[str] = []
    vectors: dict[str, bool] = {}
    contracts: list[str] = []
    token_like = False
    for f in files:
        try:
            source = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{f}: {exc}")
            continue
        rel = str(f)
        findings, meta = scan_source(rel, source)
        all_findings += findings
        for k, v in meta["vectors"].items():
            vectors[k] = vectors.get(k, False) or v
        token_like = token_like or meta["token_like_source"]
        contracts += meta["contracts"]
    if errors:
        for e in errors:
            print(f"[rug-scan] error baca: {e}", file=sys.stderr)
        return 2  # fail-closed: jangan lapor hasil parsial sebagai sukses
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
        "token_like_source": token_like,
        "vectors": vectors,
        "summary": {
            "total": len(all_findings),
            "by_class": by_class,
            "by_severity": by_sev,
            "by_verdict": {f"L{v}": c for v, c in sorted(by_verdict.items())},
        },
        "findings": all_findings,
        "contracts": sorted(set(contracts)),
        "offline_limits": [
            "TIDAK ada klaim harga, kedalaman likuiditas, distribusi "
            "holder, atau riwayat deployer — semua butuh data on-chain "
            "live dan berada di luar tool ini",
            "LP lock yang hanya tertulis di source = note L0; verifikasi "
            "nyata butuh explorer/locker (alamat, tx, kedaluwarsa, burn)",
            "state authority on-chain (owner saat ini, admin proxy, "
            "mint authority) tidak diperiksa offline",
            "analisis teks/struktur tanpa compiler — pewarisan & "
            "interface tak diikuti; semua temuan = lead maks L2 "
            "(status unconfirmed)",
        ],
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    active_vectors = [k for k, v in vectors.items() if v]
    print(f"[rug-scan] {len(files)} file .sol; "
          f"{len(all_findings)} temuan "
          f"({', '.join(f'{k}={v}' for k, v in by_class.items()) or 'bersih'})")
    print(f"[rug-scan] vektor aktif: "
          f"{', '.join(active_vectors) or '-'}")
    if not args.quiet:
        for f in all_findings[:12]:
            print(f"  [{f['severity']:8}] {f['verdict_tag']:22} "
                  f"{f['class_id']:24} {f['file']}:{f['line']}")
        if len(all_findings) > 12:
            print(f"  ... {len(all_findings) - 12} temuan lagi "
                  f"(--out utk lengkap)")
    if args.fail_on:
        floor = 4 if args.fail_on == "any" else SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f["severity"], 9) <= floor
               for f in all_findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
