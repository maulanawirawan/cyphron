"""[GUARD] ingest_gate — gerbang pra-ingesti konten TIDAK TEPERCAYA sebelum
dibaca agent/LLM: ekstraksi teks tersembunyi HTML, kanal kover Unicode,
de-obfuscation, dan pemindaian pola penyelundupan instruksi (indirect
prompt injection).

Lapisan yang diekstrak (tersedia bagi LLM tapi lazimnya tak terbaca
manusia):
  html-comment   komentar HTML
  css-hidden     teks dalam elemen style display:none / visibility:
                 hidden / opacity:0 / font-size:0 (1px)
  hidden-attr    elemen beratribut hidden atau <input type=hidden>
  img-alt        alt-text gambar
  unicode-tag    karakter Unicode Tags U+E0000..U+E007F DI-DECODE ke
                 ASCII (stego siap-baca)
  b64-decoded    token base64 (>=16 char) yang ter-decode printable
  rot13          rot13 dari teks utama (instruksi yang disandarkan)
  main           teks utama (visibel) — tetap di-scan utk konteks

Kanal kover dilaporkan sebagai kanal (hitungan): zero-width
(U+200B..U+200F, U+2060..U+2063, U+FEFF), bidi-control
(U+202A..U+202E, U+2066..U+2069), unicode-tag. Semuanya dihapus dari
teks yang di-scan (normalisasi), tak pernah dibiarkan lewat diam-diam.

Keputusan fail-closed per sumber:
  block  pola penyelundupan ditemukan di lapisan TERSEMBUNYI/DERIVATIF
         (komentar, css-hidden, hidden-attr, alt, unicode-tag, b64,
         rot13) — konten tak kasat mata membawa instruksi
  flag   pola di teks utama ATAU kanal kover ada walau tanpa pola
         ATAU ada lapisan tersembunyi non-kosong (perlu tatap mata)
  allow  bersih semua

Semua temuan = LEAD "penyelundupan teramati", bukan verdict kompromi.
Output JSON deterministik terurut. NOL jaringan.

Pemakaian:
  python tools/ingest_gate.py --file halaman.html --out gate.json
  python tools/ingest_gate.py --file a.html --file b.md --file c.txt
  python tools/ingest_gate.py --text "teks dari server tak dikenal"
Exit: 0 selesai (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

SCHEMA = "secai.ingest-gate/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

# ------------------------------------------------------------ unicode
_ZERO_WIDTH = frozenset(map(ord, "\u200b\u200c\u200d\u200e\u200f"
                                 "\u2060\u2061\u2062\u2063\ufeff"))
_BIDI = frozenset(range(0x202A, 0x202F)) | {0x2066, 0x2067, 0x2068,
                                            0x2069}
_TAG_LO, _TAG_HI = 0xE0000, 0xE01EF

_RE_B64_TOKEN = re.compile(r"[A-Za-z0-9+/=]{16,}")

_CSS_HIDDEN_HINTS = ("display:none", "display: none", "visibility:hidden",
                     "visibility: hidden", "opacity:0", "opacity: 0",
                     "font-size:0", "font-size: 0", "font-size:0px",
                     "font-size: 1px")

# ------------------------------------------------------------- pola
# Daftar terbuka dan terdokumentasi (heuristik repo), bukan rahasia.
# Label = kategori penyelundupan, bukan verdict.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for label, pattern in (
        ("instruction-override",
         r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?"
         r"(?:previous|prior|earlier|above|your)\s+"
         r"(?:instructions?|rules?|prompts?|guidelines?|safety)"),
        ("role-hijack",
         r"\b(?:you\s+are\s+now|pretend\s+(?:that\s+)?you\s+are|"
         r"act\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored))\b"),
        ("jailbreak-lexicon",
         r"\b(?:do\s+anything\s+now|(?:developer|god)\s+mode|"
         r"no\s+restrictions\s+(?:apply|activated|enabled))\b"),
        ("fake-system",
         r"(?:<\|?(?:im_start|system|endoftext)\|?>|"
         r"\b(?:new|updated|revised)\s+(?:system\s+)?instructions?\s*[:：]|"
         r"\b(?:system|assistant)\s*(?:prompt|message)\s*[:：])"),
        ("prompt-exfiltration",
         r"\b(?:reveal|print|show|repeat|output|encode|spill)\b[^.]{0,60}"
         r"\b(?:system\s+prompt|your\s+instructions?|api\s+keys?|"
         r"passwords?|secrets?|credentials?)\b"),
        ("tool-invocation",
         r"\b(?:run|execute|curl|wget|download|open)\b[^.]{0,60}"
         r"\b(?:https?://|powershell|\.sh\b|cmd\.exe|/etc/passwd)"),
        ("silent-channel",
         r"\b(?:secretly|covertly|without\s+(?:the\s+)?(?:user|human)"
         r"\s+(?:noticing|knowing|seeing))\b"),
    ))

# ------------------------------------------------------------- parser
class _HiddenExtractor(HTMLParser):
    """Ekstrak lapisan teks HTML: utama + tersembunyi (stdlib murni)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.main: list[str] = []
        self.comment: list[str] = []
        self.css_hidden: list[str] = []
        self.hidden_attr: list[str] = []
        self.img_alt: list[str] = []
        # stack konteks tersembunyi: "css" / "attr" / None (None = utama)
        self._stack: list[str | None] = []

    @staticmethod
    def _style_hidden(style: str) -> bool:
        s = style.lower().replace(" ", "")
        return any(h in s for h in _CSS_HIDDEN_HINTS)

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        parent = self._stack[-1] if self._stack else None
        tag_l = tag.lower()
        if tag_l == "img":
            if d.get("alt"):
                self.img_alt.append(d["alt"].strip())
            return
        if parent is not None:
            # di dalam elemen tersembunyi: konteks mengikuti induk
            self._stack.append(parent)
            return
        if self._style_hidden(d.get("style", "")):
            self._stack.append("css")
        elif d.get("hidden") is not None or (
                tag_l == "input" and d.get("type", "").lower() == "hidden"):
            self._stack.append("attr")
            if tag_l == "input" and d.get("value"):
                self.hidden_attr.append(d["value"].strip())
        else:
            self._stack.append(None)

    def handle_endtag(self, tag):
        if self._stack:
            self._stack.pop()

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return
        ctx = self._stack[-1] if self._stack else None
        if ctx == "css":
            self.css_hidden.append(text)
        elif ctx == "attr":
            self.hidden_attr.append(text)
        else:
            self.main.append(text)

    def handle_comment(self, data):
        text = data.strip()
        if text:
            self.comment.append(text)


def decode_tag_chars(text: str) -> tuple[str, int]:
    """Decode karakter Unicode Tags (U+E0000..) ke ASCII yang diselundup.

    Return (teks hasil decode, jumlah karakter tag ditemukan).
    """
    chars = [chr(ord(ch) - _TAG_LO) for ch in text
             if _TAG_LO <= ord(ch) <= _TAG_HI]
    decoded = "".join(chars)
    # hanya lapisan yang benar-benar berbentuk teks yang dilaporkan
    return decoded, len(chars)


def strip_covert(text: str) -> tuple[str, int, int, int]:
    """Normalisasi: buang zero-width/bidi/tag-char dari teks.

    Return (teks bersih, jumlah zero-width, jumlah bidi, jumlah tag).
    """
    zw = sum(1 for ch in text if ord(ch) in _ZERO_WIDTH)
    bidi = sum(1 for ch in text if ord(ch) in _BIDI)
    tag = sum(1 for ch in text if _TAG_LO <= ord(ch) <= _TAG_HI)
    cleaned = "".join(ch for ch in text
                      if ord(ch) not in _ZERO_WIDTH
                      and ord(ch) not in _BIDI
                      and not (_TAG_LO <= ord(ch) <= _TAG_HI))
    return cleaned, zw, bidi, tag


def decode_b64_payloads(text: str) -> list[str]:
    """Decode token base64 panjang yang hasilnya printable (>=8 char)."""
    out: list[str] = []
    for tok in _RE_B64_TOKEN.findall(text):
        if len(tok) < 16:
            continue
        pad = tok + "=" * (-len(tok) % 4)
        try:
            raw = base64.b64decode(pad, validate=True)
            decoded = raw.decode("utf-8", "ignore")
        except Exception:
            continue
        if len(decoded) >= 8:
            printable = sum(ch.isprintable() for ch in decoded)
            if printable / len(decoded) >= 0.9:
                out.append(decoded)
    return out


def rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


# ------------------------------------------------------------- scan
def _scan_patterns(text: str) -> list[tuple[str, str]]:
    """Kembalikan (label, excerpt) pola yang cocok; deterministik."""
    hits: list[tuple[str, str]] = []
    for label, pattern in PATTERNS:
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 30)
            excerpt = text[start:m.end() + 30].replace("\n", " ")
            hits.append((label, excerpt[:180]))
    return hits


def scan_source(name: str, raw: str) -> dict:
    """Analisis satu sumber: ekstraksi lapisan -> normalisasi -> scan."""
    parser = _HiddenExtractor()
    try:
        parser.feed(raw)
        parser.close()
    except Exception:
        # HTML rusak: tetap gunakan teks utama mentah (fail-open ekstraksi,
        # bukan fail-closed output — konten tetap di-scan)
        parser.main.append(raw)

    layers: dict[str, str] = {
        "main": "\n".join(parser.main),
        "html-comment": "\n".join(parser.comment),
        "css-hidden": "\n".join(parser.css_hidden),
        "hidden-attr": "\n".join(
            parser.hidden_attr) if parser.hidden_attr else "",
        "img-alt": "\n".join(parser.img_alt),
    }

    zw_total = bidi_total = tag_total = 0
    tag_decoded = ""
    for key in list(layers):
        clean, zw, bidi, tag = strip_covert(layers[key])
        zw_total += zw
        bidi_total += bidi
        tag_total += tag
        layers[key] = clean
        if tag:
            dec, _ = decode_tag_chars(raw)
            if dec and not tag_decoded:
                tag_decoded = dec

    # lapisan derivatif dari teks utama (setelah normalisasi)
    b64_list = decode_b64_payloads(layers["main"]) if layers["main"] else []
    layers["b64-decoded"] = "\n".join(b64_list)
    layers["unicode-tag"] = tag_decoded
    layers["rot13"] = rot13(layers["main"]) if layers["main"] else ""

    HIDDEN_KEYS = ("html-comment", "css-hidden", "hidden-attr", "img-alt",
                   "unicode-tag", "b64-decoded", "rot13")

    findings: list[dict] = []

    def _add(layer: str, context: str, hits: list[tuple[str, str]]) -> None:
        for label, excerpt in hits:
            findings.append({"layer": layer, "category": label,
                             "context": context, "match": excerpt})

    # 1. lapisan tersembunyi/derivatif -> block
    for key in HIDDEN_KEYS:
        if layers.get(key):
            _add(key, "hidden", _scan_patterns(layers[key]))

    # 2. teks utama -> flag
    _add("main", "main", _scan_patterns(layers["main"]))

    blocked = any(f["context"] == "hidden" for f in findings)
    # presence-only lapisan yang benar-benar tersembunyi / kanal kover
    # -> flag; komentar/alt/rot13 utama saja TIDAK cukup (terlalu umum)
    flagged = bool(findings) or zw_total or bidi_total or tag_total \
        or bool(layers.get("css-hidden") or layers.get("hidden-attr")
                or layers.get("unicode-tag") or layers.get("b64-decoded"))
    decision = "block" if blocked else ("flag" if flagged else "allow")

    # keluaran lapisan dibatasi (excerpt, deterministik)
    layer_out = {}
    for key in ("main", "html-comment", "css-hidden", "hidden-attr",
                "img-alt", "unicode-tag", "b64-decoded"):
        val = layers.get(key, "")
        if val:
            layer_out[key] = val[:400]

    return {
        "source": name,
        "decision": decision,
        "channels": {"zero-width": zw_total, "bidi-control": bidi_total,
                     "unicode-tag": tag_total},
        "layers": layer_out,
        "findings": sorted(
            findings, key=lambda f: (f["context"], f["layer"],
                                     f["category"], f["match"])),
    }


# ------------------------------------------------------------- cli
def _read_input(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file melebihi {MAX_FILE_BYTES} byte: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Gerbang pra-ingesti konten tidak tepercaya "
                    "(indirect prompt injection) — offline, fail-closed.")
    ap.add_argument("--file", action="append", default=[],
                    help="file input (HTML/teks), boleh diulang")
    ap.add_argument("--text", action="append", default=[],
                    help="teks mentah sebagai sumber, boleh diulang")
    ap.add_argument("--out", help="tulis JSON ke file (selain stdout)")
    args = ap.parse_args(argv)

    sources: list[tuple[str, str]] = []
    try:
        for fp in args.file:
            p = Path(fp)
            if not p.is_file():
                raise ValueError(f"file tidak ada: {p}")
            sources.append((p.name, _read_input(p)))
    except ValueError as exc:
        print(f"[ingest-gate] input error: {exc}", file=sys.stderr)
        return 2
    for i, t in enumerate(args.text):
        sources.append((f"text-{i + 1}", t))
    if not sources:
        print("[ingest-gate] input error: --file/--text wajib",
              file=sys.stderr)
        return 2

    results = [scan_source(name, raw) for name, raw in sources]
    summary = {"block": 0, "flag": 0, "allow": 0}
    for r in results:
        summary[r["decision"]] += 1
    payload = {"schema": SCHEMA, "summary": summary, "results": results}

    rendered = json.dumps(payload, ensure_ascii=False, indent=2,
                          sort_keys=True)
    print(rendered)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
