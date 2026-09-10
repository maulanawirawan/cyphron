"""Cyphron PDF design system (stdlib-only PDF 1.4 writer).

Dua API:
- render(blocks, footer)            -> writer lama (kompatibel docx/md flow)
- render_report(doc) -> bytes       -> laporan branded penuh: cover brand+chip,
  tabel metadata, callout, section bernomor, tabel navy/zebra, kartu temuan
  dengan band VERDICT, matriks "TIDAK DITEMUKAN", footer ref/halaman.

Palet mengikuti standar laporan enterprise (referensi desain MoM/render.py):
NAVY untuk band judul, TEAL untuk status aman, AMBER untuk peringatan,
RED untuk kritikal. Semua elemen digambar langsung ke content stream."""

from __future__ import annotations

import hashlib

PAGE_W, PAGE_H = 595.28, 841.89
MARGIN = 48.0
USABLE = PAGE_W - 2 * MARGIN

# ---- palet (r g b 0..1) ----
C = {
    "navy": (0.09, 0.20, 0.30), "navy_soft": (0.94, 0.96, 0.97),
    "ink": (0.10, 0.11, 0.13), "muted": (0.40, 0.45, 0.47),
    "line": (0.85, 0.88, 0.89), "surface": (0.957, 0.968, 0.966),
    "teal": (0.12, 0.48, 0.41), "teal_surface": (0.914, 0.957, 0.945),
    "amber": (0.72, 0.45, 0.06), "amber_surface": (1.0, 0.957, 0.847),
    "red": (0.69, 0.12, 0.12), "red_surface": (0.984, 0.918, 0.918),
    "green": (0.13, 0.45, 0.20), "white": (1, 1, 1),
    "code": (0.945, 0.953, 0.949), "code_ink": (0.15, 0.17, 0.18),
}

SEV_CHIP = {  # label, warna teks, warna surface
    "critical": ("KRITIKAL", C["red"], C["red_surface"]),
    "high": ("TINGGI", C["amber"], C["amber_surface"]),
    "medium": ("SEDANG", (0.72, 0.55, 0.05), (1.0, 0.97, 0.88)),
    "low": ("RENDAH", C["green"], C["teal_surface"]),
    "info": ("INFO", C["muted"], C["surface"]),
}
SEV_ORDER = ("critical", "high", "medium", "low", "info")

_FW = {"F1": 0.505, "F2": 0.535, "F3": 0.60}  # lebar rata-rata per char / size


_UNI_MAP = {
    "—": "-", "–": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", "•": "-",
    "≥": ">=", "≤": "<=", "×": "x", "±": "+/-",
    "→": "->", "≠": "!=", " ": " ",
}


def _sanitize(text: str) -> str:
    for k, v in _UNI_MAP.items():
        text = text.replace(k, v)
    return text


def _esc(text: str) -> str:
    text = _sanitize(text)
    text = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return text.encode("latin-1", "replace").decode("latin-1")


def _wrap(text: str, font: str, size: float, width: float) -> list[str]:
    text = _sanitize(text)
    limit = max(int(width / (_FW[font] * size)), 8)
    out: list[str] = []
    for raw in (text or "").splitlines() or [""]:
        if not raw.strip():
            out.append("")
            continue
        line = raw
        while len(line) > limit:
            cut = line.rfind(" ", 0, limit)
            if cut <= 0:
                cut = limit
            out.append(line[:cut])
            line = line[cut:].lstrip()
        out.append(line)
    return out


class _Page:
    """Kanvas satu dokumen: ops + kursor y, page-break otomatis."""

    def __init__(self, footer_ref: str):
        self.footer_ref = footer_ref
        self.pages: list[list[str]] = []
        self.ops: list[str] = []
        self.y = PAGE_H - MARGIN
        self.strict = False  # True = jangan pecah di tengah elemen

    def break_if(self, need: float) -> None:
        if self.strict:
            return
        if self.y - need < MARGIN + 40:
            self.new_page()

    def new_page(self) -> None:
        self.pages.append(self.ops)
        self.ops = []
        self.y = PAGE_H - MARGIN

    def text(self, x: float, y: float, font: str, size: float, color, s: str) -> None:
        r, g, b = color
        self.ops.append(
            f"BT /{font} {size} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_esc(s)}) Tj ET")

    def rect(self, x: float, y: float, w: float, h: float, color) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    def line(self, x1: float, y1: float, x2: float, y2: float, color, w: float = 0.7) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG {w:.2f} w "
                        f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def para(self, x: float, w: float, text: str, font: str = "F1", size: float = 9.5,
             color=None, leading: float = 13.0, gap: float = 0.0) -> None:
        color = color or C["ink"]
        self.break_if(leading)
        for ln in _wrap(text, font, size, w):
            self.break_if(leading)
            self.text(x, self.y, font, size, color, ln)
            self.y -= leading
        self.y -= gap

    def box(self, x: float, w: float, h: float, color) -> None:
        self.break_if(h + 6)
        self.rect(x, self.y - h, w, h, color)

    def chip(self, x: float, y: float, label: str, fg, bg, size: float = 8.2) -> float:
        w = _FW["F2"] * size * len(label) + 14
        self.rect(x, y - 5, w, size + 7, bg)
        self.text(x + 7, y + 1.5, "F2", size, fg, label)
        return w

    def code_block_h(self, w: float, text: str, max_lines: int = 14) -> float:
        lines = []
        for raw in (text or "").splitlines():
            lines.extend(_wrap(raw, "F3", 8.0, w - 16)[:2] if len(raw) > 160 else [raw])
        lines = lines[:max_lines]
        return len(lines) * 10.6 + 12

    def code_block(self, x: float, w: float, text: str, max_lines: int = 14) -> None:
        h = self.code_block_h(w, text, max_lines)
        self.break_if(h + 6)
        self.rect(x, self.y - h, w, h, C["code"])
        self.rect(x, self.y - h, 2.5, h, C["navy"])
        lines = []
        for raw in (text or "").splitlines():
            lines.extend(_wrap(raw, "F3", 8.0, w - 16)[:2] if len(raw) > 160 else [raw])
        lines = lines[:max_lines]
        yy = self.y - 13
        for ln in lines:
            self.text(x + 10, yy, "F3", 8.0, C["code_ink"], ln)
            yy -= 10.6
        self.y -= h + 6

    def kv_table(self, rows: list[tuple[str, str]], col_gap: float = 12.0) -> None:
        """Tabel metadata 2 pasang kolom per baris: (k, v, k, v) atau (k, v)."""
        col_w = (USABLE - col_gap) / 2
        label_w = 118.0
        i = 0
        while i < len(rows):
            self.break_if(20)
            pair = rows[i:i + 2]
            h = 17.0
            self.rect(MARGIN, self.y - h, USABLE, h, C["surface"])
            for j, (k, v) in enumerate(pair):
                x0 = MARGIN + j * (col_w + col_gap)
                self.text(x0 + 6, self.y - 11.5, "F1", 8.2, C["muted"], k)
                vx = x0 + 6 + label_w if j == 0 else x0 + 6 + label_w - 40
                val = _wrap(v, "F1", 8.6, col_w - label_w - 10)[0]
                self.text(x0 + 6 + label_w, self.y - 11.5, "F1", 8.6, C["ink"], val)
            self.y -= h + 3
            i += 2

    def data_table(self, head: list[str], rows: list[list[str]], widths: list[float],
                   zebra: bool = True, size: float = 8.2) -> None:
        scale = USABLE / sum(widths)
        widths = [w * scale for w in widths]
        # header band
        self.break_if(46)
        hh = 16.0
        self.rect(MARGIN, self.y - hh, USABLE, hh, C["navy"])
        x = MARGIN
        for label, w in zip(head, widths):
            self.text(x + 6, self.y - 11.2, "F2", 8.4, C["white"], label)
            x += w
        self.y -= hh
        for ri, row in enumerate(rows):
            cells = [_wrap(str(cell), "F1", size, widths[ci] - 12)
                     for ci, cell in enumerate(row)]
            rh = max(len(c) for c in cells) * (size + 3.2) + 7
            if self.y - rh < MARGIN + 40:
                self.new_page()
                self.rect(MARGIN, self.y - hh, USABLE, hh, C["navy"])
                x = MARGIN
                for label, w in zip(head, widths):
                    self.text(x + 6, self.y - 11.2, "F2", 8.4, C["white"], label)
                    x += w
                self.y -= hh
            if zebra and ri % 2 == 1:
                self.rect(MARGIN, self.y - rh, USABLE, rh, C["surface"])
            x = MARGIN
            for ci, cell_lines in enumerate(cells):
                yy = self.y - 11
                for ln in cell_lines:
                    self.text(x + 6, yy, "F1", size, C["ink"], ln)
                    yy -= size + 3.2
                x += widths[ci]
            self.line(MARGIN, self.y - rh, MARGIN + USABLE, self.y - rh, C["line"], 0.5)
            self.y -= rh
        self.y -= 6

    def section(self, no: str, title: str) -> None:
        self.break_if(170)  # heading tidak boleh yatim di dasar halaman
        self.y -= 8
        self.text(MARGIN, self.y, "F2", 13.5, C["navy"], f"{no} - {title}")
        self.line(MARGIN, self.y - 6, MARGIN + USABLE, self.y - 6, C["navy"], 1.1)
        self.y -= 18

    def callout_h(self, text: str) -> float:
        lines = _wrap(text, "F1", 9.2, USABLE - 150)
        return max(len(lines) * 12.5 + 14, 34)

    def callout(self, label: str, text: str, fg, bg) -> None:
        h = self.callout_h(text)
        self.break_if(h + 8)
        self.rect(MARGIN, self.y - h, USABLE, h, bg)
        self.rect(MARGIN, self.y - h, 108, h, fg)
        self.text(MARGIN + 10, self.y - h / 2 - 2, "F2", 8.6, C["white"], label)
        lines = _wrap(text, "F1", 9.2, USABLE - 150)
        yy = self.y - 16
        for ln in lines:
            self.text(MARGIN + 120, yy, "F1", 9.2, C["ink"], ln)
            yy -= 12.5
        self.y -= h + 10

    def finding(self, idx: str, sev: str, title: str, verdict: str,
                meta: str, desc: str, req: str | None, resp: str | None,
                poc: str | None, rec: str | None) -> None:
        chip_label, fg, bg = SEV_CHIP.get(sev, SEV_CHIP["info"])
        # KEEP-TOGETHER: hitung tinggi total kartu; jika tak muat di sisa
        # halaman, pindah halaman SEKALI di depan -> kartu tidak pernah terbelah
        est = 26 + 16 + 16
        est += len(_wrap(title, "F2", 10.6, USABLE)) * 13.5 + 3
        if meta:
            est += len(_wrap(meta, "F1", 8.4, USABLE)) * 11.5 + 4
        if desc:
            est += len(_wrap("Uraian: " + desc, "F1", 9.5, USABLE)) * 13 + 5
        for t in (req, resp):
            if t:
                est += 13 + self.code_block_h(USABLE, t) + 6
        if poc:
            est += 13 + self.code_block_h(USABLE, poc, max_lines=6) + 6
        if rec:
            est += self.callout_h(rec) + 8
        self.break_if(min(est, PAGE_H - 2 * MARGIN - 60))
        self.strict = True
        self.rect(MARGIN, self.y - 22, USABLE, 22, C["navy_soft"])
        self.text(MARGIN + 8, self.y - 15, "F2", 10, C["navy"], f"{idx}")
        x = MARGIN + 8 + _FW["F2"] * 10 * (len(idx) + 2)
        x += self.chip(x, self.y - 12, chip_label, fg, bg) + 6
        vx, vw = C["teal"], C["teal_surface"]
        if verdict.startswith("TIDAK"):
            vx, vw = C["teal"], C["teal_surface"]
        self.chip(x, self.y - 12, verdict, vx, vw)
        self.y -= 26
        self.para(MARGIN, USABLE, title, "F2", 10.6, gap=3)
        if meta:
            self.para(MARGIN, USABLE, meta, "F1", 8.4, C["muted"], gap=4)
        if desc:
            self.para(MARGIN, USABLE, "Uraian: " + desc, gap=5)
        if req:
            self.y -= 4
            self.para(MARGIN, USABLE, "Bukti permintaan:", "F2", 8.6, C["muted"], gap=2)
            self.code_block(MARGIN, USABLE, req)
        if resp:
            self.y -= 4
            self.para(MARGIN, USABLE, "Bukti respons:", "F2", 8.6, C["muted"], gap=2)
            self.code_block(MARGIN, USABLE, resp)
        if poc:
            self.y -= 4
            self.para(MARGIN, USABLE, "Langkah reproduksi (PoC):", "F2", 8.6, C["muted"], gap=2)
            self.code_block(MARGIN, USABLE, poc, max_lines=6)
        if rec:
            self.callout("PERBAIKAN", rec, C["teal"], C["teal_surface"])
        self.strict = False
        self.y -= 10


def _decorate(p: _Page, brand: str, doc_title: str) -> None:
    total = len(p.pages)
    for i, ops in enumerate(p.pages, start=1):
        if i == 1:
            continue  # halaman 1 = cover band penuh, tanpa header
        ops.append(f"BT /F1 7.6 Tf {C['muted'][0]:.3f} {C['muted'][1]:.3f} {C['muted'][2]:.3f} rg "
                   f"1 0 0 1 {MARGIN} {PAGE_H - 30:.2f} Tm ({_esc(brand)}) Tj ET")
        ops.append(f"BT /F1 7.6 Tf {C['muted'][0]:.3f} {C['muted'][1]:.3f} {C['muted'][2]:.3f} rg "
                   f"1 0 0 1 {PAGE_W - MARGIN - _FW['F1'] * 7.6 * len(doc_title):.2f} "
                   f"{PAGE_H - 30:.2f} Tm ({_esc(doc_title)}) Tj ET")
        ops.append(f"{C['line'][0]:.3f} {C['line'][1]:.3f} {C['line'][2]:.3f} RG 0.7 w "
                   f"{MARGIN} {PAGE_H - 36:.2f} m {PAGE_W - MARGIN} {PAGE_H - 36:.2f} l S")
        ops.append(f"BT /F1 7.6 Tf {C['muted'][0]:.3f} {C['muted'][1]:.3f} {C['muted'][2]:.3f} rg "
                   f"1 0 0 1 {MARGIN} {MARGIN - 16:.2f} Tm "
                   f"({_esc(p.footer_ref)}) Tj ET")
        pn = f"Halaman {i} dari {total}"
        ops.append(f"BT /F1 7.6 Tf {C['muted'][0]:.3f} {C['muted'][1]:.3f} {C['muted'][2]:.3f} rg "
                   f"1 0 0 1 {PAGE_W - MARGIN - _FW['F1'] * 7.6 * len(pn):.2f} "
                   f"{MARGIN - 16:.2f} Tm ({_esc(pn)}) Tj ET")


def render_report(doc: dict) -> bytes:
    ref = doc.get("ref", "CYPHRON")
    p = _Page(f"{ref} - dokumen terkendali - dihasilkan otomatis oleh Cyphron Core")
    brand, doc_title = doc.get("brand", "CYPHRON"), doc.get("doc_title", "Security Assessment")

    # ---- cover header ----
    p.rect(MARGIN, p.y - 40, 34, 34, C["navy"])
    p.text(MARGIN + 12, p.y - 28, "F2", 16, C["white"], "C")
    p.text(MARGIN + 46, p.y - 15, "F2", 14.5, C["navy"], brand)
    p.text(MARGIN + 46, p.y - 27, "F1", 7.6, C["muted"], doc.get("brand_sub",
           "SECURITY ASSESSMENT - DOKUMEN TERKENDALI"))
    chip = doc.get("chip") or {"text": "LAPORAN", "kind": "teal"}
    colors = {"teal": (C["teal"], C["teal_surface"]), "amber": (C["amber"], C["amber_surface"]),
              "red": (C["red"], C["red_surface"])}
    fg, bg = colors.get(chip["kind"], colors["teal"])
    p.chip(PAGE_W - MARGIN - _FW["F2"] * 8.6 * len(chip["text"]) - 16, p.y - 20,
           chip["text"], fg, bg, size=8.6)
    p.line(MARGIN, p.y - 48, PAGE_W - MARGIN, p.y - 48, C["navy"], 1.6)
    p.y -= 74
    p.para(MARGIN, USABLE, doc.get("title", "Laporan Uji Keamanan"), "F2", 19, C["navy"], gap=6)
    if doc.get("subtitle"):
        p.para(MARGIN, USABLE, doc["subtitle"], "F1", 10.5, C["muted"], gap=10)
    if doc.get("meta"):
        p.kv_table(doc["meta"])
        p.y -= 6
    if doc.get("callout"):
        p.callout(doc["callout"]["label"], doc["callout"]["text"],
                  C["amber"], C["amber_surface"])

    for sec in doc.get("sections", []):
        p.section(sec["no"], sec["title"])
        kind = sec.get("kind", "generic")
        if kind == "table":
            p.data_table(sec["head"], sec["rows"], sec["widths"])
        elif kind == "findings":
            items = sec.get("items", [])
            if not items:
                p.para(MARGIN, USABLE, "Tidak ada temuan terkonfirmasi dalam cakupan ini.",
                       "F1", 9.6, C["teal"], gap=4)
            for i, f in enumerate(items, start=1):
                p.finding(sec["no"] + "." + str(i), f.get("sev", "info"),
                          f.get("title", ""), f.get("verdict", "TERKONFIRMASI ADA"),
                          f.get("meta", ""), f.get("desc", ""), f.get("req"),
                          f.get("resp"), f.get("poc"), f.get("rec"))
        else:
            for style, text in sec.get("blocks", []):
                if style == "box":
                    lines = _wrap(text, "F1", 9.4, USABLE - 24)
                    h = len(lines) * 12.8 + 14
                    p.break_if(h + 8)
                    p.rect(MARGIN, p.y - h, USABLE, h, C["teal_surface"])
                    p.rect(MARGIN, p.y - h, 2.5, h, C["teal"])
                    yy = p.y - 16
                    for ln in lines:
                        p.text(MARGIN + 12, yy, "F1", 9.4, C["ink"], ln)
                        yy -= 12.8
                    p.y -= h + 8
                elif style == "mono":
                    p.code_block(MARGIN, USABLE, text)
                elif style == "bullet":
                    p.break_if(13)
                    p.text(MARGIN + 2, p.y, "F1", 9.5, C["navy"], "-")
                    p.para(MARGIN + 14, USABLE - 14, text, gap=1)
                elif style == "kv":
                    p.para(MARGIN, USABLE, text, "F1", 8.8, C["muted"], gap=0.5)
                elif style == "h3":
                    p.para(MARGIN, USABLE, text, "F2", 10.2, C["navy"], gap=3)
                else:
                    p.para(MARGIN, USABLE, text)
            p.y -= 4

    if p.ops:
        p.pages.append(p.ops)  # flush halaman terakhir (bug: halaman akhir hilang)
    _decorate(p, brand, doc_title)
    return _assemble(p.pages)


def _assemble(pages: list[list[str]]) -> bytes:
    plan: dict[int, bytes] = {}
    plan[1] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    plan[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    plan[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
    n = 4
    content_ids: list[int] = []
    for page_ops in pages:
        stream = ("\n".join(page_ops) or " ").encode("latin-1", "replace")
        plan[n] = (b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                   + stream + b"\nendstream")
        content_ids.append(n)
        n += 1
    pages_id = n + len(pages)
    page_ids: list[int] = []
    for cid in content_ids:
        plan[n] = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 1 0 R /F2 2 0 R /F3 3 0 R >> >> /Contents {cid} 0 R >>"
        ).encode()
        page_ids.append(n)
        n += 1
    assert n == pages_id
    plan[pages_id] = ("<< /Type /Pages /Kids [" + " ".join(f"{p} 0 R" for p in page_ids) +
                      f"] /Count {len(page_ids)} >>").encode()
    catalog_id = pages_id + 1
    plan[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()

    out = bytearray()
    out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets: list[int] = [0]
    for num in range(1, catalog_id + 1):
        offsets.append(len(out))
        out += f"{num} 0 obj\n".encode() + plan[num] + b"\nendobj\n"
    xref_at = len(out)
    count = catalog_id + 1
    out += f"xref\n0 {count}\n".encode()
    out += b"0000000000 65535 f \n"
    for num in range(1, count):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {count} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF").encode()
    return bytes(out)


# ---- writer lama (kompatibel) ----
STYLES = {
    "title": ("F2", 19, 26, "0.10 0.10 0.12"),
    "subtitle": ("F1", 10.5, 15, "0.35 0.35 0.38"),
    "h1": ("F2", 14.5, 20, "0.10 0.10 0.12"),
    "h2": ("F2", 12, 17, "0.15 0.15 0.20"),
    "h3": ("F2", 10.5, 15, "0.25 0.25 0.30"),
    "body": ("F1", 9.5, 13.5, None),
    "bullet": ("F1", 9.5, 13.5, None),
    "kv": ("F1", 9.5, 13.5, None),
    "mono": ("F3", 8.5, 12, None),
    "sepcritical": ("F2", 10, 14.5, "0.72 0.10 0.10"),
    "sephigh": ("F2", 10, 14.5, "0.75 0.42 0.05"),
    "sepmedium": ("F2", 10, 14.5, "0.72 0.60 0.05"),
    "seplow": ("F2", 10, 14.5, "0.20 0.45 0.20"),
    "sepinfo": ("F2", 10, 14.5, "0.40 0.40 0.42"),
}
CHAR_W = {"F1": 0.50, "F2": 0.53, "F3": 0.60}
WRAP_CHARS = {s: int(USABLE / (CHAR_W[f] * sz)) for s, (f, sz, _l, _c) in STYLES.items()}
WRAP_CHARS["bullet"] -= 3
WRAP_CHARS["mono"] = int(USABLE / (0.60 * 8.5))


def render(blocks: list[tuple[str, str]], footer: str) -> bytes:
    """Writer lama berbasis blocks (dipakai fallback + docx flow)."""
    pages: list[list[str]] = []
    ops: list[str] = []
    y = PAGE_H - MARGIN
    for style, text in blocks:
        font, size, leading, color = STYLES[style]
        lines = _wrap(text, font, size, USABLE if style != "bullet" else USABLE - 14)
        indent_x = MARGIN + (14 if style == "bullet" else 0)
        for i, line in enumerate(lines):
            if y - leading < MARGIN + 26:
                pages.append(ops)
                ops = []
                y = PAGE_H - MARGIN
            shown = ("- " if i == 0 else "  ") + line if style == "bullet" else line
            color_op = f" {color} rg" if color else ""
            ops.append(
                f"BT{color_op} /{font} {size} Tf 1 0 0 1 {indent_x} {y} Tm ({_esc(shown)}) Tj ET")
            y -= leading
        if style in ("h1", "h2", "h3", "title"):
            y -= leading * 0.35
    if ops:
        pages.append(ops)
    total = len(pages)
    for page_no, page_ops in enumerate(pages, start=1):
        page_ops.append(
            f"BT /F1 8 Tf 0.45 0.45 0.48 rg 1 0 0 1 {MARGIN} {MARGIN - 18} Tm "
            f"({_esc(footer)} - Halaman {page_no} dari {total}) Tj ET")
    return _assemble(pages)


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]
