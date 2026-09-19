"""Minimal DOCX writer (stdlib-only): packages styled text blocks into a valid
Word .docx (OOXML). Direct formatting for headings/body/mono; bullets as
prefixed paragraphs. Opens in Word/LibreOffice/Google Docs."""

from __future__ import annotations

import io
import zipfile
from xml.sax.saxutils import escape

_STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="21"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Normal" w:default="1"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="160"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/><w:color w:val="1A1A1F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="280" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="29"/><w:color w:val="1A1A1F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="220" w:after="100"/><w:outlineLvl w:val="1"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="26262E"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="160" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="40404A"/></w:rPr></w:style>
</w:styles>"""

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_SEVERITY_COLORS = {
    "CRITICAL": "9E1B1B", "HIGH": "B4530A", "MEDIUM": "A8870A",
    "LOW": "2E6B2E", "INFO": "55555C",
}


def _p(style: str, text: str, mono: bool = False, color: str | None = None) -> str:
    runs: list[str] = []
    rpr = ""
    if mono:
        rpr = '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="18"/></w:rPr>'
    if color:
        rpr = f'<w:rPr><w:b/><w:color w:val="{color}"/><w:sz w:val="22"/></w:rPr>'
    # karakter kontrol dari wire (ANSI \x1b, \x00, dll.) korupkan document.xml
    text = "".join(ch if ch >= " " or ch in "\t\n\r" else f"\\x{ord(ch):02x}"
                   for ch in text)
    runs.append(f"<w:r>{rpr}<w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r>")
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{"".join(runs)}</w:p>'


def render(blocks: list[tuple[str, str]], footer: str) -> bytes:
    body: list[str] = []
    for style, text in blocks:
        if style == "title":
            body.append(_p("Title", text))
        elif style == "subtitle":
            body.append(_p("Normal", text))
        elif style == "h1":
            body.append(_p("Heading1", text))
        elif style == "h2":
            body.append(_p("Heading2", text))
        elif style == "h3":
            body.append(_p("Heading3", text))
        elif style == "bullet":
            body.append(_p("Normal", "- " + text))
        elif style == "kv":
            body.append(_p("Normal", text))
        elif style == "mono":
            body.append(_p("Normal", text, mono=True))
        elif style.startswith("sep"):
            sev = style[3:].upper()
            body.append(_p("Normal", text, color=_SEVERITY_COLORS.get(sev)))
        else:
            body.append(_p("Normal", text))
    body.append(_p("Normal", footer))
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{"".join(body)}'
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr>'
        "</w:body></w:document>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", _STYLES_XML)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
    return buf.getvalue()
