"""test_qr_payload_triage — skor payload QR terdekodenya, nol jaringan."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import qr_payload_triage as qpt  # noqa: E402


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "qr_payload_triage.py"), "--file",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------- unit ----------

def test_score_ip_lure_high():
    r = qpt.score_payload("http://198.51.100.5/login/verify.php")
    assert "ip-literal" in r["signals"] and "credential-lure" in r["signals"]
    assert r["severity"] == "high"


def test_score_shortener():
    r = qpt.score_payload("https://bit.ly/3xYzAbc")
    assert "shortener" in r["signals"]


def test_score_userinfo_trick():
    r = qpt.score_payload("https://microsoft.comverify@example.net/signin")
    assert "userinfo-trick" in r["signals"]
    assert "credential-lure" in r["signals"]


def test_score_punycode():
    r = qpt.score_payload("https://xn--pple-43d.com/account")
    assert "punycode" in r["signals"]


def test_score_benign_clean():
    r = qpt.score_payload("https://www.wikipedia.org/Lembah_Baliem")
    assert r["score"] == 0 and r["severity"] == "info"


def test_non_http_scheme():
    r = qpt.score_payload("sms:+6281100000000?body=Klik bit.ly/xyz")
    assert "non-http-scheme" in r["signals"]
    assert "shortener" in r["signals"]


# ---------- end-to-end ----------

def test_e2e_txt(tmp_path):
    text = ("\n".join([
        "http://198.51.100.5/login/verify.php",
        "https://bit.ly/3xYzAbc",
        "https://www.wikipedia.org/Hanoi",
    ]) + "\n")
    p = _tmp(tmp_path, "payloads.txt", text)
    code, out = _run(p)
    assert code == 0 and out["payloads"] == 3
    assert out["severity_counts"]["high"] >= 1
    assert out["clean_count"] == 1
    assert out["findings"][0]["score"] >= out["findings"][-1]["score"]


def test_e2e_json_input(tmp_path):
    data = {"scans": ["https://bit.ly/abc", "tel:+6281100000000"]}
    p = _tmp(tmp_path, "scans.json", json.dumps(data))
    code, out = _run(p)
    assert code == 0 and out["payloads"] == 2


def test_embedded_url_flag(tmp_path):
    r = qpt.score_payload(
        "https://mail.corp.example/redirect?url=http://evil.example/login")
    assert "embedded-url" in r["signals"]
    assert "credential-lure" in r["signals"]


def test_fail_closed(tmp_path):
    p = _tmp(tmp_path, "empty.txt", "\n\n")
    code, out = _run(p)
    assert code == 2 and out is None
    code2, _ = _run(tmp_path / "missing.txt")
    assert code2 == 2
