"""test_rat_config_scan — triase kanal ekstraksi & IOC dari sampel
biner offline (#0517 #0519), nol jaringan, sampel tidak dieksekusi.

Fixture = blob sintetis berisi format konfigurasi publik (token bot
Telegram, URL webhook Discord, skema SMTP/FTP) — BUKAN sampel malware
asli, bukan salinan kode alat sumber.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import rat_config_scan as rcs  # noqa: E402


def _blob(parts: "list[bytes]") -> bytes:
    return b"\x00" + b"\x00".join(parts) + b"\x00"


def _sample(tmp_path, parts, name="sample.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(_blob(parts))
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "rat_config_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _types(out: dict) -> "set[str]":
    detail = out.get("detail") or {}
    return {c["type"] for c in detail.get("channels", [])}


# ------------------------------------------------------- parsing/error
def test_missing_file_exit2(tmp_path):
    rc, out, _ = _run("--file", str(tmp_path / "nope.bin"))
    assert rc == 2 and out is None


def test_empty_dir_exit2(tmp_path):
    rc, out, _ = _run("--dir", str(tmp_path))
    assert rc == 2


def test_hashes_present(tmp_path):
    p = _sample(tmp_path, [b"hello world payload"])
    rc, out, _ = _run("--file", str(p))
    assert rc == 0
    assert len(out["detail"]["hashes"]["sha256"]) == 64


# ------------------------------------------------------- kanal SMTP
def test_smtp_channel(tmp_path):
    p = _sample(tmp_path, [
        b"smtp.mail.yahoo.com",
        b"sender@yahoo.com",
        b"port=587",
    ])
    rc, out, _ = _run("--file", str(p))
    assert rc == 1
    types = _types(out)
    assert "smtp" in types and "smtp-email" in types
    checks = [f["check"] for f in out["detail"]["findings"]]
    assert "smtp-channel" in checks


def test_clean_binary_no_findings(tmp_path):
    p = _sample(tmp_path, [b"just a readme text file with words"])
    rc, out, _ = _run("--file", str(p))
    assert rc == 0 and out["detail"]["findings"] == []


# ------------------------------------------------------- FTP / Telegram
def test_ftp_channel(tmp_path):
    p = _sample(tmp_path, [b"ftp://uploads.evil-zone.net:2121/in"])
    rc, out, _ = _run("--file", str(p))
    assert rc == 1 and "ftp" in _types(out)


def test_telegram_token_format(tmp_path):
    token = b"1234567890:" + b"A" * 35  # format token bot: 35 char
    p = _sample(tmp_path, [token, b"chat_id=-100123456789"])
    rc, out, _ = _run("--file", str(p))
    assert rc == 1 and "telegram" in _types(out)
    tg = next(c for c in out["detail"]["channels"]
              if c["type"] == "telegram")
    assert any("1234567890:" in i for i in tg["iocs"])


def test_bogus_telegram_token_not_matched(tmp_path):
    # Panjang salah -> bukan token bot (anti-FP format ketat).
    p = _sample(tmp_path, [b"1234567890:shorttoken", b"chat_id=1"])
    rc, out, _ = _run("--file", str(p))
    assert "telegram" not in _types(out)


def test_discord_webhook(tmp_path):
    p = _sample(tmp_path, [
        b"https://discord.com/api/webhooks/123456789012345678/"
        b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd",
    ])
    rc, out, _ = _run("--file", str(p))
    assert rc == 1 and "discord-webhook" in _types(out)


# ------------------------------------------------------- kredensial/b64
def test_cred_assignment_medium(tmp_path):
    p = _sample(tmp_path, [b"password=Sup3rSecret!"])
    rc, out, _ = _run("--file", str(p))
    checks = [f["check"] for f in out["detail"]["findings"]]
    assert rc == 1 and "cred-assignment" in checks


def test_base64_blob_decoded_recorded(tmp_path):
    payload = base64.b64encode("https://c2.example/gate.php".encode())
    p = _sample(tmp_path, [payload])
    rc, out, _ = _run("--file", str(p))
    assert "base64-decoded" in _types(out)
    assert any("c2.example" in s for s in
               out["detail"]["channels"][-1]["iocs"])


# ------------------------------------------------------- IOC candidates
def test_ioc_candidates_defanged(tmp_path):
    p = _sample(tmp_path, [
        b"visit https://update.evil-cdn.example/drop.exe now",
    ])
    rc, out, _ = _run("--file", str(p))
    urls = out["detail"]["ioc_candidates"].get("url", [])
    assert urls and all("hxxp" in u or "[.]" in u for u in urls)


# ------------------------------------------------------- dir mode
def test_dir_mode_multiple(tmp_path):
    _sample(tmp_path, [b"smtp.gmail.com"], "a.bin")
    _sample(tmp_path, [b"nothing here"], "b.bin")
    rc, out, _ = _run("--dir", str(tmp_path))
    assert rc == 1
    assert out["samples"] == 2
    assert len(out["summary"]) == 2


# ------------------------------------------------------- determinisme
def test_deterministic(tmp_path):
    p = _sample(tmp_path, [b"smtp.mail.ru", b"admin@mail.ru",
                           b"password=abc12345"])
    a = rcs._scan_one(Path(p))
    b = rcs._scan_one(Path(p))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_notes_fail_closed(tmp_path):
    p = _sample(tmp_path, [b"plain text only"])
    rc, out, _ = _run("--file", str(p))
    assert any("tidak dieksekusi" in n for n in out["notes"])
    assert any("KANDIDAT" in n for n in out["notes"])
