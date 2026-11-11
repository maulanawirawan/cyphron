"""test_jwt_crypto_attack — offline JWT crypto engine, nol jaringan.
Semua token DIBANGUN runtime (hmac/base64) — tidak ada literal secret/token
di file ini (disiplin fixture repo). Mencakup: crack HS256 -> L3 arithmetic,
secret kuat -> L0 (kontrol anti-FP), alg:none -> L1 LEAD, konfusi RS->HS ->
L3, redaksi rahasia, validasi kontrak per-finding, exit-code CLI, determinisme.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(CORE))

import jwt_crypto_attack as J  # noqa: E402
from findings import validate_finding  # noqa: E402


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint(secret: bytes, payload: dict, alg: str = "HS256") -> str:
    hashfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[alg]
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    si = ("%s.%s" % (h, p)).encode("ascii")
    sig = hmac.new(secret, si, hashfn).digest()
    return "%s.%s.%s" % (h, p, _b64(sig))


def _mint_unsigned(payload: dict, alg: str = "none") -> str:
    h = _b64(json.dumps({"alg": alg}, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return "%s.%s." % (h, p)


# ----------------------------------------------------------- crack -> L3
def test_weak_builtin_secret_cracked_is_L3_arithmetic():
    tok = _mint(b"secret", {"user": "bob", "admin": False})  # "secret" = bawaan
    r = J.analyze([tok])
    f = r["findings"][0]
    assert f["status"] == "confirmed"
    assert f["verdict"] == 3
    assert f["verdict_tag"].startswith("L3")
    assert f["severity"] == "critical"
    assert f["reportable"] is True
    assert f["cwe"] == "CWE-321"
    assert "ARITHMETIC PROOF" in (f["poc"] or "")
    assert validate_finding(f) == []


def test_crack_redacts_the_secret_value():
    distinct = b"CorrectHorseBatteryStaple-42"
    tok = _mint(distinct, {"user": "x"})
    r = J.analyze([tok], wordlist=[distinct.decode()])
    f = r["findings"][0]
    assert f["verdict"] == 3
    # nilai rahasia TIDAK pernah muncul cleartext di output
    assert distinct.decode() not in json.dumps(r)
    assert "sha256:" in f["extra_secret_marker"] if "extra_secret_marker" in f \
        else "sha256:" in f.get("secret_marker", "")
    assert validate_finding(f) == []


# ----------------------------------------------------------- kontrol anti-FP
def test_strong_secret_not_cracked_is_L0_no_false_positive():
    strong = b"R7!" + hashlib.sha512(b"high-entropy-demo-key").digest()
    tok = _mint(strong, {"user": "bob"})
    r = J.analyze([tok])  # wordlist bawaan saja, tak memuat `strong`
    f = r["findings"][0]
    assert f["verdict"] == 0           # OBSERVED — diperiksa, tidak lemah
    assert f["severity"] == "info"
    assert f["reportable"] is False
    assert f["status"] == "confirmed"
    assert "not recovered" in f["title"]
    assert validate_finding(f) == []


# ----------------------------------------------------------- alg:none -> L1
def test_alg_none_is_L1_lab_only_lead():
    tok = _mint_unsigned({"user": "attacker"})
    r = J.analyze([tok])
    f = r["findings"][0]
    assert f["status"] == "unconfirmed"
    assert f["verdict"] == 1
    assert f["lab_only"] is True
    assert f["cwe"] == "CWE-347"
    assert "next-step" in (f["poc"] or "")
    assert validate_finding(f) == []


# ----------------------------------------------------------- konfusi RS->HS
def test_hs_verified_with_pubkey_is_L3_confusion():
    pub = b"-----BEGIN PUBLIC KEY-----\nMFkwdemoDEMOkeybytes0123456789\n-----END PUBLIC KEY-----"
    tok = _mint(pub, {"user": "bob"})          # HS256 ditandatangani pakai pubkey
    r = J.analyze([tok], pubkey=pub)
    f = r["findings"][0]
    assert f["verdict"] == 3
    assert f["cwe"] == "CWE-347"
    assert "confusion" in f["title"].lower()
    assert validate_finding(f) == []


def test_asymmetric_without_pubkey_is_L0():
    # token beralg RS256 dgn signature acak: tak bisa di-crack, tanpa pubkey -> L0
    tok = _mint(b"irrelevant", {"user": "x"}).rsplit(".", 1)[0] + "." + _b64(b"notarealrssig")
    tok = tok.split(".")
    import json as _j
    h = _b64(_j.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    token = "%s.%s.%s" % (h, tok[1], _b64(b"bogus-sig"))
    r = J.analyze([token])
    f = r["findings"][0]
    assert f["verdict"] == 0
    assert "asymmetric" in f["title"].lower()
    assert validate_finding(f) == []


# ----------------------------------------------------------- selalu >=1 finding
def test_every_token_yields_a_finding():
    toks = [_mint(b"secret", {"a": 1}),
            _mint(b"R7!" + hashlib.sha256(b"z").digest(), {"b": 2})]
    r = J.analyze(toks)
    assert len(r["findings"]) == 2
    for f in r["findings"]:
        assert validate_finding(f) == []


def test_malformed_token_noted_not_crash():
    r = J.analyze(["this-is-not-a-jwt"])
    assert any("rusak" in n for n in r["notes"])


# ----------------------------------------------------------- determinisme
def test_deterministic_output():
    tok = _mint(b"secret", {"user": "bob"})
    a = json.dumps(J.analyze([tok]), sort_keys=True)
    b = json.dumps(J.analyze([tok]), sort_keys=True)
    assert a == b


# ----------------------------------------------------------- fail-closed CLI
def _cli(tmp, *argv):
    import os
    env = dict(os.environ); env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, str(TOOLS / "jwt_crypto_attack.py"), *argv],
                          capture_output=True, text=True, cwd=str(tmp), env=env)


def test_cli_no_input_exit2(tmp_path):
    assert _cli(tmp_path).returncode == 2


def test_cli_missing_tokens_file_exit2(tmp_path):
    assert _cli(tmp_path, "--tokens", str(tmp_path / "nope.txt")).returncode == 2


def test_cli_out_contract_and_failon(tmp_path):
    tok = _mint(b"secret", {"user": "bob"})
    out = tmp_path / "f.json"
    p = _cli(tmp_path, "--token", tok, "--fail-on", "any", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True and doc["requests"] == 0
    assert len(doc["findings"]) >= 1
    for fd in doc["findings"]:
        assert validate_finding(fd) == []


def test_cli_strong_secret_failon_high_exit0(tmp_path):
    strong = b"R7!" + hashlib.sha256(b"q").digest()
    tok = _mint(strong, {"user": "bob"})
    p = _cli(tmp_path, "--token", tok, "--fail-on", "high")
    assert p.returncode == 0
