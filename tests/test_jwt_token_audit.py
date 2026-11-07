"""test_jwt_token_audit — audit OFFLINE konten token JWT utk vektor
header & higiene exp (#0498), nol jaringan.

Fixture = token sintetis (base64url dibangun langsung di test dgn
formula standar base64url, independen dari dekoder tool).
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import jwt_token_audit as jta  # noqa: E402

NOW = 1_700_000_000  # unix epoch tetap utk determinisme


def _b64(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _tok(header: dict, claims: dict, sig: str = "c2ln") -> str:
    return f"{_b64(header)}.{_b64(claims)}.{sig}"


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "jwt_token_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> set[str]:
    return {f["check"] for f in out["findings"]}


# ------------------------------------------------------- parser
def test_parse_token_ok():
    tok = jta.parse_token(_tok({"alg": "HS256"},
                               {"sub": "u", "exp": NOW + 60}))
    assert tok["header"]["alg"] == "HS256"
    assert tok["sig_len"] == 4


def test_parse_token_two_segments():
    tok = jta.parse_token(f"{_b64({'alg': 'none'})}."
                          f"{_b64({'sub': 'x'})}")
    assert tok["sig_len"] == 0


def test_parse_token_broken_raises():
    for bad in ("abc", "a.b", f"{_b64({'alg': 'x'})}.!!!"):
        try:
            jta.parse_token(bad)
        except (ValueError, base64.binascii.Error):
            pass
        else:
            raise AssertionError(f"harusnya error: {bad}")


# ------------------------------------------------------- audit
def test_alg_none_variants():
    for alg in ("none", "None", "NONE", "nOnE", ""):
        tok = {"header": {"alg": alg} if alg else {},
               "claims": {"sub": "u"}, "sig_len": 3}
        f = jta.audit_token(0, tok, NOW)
        assert any(x["check"] == "alg-none" and x["severity"] == "high"
                   for x in f), alg


def test_kid_injection_shapes():
    shapes = ["../../etc/passwd.pem", "%2e%2e%2fkey",
              "' UNION SELECT 'secret' -- ", "https://evil.com/k.pem"]
    for kid in shapes:
        tok = {"header": {"alg": "HS256", "kid": kid},
               "claims": {}, "sig_len": 3}
        f = jta.audit_token(0, tok, NOW)
        assert any(x["check"] == "kid-injection" for x in f), kid


def test_kid_benign_not_flagged():
    tok = {"header": {"alg": "HS256", "kid": "key-2026-11"},
           "claims": {}, "sig_len": 3}
    f = jta.audit_token(0, tok, NOW)
    assert not any(x["check"] == "kid-injection" for x in f)


def test_jku_x5u_jwk():
    tok = {"header": {"alg": "RS256", "jku": "https://evil/jwks",
                      "x5u": "https://evil/c.pem", "jwk": {"kty": "RSA"}},
           "claims": {}, "sig_len": 3}
    f = jta.audit_token(0, tok, NOW)
    checks = {x["check"]: x for x in f}
    assert checks["jwk-header"]["severity"] == "high"
    assert checks["jku-header"]["severity"] == "medium"
    assert checks["x5u-header"]["severity"] == "medium"
    assert checks["alg-asym-surface"]["severity"] == "medium"


def test_exp_hygiene():
    tok_missing = {"header": {"alg": "HS256"}, "claims": {"sub": "u"},
                   "sig_len": 3}
    tok_stale = {"header": {"alg": "HS256"},
                 "claims": {"exp": NOW - 100_000}, "sig_len": 3}
    tok_long = {"header": {"alg": "HS256"},
                "claims": {"iat": NOW, "exp": NOW + 400 * 86400},
                "sig_len": 3}
    assert any(x["check"] == "exp-missing"
               for x in jta.audit_token(0, tok_missing, NOW))
    stale = [x for x in jta.audit_token(1, tok_stale, NOW)
             if x["check"] == "exp-stale"]
    assert stale and stale[0]["severity"] == "low"
    long_ = [x for x in jta.audit_token(2, tok_long, NOW)
             if x["check"] == "exp-long-lived"]
    assert long_ and long_[0]["age_days"] == 400


def test_clean_token_zero_findings():
    tok = {"header": {"alg": "HS256", "kid": "key-1"},
           "claims": {"sub": "u", "iat": NOW, "exp": NOW + 3600},
           "sig_len": 6}
    assert jta.audit_token(0, tok, NOW) == []


# ------------------------------------------------------- end-to-end
def test_e2e_alg_none_exit_1():
    code, out, err = _run("--token", _tok({"alg": "none"}, {"sub": "x"},
                                          sig=""),
                          "--now", str(NOW))
    assert code == 1
    assert out["schema"] == "cyphron.jwt-token-audit/1"
    assert {"alg-none", "signature-empty"} <= _checks(out)


def test_e2e_clean_exit_0():
    code, out, _ = _run("--token", _tok({"alg": "HS256", "kid": "k1"},
                                        {"sub": "u", "iat": NOW,
                                         "exp": NOW + 3600}),
                        "--now", str(NOW))
    assert code == 0
    assert out["findings"] == []


def test_e2e_medium_gate(tmp_path):
    p = tmp_path / "jwt.txt"
    p.write_text(
        _tok({"alg": "RS256", "jku": "https://evil/jwks"}, {"sub": "x"})
        + "\n"
        + _tok({"alg": "HS256"}, {"sub": "u", "iat": NOW,
                                  "exp": NOW + 3600}) + "\n",
        encoding="utf-8")
    code, out, _ = _run("--tokens", str(p), "--now", str(NOW))
    assert code == 0  # hanya medium/RS256 -> di bawah gate high
    code2, out2, _ = _run("--tokens", str(p), "--now", str(NOW),
                          "--fail-on", "medium")
    assert code2 == 1
    assert {"jku-header", "alg-asym-surface"} <= _checks(out2)


def test_e2e_file_multi_token_and_broken(tmp_path):
    p = tmp_path / "jwt.txt"
    p.write_text("# komentar\n"
                 + _tok({"alg": "none"}, {"sub": "x"}) + "\n"
                 + "bukan-jwt-token-rusak\n"
                 + f"{_b64({'alg': 'HS256'})}.!!!\n",
                 encoding="utf-8")
    code, out, _ = _run("--tokens", str(p), "--now", str(NOW))
    assert code == 1
    assert out["stats"]["tokens_parsed"] == 1
    assert len(out["meta"]["broken_samples"]) == 2
    assert any("komentar" not in b for b in out["meta"]["broken_samples"])


def test_e2e_all_broken_exit_2(tmp_path):
    p = tmp_path / "jwt.txt"
    p.write_text("rusak1\nrusak2\n", encoding="utf-8")
    code, out, err = _run("--tokens", str(p))
    assert code == 2
    assert out is None


def test_e2e_missing_file_exit_2(tmp_path):
    code, out, err = _run("--tokens", str(tmp_path / "tidakada.txt"))
    assert code == 2


def test_e2e_no_input_exit_2():
    code, out, err = _run()
    assert code == 2
    assert "butuh" in err
