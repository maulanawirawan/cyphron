"""test_paste_triage — triase isi paste/dump tersimpan offline (#0868),
nol jaringan.

Fixture = isi paste sintetis dgn kredensial PALSU (nilai dummy jelas
bukan kredensial nyata); pola mengikuti konsep publik, bukan salinan
regex/kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import paste_triage as pti  # noqa: E402

_GH_TOKEN = "ghp_" + "A" * 36  # ghp_ + tepat 36 char
# token Slack palsu dibangun runtime (konket) supaya source tidak
# memuat string ber-bentuk-token — GitHub Push Protection lolos
_SLACK_TOKEN = "xox" + "b-" + "123456789012-" + "abcdefghij" + "klmnop"

DUMP_ORG = ("""internal dump corp.example.id project-apollo
admin@corp.example.id:Passw0rd Dummy!
AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""" + _GH_TOKEN + "\n" + _SLACK_TOKEN + """
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N
-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAK
-----END RSA PRIVATE KEY-----
postgres://svcuser:svcPass99@db-internal.corp.example.id:5432/prod
api_key = AbCdEfGhIjKlMnOpQrStUv01
""")

DUMP_PLAIN = """some random paste without anything relevant
just text, maybe an email like someone@example.com for context
"""


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "paste_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _types(out: dict) -> "list[str]":
    return [f.get("type", "") for f in out["findings"]
            if f["check"] == "credential-leak"]


# ------------------------------------------------------- input
def test_no_args_error():
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "paste_triage.py")],
        capture_output=True, text=True)
    assert proc.returncode == 2


def test_missing_file_exit2(tmp_path):
    rc, out, err = _run("--paste", str(tmp_path / "no.txt"))
    assert rc == 2 and out is None and "tidak ada" in err


# ------------------------------------------------------- deteksi pola
def test_all_credential_types_detected(tmp_path):
    p = _write(tmp_path, "dump.txt", DUMP_ORG)
    rc, out, _ = _run("--paste", str(p), "--keyword",
                      "corp.example.id")
    types = _types(out)
    for t in ("aws-key-id", "aws-secret", "github-token", "slack-token",
              "jwt-token", "private-key", "email-password",
              "db-connection", "api-key-assignment"):
        assert t in types, f"missing {t}"
    verdict = [f for f in out["findings"] if f["check"] == "paste-verdict"]
    assert len(verdict) == 1 and verdict[0]["severity"] == "critical"


def test_keyword_plus_creds_critical(tmp_path):
    p = _write(tmp_path, "dump.txt", DUMP_ORG)
    _, out, _ = _run("--paste", str(p), "--keyword", "project-apollo")
    v = [f for f in out["findings"] if f["check"] == "paste-verdict"][0]
    assert v["severity"] == "critical"


def test_keyword_only_high(tmp_path):
    p = _write(tmp_path, "dump.txt",
               "notes about corp.example.id roadmap 2027")
    _, out, _ = _run("--paste", str(p), "--keyword", "corp.example.id")
    v = [f for f in out["findings"] if f["check"] == "paste-verdict"]
    assert len(v) == 1 and v[0]["severity"] == "high"
    kh = [f for f in out["findings"]
          if f["check"] == "org-keyword-hit"]
    assert len(kh) == 1 and kh[0]["severity"] == "info"


def test_creds_without_keyword_medium(tmp_path):
    p = _write(tmp_path, "dump.txt",
               "AKIAIOSFODNN7EXAMPLE and " + _GH_TOKEN)
    _, out, _ = _run("--paste", str(p))
    v = [f for f in out["findings"] if f["check"] == "paste-verdict"][0]
    assert v["severity"] == "medium"


def test_many_creds_without_keyword_high(tmp_path):
    lines = [f"user{i}@ex.com:Passw0rd{i}!" for i in range(15)]
    p = _write(tmp_path, "dump.txt", "\n".join(lines))
    _, out, _ = _run("--paste", str(p))
    v = [f for f in out["findings"] if f["check"] == "paste-verdict"][0]
    assert v["severity"] == "high"
    assert out["stats"]["total_credentials"] == 15


# ------------------------------------------------------- anti-FP
def test_plain_paste_clean(tmp_path):
    p = _write(tmp_path, "dump.txt", DUMP_PLAIN)
    rc, out, _ = _run("--paste", str(p))
    assert rc == 0
    assert _types(out) == []
    assert "paste-verdict" not in [f["check"] for f in out["findings"]]


def test_bare_40char_no_context_not_flagged(tmp_path):
    # 40-char acak TANPA konteks assignment = bukan aws-secret
    p = _write(tmp_path, "dump.txt",
               "random string " + "aB3" * 13 + "x" + " end")
    rc, out, _ = _run("--paste", str(p))
    assert "aws-secret" not in _types(out)


def test_email_no_separator_not_flagged(tmp_path):
    # email diikuti spasi (bukan tanda baca) = bukan email:password
    p = _write(tmp_path, "dump.txt",
               "contact john.doe@example.com for details please")
    rc, out, _ = _run("--paste", str(p))
    assert "email-password" not in _types(out)


# ------------------------------------------------------- redaksi
def test_redaction_no_full_secret(tmp_path):
    p = _write(tmp_path, "dump.txt", DUMP_ORG)
    _, out, _ = _run("--paste", str(p), "--keyword", "corp.example.id")
    blob = json.dumps(out)
    for secret in ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                   _GH_TOKEN,
                   _SLACK_TOKEN,
                   "Passw0rd Dummy!", "svcPass99",
                   "AbCdEfGhIjKlMnOpQrStUv01"):
        assert secret not in blob, f"bocor: {secret}"
    leak = [f for f in out["findings"]
            if f["check"] == "credential-leak"]
    assert all("DIREDAKSI" in f["message"] for f in leak)


# ------------------------------------------------------- fail-closed
def test_binary_content_skipped(tmp_path):
    p = tmp_path / "bin.txt"
    p.write_bytes(b"\x00\x01\x02binary-ish\x00content")
    rc, out, _ = _run("--paste", str(p))
    assert rc == 1
    bc = [f for f in out["findings"]
          if f["check"] == "binary-content-skipped"]
    assert len(bc) == 1 and bc[0]["severity"] == "medium"


def test_multiple_pastes(tmp_path):
    a = _write(tmp_path, "a.txt", DUMP_ORG)
    b = _write(tmp_path, "b.txt",
               "mention corp.example.id in changelog only")
    _, out, _ = _run("--paste", str(a), "--paste", str(b),
                     "--keyword", "corp.example.id")
    assert out["stats"]["pastes"] == 2
    pastes = {f.get("paste") for f in out["findings"]}
    assert pastes == {"a.txt", "b.txt"}
    vb = [f for f in out["findings"]
          if f["check"] == "paste-verdict" and f["paste"] == "b.txt"]
    assert len(vb) == 1 and vb[0]["severity"] == "high"


# ------------------------------------------------------- kontrak
def test_schema_sorted_notes(tmp_path):
    p = _write(tmp_path, "dump.txt", DUMP_ORG)
    _, out, _ = _run("--paste", str(p), "--keyword", "corp.example.id")
    assert out["schema"] == pti.SCHEMA
    sevs = [pti.SEV_ORDER[f["severity"]] for f in out["findings"]]
    assert sevs == sorted(sevs, reverse=True)
    assert any("leak_triage" in n for n in out["notes"])
    assert out["stats"]["redaction"] is True if "redaction" in \
        out["stats"] else any("REDAKSI" in n for n in out["notes"])
    assert all({"check", "severity", "paste", "message"}
               <= set(f) for f in out["findings"])


def test_fail_on_info(tmp_path):
    p = _write(tmp_path, "dump.txt",
               "notes about corp.example.id roadmap")
    rc, out, _ = _run("--paste", str(p), "--keyword", "corp.example.id",
                      "--fail-on", "info")
    assert rc == 1  # org-keyword-hit info -> exit 1 saat fail-on info
