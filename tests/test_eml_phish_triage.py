"""test_eml_phish_triage — triase header email phishing (#0199),
nol jaringan.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import eml_phish_triage as ept  # noqa: E402


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "eml_phish_triage.py"), "--eml",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _raw(headers: dict[str, str], body: str) -> bytes:
    lines = [f"{k}: {v}" for k, v in headers.items()]
    lines += ["Received: from mail-server.xyz (203.0.113.45) by "
              "relay1.isp.com with SMTP",
              "Received: from relay1.isp.com (198.51.100.9) by "
              "mx.corp.example with ESMTP",
              "Received: from mx.corp.example by mailstore.corp.example "
              "(Postfix)",
              "", body]
    return ("\r\n".join(lines)).encode("utf-8")


BENIGN = _raw({
    "From": "Andi <andi@example-corp.com>",
    "To": "budi@example-corp.com",
    "Subject": "Q4 report",
    "Date": "Wed, 15 Jan 2025 09:23:45 +0000",
    "Message-ID": "<ok-1@example-corp.com>",
    "Return-Path": "<andi@example-corp.com>",
    "Authentication-Results": "mx.example-corp.com; spf=pass "
                              "smtp.mailfrom=example-corp.com; "
                              "dkim=pass header.d=example-corp.com; "
                              "dmarc=pass (p=reject)",
}, "Silakan cek https://docs.example-corp.com/handbook ya.")


def test_benign_no_findings(tmp_path):
    p = _tmp(tmp_path, "ok.eml", BENIGN)
    rc, out = _run(p)
    assert rc == 0 and out is not None
    assert out["finding_count"] == 0
    assert out["hops"] == 3
    assert out["auth_verdicts"] == {"spf": "pass", "dkim": "pass",
                                    "dmarc": "pass"}
    assert out["auth_missing"] is False
    assert out["url_count"] == 1
    assert out["subject"] == "Q4 report"
    # tampilan ter-defang
    assert "[.]" in out["urls_display"][0]


def test_replyto_and_returnpath_mismatch(tmp_path):
    p = _tmp(tmp_path, "bec.eml", _raw({
        "From": "CEO <ceo@example-corp.com>",
        "To": "finance@example-corp.com",
        "Subject": "Urgent wire",
        "Reply-To": "payments.urgent@gmail.com",
        "Return-Path": "<bounce@mail-server.xyz>",
        "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
    }, "Transfer sekarang."))
    rc, out = _run(p)
    assert rc == 0
    types = {f["type"]: f for f in out["findings"]}
    assert types["replyto-mismatch"]["severity"] == "high"
    assert "gmail[.]com" in types["replyto-mismatch"]["evidence"][
        "reply_to"]
    assert types["returnpath-mismatch"]["severity"] == "medium"


def test_auth_fail_verdicts(tmp_path):
    p = _tmp(tmp_path, "authfail.eml", _raw({
        "From": "pay@examp1e-corp.com",
        "To": "victim@corp.example",
        "Subject": "invoice",
        "Authentication-Results": "mx.corp.example; spf=fail (sender "
                                  "IP is 203.0.113.45) "
                                  "smtp.mailfrom=examp1e-corp.com; "
                                  "dkim=none; dmarc=fail (p=none)",
    }, "body"))
    rc, out = _run(p)
    assert rc == 0
    av = [f for f in out["findings"] if f["type"] == "auth-verdict"]
    assert len(av) == 1 and av[0]["severity"] == "high"
    assert av[0]["evidence"]["verdicts"]["spf"] == "fail"
    assert av[0]["evidence"]["verdicts"]["dmarc"] == "fail"
    assert av[0]["evidence"]["verdicts"]["dkim"] == "none"
    assert av[0]["evidence"]["dmarc_policy"] == "none"


def test_auth_softfail_is_medium(tmp_path):
    p = _tmp(tmp_path, "soft.eml", _raw({
        "From": "a@b.example",
        "Subject": "s",
        "Authentication-Results": "mx; spf=softfail; dkim=pass; "
                                  "dmarc=pass",
    }, "x"))
    rc, out = _run(p)
    av = [f for f in out["findings"] if f["type"] == "auth-verdict"]
    assert av[0]["severity"] == "medium"


def test_auth_missing_fail_closed_no_claim(tmp_path):
    p = _tmp(tmp_path, "noauth.eml", _raw({
        "From": "a@b.example",
        "Subject": "s",
    }, "x"))
    rc, out = _run(p)
    assert rc == 0
    assert out["auth_missing"] is True
    assert not [f for f in out["findings"]
                if f["type"] == "auth-verdict"]
    assert "JANGAN disimpulkan aman" in out["note"]


def test_homoglyph_critical(tmp_path):
    p = _tmp(tmp_path, "homoglyph.eml", _raw({
        "From": "pay <pay@microsоft.com>",  # 'о' = Cyrillic U+043E
        "Subject": "password reset",
    }, "click here"))
    rc, out = _run(p, "--legit", "microsoft.com")
    lk = [f for f in out["findings"] if f["type"] == "lookalike-domain"]
    assert len(lk) == 1 and lk[0]["severity"] == "critical"


def test_lookalike_ratio(tmp_path):
    p = _tmp(tmp_path, "ratio.eml", _raw({
        "From": "hr <hr@examplee-corp.com>",  # huruf ekstra
        "Subject": "kickoff",
    }, "agenda"))
    rc, out = _run(p, "--legit", "example-corp.com")
    lk = [f for f in out["findings"] if f["type"] == "lookalike-domain"]
    assert len(lk) == 1 and lk[0]["severity"] == "high"
    assert lk[0]["evidence"]["similarity"] >= 0.8


def test_same_domain_no_lookalike(tmp_path):
    rc, out = _run(_tmp(tmp_path, "same.eml", _raw({
        "From": "a <a@example-corp.com>",
        "Subject": "s",
    }, "x")), "--legit", "example-corp.com")
    assert not [f for f in out["findings"]
                if f["type"] == "lookalike-domain"]


def test_url_display_mismatch(tmp_path):
    html = ('<html><body><a href="http://phish.example.com/login">'
            'https://login.microsoft.com/verify</a></body></html>')
    p = _tmp(tmp_path, "html.eml", _raw({
        "From": "x <x@example.com>",
        "Subject": "verify",
        "MIME-Version": "1.0",
        "Content-Type": 'text/html; charset="utf-8"',
    }, html))
    rc, out = _run(p)
    mm = [f for f in out["findings"]
          if f["type"] == "url-display-mismatch"]
    assert len(mm) == 1 and mm[0]["severity"] == "high"
    assert "phish[.]example[.]com" in mm[0]["evidence"]["href"]
    assert "login[.]microsoft[.]com" in mm[0]["evidence"]["display"]


def _multipart(name: str, content: bytes) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "x <x@example.com>"
    msg["Subject"] = "att"
    msg.attach(MIMEText("lihat lampiran", "plain"))
    att = MIMEApplication(content, Name=name)
    att.add_header("Content-Disposition", "attachment", filename=name)
    msg.attach(att)
    return msg.as_bytes()


def test_attachment_double_extension_critical(tmp_path):
    content = b"MZfakepayloadbinary"
    p = _tmp(tmp_path, "dbl.eml", _multipart("invoice.pdf.exe", content))
    rc, out = _run(p)
    da = [f for f in out["findings"]
          if f["type"] == "dangerous-attachment"]
    assert len(da) == 1 and da[0]["severity"] == "critical"
    assert da[0]["evidence"]["sha256"] == hashlib.sha256(
        content).hexdigest()
    assert da[0]["evidence"]["extensions"][-1] == ".exe"


def test_attachment_macro_and_benign(tmp_path):
    msg = MIMEMultipart()
    msg["From"] = "x <x@example.com>"
    msg["Subject"] = "two"
    msg.attach(MIMEText("body", "plain"))
    a1 = MIMEApplication(b"X", Name="macros.xlsm")
    a1.add_header("Content-Disposition", "attachment",
                  filename="macros.xlsm")
    a2 = MIMEApplication(b"Y", Name="report.pdf")
    a2.add_header("Content-Disposition", "attachment",
                  filename="report.pdf")
    msg.attach(a1)
    msg.attach(a2)
    p = _tmp(tmp_path, "two.eml", msg.as_bytes())
    rc, out = _run(p)
    da = [f for f in out["findings"]
          if f["type"] == "dangerous-attachment"]
    assert len(da) == 1 and da[0]["evidence"]["name"] == "macros.xlsm"
    assert out["attachment_count"] == 2


def test_fail_closed_inputs(tmp_path):
    p = _tmp(tmp_path, "empty.eml", b"")
    rc, out = _run(p)
    assert rc == 2 and out is None

    p2 = _tmp(tmp_path, "garbage.eml", b"baris teks biasa tanpa header\n")
    rc2, out2 = _run(p2)
    assert rc2 == 2 and out2 is None

    rc3, out3 = _run(tmp_path / "missing.eml")
    assert rc3 == 2 and out3 is None


def test_cli_out_schema(tmp_path):
    p = _tmp(tmp_path, "cli.eml", BENIGN)
    outp = tmp_path / "out.json"
    rc, _ = _run(p, "--out", str(outp))
    assert rc == 0 and outp.is_file()
    data = json.loads(outp.read_text(encoding="utf-8"))
    assert data["schema"] == "secai.eml-phish-triage/1"
    assert data["read_only"] is True
    assert data["note"].startswith("semua temuan = LEAD")


# ---------- unit langsung ----------

def test_parse_auth_worst():
    verdicts, sources = ept.parse_auth([
        "mx1; spf=pass; dkim=pass; dmarc=pass",
        "mx2; spf=fail; dkim=none",
    ])
    assert verdicts["spf"] == "fail"  # terburuk menang
    assert verdicts["dkim"] == "none"
    assert verdicts["dmarc"] == "pass"
    assert len(sources) == 2
    worst = ept._worst(verdicts)
    assert worst is not None and worst[0] == "spf"


def test_levenshtein_and_defang():
    assert ept._levenshtein("kitten", "sitting") == 3
    assert ept._defang("http://evil.com/a") == "http[://]evil[.]com/a"
