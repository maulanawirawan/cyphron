"""test_dmarc_report_triage — triase laporan agregat DMARC, nol jaringan.

Fixture = XML feedback DMARC sintetis (spesifikasi RFC 7489 aggregate
report) + kontrol false-positive (pengirim alignment penuh tidak boleh
memicu spoof-candidate).
"""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import dmarc_report_triage as drt  # noqa: E402

TPL = """<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>{org}</org_name>
    <report_id>{rid}</report_id>
    <date_range><begin>1731388800</begin><end>1731475199</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{domain}</domain>
    <p>{p}</p>
    <sp>reject</sp>
    <pct>{pct}</pct>
    <adkim>r</adkim>
    <aspf>r</aspf>
  </policy_published>
{records}
</feedback>
"""

ROW = """  <record>
    <row><source_ip>{ip}</source_ip><count>{count}</count>
      <policy_evaluated>
        <disposition>{disp}</disposition><dkim>{dkim}</dkim><spf>{spf}</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>{hfrom}</header_from></identifiers>
  </record>
"""


def _xml(org="relay.example.net", rid="r1", domain="corp.example.com",
         p="none", pct="100", records=""):
    return TPL.format(org=org, rid=rid, domain=domain, p=p, pct=pct,
                      records=records)


def _row(ip="198.51.100.9", count=50, disp="none", dkim="fail", spf="fail",
         hfrom="corp.example.com"):
    return ROW.format(ip=ip, count=count, disp=disp, dkim=dkim, spf=spf,
                      hfrom=hfrom)


def _run(*paths, **kw) -> tuple[int, dict | None]:
    args = []
    for p in paths:
        args += ["--report", str(p)]
    for k, v in kw.items():
        args += [f"--{k.replace('_', '-')}", str(v)]
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "dmarc_report_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------- unit kecil ----------

def test_strip_doctype():
    raw = b'<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY x "y">]><feedback/>'
    assert b"DOCTYPE" not in drt._strip_doctype(raw)
    assert b"<feedback/>" in drt._strip_doctype(raw)


def test_parse_report_shapes():
    rep = drt.parse_report(_xml(records=_row()).encode(), "t.xml")
    assert rep is not None and rep["policy"]["domain"] == "corp.example.com"
    assert rep["records"][0]["source_ip"] == "198.51.100.9"
    assert rep["records"][0]["count"] == 50
    assert rep["records"][0]["spf_pass"] is False


def test_parse_rejects_non_dmarc():
    assert drt.parse_report(b"<root/>", "x.xml") is None
    assert drt.parse_report(b"not xml", "x.xml") is None


# ---------- end-to-end ----------

def test_spoof_candidate_high(tmp_path):
    xml = _xml(records=_row(ip="203.0.113.9", count=30)
               + _row(ip="198.51.100.9", count=50))
    p = _tmp(tmp_path, "r.xml", xml.encode())
    code, out = _run(p)
    assert code == 0 and out["valid_reports"] == 1
    types = {f["type"] for f in out["findings"]}
    assert "spoof-candidate" in types
    spoof = [f for f in out["findings"] if f["type"] == "spoof-candidate"]
    srcs = {f["src"] for f in spoof}
    assert {"203.0.113.9", "198.51.100.9"} <= srcs
    assert out["messages"] == 80


def test_gzip_container(tmp_path):
    xml = _xml(records=_row()).encode()
    p = _tmp(tmp_path, "rua.xml.gz", gzip.compress(xml))
    code, out = _run(p)
    assert code == 0 and out["containers"] == ["gz"]
    assert any(f["type"] == "spoof-candidate" for f in out["findings"])


def test_false_positive_control_full_pass(tmp_path):
    # Pengirim alignment penuh (SPF+DKIM pass) TIDAK boleh spoof-candidate
    xml = _xml(records=_row(ip="198.51.100.9", count=100, dkim="pass",
                            spf="pass"))
    p = _tmp(tmp_path, "clean.xml", xml.encode())
    code, out = _run(p)
    assert code == 0
    assert all(f["type"] != "spoof-candidate" for f in out["findings"])


def test_policy_soft_flagged(tmp_path):
    xml = _xml(p="none", pct="25", records=_row(dkim="pass", spf="pass"))
    p = _tmp(tmp_path, "soft.xml", xml.encode())
    code, out = _run(p)
    soft = [f for f in out["findings"] if f["type"] == "policy-soft"]
    assert soft and "p=none" in soft[0]["detail"] and "pct=25" in soft[0]["detail"]


def test_new_source_known_ips(tmp_path):
    xml = _xml(records=_row(ip="203.0.113.77", count=20))
    p = _tmp(tmp_path, "r.xml", xml.encode())
    k = _tmp(tmp_path, "known.json", json.dumps(["203.0.113.77"]).encode())
    code, out = _run(p, known_ips=k)
    assert code == 0
    assert all(f["type"] != "new-source" for f in out["findings"])
    code2, out2 = _run(p, known_ips=tmp_path / "known2.json" if False else k)  # jalur sama
    assert code2 == 0


def test_fail_closed_empty(tmp_path):
    p = _tmp(tmp_path, "junk.xml", b"<root/>")
    code, out = _run(p)
    assert code == 2 and out is None
    code2, _ = _run(tmp_path / "missing.xml")
    assert code2 == 2


def test_single_entry_zip(tmp_path):
    import zipfile as zf
    xml = _xml(records=_row()).encode()
    p = _tmp(tmp_path, "rua.zip", b"")
    with zf.ZipFile(p, "w") as z:
        z.writestr("report.xml", xml)
    code, out = _run(p)
    assert code == 0 and out["containers"] == ["zip"]
