"""test_dns_log_triage — triase log DNS utk eksfiltrasi (#0197),
nol jaringan.

Fixture = log Zeek dns.log TSV / BIND query log / format sederhana
sintetis dari spesifikasi heuristik (panjang subdomain, entropi
Shannon, volume TXT, interval beacon).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import dns_log_triage as dlt  # noqa: E402

ZEEK_HDR = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tquery\tqtype_name\n"
)


def _zeek(ts: float, src: str, query: str, qtype: str = "A",
          uid: str = "Cabc123") -> str:
    return f"{ts:.6f}\t{uid}\t{src}\t41234\t{query}\t{qtype}\n"


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "dns_log_triage.py"), "--log",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------- unit kecil ----------

def test_entropy_basics():
    assert dlt._entropy("") == 0.0
    assert dlt._entropy("aaaa") == 0.0
    assert dlt._entropy("ab") == 1.0
    assert dlt._entropy("x7a2k9qz4v6b") > 3.5


def test_split_query_suffix():
    assert dlt._split_query("www.example.com") == ("example.com",
                                                   "www", "example")
    reg, sub, sld = dlt._split_query("a.b.example.co.uk")
    assert reg == "example.co.uk" and sub == "a.b" and sld == "example"
    assert dlt._split_query("x8kj2m9p4qw7n.com")[0] == "x8kj2m9p4qw7n.com"


def test_bind_ts_locale_free():
    ts = dlt._parse_bind_ts("14-Mar-2024", "10:15:32", "123")
    assert ts is not None and abs(ts - 1710411332.123) < 0.01
    assert dlt._parse_bind_ts("14-Xyz-2024", "10:15:32", None) is None


# ---------- parse format ----------

def test_zeek_parse_and_counts(tmp_path):
    text = ZEEK_HDR + _zeek(1700000000.0, "10.0.0.5", "www.google.com")
    text += _zeek(1700000001.0, "10.0.0.5", "api.example.com", "AAAA")
    p = _tmp(tmp_path, "z.log", text)
    rc, out = _run(p)
    assert rc == 0 and out is not None
    assert out["parsed"] == 2 and out["by_format"] == {"zeek": 2}
    assert out["src_unique"] == 1 and out["domain_unique"] == 2
    assert out["qtype_top"][0] == ["A", 1]


def test_bind_and_simple_mixed(tmp_path):
    text = (
        "14-Mar-2024 10:15:32.123 queries: client 192.168.1.105#41234 "
        "(a.b.evil.com): query: a.b.evil.com IN TXT +E(0) (10.0.0.53)\n"
        "14-Mar-2024 10:15:33.100 queries: client @0x7f8b1c 192.168.1.6"
        "#5000: query: www.google.com IN A +\n"
        "10.0.0.9 dns2tcp-victim.example.net TXT\n"
    )
    p = _tmp(tmp_path, "b.log", text)
    rc, out = _run(p)
    assert rc == 0
    assert out["by_format"] == {"bind": 2, "simple": 1}
    assert out["parsed"] == 3 and out["unparsed_count"] == 0


def test_unparsed_lines_recorded(tmp_path):
    text = ZEEK_HDR + _zeek(1700000000.0, "10.0.0.5", "a.com")
    text += "baris rusak bukan log\nini juga bukan\n"
    p = _tmp(tmp_path, "mixed.log", text)
    rc, out = _run(p)
    assert rc == 0
    assert out["parsed"] == 1 and out["unparsed_count"] == 2
    assert out["unparsed_sample"][0].startswith("baris rusak")


def test_empty_and_unparseable_exit_2(tmp_path):
    p = _tmp(tmp_path, "empty.log", "")
    rc, out = _run(p)
    assert rc == 2 and out is None

    p2 = _tmp(tmp_path, "noise.log", "hello world\nfoo bar baz\n")
    rc2, out2 = _run(p2)
    assert rc2 == 2 and out2 is None


def test_zeek_missing_fields_exit_2(tmp_path):
    p = _tmp(tmp_path, "zbad.log",
             "#separator \\x09\n#fields\tts\tuid\n1.0\tCabc\n")
    rc, out = _run(p)
    assert rc == 2 and out is None


def test_simple_requires_ip_token(tmp_path):
    # token pertama bukan IP -> baris tetap unparsed (tanggal BIND
    # tanpa match regex tidak boleh jadi 'sumber')
    p = _tmp(tmp_path, "s.log", "14-Mar-2024 10:15:32 a.com\n")
    rc, out = _run(p)
    assert rc == 2  # nol baris ter-parse


# ---------- heuristik ----------

def test_tunnel_candidate_with_est_bytes(tmp_path):
    lines = ZEEK_HDR
    for i in range(25):
        sub = f"b{i:02d}" * 20  # 60 char
        lines += _zeek(1700000000.0 + i, "192.168.1.105",
                       f"{sub}.evil-tunnel.com", "TXT")
    p = _tmp(tmp_path, "tunnel.log", lines)
    rc, out = _run(p)
    assert rc == 0
    tun = [f for f in out["findings"]
           if f["type"] == "tunnel-candidate"]
    assert len(tun) == 1
    f = tun[0]
    assert f["severity"] == "high" and f["src"] == "192.168.1.105"
    assert f["domain"] == "evil-tunnel.com"
    assert f["evidence"]["queries"] == 25
    assert f["evidence"]["unique_subdomains"] == 25
    assert f["evidence"]["subdomain_len_max"] == 60
    assert f["evidence"]["exfil_bytes_est"] == int(25 * 60 * 0.75)
    assert len(f["evidence"]["sample_subdomains"]) == 3


_IRREGULAR = [0, 3, 17, 19, 44, 61, 89, 90, 130, 160, 199, 240, 290,
              350, 410, 480, 555, 640, 730, 830, 940, 1060, 1190,
              1330, 1480, 1640, 1810, 1990, 2180, 2380, 2590, 2810,
              3040, 3280, 3530, 3790, 4060, 4340, 4630, 4930]


def test_below_tunnel_thresholds_no_finding(tmp_path):
    lines = ZEEK_HDR
    for i in range(10):  # < tunnel-queries default 20
        sub = "x" * 60
        lines += _zeek(1700000000.0 + _IRREGULAR[i], "10.0.0.5",
                       f"{sub}.a.com")
    p = _tmp(tmp_path, "quiet.log", lines)
    rc, out = _run(p)
    assert rc == 0 and out["finding_count"] == 0


def test_txt_abuse_severity_tiers():
    rows = [("10.0.0.5", f"h{i}.a.com", "TXT", None, "zeek")
            for i in range(105)]
    f_med = dlt.analyze(rows, 50, 20, 100, 10, 12, 5)
    txt = [f for f in f_med if f["type"] == "txt-abuse"]
    assert len(txt) == 1 and txt[0]["severity"] == "medium"
    rows_hi = [("10.0.0.5", f"h{i}.a.com", "TXT", None, "zeek")
               for i in range(510)]
    f_hi = dlt.analyze(rows_hi, 50, 20, 100, 10, 12, 5)
    assert f_hi[0]["severity"] == "high"
    rows_cr = [("10.0.0.5", f"h{i}.a.com", "TXT", None, "zeek")
               for i in range(1005)]
    f_cr = dlt.analyze(rows_cr, 50, 20, 100, 10, 12, 5)
    assert f_cr[0]["severity"] == "critical"


def test_dga_char_class_threshold():
    # 10 domain unik SLD 14-char tanpa vokal (DGA = domain itu sendiri)
    rows = [("10.0.0.7", f"xqjkwpvhrtnmz{i}.com", "A", None, "zeek")
            for i in range(10)]
    f = dlt.analyze(rows, 50, 20, 100, 10, 12, 5)
    dga = [x for x in f if x["type"] == "dga-candidate"]
    assert len(dga) == 1 and dga[0]["evidence"]["unique_domains"] == 10
    # 9 domain -> tidak memicu
    f9 = dlt.analyze(rows[:9], 50, 20, 100, 10, 12, 5)
    assert not [x for x in f9 if x["type"] == "dga-candidate"]


def test_dga_entropy_route_only():
    # SLD 12 char: kelas-karakter butuh len > 12, jadi hanya entropi
    # (12 char unik -> entropi 3.58) yang memicu; 10 rotasi = 10 domain
    base = "x7a2k9qz4v6b"
    rows = [("10.0.0.8", f"{base[i:] + base[:i]}.com", "A", None,
             "zeek") for i in range(10)]
    f = dlt.analyze(rows, 50, 20, 100, 10, 12, 5)
    dga = [x for x in f if x["type"] == "dga-candidate"]
    assert len(dga) == 1
    reason = list(dga[0]["evidence"]["sample"].values())[0]
    assert "entropi" in reason


def test_beacon_candidate_regular_intervals():
    rows = []
    for i in range(6):
        rows.append(("10.0.0.5", f"q{i}.beacon.evil.com", "A",
                     1700000000.0 + i * 30.0, "zeek"))
    f = dlt.analyze(rows, 50, 20, 100, 10, 12, 5)
    bc = [x for x in f if x["type"] == "beacon-candidate"]
    assert len(bc) == 1
    assert bc[0]["evidence"]["interval_stdev_s"] <= 2.0
    assert bc[0]["domain"] == "evil.com"


def test_null_and_tool_signature():
    rows = [("10.0.0.9", "a.dnscat2.c2.example.com", "TXT", None,
             "zeek"),
            ("10.0.0.9", "b.dnscat2.c2.example.com", "TXT", None,
             "zeek"),
            ("10.0.0.9", "payload.iodine.tunnel.example.net", "NULL",
             None, "zeek")]
    f = dlt.analyze(rows, 50, 20, 100, 10, 12, 5)
    types = {x["type"]: x for x in f}
    assert types["tool-signature"]["severity"] == "high"
    assert types["tool-signature"]["evidence"]["queries"] == 3
    assert types["null-queries"]["evidence"]["null_queries"] == 1


def test_benign_log_no_findings(tmp_path):
    lines = ZEEK_HDR
    for i in range(40):
        ts = 1700000000.0 + _IRREGULAR[i]
        lines += _zeek(ts, f"10.0.0.{i % 5}", "www.google.com")
        lines += _zeek(ts, f"10.0.0.{i % 5}",
                       f"host{i}.cdn.example.net")
    p = _tmp(tmp_path, "benign.log", lines)
    rc, out = _run(p)
    assert rc == 0 and out["finding_count"] == 0


# ---------- CLI end-to-end ----------

def test_cli_out_file_and_schema(tmp_path):
    lines = ZEEK_HDR
    for i in range(25):
        lines += _zeek(1700000000.0 + i, "192.168.1.105",
                       f"{'c' * 60}{i}.evil.com", "TXT")
    p = _tmp(tmp_path, "cli.log", lines)
    outp = tmp_path / "out.json"
    rc, _ = _run(p, "--out", str(outp))
    assert rc == 0 and outp.is_file()
    data = json.loads(outp.read_text(encoding="utf-8"))
    assert data["schema"] == "secai.dns-log-triage/1"
    assert data["read_only"] is True
    assert data["note"].startswith("semua temuan = LEAD")
    assert data["thresholds"]["subdomain_len"] == 50


def test_cli_custom_threshold(tmp_path):
    lines = ZEEK_HDR
    for i in range(10):  # di bawah default 20
        lines += _zeek(1700000000.0 + i, "10.0.0.5", f"{'y' * 60}.a.com")
    p = _tmp(tmp_path, "thr.log", lines)
    rc, out = _run(p, "--tunnel-queries", "5")
    assert rc == 0
    assert any(f["type"] == "tunnel-candidate"
               for f in out["findings"])
