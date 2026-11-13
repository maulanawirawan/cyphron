"""test_cryptojack_log_triage — indikasi cryptojacking di log proxy/DNS,
nol jaringan.

Fixture = squid access log / DNS sederhana / format simple sintetis +
kontrol false-positive (traffic normal tidak boleh memicu pool-domain).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import cryptojack_log_triage as clt  # noqa: E402


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "cryptojack_log_triage.py"), "--log",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ---------- unit kecil ----------

def test_pool_hit():
    assert clt._pool_hit("xmrpool.eu") == "xmrpool"
    assert clt._pool_hit("ethermine.org") == "ethermine"
    assert clt._pool_hit("minexmr.example") == "minexmr"
    assert clt._pool_hit("microsoft.com") is None
    assert clt._pool_hit("eu-pool.com") == "generic-pool-suffix"
    assert clt._pool_hit("mypool.example.com") is None  # label bukan sebelum TLD


def test_parse_squid_line():
    line = ('192.168.1.50 - - [13/Nov/2026:10:00:00 +0000] '
            '"GET http://xmrpool.eu/notify HTTP/1.1" 200 210')
    rows, unp = clt.parse_log(line)
    assert len(rows) == 1 and unp == []
    assert rows[0][0] == "192.168.1.50"
    assert rows[0][1] == "xmrpool.eu"
    assert rows[0][5] == "squid"


def test_parse_dns_line():
    rows, unp = clt.parse_log("192.168.1.51 pool.supportxmr.com A")
    assert len(rows) == 1
    assert rows[0][1] == "pool.supportxmr.com"


def test_unparsed_counted():
    rows, unp = clt.parse_log("ini bukan log")
    assert rows == [] and len(unp) == 1


# ---------- end-to-end ----------

def test_pool_domain_found_squid(tmp_path):
    lines = []
    for i in range(6):
        lines.append(f'192.168.1.50 - - [13/Nov/2026:10:0{i}:00 +0000] '
                     f'"GET http://xmrpool.eu/api HTTP/1.1" 200 {100+i}')
    p = _tmp(tmp_path, "proxy.log", "\n".join(lines))
    code, out = _run(p)
    assert code == 0 and out["parsed"] == 6
    pool = [f for f in out["findings"] if f["type"] == "pool-domain"]
    assert pool and pool[0]["src"] == "192.168.1.50"
    assert "xmrpool" in pool[0]["evidence"]["pool_keys"]


def test_stratum_and_tokens(tmp_path):
    text = ("10.0.0.7 - - [13/Nov/2026:10:00:00 +0000] "
            '"POST stratum+tcp://pool.example:3333 HTTP/1.1" 200 50\n'
            "10.0.0.8 xmrpool.net A\n")
    p = _tmp(tmp_path, "mix.log", text)
    code, out = _run(p)
    types = {f["type"] for f in out["findings"]}
    assert "stratum-usage" in types
    assert "pool-domain" in types


def test_long_uniform_beacon(tmp_path):
    # 12 koneksi tiap 10 detik selama 110 detik ke host yang sama
    lines = []
    for i in range(12):
        lines.append(f"{1700000000 + i * 10}\t192.168.1.60\tGET\t"
                     f"mining.example.com\t/submit\t80\t200\t120")
    p = _tmp(tmp_path, "simple.log", "\n".join(lines))
    code, out = _run(p, "--conn-min", "8", "--uniform-mins", "1.0")
    lu = [f for f in out["findings"] if f["type"] == "long-uniform"]
    assert lu and lu[0]["evidence"]["connections"] == 12


def test_false_positive_control_normal_traffic(tmp_path):
    # browsing normal: host umum, satu kali — tidak boleh ada temuan high
    text = ("192.168.1.77 - - [13/Nov/2026:10:00:00 +0000] "
            '"GET https://www.wikipedia.org/ HTTP/1.1" 200 5000\n'
            "192.168.1.78 www.google.com A\n")
    p = _tmp(tmp_path, "normal.log", text)
    code, out = _run(p)
    assert code == 0
    assert all(f["type"] not in ("pool-domain", "stratum-usage",
                                "mining-token-uri")
               for f in out["findings"])


def test_fail_closed(tmp_path):
    p = _tmp(tmp_path, "junk.log", "garbage line one\ngarbage two")
    code, out = _run(p)
    assert code == 2 and out is None
    code2, _ = _run(tmp_path / "missing.log")
    assert code2 == 2
