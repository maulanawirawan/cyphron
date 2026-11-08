"""test_broken_link_scan — inventaris referensi eksternal isi halaman +
penanda broken link hijacking (#1010), nol jaringan. Semua fixture dibangun
runtime (tanpa literal secret, tanpa jaringan): resolver DILUCUTI dari tool
— liveness hanya dari --resolutions milik operator.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE))

import broken_link_scan as bls  # noqa: E402
from findings import validate_finding  # noqa: E402

PAGE = """<!doctype html>
<html><head>
<script src="https://static.targetsite.com/app.js"></script>
<script src="https://cdn.thirdparty-example.com/lib.js"></script>
<script src="http://insecure-cdn.example.net/old.js"></script>
<link href="https://fonts.example.org/css" rel="stylesheet">
</head><body>
<img src="/local.png" alt="">
<img src="https://img.thirdparty-example.com/pic.png">
</body></html>"""

JS = """fetch('https://api.thirdparty-example.com/v1/data');
var u = "//old-cdn.example.org/lib.js";
load("//metrics.example.io/t.gif");
"""


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


def _scan(tmp: Path, files: dict[str, str], resolutions: dict | None = None,
          base: str | None = None):
    paths = []
    for name, text in files.items():
        paths.append(_write(tmp, name, text))
    arts = [(str(p), p.read_text(encoding="utf-8")) for p in paths]
    return bls.scan(arts, base, resolutions or {})


# ------------------------------------------------------- ekstraksi referensi
def test_html_extraction_internal_and_external(tmp_path):
    r = _scan(tmp_path, {"page.html": PAGE}, base="targetsite.com")
    hosts = {f["target_url"].split("/")[2] for f in r["findings"]} \
        if r["findings"] else set()
    # tanpa resolutions: semua host eksternal = info unresolved
    ext = r["stats"]["external_hosts"]
    assert ext == 4  # thirdparty-example.com, insecure-cdn, fonts, img
    assert r["stats"]["internal_refs"] >= 1  # static.targetsite.com = internal
    assert r["stats"]["skipped_hosts"] == 0


def test_js_protocol_relative_and_css_url(tmp_path):
    css = "body { background: url(https://bg.example.org/i.png); }"
    r = _scan(tmp_path, {"app.js": JS, "s.css": css})
    assert r["stats"]["external_hosts"] == 4  # api, old-cdn, metrics, bg


def test_srcset_first_candidate(tmp_path):
    page = '<img srcset="https://a.example.com/1.png 1x, https://b.example.com/2.png 2x">'
    r = _scan(tmp_path, {"p.html": page})
    urls = [f["target_url"] for f in r["findings"]]
    assert any("a.example.com" in u for u in urls)


def test_line_numbers_are_real(tmp_path):
    r = _scan(tmp_path, {"page.html": PAGE})
    f = [x for x in r["findings"]
         if "insecure-cdn" in (x["target_url"] or "")][0]
    assert f["line_start"] == 5  # baris ke-5 PAGE


def test_dedup_same_url_same_line(tmp_path):
    page = '<a href="https://x.example.com/a">1</a><a href="https://x.example.com/a">2</a>'
    r = _scan(tmp_path, {"p.html": page})
    assert r["stats"]["external_hosts"] == 1
    assert all(isinstance(f.get("ref_count"), int) and f["ref_count"] >= 1
               for f in r["findings"])


# ------------------------------------------------------- klasifikasi liveness
def test_nxdomain_is_high_lead_with_resolution_evidence(tmp_path):
    res = {"cdn.thirdparty-example.com": "nxdomain"}
    r = _scan(tmp_path, {"page.html": PAGE}, resolutions=res)
    highs = [f for f in r["findings"] if f["severity"] == "high"]
    assert len(highs) == 1
    f = highs[0]
    assert f["finding_class"] in ("weakness", "posture")
    assert f["status"] == "unconfirmed"
    assert f["verdict"] == 1  # LEAD maksimal
    assert f["verdict_tag"].startswith("L1")
    assert "NXDOMAIN" in f["description"]
    assert '"rcode": 3' in (f["response"] or "")
    assert validate_finding(f) == []


def test_servfail_is_not_nxdomain_kejujuran(tmp_path):
    # SERVFAIL (rcode 2) TIDAK boleh jadi "domain mati" — fail-safe
    res = {"cdn.thirdparty-example.com": {"Status": 2}}
    r = _scan(tmp_path, {"page.html": PAGE}, resolutions=res)
    assert not [f for f in r["findings"] if f["severity"] == "high"]
    infos = [f for f in r["findings"] if f["severity"] == "info"]
    assert any("SERVFAIL" in f["description"] or "tak-menentukan"
               in f["description"] for f in infos)


def test_doh_object_status3_and_cname_capture(tmp_path):
    res = {
        "cdn.thirdparty-example.com": {"Status": 3},
        "insecure-cdn.example.net": {
            "Status": 0,
            "Answer": [{"name": "insecure-cdn.example.net.",
                        "type": 5, "data": "legacy-app.azurewebsites.net."}],
        },
    }
    r = _scan(tmp_path, {"page.html": PAGE}, resolutions=res)
    highs = [f for f in r["findings"] if f["severity"] == "high"]
    assert len(highs) == 1 and "tak-terdaftar" in highs[0]["title"]
    dangling = [f for f in r["findings"]
                if "CNAME marker layanan" in f["title"]]
    assert len(dangling) == 1 and "azurewebsites.net" in \
        dangling[0]["description"]


def test_resolved_clean_not_finding(tmp_path):
    res = {h: {"Status": 0} for h in (
        "cdn.thirdparty-example.com", "insecure-cdn.example.net",
        "fonts.example.org", "img.thirdparty-example.com")}
    r = _scan(tmp_path, {"page.html": PAGE}, resolutions=res,
              base="targetsite.com")
    # insecure-cdn = http:// -> low cleartext; sisanya https OK -> bersih
    assert r["stats"]["findings"] == 1
    assert r["findings"][0]["severity"] == "low"


def test_cleartext_script_low(tmp_path):
    res = {"insecure-cdn.example.net": {"Status": 0}}
    r = _scan(tmp_path, {"page.html": PAGE}, resolutions=res)
    lows = [f for f in r["findings"] if f["severity"] == "low"]
    assert len(lows) == 1 and "cleartext" in lows[0]["title"]


def test_without_resolutions_everything_unresolved_info(tmp_path):
    r = _scan(tmp_path, {"page.html": PAGE})
    # 5 host unresolved (info) + 1 fakta cleartext terpisah utk insecure-cdn
    assert r["stats"]["findings"] == r["stats"]["external_hosts"] + 1
    infos = [f for f in r["findings"] if f["severity"] == "info"]
    assert len(infos) == r["stats"]["external_hosts"]


# ------------------------------------------------------- host yang dilewati
def test_reserved_and_ip_and_single_label_skipped(tmp_path):
    page = ('<img src="https://box.invalid/p.png">'
            '<img src="http://192.168.1.10/x.png">'
            '<img src="https://intranet/x.png">'
            '<img src="https://real.example.com/y.png">')
    r = _scan(tmp_path, {"p.html": page})
    assert r["stats"]["external_hosts"] == 1  # real.example.com saja
    assert r["skipped_hosts"] == {"box.invalid": "reserved-tld",
                                  "192.168.1.10": "ip-literal",
                                  "intranet": "single-label"}


def test_internal_refs_counted_not_external(tmp_path):
    r = _scan(tmp_path, {"page.html": PAGE}, base="targetsite.com")
    assert r["stats"]["internal_refs"] >= 1
    assert not [f for f in r["findings"]
                if "static.targetsite.com" in (f["target_url"] or "")]


def test_bad_base_domain_fail_closed(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        _scan(tmp_path, {"p.html": "<p>x</p>"}, base="box.invalid")


# ------------------------------------------------------- skip artefak
def test_binary_skipped_recorded(tmp_path):
    r = _scan(tmp_path, {"blob.bin": "AB\x00CD", "app.js": JS})
    assert any("biner" in n for n in r["notes"])
    assert r["stats"]["external_hosts"] == 3  # api, old-cdn, metrics


def test_oversize_skipped_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(bls, "MAX_FILE_BYTES", 32)
    r = _scan(tmp_path, {"big.js": "x" * 200 + " https://ov.example.com/a.js",
                         "ok.js": "https://ok.example.com/a.js"})
    assert any("melebihi" in n for n in r["notes"])
    assert r["stats"]["external_hosts"] == 1


# ------------------------------------------------------- fail-closed CLI
def _cli(tmp_path, *argv):
    return subprocess.run(
        [sys.executable, str(TOOLS / "broken_link_scan.py"), *argv],
        capture_output=True, text=True, cwd=str(tmp_path))


def test_cli_missing_file_exit2(tmp_path):
    p = _cli(tmp_path, "--file", str(tmp_path / "nope.html"))
    assert p.returncode == 2 and "input error" in p.stderr


def test_cli_no_input_exit2(tmp_path):
    p = _cli(tmp_path)
    assert p.returncode == 2


def test_cli_broken_resolutions_exit2(tmp_path):
    f = _write(tmp_path, "p.html", PAGE)
    r = _write(tmp_path, "res.json", "{bukan json")
    p = _cli(tmp_path, "--file", str(f), "--resolutions", str(r))
    assert p.returncode == 2


def test_cli_resolutions_non_dict_exit2(tmp_path):
    f = _write(tmp_path, "p.html", PAGE)
    r = _write(tmp_path, "res.json", "[1,2]")
    p = _cli(tmp_path, "--file", str(f), "--resolutions", str(r))
    assert p.returncode == 2


def test_cli_failon_any_exit1_and_high_gate(tmp_path):
    f = _write(tmp_path, "p.html", PAGE)
    res = _write(tmp_path, "res.json",
                 json.dumps({"cdn.thirdparty-example.com": "nxdomain"}))
    p1 = _cli(tmp_path, "--file", str(f), "--resolutions", str(res),
              "--fail-on", "any")
    assert p1.returncode == 1
    # hanya info (tanpa high): ambang high = exit 0
    p2 = _cli(tmp_path, "--file", str(f), "--fail-on", "high")
    assert p2.returncode == 0


def test_cli_out_contract_wrapper(tmp_path):
    f = _write(tmp_path, "p.html", PAGE)
    res = _write(tmp_path, "res.json",
                 json.dumps({"cdn.thirdparty-example.com": "nxdomain"}))
    out = tmp_path / "findings.json"
    p = _cli(tmp_path, "--file", str(f), "--resolutions", str(res),
             "--fail-on", "any", "--out", str(out))
    assert p.returncode == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["ok"] is True and isinstance(doc["findings"], list)
    assert doc["requests"] == 0
    for fd in doc["findings"]:
        assert validate_finding(fd) == []


def test_deterministic_output(tmp_path):
    f = _write(tmp_path, "p.html", PAGE)
    a = _cli(tmp_path, "--file", str(f))
    b = _cli(tmp_path, "--file", str(f))
    assert a.returncode == b.returncode == 0
    assert a.stdout == b.stdout
