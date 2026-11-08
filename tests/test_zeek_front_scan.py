"""test_zeek_front_scan — deteksi domain fronting SNI-vs-Host (#0545),
nol jaringan.

Fixture = http.log + ssl.log Zeek sintetis (TSV #fields dan JSONL).
Pembagian ranah diuji: conn.log beacon = zeek_beacon_scan (B13),
smb/dce = zeek_lateral_scan (B15), dns = dns_log_triage (B07).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import zeek_front_scan as zf  # noqa: E402

HTTP_FIELDS = ("uid", "host", "method", "uri", "id.orig_h", "id.resp_h")
SSL_FIELDS = ("uid", "server_name", "id.orig_h", "id.resp_h")


def _tsv(path: Path, fields: "tuple[str, ...]", rows: list[dict]) -> None:
    lines = ["#separator \\x09", "#fields\t" + "\t".join(fields)]
    for r in rows:
        lines.append("\t".join(r.get(f, "-") for f in fields))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _jsonl(path: Path, rows: list[dict], nested: bool = False) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            if nested:
                r = {
                    "uid": r["uid"],
                    "id": {"orig_h": r.get("id.orig_h", ""),
                           "resp_h": r.get("id.resp_h", "")},
                    **{k: v for k, v in r.items()
                       if not k.startswith("id.")},
                }
            fh.write(json.dumps(r) + "\n")


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "zeek_front_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _findings(out, check):
    return [x for x in out["findings"] if x["check"] == check]


# ------------------------------------------------------- deteksi inti
def test_sni_host_mismatch(tmp_path):
    _tsv(tmp_path / "http.log", HTTP_FIELDS, [
        {"uid": "C1", "host": "evil.example.net", "method": "POST",
         "uri": "/gate.php", "id.orig_h": "10.0.0.9",
         "id.resp_h": "104.16.1.5"}])
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "104.16.1.5"}])
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"), "--json")
    assert rc == 1 and out is not None, err
    f = _findings(out, "sni-host-mismatch")
    assert len(f) == 1
    assert f[0]["sni"] == "cdn.trusted.example"
    assert f[0]["host"] == "evil.example.net"
    assert "T1090.004" in f[0]["message"]


def test_same_domain_suffix_not_flagged(tmp_path):
    _tsv(tmp_path / "http.log", HTTP_FIELDS, [
        {"uid": "C1", "host": "api.example.com", "method": "GET",
         "uri": "/", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"},
        {"uid": "C2", "host": "example.com", "method": "GET",
         "uri": "/", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.2"}])
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "example.com",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"},
        {"uid": "C2", "server_name": "www.example.com",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.2"}])
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"), "--json")
    assert rc == 0 and out["findings"] == []


def test_missing_host_or_sni_skipped_counted(tmp_path):
    _tsv(tmp_path / "http.log", HTTP_FIELDS, [
        {"uid": "C1", "host": "-", "method": "GET", "uri": "/",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "a.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"), "--json")
    assert rc == 0
    assert out["stats"]["matched_uid"] == 0


# ------------------------------------------------------- agregasi
def test_fronting_source_summary(tmp_path):
    http_rows = [
        {"uid": f"C{i}", "host": f"e{i}.example.net", "method": "POST",
         "uri": "/x", "id.orig_h": "10.0.0.9", "id.resp_h": "104.16.1.5"}
        for i in range(3)]
    ssl_rows = [
        {"uid": f"C{i}", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "104.16.1.5"}
        for i in range(3)]
    _tsv(tmp_path / "http.log", HTTP_FIELDS, http_rows)
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, ssl_rows)
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"),
                        "--fail-on", "medium", "--json")
    f = _findings(out, "fronting-source")
    assert len(f) == 1 and f[0]["orig"] == "10.0.0.9"


def test_fronting_source_below_threshold(tmp_path):
    http_rows = [
        {"uid": "C1", "host": "e1.example.net", "method": "POST",
         "uri": "/x", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}]
    ssl_rows = [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}]
    _tsv(tmp_path / "http.log", HTTP_FIELDS, http_rows)
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, ssl_rows)
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"),
                        "--fail-on", "medium", "--json")
    assert _findings(out, "fronting-source") == []
    assert len(_findings(out, "sni-host-mismatch")) == 1


# ------------------------------------------------------- format & join
def test_jsonl_and_nested_id(tmp_path):
    _jsonl(tmp_path / "http.json", [
        {"uid": "C1", "host": "evil.example.net", "method": "POST",
         "uri": "/g", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    _jsonl(tmp_path / "ssl.json", [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}], nested=True)
    rc, out, err = _run("--http", str(tmp_path / "http.json"),
                        "--ssl", str(tmp_path / "ssl.json"), "--json")
    assert rc == 1, err
    f = _findings(out, "sni-host-mismatch")
    assert len(f) == 1 and f[0]["orig"] == "10.0.0.9"


def test_uid_missing_counted(tmp_path):
    _jsonl(tmp_path / "http.json", [
        {"host": "evil.example.net", "method": "POST", "uri": "/g",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    _jsonl(tmp_path / "ssl.json", [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    rc, out, err = _run("--http", str(tmp_path / "http.json"),
                        "--ssl", str(tmp_path / "ssl.json"), "--json")
    assert rc == 0
    assert out["stats"]["uid_missing_http"] == 1
    assert any("tanpa uid" in n for n in out["notes"])


def test_http_uid_not_in_ssl_joined_out(tmp_path):
    _tsv(tmp_path / "http.log", HTTP_FIELDS, [
        {"uid": "C9", "host": "evil.example.net", "method": "POST",
         "uri": "/g", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"), "--json")
    assert rc == 0 and out["findings"] == []


# ------------------------------------------------------- fail-closed
def test_missing_file_fails_closed(tmp_path):
    rc, out, err = _run("--http", str(tmp_path / "nope.log"),
                        "--ssl", str(tmp_path / "nope2.log"))
    assert rc == 2


def test_empty_records_fail_closed(tmp_path):
    (tmp_path / "http.log").write_text("garbage only\n", encoding="utf-8")
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "a.example", "id.orig_h": "1.1.1.1",
         "id.resp_h": "2.2.2.2"}])
    rc, out, err = _run("--http", str(tmp_path / "http.log"),
                        "--ssl", str(tmp_path / "ssl.log"))
    assert rc == 2


# ------------------------------------------------------- unit + modes
def test_same_domain_unit():
    assert zf._same_domain("a.example", "a.example")
    assert zf._same_domain("sub.a.example", "a.example")
    assert zf._same_domain("a.example", "sub.a.example")
    assert not zf._same_domain("evil.example.net", "cdn.trusted.example")
    assert not zf._same_domain("example.net", "example.com")


def test_determinism_and_out(tmp_path):
    _tsv(tmp_path / "http.log", HTTP_FIELDS, [
        {"uid": "C1", "host": "evil.example.net", "method": "POST",
         "uri": "/g", "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    _tsv(tmp_path / "ssl.log", SSL_FIELDS, [
        {"uid": "C1", "server_name": "cdn.trusted.example",
         "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"}])
    rc1, o1, _ = _run("--http", str(tmp_path / "http.log"),
                      "--ssl", str(tmp_path / "ssl.log"), "--json")
    rc2, o2, _ = _run("--http", str(tmp_path / "http.log"),
                      "--ssl", str(tmp_path / "ssl.log"), "--json")
    assert rc1 == rc2 == 1 and o1 == o2
    outp = tmp_path / "rep.json"
    rc3, _, _ = _run("--http", str(tmp_path / "http.log"),
                     "--ssl", str(tmp_path / "ssl.log"),
                     "--out", str(outp))
    assert rc3 == 1
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        zf.SCHEMA
