"""test_ws_handshake_audit — audit bukti handshake WebSocket offline
(#0514), nol jaringan.

Fixture = bukti handshake/halaman sintetis dari spesifikasi RFC 6455 +
konsep pengujian CSWSH sumber; bukan salinan kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import ws_handshake_audit as ws  # noqa: E402

URL = "wss://target.example/ws"


def _hs(url=URL, status=101, req=None, resp=None) -> dict:
    return {"url": url, "status": status,
            "request_headers": req or {},
            "response_headers": resp or {}}


def _write(tmp_path, records, name="ev.jsonl", jsonl=True) -> Path:
    p = tmp_path / name
    if jsonl:
        p.write_text(
            "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    else:
        p.write_text(json.dumps(records), encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "ws_handshake_audit.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- parsing
def test_jsonl_and_array_parse(tmp_path):
    recs = [_hs()]
    assert len(ws.load_evidence(_write(tmp_path, recs, "a.jsonl"))) == 1
    assert len(ws.load_evidence(_write(tmp_path, recs, "a.json", False))) == 1


def test_invalid_exit2(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text("xxx\n", encoding="utf-8")
    rc, out, err = _run("--evidence", str(p))
    assert rc == 2 and out is None and "tidak valid" in err


def test_empty_exit2(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    rc, _, _ = _run("--evidence", str(p))
    assert rc == 2


def test_page_record_kind_detection(tmp_path):
    recs = [{"url": "https://t.example/", "html": "<p>halo</p>"}]
    ev = ws.load_evidence(_write(tmp_path, recs))
    assert ev[0]["kind"] == "page"


# ------------------------------------------------------- CSWSH origin
def test_cswsh_origin_evil_101(tmp_path):
    p = _write(tmp_path, [_hs(req={
        "Origin": "https://evil.example.com",
        "X-Probe-Evil": "1",
        "Cookie": "session=victim",
    })])
    rc, out, _ = _run("--evidence", str(p))
    assert rc == 1 and "cswsh-origin-unvalidated" in _checks(out)


def test_cswsh_evil_in_origin_label(tmp_path):
    p = _write(tmp_path, [_hs(req={
        "Origin": "https://attacker.test",
        "Cookie": "session=victim",
    })])
    rc, out, _ = _run("--evidence", str(p))
    assert "cswsh-origin-unvalidated" in _checks(out)


def test_origin_enforced_403_positive_note(tmp_path):
    p = _write(tmp_path, [_hs(status=403, req={
        "Origin": "https://attacker.test", "Cookie": "s=1"})])
    rc, out, _ = _run("--evidence", str(p))
    assert rc == 0 and out["findings"] == []
    assert any("DITEGAKKAN" in n for n in out["notes"])


# ------------------------------------------------------- RFC conform
def test_upgrade_without_key_flagged(tmp_path):
    p = _write(tmp_path, [_hs(req={"Cookie": "s=1"})])
    rc, out, _ = _run("--evidence", str(p))
    assert rc == 1 and "nonconform-key-accepted" in _checks(out)


def test_upgrade_with_key_ok(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
             "Cookie": "s=1"})])
    rc, out, _ = _run("--evidence", str(p))
    assert "nonconform-key-accepted" not in _checks(out)


# ------------------------------------------------------- anon
def test_anon_handshake_accepted_medium(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})])
    rc, out, _ = _run("--evidence", str(p), "--fail-on", "medium")
    assert rc == 1 and "anon-handshake-accepted" in _checks(out)


def test_anon_not_failing_at_high(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})])
    rc, _, _ = _run("--evidence", str(p))
    assert rc == 0


# ------------------------------------------------------- transport/query
def test_ws_plaintext_and_token_in_query(tmp_path):
    p = _write(tmp_path, [
        _hs(url="ws://target.example/ws?token=abc123",
            req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                 "Cookie": "s=1"}),
    ])
    rc, out, _ = _run("--evidence", str(p), "--fail-on", "medium")
    checks = _checks(out)
    assert "ws-plaintext" in checks and "token-in-query" in checks


def test_wss_no_plaintext(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
             "Cookie": "s=1"})])
    rc, out, _ = _run("--evidence", str(p))
    assert "ws-plaintext" not in _checks(out)


def test_mixed_ws_on_https_page(tmp_path):
    p = _write(tmp_path, [{
        "url": "https://target.example/",
        "html": "<script>var ws = new WebSocket("
                "\"ws://target.example/live\");</script>",
    }])
    rc, out, _ = _run("--evidence", str(p), "--fail-on", "medium")
    assert "mixed-ws-on-https-page" in _checks(out)


# ------------------------------------------------------- extensions
def test_permessage_deflate_low(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
             "Cookie": "s=1"},
        resp={"Sec-WebSocket-Extensions": "permessage-deflate"})])
    rc, out, _ = _run("--evidence", str(p), "--fail-on", "low")
    assert "permessage-deflate" in _checks(out)


def test_subprotocol_echo_low(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
             "Cookie": "s=1", "Sec-WebSocket-Protocol": "admin-protocol"},
        resp={"Sec-WebSocket-Protocol": "admin-protocol"})])
    rc, out, _ = _run("--evidence", str(p), "--fail-on", "low")
    assert "subprotocol-echo" in _checks(out)


# ------------------------------------------------------- fail-closed notes
def test_message_scope_note_present(tmp_path):
    p = _write(tmp_path, [_hs(
        req={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
             "Cookie": "s=1"})])
    rc, out, _ = _run("--evidence", str(p))
    assert any("bukan dari kegelapan" in n or
               "tidak dinilai dari bukti handshake" in n
               for n in out["notes"])


def test_deterministic(tmp_path):
    p = _write(tmp_path, [_hs(req={"Origin": "https://evil.example",
                                   "X-Probe-Evil": "1"})])
    ev = ws.load_evidence(p)
    a = ws.analyze([dict(r) for r in ev])
    b = ws.analyze([dict(r) for r in ev])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_out_file(tmp_path):
    p = _write(tmp_path, [_hs(req={"Origin": "https://evil.example",
                                   "X-Probe-Evil": "1"})])
    o = tmp_path / "rep.json"
    rc, _, _ = _run("--evidence", str(p), "--out", str(o))
    assert rc == 1 and o.exists()
    assert json.loads(o.read_text(encoding="utf-8"))["schema"] == \
        "secai.ws-handshake-audit/1"
