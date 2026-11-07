"""test_shadow_api_diff — diff OFFLINE endpoint teramati vs
terdokumentasi OpenAPI utk shadow/zombie API (#0458), nol jaringan.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import shadow_api_diff as sad  # noqa: E402

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/users": {"get": {}},
        "/api/users/{user_id}": {"get": {}},
        "/api/orders": {"post": {}},
    },
}


def _spec_file(tmp_path) -> Path:
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(SPEC), encoding="utf-8")
    return p


def _log_file(tmp_path, lines: list[str]) -> Path:
    p = tmp_path / "access.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _clf(ip: str, method: str, uri: str, status: int = 200) -> str:
    return (f'{ip} - - [08/Nov/2026:10:00:00 +0000] "{method} {uri} '
            f'HTTP/1.1" {status} 123 "-" "ua/1.0"')


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "shadow_api_diff.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


# ------------------------------------------------------- normalisasi
def test_normalize_dynamic_segments():
    assert sad.normalize_observed("/api/users/123") == \
        "/api/users/{var}"
    assert sad.normalize_observed("/api/x/550e8400-e29b-41d4-a716-"
                                  "446655440000") == "/api/x/{var}"
    assert sad.normalize_observed("/api/users") == "/api/users"


def test_spec_template_re():
    rx = sad.spec_template_re("/api/users/{user_id}")
    assert rx.match("/api/users/123")
    assert rx.match("/api/users/abc-def")
    assert not rx.match("/api/users/123/extra")
    assert not rx.match("/api/users")


# ------------------------------------------------------- parser log
def test_parse_clf_and_jsonl(tmp_path):
    text = _clf("10.0.0.1", "GET", "/api/users") + "\n" + json.dumps(
        {"method": "POST", "path": "/api/orders", "status": 201,
         "ip": "10.0.0.2"})
    reqs, unparsed = sad.parse_log(text, "x")
    assert len(reqs) == 2 and unparsed == []
    assert reqs[1]["auth_known"] is True


def test_parse_log_unparsed_recorded(tmp_path):
    mixed = _clf("10.0.0.1", "GET", "/api/users") + "\nbaris sampah\n"
    reqs, unparsed = sad.parse_log(mixed, "x")
    assert len(reqs) == 1 and unparsed
    try:
        sad.parse_log("baris sampah\n", "x")
    except ValueError as exc:
        assert "nol baris" in str(exc)
    else:
        raise AssertionError("harusnya ValueError (fail-closed)")


# ------------------------------------------------------- shadow
def test_shadow_endpoint_flagged(tmp_path):
    log = _log_file(tmp_path, [
        _clf("10.0.0.1", "GET", "/api/internal/debug?verbose=1", 200),
        _clf("10.0.0.2", "GET", "/api/internal/debug", 200),
    ])
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log))
    shadows = [f for f in out["findings"]
               if f["check"] == "shadow-endpoint"]
    assert len(shadows) == 1
    assert shadows[0]["normalized"] == "/api/internal/debug"


def test_documented_dynamic_match_clean(tmp_path):
    log = _log_file(tmp_path, [
        _clf("10.0.0.1", "GET", "/api/users/42", 200),
        _clf("10.0.0.1", "GET", "/api/users", 200),
        _clf("10.0.0.1", "POST", "/api/orders", 201),
    ])
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log))
    shadows = [f for f in out["findings"]
               if f["check"] == "shadow-endpoint"]
    assert shadows == [] and rc == 0


def test_zombie_documented_listed(tmp_path):
    log = _log_file(tmp_path, [_clf("10.0.0.1", "GET", "/api/users")])
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log))
    zomb = next(f for f in out["findings"]
                if f["check"] == "unobserved-documented")
    assert "/api/orders" in zomb["paths"]
    assert "/api/users/{var}" in zomb["paths"]


def test_risk_score_volume_and_auth(tmp_path):
    # 101 request tanpa auth (JSON log auth=no), 1 IP:
    # 3 (tanpa auth) + 1 (volume>100) + 0 (1 IP) + 1 (2xx) = 5 -> high
    lines = [json.dumps({"method": "GET", "path": "/api/hidden",
                         "status": 200, "ip": "10.9.0.1",
                         "authorization": ""})
             for _ in range(101)]
    log = _log_file(tmp_path, lines)
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log))
    sh = out["findings"][0]
    assert sh["risk_score"] == 5 and sh["severity"] == "high"
    assert rc == 1


def test_risk_score_unique_ips(tmp_path):
    # 12 IP berbeda tanpa auth, 2xx: 3+0(2 req)+2(>10 ip)+1 = 6 -> high
    lines = [json.dumps({"method": "GET", "path": "/api/hidden",
                         "status": 200, "ip": f"10.9.{i}.1",
                         "authorization": ""})
             for i in range(12)]
    log = _log_file(tmp_path, lines)
    _, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                     "--log", str(log))
    sh = out["findings"][0]
    assert sh["risk_score"] == 6 and sh["unique_ips"] == 12


def test_clf_auth_unknown_score(tmp_path):
    # CLF: auth tak diketahui -> +1; 2 request sukses -> +1 -> 2 = low
    log = _log_file(tmp_path, [
        _clf("10.0.0.1", "GET", "/api/lowkey", 200),
        _clf("10.0.0.2", "GET", "/api/lowkey", 404),
    ])
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log))
    sh = next(f for f in out["findings"]
              if f["check"] == "shadow-endpoint")
    assert sh["severity"] == "low" and rc == 0


def test_prefix_filter(tmp_path):
    log = _log_file(tmp_path, [
        _clf("10.0.0.1", "GET", "/static/logo.png"),
        _clf("10.0.0.1", "GET", "/api/hidden", 200),
    ])
    rc, out, _ = _run("--spec", str(_spec_file(tmp_path)),
                      "--log", str(log), "--prefix", "/api")
    shadows = [f for f in out["findings"]
               if f["check"] == "shadow-endpoint"]
    assert len(shadows) == 1 and shadows[0]["path"] == "/api/hidden"


# ------------------------------------------------------- fail-closed
def test_missing_log_exit2(tmp_path):
    rc, out, err = _run("--spec", str(_spec_file(tmp_path)),
                        "--log", "TIDAK-ADA.log")
    assert rc == 2 and out is None


def test_no_spec_or_paths_exit2(tmp_path):
    log = _log_file(tmp_path, [_clf("1.1.1.1", "GET", "/x")])
    rc, out, err = _run("--log", str(log))
    assert rc == 2 and "wajib --spec" in err


def test_spec_no_paths_exit2(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("{}", encoding="utf-8")
    log = _log_file(tmp_path, [_clf("1.1.1.1", "GET", "/x")])
    rc, out, err = _run("--spec", str(p), "--log", str(log))
    assert rc == 2 and "paths" in err


def test_zero_parsed_log_exit2(tmp_path):
    p = tmp_path / "bad.log"
    p.write_text("sampah\nsampah2\n", encoding="utf-8")
    rc, out, err = _run("--spec", str(_spec_file(tmp_path)),
                        "--log", str(p))
    assert rc == 2 and "nol baris" in err


def test_paths_file_alternative(tmp_path):
    pf = tmp_path / "paths.txt"
    pf.write_text("GET /api/users\nPOST /api/orders\n",
                  encoding="utf-8")
    log = _log_file(tmp_path, [_clf("10.0.0.1", "GET", "/api/ghost")])
    rc, out, _ = _run("--paths", str(pf), "--log", str(log))
    shadows = [f for f in out["findings"]
               if f["check"] == "shadow-endpoint"]
    assert len(shadows) == 1
    assert out["stats"]["documented_endpoints"] == 2
