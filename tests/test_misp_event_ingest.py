"""test_misp_event_ingest — ingest event JSON MISP, nol jaringan."""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import misp_event_ingest as mei  # noqa: E402


def _run(path: Path, *extra: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "misp_event_ingest.py"), "--event",
         str(path), *extra], capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


def _tmp(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _event() -> dict:
    return {"Event": {
        "id": "4242",
        "info": "Phishing campaign targeting corp.example.com",
        "Attribute": [
            {"type": "ip-dst", "value": "203.0.113.9", "category": "Network activity",
             "Tag": [{"name": "type:phishing"}, {"name": "priority:high"}]},
            {"type": "domain", "value": "corp-login.example.net",
             "category": "Network activity", "Tag": []},
            {"type": "url", "value": "http://corp-login.example.net/ok",
             "category": "Network activity", "Tag": []},
            {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e",
             "category": "Payload delivery", "Tag": []},
            {"type": "yara", "value": "rule x { condition: true }",
             "category": "Payload delivery", "Tag": []},
        ],
    }}


def test_in_scope_flagged_high(tmp_path):
    p = _tmp(tmp_path, "ev.json", json.dumps(_event()).encode())
    s = _tmp(tmp_path, "scope.json", json.dumps(
        {"ips": ["203.0.113.9"],
         "domains": ["corp-login.example.net"]}).encode())
    code, out = _run(p, "--scope", s)
    assert code == 0
    hi = [f for f in out["findings"] if f["type"] == "ioc-in-scope"]
    assert len(hi) == 3  # ip-dst + domain + url (host-nya di scope)
    assert hi[0]["evidence"]["misp_event"] == "4242"


def test_notable_by_tag(tmp_path):
    p = _tmp(tmp_path, "ev.json", json.dumps(_event()).encode())
    code, out = _run(p)
    notables = [f for f in out["findings"] if f["type"] == "ioc-notable"]
    assert notables and "priority:high" in notables[0]["evidence"]["tags"]


def test_catalog_and_unknown(tmp_path):
    p = _tmp(tmp_path, "ev.json", json.dumps(_event()).encode())
    code, out = _run(p)
    types = {f["type"] for f in out["findings"]}
    assert "ioc-catalog" in types and "event-summary" in types
    cat = [f for f in out["findings"] if f["type"] == "ioc-catalog"][0]
    assert cat["evidence"]["count"] >= 2  # md5 + yara


def test_gzip_input(tmp_path):
    p = _tmp(tmp_path, "ev.json.gz", gzip.compress(json.dumps(_event()).encode()))
    code, out = _run(p)
    assert code == 0 and out["attributes_total"] == 5


def test_fail_closed(tmp_path):
    p = _tmp(tmp_path, "junk.json", b'{"foo": 1}')
    code, out = _run(p)
    assert code == 2 and out is None
    code2, _ = _run(tmp_path / "missing.json")
    assert code2 == 2
