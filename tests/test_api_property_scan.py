"""test_api_property_scan — audit statis eksposur properti API (#0392),
nol jaringan.

Fixture = tangkapan respons API sintetis dari spesifikasi taksonomi
sensitivitas (critical/high/medium/low) + allowlist + kandidat
mass-assignment.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import api_property_scan as aps  # noqa: E402

RESP = {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "profile": {
        "fullName": "John Doe",
        "ssn": "123-45-6789",
        "salary": 95000,
        "internal_notes": "VIP client",
        "password_hash": "$2b$12...",
        "role": "admin",
        "created_by": "system_admin",
    },
    "payment": {"creditCardNumber": "4242 4242 4242 4242"},
    "pagination": {"next_token": "abc", "page": 2},
    "phone": "+1-555-0100",
}

RESP_JSONL = (
    json.dumps({"path": "/api/v1/users/123", "response": RESP}) + "\n"
    + json.dumps({"path": "/api/v1/ping", "response": {"ok": True}})
)

BENIGN = {"console": "web", "enrolled": True, "message": "ok",
          "management": "x", "page": 3, "nextToken": "abc"}


def _run(*args: str) -> tuple[int, dict | None]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "api_property_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out


# ------------------------------------------------------- klasifikasi
def test_taxonomy_severity():
    assert aps.classify_property("password_hash") == "critical"
    assert aps.classify_property("passwordHash") == "critical"
    assert aps.classify_property("api_key") == "critical"
    assert aps.classify_property("creditCardNumber") == "high"
    assert aps.classify_property("ssn") == "high"
    assert aps.classify_property("salary") == "high"
    assert aps.classify_property("internal_notes") == "medium"
    assert aps.classify_property("userRole") == "medium"
    assert aps.classify_property("is_admin") == "medium"
    assert aps.classify_property("phone") == "low"


def test_no_false_positive_on_lookalike_words():
    # 'role' TIDAK boleh kena 'console'/'enrolled'; 'age' TIDAK kena
    # 'page'; 'admin' TIDAK kena 'domain'
    assert aps.classify_property("console") is None
    assert aps.classify_property("enrolled") is None
    assert aps.classify_property("page") is None
    assert aps.classify_property("domain") is None
    assert aps.classify_property("usage") is None
    assert aps.classify_property("message") is None


def test_benign_pagination_token_skipped():
    assert aps.classify_property("next_token") is None
    assert aps.classify_property("paginationToken") is None


# ------------------------------------------------------- pemindaian
def test_walk_finds_nested_properties():
    result = aps.scan([("/api/v1/users/123", RESP)], {}, None)
    props = {f["property"]: f["severity"]
             for f in result["findings"]
             if f["type"] == "property-exposure"}
    assert props["profile.password_hash"] == "critical"
    assert props["profile.ssn"] == "high"
    assert props["payment.creditCardNumber"] == "high"
    assert props["phone"] == "low"
    # teks biasa tidak dilaporkan
    assert "username" not in props
    assert "pagination.next_token" not in props
    # hasil terurut deterministik
    keys = [(f["type"], f["path"], f["property"])
            for f in result["findings"]]
    assert keys == sorted(keys)


def test_allowlist_filters_expected_fields():
    exp = {"/api/v1/users/123": {"id", "username", "email", "phone"}}
    result = aps.scan([("/api/v1/users/123", RESP)], exp, None)
    props = {f["property"] for f in result["findings"]
             if f["type"] == "property-exposure"}
    # phone ada di allowlist -> tidak dilaporkan
    assert "phone" not in props
    # ssn di luar allowlist -> dilaporkan
    assert "profile.ssn" in props


def test_mass_assignment_candidates_from_request():
    body = {"name": "X", "role": "admin", "is_admin": True,
            "accountBalance": 999999, "discountRate": 100}
    result = aps.scan([("", {})], {}, body)
    cands = [f["property"] for f in result["findings"]
             if f["type"] == "mass-assignment-candidate"]
    assert "role" in cands and "is_admin" in cands
    assert "accountBalance" in cands and "discountRate" in cands
    assert "name" not in cands


# ------------------------------------------------------- parsing input
def test_jsonl_envelope_and_plain(tmp_path):
    p = tmp_path / "cap.jsonl"
    p.write_text(RESP_JSONL, encoding="utf-8")
    result = aps.scan(aps._load_objects(
        p.read_text(encoding="utf-8"), "cap.jsonl"), {}, None)
    paths = {f["path"] for f in result["findings"]}
    assert "/api/v1/users/123" in paths
    assert "/api/v1/ping" not in paths  # respons ping bersih


def test_cli_end_to_end(tmp_path):
    p = tmp_path / "resp.json"
    p.write_text(json.dumps(RESP), encoding="utf-8")
    out = tmp_path / "temuan.json"
    rc, payload = _run("--file", str(p), "--out", str(out))
    assert rc == 0
    assert payload["schema"] == "cyphron.api-property-scan/1"
    assert payload["stats"]["critical"] >= 1
    assert out.read_text(encoding="utf-8").startswith("{")


def test_cli_fail_closed(tmp_path):
    rc, _ = _run()
    assert rc == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{ini bukan json", encoding="utf-8")
    rc, _ = _run("--file", str(bad))
    assert rc == 2
    rc, _ = _run("--file", str(tmp_path / "hilang.json"))
    assert rc == 2
