"""test_ssti_engine_id — identifikasi mesin template dari bukti probe
SSTI offline (#0511), nol jaringan.

Fixture = bukti probe sintetis dari spesifikasi konsep sumber (polyglot
aritmetika + pembeda mesin publik); bukan salinan kode alat sumber.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import ssti_engine_id as sei  # noqa: E402


def _write(tmp_path, records, name="probes.jsonl", jsonl=True) -> Path:
    p = tmp_path / name
    if jsonl:
        p.write_text(
            "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    else:
        p.write_text(json.dumps(records), encoding="utf-8")
    return p


def _run(*args: str) -> "tuple[int, dict | None, str]":
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "ssti_engine_id.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> "list[str]":
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- input parsing
def test_jsonl_and_array_both_parse(tmp_path):
    recs = [{"payload": "{{7*7}}", "response": "halo 49"}]
    f1 = _write(tmp_path, recs, "a.jsonl", jsonl=True)
    f2 = _write(tmp_path, recs, "a.json", jsonl=False)
    assert len(sei.load_probes(f1)) == 1
    assert len(sei.load_probes(f2)) == 1


def test_invalid_input_exit2(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text("bukan json\n", encoding="utf-8")
    rc, out, err = _run("--probes", str(p))
    assert rc == 2 and out is None and "tidak valid" in err


def test_empty_file_exit2(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    rc, _, _ = _run("--probes", str(p))
    assert rc == 2


def test_records_without_required_fields_skipped(tmp_path):
    p = _write(tmp_path, [{"foo": "bar"}, {"payload": "x", "response": 5}])
    rc, _, _ = _run("--probes", str(p))
    assert rc == 2  # nol probe valid


def test_alias_fields_accepted(tmp_path):
    p = _write(tmp_path, [{"probe": "{{7*7}}", "body": "49"}])
    rc, out, _ = _run("--probes", str(p))
    assert rc == 0
    assert out["probes_evaluated"] == 1


# ------------------------------------------------------- evaluasi
def test_eval_confirmed_two_payloads(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "<h1>49</h1>"},
        {"payload": "{{8*7}}", "response": "<h1>56</h1>"},
        {"payload": "{{7*7}}", "response": "halaman 49 umur"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert rc == 1 and "ssti-eval-confirmed" in _checks(out)


def test_echo_rejected_not_evaluation(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "kata {{7*7}} di-escape"},
        {"payload": "{{8*7}}", "response": "kata {{8*7}} di-escape"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert rc == 0 and "ssti-eval-confirmed" not in _checks(out)
    assert out["math_evaluated"] == []


def test_single_math_match_is_lead(tmp_path):
    p = _write(tmp_path, [{"payload": "${7*7}", "response": "x49y"}])
    rc, out, _ = _run("--probes", str(p), "--fail-on", "medium")
    assert rc == 1 and "ssti-eval-lead" in _checks(out)


def test_fail_on_high_medium_lead_not_failing(tmp_path):
    p = _write(tmp_path, [{"payload": "${7*7}", "response": "x49y"}])
    rc, _, _ = _run("--probes", str(p))
    assert rc == 0


# ------------------------------------------------------- pembeda mesin
def test_jinja2_discriminator(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
        {"payload": "{{7*'7'}}", "response": "7777777"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert out["engine"]["name"] == "jinja2"
    assert out["engine"]["confidence"] == "identified"


def test_twig_discriminator(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
        {"payload": "{{7*'7'}}", "response": "49"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert out["engine"]["name"] == "twig"


def test_no_engine_without_discriminator_notes_recommend(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert out["engine"] is None
    assert any("pembeda belum diuji" in n for n in out["notes"])
    assert "{{7*'7'}}" in "".join(out["notes"])


def test_engine_echo_discriminator_ignored(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
        {"payload": "{{7*'7'}}", "response": "{{7*'7'}}"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert out["engine"] is None


# ------------------------------------------------------- RCE marker
def test_rce_marker_requires_exec_payload_and_shell_output(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{lipsum.__globals__['os'].popen('id').read()}}",
         "response": "uid=33(www-data) gid=33(www-data)"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert "rce-marker" in _checks(out)


def test_no_rce_marker_without_exec_token(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "uid=33(www-data)"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert "rce-marker" not in _checks(out)


def test_no_rce_marker_without_shell_output(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{cycler.__init__.__globals__.os.popen('id').read()}}",
         "response": "halaman biasa"},
    ])
    rc, out, _ = _run("--probes", str(p))
    assert "rce-marker" not in _checks(out)


# ------------------------------------------------------- laporan & exit
def test_out_file_written(tmp_path):
    p = _write(tmp_path, [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
    ])
    o = tmp_path / "rep.json"
    rc, _, _ = _run("--probes", str(p), "--out", str(o))
    assert rc == 1 and o.exists()
    rep = json.loads(o.read_text(encoding="utf-8"))
    assert rep["schema"] == "cyphron.ssti-engine-id/1"


def test_deterministic_output(tmp_path):
    recs = [
        {"payload": "{{7*7}}", "response": "49"},
        {"payload": "{{8*7}}", "response": "56"},
        {"payload": "{{7*'7'}}", "response": "7777777"},
    ]
    a = sei.analyze([dict(r) for r in recs])
    b = sei.analyze([dict(r) for r in recs])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_clean_report_has_telemetry_note(tmp_path):
    p = _write(tmp_path, [{"payload": "biasa", "response": "halaman"}])
    rc, out, _ = _run("--probes", str(p))
    assert rc == 0
    assert any("offline" in n for n in out["notes"])
