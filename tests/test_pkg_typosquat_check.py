"""test_pkg_typosquat_check — deteksi OFFLINE nama paket typosquat
(#0469 #0470), nol jaringan. Fixture manifest sintetis.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import pkg_typosquat_check as ptc  # noqa: E402


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "pkg_typosquat_check.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> list[str]:
    return [f["check"] for f in out["findings"]]


def _pkg(out: dict, check: str) -> dict:
    return next(f for f in out["findings"] if f["check"] == check)


# ------------------------------------------------------- primitif
def test_typo_distance_1():
    _, out, _ = _run("--name", "reqeusts")
    f = _pkg(out, "typo-distance-1")
    assert f["severity"] == "high" and f["target"] == "requests"


def test_typo_distance_2():
    _, out, _ = _run("--name", "raqeusts")
    f = _pkg(out, "typo-distance-2")
    assert f["severity"] == "medium"


def test_delimiter_swap():
    _, out, _ = _run("--name", "crossenv", "--ecosystem", "npm")
    f = _pkg(out, "delimiter-swap")
    assert f["target"] == "cross-env"


def test_word_order_swap():
    _, out, _ = _run("--name", "dateutil-python")
    f = _pkg(out, "word-order-swap")
    assert f["target"] == "python-dateutil"


def test_scope_confusion():
    _, out, _ = _run("--name", "types-node", "--ecosystem", "npm")
    # types-node sendiri mirip @types/node via scope-confusion
    assert "scope-confusion" in _checks(out)


def test_suffix_variant():
    _, out, _ = _run("--name", "requestss")
    # requestss = requests + s -> suffix-variant ATAU typo-2
    assert _checks(out), "harusnya ada temuan utk requestss"


def test_homoglyph_name():
    _, out, _ = _run("--name", "requeѕts")  # s cyrillic
    f = _pkg(out, "homoglyph-name")
    assert f["severity"] == "high"


def test_exact_corpus_clean():
    _, out, _ = _run("--name", "requests")
    assert out["findings"] == []


def test_unknown_name_far_clean():
    _, out, _ = _run("--name", "zyxwv-abcd-9999")
    assert out["findings"] == []


def test_case_canonical():
    _, out, _ = _run("--name", "ReQeUsTs")
    assert "typo-distance-1" in _checks(out)


# ------------------------------------------------------- manifest
def test_requirements_file(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\nreqeusts==1.0.0\n# komentar\n"
                 "numpy\n-r base.txt\n", encoding="utf-8")
    rc, out, _ = _run("--file", str(f))
    assert rc == 1
    names = out["stats"]["names_checked"]
    assert names == 3  # komentar & -r dilewati
    assert "typo-distance-1" in _checks(out)


def test_package_json_file(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "name": "app", "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"lodahs": "^1.0.0"},
    }), encoding="utf-8")
    rc, out, _ = _run("--file", str(f))
    assert rc == 1
    assert out["stats"]["ecosystem"] == "npm"
    assert "typo-distance-1" in _checks(out)


def test_pyproject_file(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text('[project]\nname = "app"\nversion = "1.0"\n'
                 'dependencies = [\n  "flask>=3.0",\n'
                 '  "flak>=3.0",\n]\n', encoding="utf-8")
    rc, out, _ = _run("--file", str(f))
    assert rc == 1
    assert out["stats"]["names_checked"] == 2


# ------------------------------------------------------- fail-closed
def test_missing_file_exit2():
    rc, out, err = _run("--file", "TIDAK-ADA.txt")
    assert rc == 2 and out is None


def test_no_names_exit2():
    rc, out, err = _run("--ecosystem", "pypi")
    assert rc == 2 and "tidak ada nama" in err


def test_invalid_json_exit2(tmp_path):
    f = tmp_path / "package.json"
    f.write_text("{bukan json", encoding="utf-8")
    rc, out, err = _run("--file", str(f))
    assert rc == 2 and "tidak valid" in err


def test_meta_limitation_written():
    _, out, _ = _run("--name", "requests")
    assert any("snapshot" in n for n in out["notes"])


def test_fail_on_high_gate(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("numpy-numpy\n", encoding="utf-8")
    # numpy-numpy: jarak edit > 2, tapi word-order/delimiter? bukan.
    # pakai near-miss medium-only: raqeusts
    f.write_text("raqeusts\n", encoding="utf-8")
    rc, out, _ = _run("--file", str(f), "--fail-on", "high")
    assert rc == 0 and out["stats"]["names_checked"] == 1
