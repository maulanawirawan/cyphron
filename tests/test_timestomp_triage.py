"""test_timestomp_triage — deteksi timestomping SI-vs-FN (#0542), nol
jaringan.

Fixture = CSV MFTECmd sintetis (format kolom Created0x10/Created0x30
dst., pecahan 7 digit = presisi 100ns) + JSON mft_scan sintetis.
Kasus: SI didorong mundur, SI Modified < FN Created, artefak nanodetik
nol, anti-FP ambang delta, baris timestamp kosong (skip tercatat),
fail-closed input salah, pembagian ranah dgn mft_scan (B08 = parser
$MFT pemulihan file terhapus; tool ini konsumen hasilnya / CSV MFTECmd).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import timestomp_triage as tt  # noqa: E402

HEADER = ("ParentPath,FileName,Created0x10,LastModified0x10,"
          "LastRecordChange0x10,LastAccess0x10,Created0x30,"
          "LastModified0x30,LastRecordChange0x30,LastAccess0x30")


def _csv(tmp_path: Path, rows: list[str], name: str = "mft.csv") -> Path:
    p = tmp_path / name
    p.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return p


def _row(si_c: str, fn_c: str, si_m: str = "2026-01-10 10:00:00.1234567",
         fn_m: str = "2026-01-10 10:00:00.1234567",
         parent: str = "Windows\\Temp", name: str = "evil.exe") -> str:
    return (f"{parent},{name},{si_c},{si_m},{si_m},{si_m},{fn_c},{fn_m},"
            f"{fn_m},{fn_m}")


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "timestomp_triage.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


# ------------------------------------------------------- deteksi inti
def test_si_created_before_fn(tmp_path):
    p = _csv(tmp_path, [_row("2015-04-01 08:00:00.0000000",
                             "2026-01-10 10:00:00.6582539")])
    rc, out, err = _run("--csv", str(p), "--json")
    assert rc == 1 and out is not None, err
    f = [x for x in out["findings"]
         if x["check"] == "si-created-before-fn"]
    assert len(f) == 1
    assert f[0]["severity"] == "high"
    assert f[0]["path"] == "Windows\\Temp\\evil.exe"
    assert f[0]["delta_s"] > 0


def test_si_modified_before_fn_created(tmp_path):
    p = _csv(tmp_path, [_row("2026-01-12 09:00:00.1111111",
                             "2026-01-10 10:00:00.6582539",
                             si_m="2026-01-09 00:00:00.5000000")])
    rc, out, err = _run("--csv", str(p), "--json")
    assert rc == 1, err
    f = [x for x in out["findings"]
         if x["check"] == "si-modified-before-fn-created"]
    assert len(f) == 1 and f[0]["severity"] == "high"


def test_zero_precision_si_only_when_fn_has_precision(tmp_path):
    zero_si = _row("2026-01-10 10:00:00.0000000",
                   "2026-01-10 10:00:01.6582539")
    precise_si = _row("2026-01-10 10:00:00.1234567",
                      "2026-01-10 10:00:01.6582539")
    _, out1, _ = _run("--csv", str(_csv(tmp_path, [zero_si], "a.csv")),
                      "--json")
    _, out2, _ = _run("--csv", str(_csv(tmp_path, [precise_si], "b.csv")),
                      "--json")
    z = [x for x in out1["findings"] if x["check"] == "zero-precision-si"]
    n = [x for x in out2["findings"] if x["check"] == "zero-precision-si"]
    assert len(z) == 1 and z[0]["severity"] == "medium"
    assert n == []


def test_normal_row_clean(tmp_path):
    p = _csv(tmp_path, [_row("2026-01-10 10:00:00.1000000",
                             "2026-01-10 09:59:59.9000000")])
    rc, out, err = _run("--csv", str(p), "--json")
    assert rc == 0 and out["findings"] == []


def test_min_delta_threshold_anti_fp(tmp_path):
    row = _row("2026-01-10 09:59:59.9000000",
               "2026-01-10 10:00:00.1000000")  # delta 0.2s
    p = _csv(tmp_path, [row])
    _, out1, _ = _run("--csv", str(p), "--json")  # default 1.0s
    rc2, out2, _ = _run("--csv", str(p), "--min-delta-seconds", "0.1",
                        "--json")
    assert out1["findings"] == []
    assert out1["stats"]["below_delta_threshold"] == 1
    assert rc2 == 1


def test_missing_timestamp_row_counted_not_silent(tmp_path):
    row = "Windows\\Temp,evil.exe,2026-01-10 10:00:00.1000000,,,,,,,"
    p = _csv(tmp_path, [row])
    rc, out, err = _run("--csv", str(p), "--json")
    assert rc == 0
    assert out["stats"]["skipped_missing_ts"] == 1
    assert out["stats"]["checked"] == 0


# ------------------------------------------------------- fail-closed
def test_wrong_columns_fail_closed(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    rc, out, err = _run("--csv", str(p))
    assert rc == 2 and "kolom hilang" in err


def test_no_input_flag_fails_closed(tmp_path):
    rc, out, err = _run()
    assert rc == 2


def test_both_inputs_fail_closed(tmp_path):
    p = _csv(tmp_path, [_row("2026-01-10 10:00:00.1000000",
                             "2026-01-10 09:59:59.9000000")])
    rc, out, err = _run("--csv", str(p), "--mft-json", str(p))
    assert rc == 2


def test_garbage_csv_row_skipped_not_crash(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("ParentPath,FileName,Created0x10,LastModified0x10,"
                 "LastRecordChange0x10,LastAccess0x10,Created0x30,"
                 "LastModified0x30,LastRecordChange0x30,LastAccess0x30\n"
                 "raw garbage line not enough\n", encoding="utf-8")
    rc, out, err = _run("--csv", str(p), "--json")
    assert rc == 0  # baris malformasi = skipped, bukan crash
    assert out is not None and out["stats"]["rows"] == 1
    assert out["stats"]["skipped_missing_ts"] == 1


# ------------------------------------------------------- mft_scan JSON
def test_mft_json_composition(tmp_path):
    doc = {"schema": "cyphron.mft-scan/1", "entries": [
        {"mft_ref": 100, "deleted": False, "is_dir": False,
         "name": "implant.dll", "size": 4096, "parent_ref": 5,
         "times": {"si_created": "2014-06-01T00:00:00Z",
                   "si_modified": "2014-06-01T00:00:00Z",
                   "si_mft_modified": "2026-01-10T10:00:00Z",
                   "si_accessed": "2026-01-10T10:00:00Z",
                   "created": "2026-01-10T09:59:59Z",
                   "modified": "2026-01-10T10:00:00Z",
                   "mft_modified": "2026-01-10T10:00:00Z",
                   "accessed": "2026-01-10T10:00:00Z"}}]}
    p = tmp_path / "mft.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    rc, out, err = _run("--mft-json", str(p), "--json")
    assert rc == 1, err
    f = [x for x in out["findings"]
         if x["check"] == "si-created-before-fn"]
    assert len(f) == 1 and f[0]["path"] == "implant.dll"
    assert any("presisi detik" in n for n in out["notes"])
    assert all(x["check"] != "zero-precision-si"
               for x in out["findings"])


def test_mft_json_bad_structure_fail_closed(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"schema": "lain", "foo": 1}', encoding="utf-8")
    rc, out, err = _run("--mft-json", str(p))
    assert rc == 2


# ------------------------------------------------------- unit + modes
def test_parse_ts_unit():
    dt, zn = tt.parse_ts("2026-01-10 10:00:00.6582539")
    assert dt is not None and dt.microsecond == 658253
    assert zn is False
    dt2, zn2 = tt.parse_ts("2026-01-10 10:00:00.0000000")
    assert zn2 is True
    assert tt.parse_ts("")[0] is None
    assert tt.parse_ts("1601-01-01 00:00:00.0000000")[0] is None
    assert tt.parse_ts("bukan-tanggal")[0] is None
    dt3, _ = tt.parse_ts("2026-01-10T10:00:00Z")
    assert dt3 is not None


def test_deterministic_and_out_file(tmp_path):
    p = _csv(tmp_path, [_row("2015-04-01 08:00:00.0000000",
                             "2026-01-10 10:00:00.6582539")])
    outp = tmp_path / "rep.json"
    rc1, o1, _ = _run("--csv", str(p), "--json")
    rc2, o2, _ = _run("--csv", str(p), "--json")
    rc3, _, _ = _run("--csv", str(p), "--out", str(outp))
    assert rc1 == rc2 == rc3 == 1
    assert o1 == o2
    assert json.loads(outp.read_text(encoding="utf-8"))["schema"] == \
        tt.SCHEMA
