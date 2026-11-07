"""test_insider_baseline_scan — baseline perilaku insider dari CSV
aktivitas file (#0421 #0423), nol jaringan.

Fixture = CSV sintetis: baseline 10 hari ~50 MB/hari, hari target
lonjakan 3x+, off-hours, bulk, peer group. Verifikasi juga jalur
fail-closed (kolom kurang, CSV kosong, baris rusak) dan determinisme.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import insider_baseline_scan as ibs  # noqa: E402

# hari baseline 01-10, hari target 11
DAYS = [f"2026-03-{d:02d}" for d in range(1, 11)]


def _csv(tmp_path: Path, rows: list[dict], name: str = "act.csv") -> Path:
    p = tmp_path / name
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return p


def _base_rows(user: str = "alice", group: str = "eng") -> list[dict]:
    out = []
    for d in DAYS:
        out.append({"timestamp": f"{d}T10:00:00", "user": user,
                    "bytes_transferred": "50_000_000".replace("_", ""),
                    "group": group, "file": "f.bin", "action": "upload"})
    return out


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "insider_baseline_scan.py"), *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


# ------------------------------------------------------- parsing
def test_parse_timestamps_and_bad_rows(tmp_path):
    rows = [{"timestamp": "2026-03-11T08:30:00", "user": "bob",
             "bytes_transferred": "100", "group": "", "file": "a",
             "action": "read"}]
    p = _csv(tmp_path, rows)
    p.write_text(p.read_text(encoding="utf-8")
                 + "2026-03-11T09:00:00,bob,NOT_A_NUMBER\n"
                   ",bob,5\n", encoding="utf-8")
    good, bad, _cols = ibs.load_activity(p)
    assert len(good) == 1 and good[0]["user"] == "bob"
    assert len(bad) == 2  # bytes rusak + timestamp kosong


def test_missing_column_fails_closed(tmp_path):
    p = tmp_path / "rusak.csv"
    p.write_text("timestamp,user\n2026-03-11T08:30:00,bob\n",
                 encoding="utf-8")
    rc, out, err = _run("--log", str(p))
    assert rc == 2 and out is None and "kolom wajib kurang" in err


def test_empty_file_fails_closed(tmp_path):
    rows = [{"timestamp": "t", "user": "u", "bytes_transferred": "1"}]
    p = _csv(tmp_path, rows)
    # header saja / nol baris valid
    (tmp_path / "kosong.csv").write_text(
        "timestamp,user,bytes_transferred\n", encoding="utf-8")
    rc, out, err = _run("--log", str(tmp_path / "kosong.csv"))
    assert rc == 2 and "nol baris" in err


# ------------------------------------------------------- cek perilaku
def test_volume_anomaly_3x(tmp_path):
    rows = _base_rows() + [
        {"timestamp": "2026-03-11T10:00:00", "user": "alice",
         "bytes_transferred": "200000000", "group": "eng",
         "file": "db.dump", "action": "upload"}]
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    assert rc == 0
    hits = [f for f in out["findings"] if f["type"] == "volume-anomaly"]
    assert len(hits) == 1 and hits[0]["user"] == "alice"
    assert hits[0]["severity"] == "high"
    assert hits[0]["today_bytes"] == 200_000_000


def test_small_baseline_skipped_with_note(tmp_path):
    # baseline ~10 KB/hari (< default 1 MB) -> dilewati + catatan, bukan FP
    rows = [{"timestamp": f"2026-03-{d:02d}T10:00:00", "user": "eve",
             "bytes_transferred": "10000", "group": "eng", "file": "x",
             "action": "upload"} for d in range(1, 11)]
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "eve",
                 "bytes_transferred": "1000000", "group": "eng",
                 "file": "x", "action": "upload"})  # 100x baseline
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    types = [f["type"] for f in out["findings"]]
    assert "volume-anomaly" not in types
    assert any("baseline kecil" in n for n in out["notes"])


def test_zscore_needs_min_days(tmp_path):
    # 2 hari baseline + 1 hari target: z-score harus dilewati dgn catatan
    rows = [{"timestamp": f"2026-03-{d:02d}T10:00:00", "user": "zoe",
             "bytes_transferred": "5000000", "group": "eng", "file": "x",
             "action": "upload"} for d in (9, 10)]
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "zoe",
                 "bytes_transferred": "50000000", "group": "eng",
                 "file": "x", "action": "upload"})
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    types = [f["type"] for f in out["findings"]]
    assert "zscore-anomaly" not in types
    assert any("z-score dilewati" in n for n in out["notes"])


def test_offhours_and_bulk(tmp_path):
    rows = _base_rows(user="mallory")
    for h in (0, 1, 2, 3, 4):  # 5 event off-hours (00:00-04:00)
        rows.append({"timestamp": f"2026-03-11T{h:02d}:30:00",
                     "user": "mallory", "bytes_transferred": "1000000",
                     "group": "eng", "file": f"f{h}.bin",
                     "action": "download"})
    rows += [{"timestamp": "2026-03-11T12:00:00", "user": "mallory",
              "bytes_transferred": "1000", "group": "eng", "file": f"g{i}",
              "action": "read"} for i in range(200)]
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    types = sorted(f["type"] for f in out["findings"])
    assert "off-hours" in types and "bulk-download" in types
    off = next(f for f in out["findings"] if f["type"] == "off-hours")
    assert off["off_hours_events"] == 5


def test_peer_deviation_requires_group(tmp_path):
    # tanpa kolom group -> peer-deviation dilewati + catatan
    rows = _base_rows(group="")
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "alice",
                 "bytes_transferred": "200000000", "group": "",
                 "file": "db", "action": "upload"})
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    assert out["meta"]["has_group_column"] is False
    types = [f["type"] for f in out["findings"]]
    assert "peer-deviation" not in types
    assert any("peer-deviation" in n for n in out["notes"])


def test_peer_deviation_flags_outlier_only(tmp_path):
    rows: list[dict] = []
    for u in ("a1", "a2", "a3"):  # peer ~50 MB
        rows += _base_rows(user=u)
    # hari target: a1 = 1 GB (outlier), a2/a3 normal ~60 MB (peer aktif)
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "a1",
                 "bytes_transferred": "1000000000", "group": "eng",
                 "file": "dump", "action": "upload"})
    for u in ("a2", "a3"):
        rows.append({"timestamp": "2026-03-11T10:30:00", "user": u,
                     "bytes_transferred": "60000000", "group": "eng",
                     "file": "src", "action": "upload"})
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    peers = [f for f in out["findings"] if f["type"] == "peer-deviation"]
    assert len(peers) == 1 and peers[0]["user"] == "a1"
    assert peers[0]["group"] == "eng"
    assert peers[0]["peer_median_bytes"] == 60_000_000


def test_peer_deviation_needs_active_peers(tmp_path):
    # hanya 1 user aktif hari target -> < peer_min peer aktif -> dilewati
    rows = _base_rows(user="solo")  # baseline eng, target kosong
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "solo",
                 "bytes_transferred": "1000000000", "group": "eng",
                 "file": "dump", "action": "upload"})
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p))
    types = [f["type"] for f in out["findings"]]
    assert "peer-deviation" not in types
    assert any("< 3 peer" in n for n in out["notes"])


def test_no_activity_target_day_note(tmp_path):
    rows = _base_rows()
    p = _csv(tmp_path, rows)
    rc, out, _ = _run("--log", str(p), "--day", "2026-03-30")
    assert rc == 0
    assert out["findings"] == []
    assert any("tidak ada aktivitas pada hari target" in n
               for n in out["notes"])


def test_clean_baseline_verdict(tmp_path):
    p = _csv(tmp_path, _base_rows())
    rc, out, _ = _run("--log", str(p))
    assert rc == 0 and out["verdict"] == "CLEAN_NO_BEHAVIORAL_LEAD"
    assert out["meta"]["users"] == 1


def test_bad_rows_counted_not_silent(tmp_path):
    rows = _base_rows()
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "alice",
                 "bytes_transferred": "1000", "group": "eng",
                 "file": "x", "action": "upload"})
    p = _csv(tmp_path, rows)
    p.write_text(p.read_text(encoding="utf-8")
                 + "bukan,baris,valid\n", encoding="utf-8")
    rc, out, _ = _run("--log", str(p))
    assert out["meta"]["bad_rows_count"] >= 1
    assert any("TIDAK dianalisis" in n for n in out["notes"])


def test_deterministic_output_order(tmp_path):
    rows = _base_rows()
    rows += _base_rows(user="bob")
    rows.append({"timestamp": "2026-03-11T10:00:00", "user": "bob",
                 "bytes_transferred": "999999999", "group": "eng",
                 "file": "db", "action": "upload"})
    rows.append({"timestamp": "2026-03-11T11:00:00", "user": "alice",
                 "bytes_transferred": "999999998", "group": "eng",
                 "file": "db", "action": "upload"})
    p = _csv(tmp_path, rows)
    _, out1, _ = _run("--log", str(p))
    _, out2, _ = _run("--log", str(p))
    assert json.dumps(out1) == json.dumps(out2)
    users = [f["user"] for f in out1["findings"]]
    assert users == sorted(users)


def test_out_file_written(tmp_path):
    p = _csv(tmp_path, _base_rows())
    outp = tmp_path / "triase.json"
    rc, _, _ = _run("--log", str(p), "--out", str(outp))
    assert rc == 0 and outp.is_file()
    data = json.loads(outp.read_text(encoding="utf-8"))
    assert data["schema"] == ibs.SCHEMA
