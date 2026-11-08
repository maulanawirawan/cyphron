"""Test secret_history_scan — kandidat rahasia di riwayat git.

NOL jaringan: semua skenario memakai repositori git lokal sementara
(tmp_path) dengan commit yang menanam/menghapus rahasia sintetis.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "core"))

import secret_history_scan as shs  # noqa: E402
from findings import read_findings, validate_finding  # noqa: E402

SECRET = "AKIA" + "IOSFODNN7EXAMPLE"       # format kuat AWS access key
PLACEHOLDER = "password = 'changeme_placeholder'"  # harus ditekan


def _git(*args: str, cwd: Path) -> str:
    r = subprocess.run(["git", *args], cwd=str(cwd), check=True,
                       capture_output=True, text=True)
    return r.stdout.strip()


def make_repo(tmp_path: Path, name: str = "tgt") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@example.test", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    return repo


def commit_file(repo: Path, rel: str, content: str, msg: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", msg, cwd=repo)


# ------------------------------------------------------------------ temuan

def test_secret_only_in_history_is_found(tmp_path):
    """Kunci differentiator: rahasia dihapus di HEAD tapi ada di commit lama."""
    repo = make_repo(tmp_path)
    commit_file(repo, "cfg/app.ini", f"[prod]\napi_key = '{SECRET}'\n", "add key")
    blob_secret = (repo / "cfg/app.ini").read_text(encoding="utf-8")
    (repo / "cfg/app.ini").write_text("[prod]\napi_key = 'REDACTED'\n",
                                      encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "remove key", cwd=repo)
    rows, meta = shs.audit_history(repo)
    assert meta["ok"] and meta["blobs_scanned"] >= 2
    hits = [r for r in rows if SECRET[:6] in r["title"] or SECRET[:6] in r["description"]]
    assert len(hits) == 1
    f = hits[0]
    assert f["status"] == "confirmed" and f["verdict"] == 2
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-798"
    assert SECRET not in json_dumps(f)  # nilai tidak pernah tampil penuh
    assert f["blob_sha"] and f["history"] is True
    assert f["intro_commit"]
    assert validate_finding(f) == []
    assert blob_secret  # gunakan variabel; bukti konten lama ada di riwayat


def json_dumps(f: dict) -> str:
    import json
    return json.dumps(f, ensure_ascii=False)


def test_working_tree_clean_but_history_dirty_exit1(tmp_path):
    repo = make_repo(tmp_path)
    commit_file(repo, "id_rsa.pub.bak", f"note {SECRET} done\n", "oops")
    (repo / "id_rsa.pub.bak").unlink()
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "delete", cwd=repo)
    out = tmp_path / "f.json"
    code = shs.main(["--repo", str(repo), "--out", str(out)])
    assert code == 1
    data = read_findings(str(out))
    assert len(data["findings"]) == 1


def test_clean_repo_exit0(tmp_path):
    repo = make_repo(tmp_path)
    commit_file(repo, "readme.md", "# aman\n", "init")
    commit_file(repo, "cfg.txt", PLACEHOLDER + "\n", "cfg")
    code = shs.main(["--repo", str(repo)])
    assert code == 0


# ------------------------------------------------------------------ meta

def test_meta_counts_and_truncation_fields(tmp_path):
    repo = make_repo(tmp_path)
    commit_file(repo, "a.txt", f"key {SECRET}\n", "c1")
    commit_file(repo, "b.txt", "biasa\n", "c2")
    rows, meta = shs.audit_history(repo)
    assert meta["commits_scanned"] == 2
    assert meta["objects_listed"] >= 2
    assert meta["blobs_scanned"] >= 2
    assert meta["blobs_truncated"] is False
    assert len(rows) == 1


def test_placeholder_and_low_entropy_suppressed(tmp_path):
    repo = make_repo(tmp_path)
    commit_file(repo, "env.example",
                "password = 'changeme_placeholder'\npassword = 'password123'\n",
                "cfg")
    rows, meta = shs.audit_history(repo)
    assert rows == []
    assert meta["blobs_scanned"] == 1


def test_binary_blob_skipped(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "img.bin").write_bytes(b"\x00\x01\x02" + b"A" * 100)
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "bin", cwd=repo)
    rows, meta = shs.audit_history(repo)
    assert rows == []
    assert meta["blobs_skipped_binary"] == 1
    assert meta["blobs_scanned"] == 0


def test_large_blob_skipped_before_read(tmp_path):
    repo = make_repo(tmp_path)
    big = ("x" * 2000 + "\n") * 600  # > MAX_BLOB_BYTES saat dinormalisasi? 
    commit_file(repo, "big.log", big, "big")
    old = shs.MAX_BLOB_BYTES
    try:
        shs.MAX_BLOB_BYTES = 100  # kecilkan ambang untuk test
        rows, meta = shs.audit_history(repo)
    finally:
        shs.MAX_BLOB_BYTES = old
    assert rows == []
    assert meta["blobs_skipped_large"] == 1
    assert meta["blobs_scanned"] == 0


def test_max_rows_cap(tmp_path):
    repo = make_repo(tmp_path)
    content = "\n".join(f"token = 'Kx{SECRET[:10]}{i:03d}zzz9f9q2'"
                        for i in range(5))
    commit_file(repo, "many.txt", content + "\n", "many")
    old = shs.MAX_ROWS
    try:
        shs.MAX_ROWS = 2
        rows, meta = shs.audit_history(repo)
    finally:
        shs.MAX_ROWS = old
    assert len(rows) == 2
    assert meta["rows_truncated"] is True


def test_max_commits_cap_limits_scope(tmp_path):
    repo = make_repo(tmp_path)
    commit_file(repo, "a.txt", "satu\n", "c1")
    commit_file(repo, "b.txt", f"key {SECRET}\n", "c2")
    rows, meta = shs.audit_history(repo, max_commits=1)
    # hanya commit terbaru yang dijangkau -> rahasia di c2 tetap terlihat,
    # tapi jumlah commit tercatat 1
    assert meta["commits_scanned"] == 1


# ------------------------------------------------------------ input error

def test_input_error_not_a_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(shs.InputError, match="bukan repositori git"):
        shs.audit_history(plain)


def test_input_error_missing_path(tmp_path):
    with pytest.raises(shs.InputError, match="repo tidak ada"):
        shs.audit_history(tmp_path / "hilang")


def test_cli_exit2_on_bad_repo(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert shs.main(["--repo", str(plain)]) == 2


def test_cli_exit0_on_empty_history_repo(tmp_path):
    repo = make_repo(tmp_path)
    assert shs.main(["--repo", str(repo)]) == 0
