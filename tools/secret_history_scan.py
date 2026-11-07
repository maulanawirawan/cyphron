"""[AUDIT: read-only] secret_history_scan — kandidat rahasia di RIWAYAT git,
bukan hanya working tree.

Inti keamanan alur "open-sourcing" (konsep dari skill open-sourcing repo
trailofbits/skills — 8k+ stars, CC-BY-SA-4.0: audit rahasia wajib PALING
AWAL karena hasilnya menentukan repo dipublikasikan apa dibuat ulang) yang
belum dipadankan di cyphron: repo-secret-scan melewati direktori .git —
coverage-nya working tree saja. Rahasia di commit lama tetap bocor begitu
repo privat dipublikasikan, meski sudah lama dihapus di HEAD. Tool ini
menutup gap itu. Dibangun from scratch (mekanisme walk-objek git ditulis
sendiri); kosakata pola DIPAKAI ULANG dari repo-secret-scan supaya disiplin
zero-FP identik (pola kuat + generik berentropi + penekan placeholder +
masking nilai). Lisensi cyphron: PolyForm NC.

Mekanisme (NOL jaringan, objek git lokal):
  1. `git rev-list --objects --all` (dibatasi --max-commits commit terbaru,
     default 5000) -> semua objek berpath yang terjangkau riwayat.
  2. `git cat-file --batch-check`: saring tipe blob + ukuran; blob >
     MAX_BLOB_BYTES di-skip SEBELUM dibaca (dicatat di meta).
  3. `git cat-file --batch` streaming (Popen, dibaca per header+body):
     blob biner (NUL di 8KB pertama) di-skip dan dicatat.
  4. Teks dipindai dengan kosakata repo_secret_scan yang di-import.
  5. Blob yang ditandai dipetakan ke commit pengenalnya
     (`git log --all --find-object`, dibatasi --max-intro-commits).

Temuan = make_finding kontrak cyphron: status "confirmed" (blob terbukti
ada di riwayat — bukti sha blob + commit), verdict L2 REPRODUCED (bukti
path+baris; klaim "terlihat publik" butuh konteks publikasi, bukan L3).
Nilai rahasia TIDAK pernah dicetak penuh (mask: prefix 6 + panjang).

Pemakaian:
  python tools/secret_history_scan.py --repo path/ke/repo --out f.json
  python tools/secret_history_scan.py --repo . --max-commits 1000
Exit: 0 bersih; 1 ada temuan; 2 input error.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

from findings import make_finding, write_findings  # noqa: E402
import repo_secret_scan as rss  # noqa: E402  (kosakata pola + shannon + mask)

SCHEMA = "cyphron.secret-history-scan/1"
TOOL_NAME = "secret-history-scan"
MAX_COMMITS_DEFAULT = 5000
MAX_BLOBS = 20000
MAX_BLOB_BYTES = 1024 * 1024
MAX_ROWS = 200
MAX_HITS_PER_BLOB = 20
MAX_INTRO_COMMITS_DEFAULT = 50
BINARY_SNIFF = 8192


class InputError(Exception):
    """Input tidak valid -> exit 2."""


def _git(repo: Path, *args: str, data: bytes | None = None,
         timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], input=data,
                          capture_output=True, timeout=timeout)


def list_objects(repo: Path, max_commits: int) -> tuple[list[tuple[str, str]], int]:
    """Semua objek berpath dari riwayat -> [(sha, path)], jumlah commit dipindai."""
    r = _git(repo, "rev-list", "--objects", "--all",
             f"--max-count={max_commits}")
    if r.returncode != 0:
        raise InputError(
            "git rev-list gagal: " + r.stderr.decode("utf-8", "replace")[:200])
    objects: list[tuple[str, str]] = []
    for raw in r.stdout.decode("utf-8", "replace").splitlines():
        if not raw:
            continue
        sha, _, path = raw.partition(" ")
        if len(sha) == 40 and path:
            objects.append((sha, path))
    # jumlah commit dihitung eksplisit (baris tanpa path di --objects bisa
    # juga root tree — bukan hanya commit)
    rc = _git(repo, "rev-list", "--all", f"--max-count={max_commits}", "--count")
    commits = int(rc.stdout.decode().strip() or "0") if rc.returncode == 0 else 0
    return objects, commits


def filter_blobs(repo: Path, objects: list[tuple[str, str]],
                 ) -> tuple[list[tuple[str, str, int]], dict[str, int]]:
    """Saring blob via cat-file --batch-check -> ([(sha, path, size)], skip).

    skip = {"non_blob": n, "large": n} — blob besar di-skip SEBELUM dibaca.
    """
    if not objects:
        return [], {"non_blob": 0, "large": 0}
    shas = [sha for sha, _ in objects]
    r = _git(repo, "cat-file", "--batch-check", data="\n".join(shas).encode())
    if r.returncode != 0:
        raise InputError("git cat-file --batch-check gagal: "
                         + r.stderr.decode("utf-8", "replace")[:200])
    info: dict[str, tuple[str, int]] = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "blob":
            try:
                info[parts[0]] = ("blob", int(parts[2]))
            except ValueError:
                continue
    blobs: list[tuple[str, str, int]] = []
    skip = {"non_blob": 0, "large": 0}
    for sha, path in objects:
        kind = info.get(sha)
        if kind is None:
            skip["non_blob"] += 1
        elif kind[1] > MAX_BLOB_BYTES:
            skip["large"] += 1
        else:
            blobs.append((sha, path, kind[1]))
    return blobs, skip


def _read_blob_batches(repo: Path, blobs: list[tuple[str, str, int]],
                       max_batch_bytes: int = 64 * 1024 * 1024):
    """Yield (sha, content_bytes) per blob via `git cat-file --batch`.

    Interaktif-pipe digantikan batch subprocess.run (protokol pipe interaktif
    tidak reliable di Windows: short-read/hang). Satu batch = sekumpulan SHA
    dengan total ukuran <= max_batch_bytes — memori terkendali, tanpa deadlock.
    Format per objek: '<sha> blob <size>\\n' + body + '\\n' (LF trailing).
    """
    batch: list[tuple[str, int]] = []
    total = 0

    def flush() -> None:
        nonlocal batch, total
        if not batch:
            return
        r = _git(repo, "cat-file", "--batch",
                 data="\n".join(s for s, _ in batch).encode())
        if r.returncode != 0:
            raise InputError("git cat-file --batch gagal: "
                             + r.stderr.decode("utf-8", "replace")[:200])
        buf = r.stdout
        pos = 0
        for sha, size in batch:
            nl = buf.find(b"\n", pos)
            if nl < 0:
                return  # respons terpotong — berhenti bersih
            header = buf[pos:nl].decode("utf-8", "replace").split()
            if len(header) != 3 or header[1] != "blob" or int(header[2]) != size:
                return  # desink/tak terduga — berhenti bersih
            start = nl + 1
            yield sha, buf[start:start + size]
            pos = start + size + 1  # +1: LF trailing tiap objek
        batch, total = [], 0

    for sha, _, size in blobs:
        if batch and total + size > max_batch_bytes:
            yield from flush()
        batch.append((sha, size))
        total += size
    yield from flush()


def scan_blob_text(text: str) -> list[tuple[str, str, int, str]]:
    """Klasifikasi hit satu blob -> [(kind, value, offset, strength)].

    Kosakata & disiplin identik repo_secret_scan: pola kuat = cukup;
    generik wajib lolos penekan placeholder + entropi minimum.
    """
    hits: list[tuple[str, str, int, str]] = []
    for kind, pattern in rss.STRONG_PATTERNS:
        for m in pattern.finditer(text):
            hits.append((kind, m.group(0), m.start(), "strong"))
    for m in rss.GENERIC_PATTERN.finditer(text):
        value = m.group(1)
        if rss.PLACEHOLDER_RE.search(value):
            continue  # placeholder — bukan rahasia
        if rss.shannon(value) < rss.ENTROPY_MIN:
            continue  # nilai generik rendah entropi
        hits.append(("generic-credential", value, m.start(1), "generic"))
    return hits


def first_intro_commit(repo: Path, blob_sha: str) -> str | None:
    """Commit pertama yang memperkenalkan blob (fail-diam: None bila gagal)."""
    r = _git(repo, "log", "--all", f"--find-object={blob_sha}",
             "--format=%H", "-n", "1", timeout=60)
    if r.returncode != 0:
        return None
    out = r.stdout.decode("utf-8", "replace").strip()
    return out or None


def audit_history(repo: Path, max_commits: int = MAX_COMMITS_DEFAULT,
                  max_intro_commits: int = MAX_INTRO_COMMITS_DEFAULT,
                  ) -> tuple[list[dict], dict]:
    """Pindai riwayat git repo -> (findings, meta). Kontrak (rows, meta)."""
    if not repo.is_dir():
        raise InputError(f"repo tidak ada: {repo}")
    if not (repo / ".git").exists():
        raise InputError(f"bukan repositori git: {repo}")
    meta: dict = {"schema": SCHEMA, "tool": TOOL_NAME, "ok": True,
                  "max_commits": max_commits,
                  "commits_scanned": 0, "objects_listed": 0,
                  "blobs_scanned": 0, "blobs_skipped_non_blob": 0,
                  "blobs_skipped_large": 0, "blobs_skipped_binary": 0,
                  "blobs_truncated": False, "rows_truncated": False,
                  "intro_map_truncated": False}
    objects, commits = list_objects(repo, max_commits)
    meta["commits_scanned"] = commits
    meta["objects_listed"] = len(objects)
    blobs, skip = filter_blobs(repo, objects)
    meta["blobs_skipped_non_blob"] = skip["non_blob"]
    meta["blobs_skipped_large"] = skip["large"]
    if len(blobs) > MAX_BLOBS:
        blobs = blobs[:MAX_BLOBS]
        meta["blobs_truncated"] = True
    paths = {sha: path for sha, path, _ in blobs}
    rows: list[dict] = []
    intro_done = 0
    for sha, content in _read_blob_batches(repo, blobs):
        path = paths.get(sha, sha[:12])
        if b"\x00" in content[:BINARY_SNIFF]:
            meta["blobs_skipped_binary"] += 1
            continue
        meta["blobs_scanned"] += 1
        text = content.decode("utf-8", "replace")
        for kind, value, offset, strength in \
                scan_blob_text(text)[:MAX_HITS_PER_BLOB]:
            if len(rows) >= MAX_ROWS:
                meta["rows_truncated"] = True
                break
            line = text.count("\n", 0, offset) + 1
            intro = None
            if intro_done < max_intro_commits:
                intro = first_intro_commit(repo, sha)
                intro_done += 1
            if intro is None and intro_done >= max_intro_commits:
                meta["intro_map_truncated"] = True
            loc = f"{path or sha[:12]}:{line}"
            extra = {"blob_sha": sha, "history": True}
            if intro:
                extra["intro_commit"] = intro
            rows.append(make_finding(
                tool=TOOL_NAME,
                title=f"Kandidat rahasia di RIWAYAT git ({kind}) di {loc}",
                severity="high" if strength == "strong" else "medium",
                description=(
                    "Pola kredensial terdeteksi pada blob riwayat git "
                    f"{sha[:12]}"
                    + (f" (commit pengenal {intro[:12]})" if intro else "")
                    + " — tetap terbaca dari history meski sudah dihapus di "
                    f"HEAD. NILAI DISENSOR: {rss.mask(value)}. Verifikasi "
                    "manual wajib sebelum disimpulkan bocor nyata (bisa "
                    "sampel/uji)."),
                recommendation=(
                    "Putar (rotate) kredensial segera; hapus dari riwayat "
                    "(git filter-repo/BFG) SEBELUM repo dipublikasikan — "
                    "hapus di commit baru tidak menghapus dari history."),
                request=f"git -C <repo> show {sha}",
                poc=f"git -C <repo> log --all --find-object={sha} --format=%H -n 1",
                file_path=path or None,
                line_start=line,
                cwe="CWE-798",
                status="confirmed",
                verdict=2,
                extra=extra,
            ))
        if meta["rows_truncated"]:
            break
    return rows, meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="secret_history_scan — kandidat rahasia di riwayat git "
                    "(blob lama tetap terbaca meski dihapus di HEAD)")
    ap.add_argument("--repo", default=".", help="path repositori git (default .)")
    ap.add_argument("--out", default=None, help="tulis findings JSON ke file")
    ap.add_argument("--max-commits", type=int, default=MAX_COMMITS_DEFAULT,
                    help=f"batas commit terbaru yang dibaca "
                         f"(default {MAX_COMMITS_DEFAULT})")
    ap.add_argument("--max-intro-commits", type=int,
                    default=MAX_INTRO_COMMITS_DEFAULT,
                    help="batas pemetaan blob->commit pengenal")
    args = ap.parse_args(argv)
    try:
        rows, meta = audit_history(Path(args.repo), args.max_commits,
                                   args.max_intro_commits)
    except InputError as e:
        print(f"[INPUT-ERROR] {e}", file=sys.stderr)
        return 2
    if args.out:
        write_findings(args.out, rows, meta)
    tag = "AMAN-RIWAYAT" if not rows else f"{len(rows)} KANDIDAT"
    print(f"secret_history_scan: {tag}; commit={meta['commits_scanned']} "
          f"blob={meta['blobs_scanned']} "
          f"(skip biner={meta['blobs_skipped_binary']} "
          f"besar={meta['blobs_skipped_large']}) "
          f"truncated={meta['blobs_truncated'] or meta['rows_truncated']}")
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
