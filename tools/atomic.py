"""Atomic file write + single-writer lock (pola dari review bridge:
state penting disimpan temp+rename agar tidak korup saat crash, dan
dua penulis tidak boleh merusak file yang sama).

- atomic_write_text/bytes: tulis ke file sementara DI FOLDER YANG SAMA,
  fsync, lalu os.replace — pembaca lain tidak pernah melihat setengah
  file. replace atomik di satu filesystem (temp harus sekolom).
- single_writer_lock: kunci eksklusif non-blocking di file .lock —
  Windows LockFileEx (msvcrt.locking), POSIX flock. Pemegang kedua
  GAGAL CEPAT (fail-closed) dengan info pemegang, bukan antre diam.
"""
from __future__ import annotations

import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


def atomic_write_bytes(path: str | Path, data: bytes,
                       retries: int = 5) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(p.parent),
                                    prefix=p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Windows: replace gagal bila pembaca lain masih memegang file
        # (sharing violation) — retry singkat, pembaca CLI berumur pendek
        for attempt in range(retries):
            try:
                os.replace(tmp_name, p)  # atomik pada filesystem yang sama
                break
            except PermissionError:
                if attempt == retries - 1:
                    raise
                time.sleep(0.02 * (attempt + 1))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return p


def atomic_write_text(path: str | Path, text: str,
                      encoding: str = "utf-8") -> Path:
    return atomic_write_bytes(path, text.encode(encoding))


@contextmanager
def single_writer_lock(lock_path: str | Path):
    """Kunci eksklusif non-blocking. RuntimeError bila dipakai proses
    lain — pemanggil memutuskan (skip / retry / fail)."""
    lp = Path(lock_path)
    lp.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lp), os.O_CREAT | os.O_RDWR)
    holder = f"pid={os.getpid()}"
    try:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ImportError) as e:
            # info pemegang ditulis mulai offset 1 — byte 0 dikunci dan
            # di Windows tidak bisa dibaca lintas handle
            existing = ""
            try:
                with open(lp, "rb") as f:
                    f.seek(1)
                    existing = f.read(120).decode("utf-8", "replace").strip()
            except OSError:
                pass
            raise RuntimeError(
                f"lock {lp} dipakai proses lain ({existing or e}) — "
                "fail-closed") from e
        try:
            os.write(fd, b" " + holder.encode())
        except OSError:
            pass
        yield lp
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        except (OSError, ImportError):
            pass
        os.close(fd)
