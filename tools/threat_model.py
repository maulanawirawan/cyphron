"""[F70-family][SAFETY: read-only] threat-model loader — konteks per program.

Terinspirasi pola anthropics/oss-scanner (riset docs/RISET-OSS-SCANNER-
2026-10.md): pemilik program bisa menyertakan threat_model.md (di mana
input untrusted masuk, scope, panduan severity, apa yang dibiarkan).
Cyphron memakainya sebagai KONTEKS TRIAGE OPERATOR + ringkasan laporan —
TANPA mengubah verdict ladder atau classification (tetap dari bukti).

Aturan fail-closed (pola riset §2):
- file opsional: tidak ada = loader mengembalikan None (bukan error);
- path selalu diselesaikan DI DALAM folder programs/ — symlink/path
  traversal keluar folder DITOLAK;
- ukuran bounded 64 KB (lebih besar = ditolak + baris audit);
- output selalu membawa sha256 (keterlacakan versi dokumen) + judul
  bagian markdown (peta isi tanpa menaruh seluruh teks di meta).
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = ROOT / "programs"
MAX_BYTES = 64 * 1024
H1_RE = re.compile(r"^#\s+(.+)$", re.M)
H2_RE = re.compile(r"^##\s+(.+)$", re.M)


def _resolve_inside(programs_dir: Path, path: Path) -> Path | None:
    """Resolve path dan pastikan tetap DI DALAM programs_dir.
    Symlink/traversal keluar = None (ditolak, bukan error)."""
    try:
        resolved = path.resolve()
    except OSError:
        return None
    try:
        resolved.relative_to(programs_dir.resolve())
    except ValueError:
        return None
    return resolved


def load_for_program(program: dict, programs_dir: Path | None = None,
                     root: Path | None = None) -> dict | None:
    """Muat threat model untuk satu entri programs/index.json.

    Sumber: field `threat_model` di program (relatif root) → default
    `programs/<id>/threat_model.md`. File WAJIB berada DI DALAM folder
    programs/ (field yang menunjuk keluar = ditolak). Mengembalikan:
      {path, sha256, bytes, title, sections, text}
    None bila tidak ada; dict `rejected` bila ditolak (ukuran, escape,
    path di luar programs/) — penelepon mencatatnya sebagai baris
    audit, bukan kegagalan scan.
    """
    root = (Path(root) if root else ROOT).resolve()
    pdir = (Path(programs_dir) if programs_dir else root / "programs").resolve()
    rel = program.get("threat_model") or str(Path("programs") / str(program.get("id", "")) / "threat_model.md")
    path = (root / rel) if not Path(rel).is_absolute() else Path(rel)
    resolved = _resolve_inside(pdir, path)
    if resolved is None:
        return {"rejected": "path di luar programs/ — ditolak", "path": rel}
    if not resolved.is_file():
        return None
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        return {"rejected": f"tidak terbaca: {exc}", "path": rel}
    if len(raw) > MAX_BYTES:
        return {"rejected": f"ukuran {len(raw)} > {MAX_BYTES} byte — ditolak",
                "path": rel}
    text = raw.decode("utf-8", errors="replace")
    title = (H1_RE.search(text) or [None, ""])[1].strip() if H1_RE.search(text) else ""
    sections = [h.strip() for h in H2_RE.findall(text)]
    try:
        shown = str(resolved.relative_to(root))
    except ValueError:
        shown = str(resolved)
    return {
        "path": shown,
        "sha256": hashlib.sha256(raw).hexdigest()[:16],
        "bytes": len(raw),
        "title": title or resolved.stem,
        "sections": sections[:12],
        "text": text,
    }


def summarize(meta: dict | None, max_chars: int = 600) -> str | None:
    """Ringkasan pendek untuk laporan: judul + daftar bagian."""
    if not meta or meta.get("rejected") or not meta.get("text"):
        return None
    parts = [f"Threat model: {meta.get('title', '')}"]
    if meta.get("sections"):
        parts.append("Bagian: " + "; ".join(meta["sections"][:8]))
    out = "\n".join(parts)
    return out[:max_chars]
